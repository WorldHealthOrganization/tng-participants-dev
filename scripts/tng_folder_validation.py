"""
tng_folder_validation.py
========================

Folder-scoped verification of a participant's onboarding tree.

Why this exists alongside the artefact-scoped engine in `tng_trust_service.py`:
four of the governance rules cannot be evaluated from a single file's bytes.

    tls_pem_without_chain   needs to know the file sits in TLS/ and is the leaf
    chain_check             needs the sibling CA*.pem to verify against
    country_flag            needs the country code, which lives in the PATH
    folder_mandatory_files  needs to know which files are ABSENT

So this module takes a *folder* and returns findings, and the service maps those
onto GITB TAR report items.

Provenance
----------
Every rule here is a port of a pytest check in
`WorldHealthOrganization/tng-participants-dev`, `scripts/tests/`. Those checks are
authoritative for governance; this module is a re-expression of them, not a new
policy. Each `check_*` function names its origin file, and where behaviour
DELIBERATELY differs the reason is stated inline and marked `DIVERGENCE:`.

What this module does NOT carry over from the pytest suite
----------------------------------------------------------
The upstream checks infer identity from path depth: `common._PATHINDEX.COUNTRY`
is -5, so the country is "the fifth-from-last path segment". That is only true
for exactly `XXX/onboarding/DOMAIN/GROUP/FILE.pem`, and `PemFileWrapper` swallows
the resulting IndexError with a bare `except: pass` — so on a shorter path the
country silently goes missing, and on a longer one (a service workspace) it
silently resolves to a directory name that is not a country at all. Discovery is
likewise pinned to the process working directory (`glob('./???')`).

Here, `MaterialFile` carries country/domain/group/filename as explicit fields
established once, at collection time, from a known root. Nothing is inferred from
path arithmetic and nothing depends on the process cwd, so the same code serves a
CI checkout and a long-lived service.

There is also no module-level memoisation in this file. Upstream caches
`collect_onboarding_files` and the parsed certificates with `functools.lru_cache`
keyed on a path, which is correct for a one-shot test run and wrong for a resident
process, where re-synced material would keep returning the first scan's verdict.

No secret material, GPG key or signing key is required or read: this module
validates, it does not deliver.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

# Optional heavy dependencies. Both degrade to an explicit INFO finding rather
# than a crash or — worse — a silent pass, matching the service's convention.
try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID

    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False

try:
    import pycountry

    _PYCOUNTRY = True
except Exception:  # pragma: no cover
    _PYCOUNTRY = False

try:
    import yaml

    _YAML = True
except Exception:  # pragma: no cover
    _YAML = False


# ---------------------------------------------------------------------------
# Findings — a storage/transport-neutral result type
# ---------------------------------------------------------------------------
# Deliberately NOT a GITB ReportItem: keeping this module free of any import
# from tng_trust_service avoids a circular import and lets the rules be unit
# tested without FastAPI or pydantic present. The service maps Finding ->
# ReportItem when it assembles the TAR.

ERROR = "error"
WARNING = "warning"
INFO = "info"


@dataclass
class Finding:
    severity: str
    description: str
    location: Optional[str] = None
    test: Optional[str] = None
    assertion_id: Optional[str] = None


@dataclass
class FolderReport:
    """All findings for one country folder, plus what was actually examined."""

    country: Optional[str]
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_examined: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for f in self.findings if f.severity == ERROR)

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.severity == WARNING)


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
# Two layouts exist in the wild and they differ by one path segment:
#
#   hub          XXR/onboarding/PH4H/TLS/TLS.pem   (tng-participants-dev)
#   participant      onboarding/PH4H/TLS/TLS.pem   (tng-participant-DEV-XXR)
#
# In the participant layout the country code is nowhere in the tree, so it has to
# be supplied by the caller. When it is not, country_flag is reported as skipped
# rather than passed — a check that cannot run must not look like a check that
# succeeded.

ISO3_RE = re.compile(r"^[A-Z]{3}$")
ONBOARDING = "onboarding"
CERT_SUFFIXES = (".pem", ".crt")

LAYOUT_HUB = "hub"
LAYOUT_PARTICIPANT = "participant"
LAYOUT_AUTO = "auto"


# ---------------------------------------------------------------------------
# The rule set — thresholds as data
# ---------------------------------------------------------------------------
# Governance owns rules.yaml: key sizes, validity windows, allowed OIDs, the
# mandatory-file list. This module owns the logic that applies them. A threshold
# change is then a data change with a version bump, reviewable by the people who
# actually set policy, and it shows up in every report.
#
# A missing or unreadable rules.yaml is a hard error, not a fallback to built-in
# defaults. Defaults would mean an installation could validate material against
# rules nobody chose, and report success for it.


class RuleSetError(RuntimeError):
    """rules.yaml is missing, unparseable, or incomplete."""


RULES_PATH = Path(os.getenv("TNG_RULES_FILE", Path(__file__).with_name("rules.yaml")))


def load_rules(path: Optional[Path] = None) -> dict:
    target = Path(path) if path else RULES_PATH
    if not target.is_file():
        raise RuleSetError(
            f"governance rule set not found at {target}. Set TNG_RULES_FILE, or "
            "reinstall — this component cannot validate without knowing the rules.")
    if not _YAML:
        raise RuleSetError(f"{target} exists but PyYAML is not installed; cannot read the rule set.")
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuleSetError(f"{target} is not valid YAML: {exc}")
    if not isinstance(data, dict) or not data.get("version"):
        raise RuleSetError(f"{target} must be a mapping carrying a 'version'.")
    for section in ("key_length", "validity", "signature_algorithm", "key_usage",
                    "extended_key_usage", "basic_constraints", "subject", "folder"):
        if section not in data:
            raise RuleSetError(f"{target} is missing the '{section}' section.")
    return data


RULES = load_rules()
RULESET_VERSION: str = str(RULES["version"])

_KEY_LENGTH = RULES["key_length"]
_VALIDITY = RULES["validity"]
_SIGALG = RULES["signature_algorithm"]
_KEY_USAGE = RULES["key_usage"]
_EKU = RULES["extended_key_usage"]
_BASIC = RULES["basic_constraints"]
_SUBJECT = RULES["subject"]
_FOLDER = RULES["folder"]

VALID_GROUPS = tuple(_FOLDER["valid_groups"])
VALID_DOMAINS = tuple(_FOLDER["valid_domains"])
MANDATORY_FILES = tuple((g, f) for g, f in _FOLDER["mandatory_files"])
ALLOWED_SIGNATURE_OIDS: dict[str, str] = {str(k): str(v) for k, v in _SIGALG["allowed"].items()}


def _matches(spec: dict, group: str, filename: str) -> bool:
    """Does a {group, filename_prefix} selector from rules.yaml match this cert?"""
    if "group" in spec and spec["group"].upper() != group:
        return False
    prefix = spec.get("filename_prefix")
    if prefix and not filename.startswith(prefix.upper()):
        return False
    return True


@dataclass
class MaterialFile:
    """One certificate file, with its identity resolved once at collection time.

    `data` lets the same record describe material that never touched a disk — an
    artefact posted to /validate. That is what allows the artefact-scoped and
    folder-scoped surfaces to run *one* set of rules rather than two
    implementations that can drift apart.
    """

    domain: str
    group: str
    filename: str
    path: Optional[Path] = None
    country: Optional[str] = None
    data: Optional[bytes] = None

    @property
    def location(self) -> str:
        """Canonical, forward-slashed, root-relative location for reports."""
        parts = [p for p in (self.country, ONBOARDING, self.domain, self.group, self.filename) if p]
        return "/".join(parts)

    def text(self) -> str:
        # latin-1 never raises on arbitrary bytes; PEM armour is ASCII either way.
        raw = self.data if self.data is not None else self.path.read_bytes()
        return raw.decode("latin-1", errors="replace")


def _subdirs(path: Path) -> list[Path]:
    """Immediate subdirectories, skipping dot-folders.

    The dot-folder skip is upstream's (`common.py`: "Allow folders like .git ...
    to be present without being seen as onboarding files").
    """
    try:
        return sorted((p for p in path.iterdir() if p.is_dir() and not p.name.startswith(".")),
                      key=lambda p: p.name)
    except OSError:
        return []


def onboarding_base(folder: Path) -> Optional[Path]:
    """Locate the `onboarding` directory for a country folder.

    Accepts either the folder that CONTAINS `onboarding/` or the `onboarding`
    directory itself. Upstream distinguishes these by comparing the path against
    the literal string `'./onboarding'` (`common.py:89`), which fails for an
    absolute path or a trailing slash; this looks at the tree instead.
    """
    if folder.name.lower() == ONBOARDING and folder.is_dir():
        return folder
    candidate = folder / ONBOARDING
    return candidate if candidate.is_dir() else None


def collect_material(folder: Path, country: Optional[str]) -> tuple[list[MaterialFile], list[Finding]]:
    """Walk one country folder into MaterialFile records."""
    findings: list[Finding] = []
    base = onboarding_base(folder)
    if base is None:
        findings.append(Finding(
            ERROR, f"No '{ONBOARDING}' folder found under {folder.name}.",
            location=folder.name, test="folder.onboarding.present",
            assertion_id="tng.folder.layout"))
        return [], findings

    materials: list[MaterialFile] = []
    for domain_dir in _subdirs(base):
        for group_dir in _subdirs(domain_dir):
            for entry in sorted(group_dir.iterdir(), key=lambda p: p.name):
                if entry.is_file() and entry.suffix.lower() in CERT_SUFFIXES:
                    materials.append(MaterialFile(
                        domain=domain_dir.name, group=group_dir.name,
                        filename=entry.name, path=entry, country=country))

        # Certificate material sitting directly under the domain, with no group
        # folder, matches none of the group-scoped rules.
        # DIVERGENCE: upstream drops these silently (its path tuples are filtered
        # on len >= 2). Silently ignoring submitted key material is the failure
        # mode this whole exercise is meant to remove, so it is reported.
        for entry in sorted(domain_dir.iterdir(), key=lambda p: p.name):
            if entry.is_file() and entry.suffix.lower() in CERT_SUFFIXES:
                findings.append(Finding(
                    WARNING,
                    f"'{entry.name}' sits directly in domain '{domain_dir.name}' with no "
                    f"group folder ({'/'.join(VALID_GROUPS)}); it was not validated.",
                    location=f"{country + '/' if country else ''}{ONBOARDING}/{domain_dir.name}/{entry.name}",
                    test="folder.group.present", assertion_id="tng.folder.layout"))

    return materials, findings


def discover_country_folders(
    root: Path, layout: str = LAYOUT_AUTO, countries: Optional[list[str]] = None,
    country: Optional[str] = None,
) -> tuple[list[tuple[Path, Optional[str]]], str, list[Finding]]:
    """Find the country folders to validate under `root`.

    Returns (folders, resolved_layout, findings) where each folder is paired with
    its country code (None when the layout does not carry one and none was given).
    """
    findings: list[Finding] = []
    wanted = {c.strip().upper() for c in countries or [] if c.strip()}

    resolved = layout
    if layout == LAYOUT_AUTO:
        if onboarding_base(root) is not None:
            resolved = LAYOUT_PARTICIPANT
        elif any(ISO3_RE.match(d.name) for d in _subdirs(root)):
            resolved = LAYOUT_HUB
        else:
            findings.append(Finding(
                ERROR,
                f"Cannot determine layout under '{root}': it contains neither an "
                f"'{ONBOARDING}' folder (participant layout) nor any ISO-3166 "
                "alpha-3 country folders (hub layout).",
                location=str(root), test="folder.layout.detect",
                assertion_id="tng.folder.layout"))
            return [], layout, findings

    if resolved == LAYOUT_PARTICIPANT:
        if onboarding_base(root) is None:
            findings.append(Finding(
                ERROR, f"No '{ONBOARDING}' folder under '{root}' (participant layout).",
                location=str(root), test="folder.onboarding.present",
                assertion_id="tng.folder.layout"))
            return [], resolved, findings
        code = (country or "").strip().upper() or None
        if code and not ISO3_RE.match(code):
            findings.append(Finding(
                ERROR, f"Country '{code}' is not an ISO-3166 alpha-3 code.",
                location=str(root), test="country.code.format",
                assertion_id="tng.folder.layout"))
            return [], resolved, findings
        return [(root, code)], resolved, findings

    # Hub layout: every top-level ISO3 directory is a country folder.
    folders: list[tuple[Path, Optional[str]]] = []
    seen: set[str] = set()
    for d in _subdirs(root):
        if not ISO3_RE.match(d.name):
            continue
        seen.add(d.name)
        if wanted and d.name not in wanted:
            continue
        folders.append((d, d.name))

    for missing in sorted(wanted - seen):
        findings.append(Finding(
            ERROR, f"No country folder '{missing}' found under '{root}'.",
            location=missing, test="country.folder.present",
            assertion_id="tng.folder.layout"))

    if not folders and not wanted:
        findings.append(Finding(
            WARNING, f"No ISO-3166 alpha-3 country folders found under '{root}'; nothing was validated.",
            location=str(root), test="country.folder.present",
            assertion_id="tng.folder.layout"))
    return folders, resolved, findings


# ---------------------------------------------------------------------------
# Certificate loading
# ---------------------------------------------------------------------------


@dataclass
class LoadedCert:
    """One X.509 certificate, possibly one of several in a single PEM file."""

    material: MaterialFile
    index: int
    cert: object = None            # x509.Certificate when parsed
    error: Optional[str] = None

    @property
    def location(self) -> str:
        # The index only matters when a file holds more than one certificate.
        return self.material.location if self.index == 0 else f"{self.material.location}#{self.index}"

    @property
    def group(self) -> str:
        return (self.material.group or "").upper()

    @property
    def filename(self) -> str:
        return (self.material.filename or "").upper()


BEGIN_CERT = "-----BEGIN CERTIFICATE-----"


def count_certificates(material: MaterialFile) -> int:
    return material.text().count(BEGIN_CERT)


def load_certs(material: MaterialFile) -> list[LoadedCert]:
    """Split a possibly multi-certificate PEM and parse each block.

    Mirrors `common.load_multipart_pem_file`, but a parse failure is recorded on
    the record instead of being attached to an object whose truthiness later
    decides whether tests silently skip.
    """
    text = material.text()
    blocks: list[str] = []
    for line in text.splitlines(keepends=True):
        if BEGIN_CERT in line:
            blocks.append(line)
        elif blocks:
            blocks[-1] += line

    if not blocks:
        return [LoadedCert(material=material, index=0, error="no PEM certificate armour found")]

    out: list[LoadedCert] = []
    for i, block in enumerate(blocks):
        if not _CRYPTO:
            out.append(LoadedCert(material=material, index=i, error=None))
            continue
        try:
            out.append(LoadedCert(material=material, index=i,
                                  cert=x509.load_pem_x509_certificate(block.encode("latin-1"))))
        except Exception as exc:
            out.append(LoadedCert(material=material, index=i, error=str(exc)))
    return out


def _not_valid_after(cert) -> datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _not_valid_before(cert) -> datetime:
    try:
        return cert.not_valid_before_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def _extension(cert, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Per-certificate rules
# ---------------------------------------------------------------------------


def check_pem_parses(lc: LoadedCert) -> Iterator[Finding]:
    """valid_pem.py — the file must parse as an X.509 certificate."""
    if lc.error is None:
        return
    if "armour" in lc.error:
        yield Finding(ERROR, f"Content is not PEM-encoded: {lc.error} (RFC 7468).",
                      location=lc.location, test="pem.armour.present", assertion_id="tng.cert.pem")
    else:
        yield Finding(ERROR, f"Certificate does not parse as X.509: {lc.error}",
                      location=lc.location, test="x509.parse", assertion_id="tng.cert.x509")


def check_validity(lc: LoadedCert) -> Iterator[Finding]:
    """validity.py — at least 30 days of validity must remain.

    DIVERGENCE: upstream compares a naive-UTC notAfter against a naive-LOCAL
    datetime.now(), so its verdict shifts with the host timezone. Both sides are
    UTC here.
    """
    minimum = int(_VALIDITY["min_remaining_days"])
    days = (_not_valid_after(lc.cert) - datetime.now(timezone.utc)).days
    if days < minimum:
        yield Finding(
            ERROR, f"Certificate must be valid for at least {minimum} days; {days} day(s) remain.",
            location=lc.location, test=f"validity.min.{minimum}d",
            assertion_id="tng.cert.validity")


def check_validity_range(lc: LoadedCert) -> Iterator[Finding]:
    """validity_range.py — SCA/DECA 2-4 years, UP/TLS 1-2 years.

    The CA chain of a TLS cert is exempt. The bounds and the asymmetry below are
    upstream's exactly: the minimum is `> min*365 - 1` days and the maximum is
    `< max*366` days, and for SCA/DECA an over-long validity is only a WARNING
    (upstream uses assert_to_warning there but a hard assert everywhere else).
    """
    group, fname = lc.group, lc.filename
    if any(_matches(e, group, fname) for e in _VALIDITY.get("exempt", [])):
        return  # e.g. the CA chain of TLS certs has no validity range restriction
    band = _VALIDITY["ranges"].get(group, _VALIDITY["ranges"]["default"])
    min_years, max_years = int(band["min_years"]), int(band["max_years"])
    max_severity = WARNING if str(band.get("max_severity", "error")) == "warning" else ERROR

    validity = _not_valid_after(lc.cert) - _not_valid_before(lc.cert)
    if not validity > timedelta(days=min_years * 365 - 1):
        yield Finding(
            ERROR,
            f"{lc.material.group} must be valid for at least {min_years} year(s) "
            f"(is: {validity.days} days).",
            location=lc.location, test=f"validity.range.min.{min_years}y",
            assertion_id="tng.cert.validity_range")
    if not validity < timedelta(days=max_years * 366):
        yield Finding(
            max_severity,
            f"{lc.material.group} must be valid for at most {max_years} year(s) "
            f"(is: {validity.days} days).",
            location=lc.location, test=f"validity.range.max.{max_years}y",
            assertion_id="tng.cert.validity_range")


def check_key_length(lc: LoadedCert) -> Iterator[Finding]:
    """key_length.py — RSA/DSA >= 3000 bits, EC >= 250 bits.

    Thresholds are upstream's (3000/250), NOT the round 3072/256 an artefact-level
    reading might assume: a 3008-bit RSA key is acceptable governance-wise.

    An unrecognised key type is an ERROR, matching upstream's `else: assert False,
    'Unsupported key type'`. That matters — an Ed25519 key satisfies neither
    isinstance branch, so a check written as two ifs with no else would pass it
    silently while upstream rejects it.
    """
    allowed = [str(t).upper() for t in _KEY_LENGTH["allowed_types"]]
    pub = lc.cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        kind, bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        kind, bits = "EC", pub.curve.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        kind, bits = "DSA", pub.key_size
    else:
        yield Finding(
            ERROR, f"Unsupported public key type: {type(pub).__name__}. "
                   f"Governance allows {', '.join(allowed)} keys only.",
            location=lc.location, test="key.type.supported",
            assertion_id="tng.crypto.keylength")
        return

    if kind not in allowed:
        yield Finding(
            ERROR, f"{kind} keys are not permitted. Governance allows "
                   f"{', '.join(allowed)} keys only.",
            location=lc.location, test="key.type.supported",
            assertion_id="tng.crypto.keylength")
        return

    minimum = int(_KEY_LENGTH[f"{kind.lower()}_min_bits"])
    if bits < minimum:
        yield Finding(ERROR, f"{kind} key not long enough: {bits} < {minimum} bits.",
                      location=lc.location, test=f"key.length.{kind.lower()}>={minimum}",
                      assertion_id="tng.crypto.keylength")


def check_subject_format(lc: LoadedCert) -> Iterator[Finding]:
    """subject_format.py — the subject must carry EXACTLY ONE country attribute.

    Exactly one, not at-least-one: a certificate with two C attributes has an
    ambiguous country and upstream rejects it.
    """
    expected = int(_SUBJECT["country_attribute_count"])
    attrs = lc.cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if len(attrs) != expected:
        yield Finding(
            ERROR, f"Certificate must have exactly {expected} subject country (C) "
                   f"attribute; found {len(attrs)}.",
            location=lc.location, test=f"subject.country.count=={expected}",
            assertion_id="tng.cert.subject")

    if _SUBJECT.get("require_common_name"):
        cn = lc.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn or not str(cn[0].value).strip():
            yield Finding(
                ERROR, "Subject common name (CN) must be present and non-empty.",
                location=lc.location, test="subject.cn.non_empty",
                assertion_id="tng.cert.subject")


def check_key_usage(lc: LoadedCert) -> Iterator[Finding]:
    """key_usage.py — required keyUsage flags per group.

    DIVERGENCE: upstream tests the TLS leaf with a case-SENSITIVE
    `filename.startswith('TLS')` while using `.upper().startswith('CA')` for the
    CA in the same function, so a file named `tls.pem` matches neither branch and
    is checked not at all. Matching is case-insensitive throughout here.
    """
    usages = _extension(lc.cert, ExtensionOID.KEY_USAGE)
    if usages is None:
        if _KEY_USAGE.get("require_extension", True):
            yield Finding(ERROR, "keyUsage not in x509 extensions.",
                          location=lc.location, test="extension.keyUsage.present",
                          assertion_id="tng.cert.key_usage")
        return

    group, fname = lc.group, lc.filename
    role = next((r for r in _KEY_USAGE["roles"] if _matches(r["match"], group, fname)), None)
    if role is None:
        return  # group carries no keyUsage requirement

    label = role["match"].get("group", group)
    for flag, expected in (role.get("flags") or {}).items():
        actual = bool(getattr(usages, flag, False))
        if actual is bool(expected):
            continue
        spelling = "".join(w.capitalize() if i else w for i, w in enumerate(flag.split("_")))
        yield Finding(
            ERROR,
            f'{label} cert should {"" if expected else "not "}have usage flag "{spelling}".',
            location=lc.location,
            test=f"keyUsage.{'' if expected else '!'}{spelling}",
            assertion_id="tng.cert.key_usage")


def check_signature_algorithm(lc: LoadedCert) -> Iterator[Finding]:
    """signature_algorithm.py — the signing algorithm must be on the allow-list."""
    oid = lc.cert.signature_algorithm_oid
    if oid.dotted_string not in ALLOWED_SIGNATURE_OIDS:
        yield Finding(
            ERROR,
            f"Signature algorithm not allowed: {oid._name if oid._name != 'Unknown OID' else ''} "
            f"({oid.dotted_string}).".replace("  ", " "),
            location=lc.location, test="signature.algorithm.allowed",
            assertion_id="tng.cert.signature_algorithm")


def check_basic_constraints(lc: LoadedCert) -> Iterator[Finding]:
    """basic_constraints.py — SCA certificates must assert CA:TRUE.

    Scoped to SCA only. Upstream's function reads as though it also constrains
    TLS/CA.pem, but its `else: return` fires first for every non-SCA group, so
    that branch is unreachable and TLS CA certificates are in practice
    unconstrained. Replicated as-is: tightening it would change governance, which
    is upstream's call, not this module's. Flagged in docs/validation-rules.md.
    """
    if lc.group not in [g.upper() for g in _BASIC["enforced_groups"]]:
        return
    bc = _extension(lc.cert, ExtensionOID.BASIC_CONSTRAINTS)
    if bc is None:
        yield Finding(ERROR, "basicConstraints not in x509 extensions.",
                      location=lc.location, test="extension.basicConstraints.present",
                      assertion_id="tng.cert.basic_constraints")
        return
    if _BASIC.get("require_ca") and not bc.ca:
        yield Finding(ERROR, "SCA and CA certs must have basicConstraints(CA:TRUE).",
                      location=lc.location, test="basicConstraints.ca",
                      assertion_id="tng.cert.basic_constraints")
    if _BASIC.get("path_length_must_be_zero_or_absent") and bc.path_length:
        yield Finding(ERROR, f"Path length must be 0 or None (is: {bc.path_length}).",
                      location=lc.location, test="basicConstraints.pathLength",
                      assertion_id="tng.cert.basic_constraints")


def check_extended_key_usage(lc: LoadedCert) -> Iterator[Finding]:
    """extended_key_usage.py — TLS leaves must allow clientAuth.

    SCA, UP, DECA and the TLS CA are exempt upstream, so only the TLS leaf is
    actually constrained.
    """
    group, fname = lc.group, lc.filename
    if group in [g.upper() for g in _EKU.get("exempt_groups", [])]:
        return
    if any(_matches(e, group, fname) for e in _EKU.get("exempt", [])):
        return

    requirement = next((r for r in _EKU.get("required_oids", [])
                        if _matches(r["match"], group, fname)), None)
    if requirement is None:
        return

    eku = _extension(lc.cert, ExtensionOID.EXTENDED_KEY_USAGE)
    if eku is None:
        yield Finding(ERROR, "extendedKeyUsage not in extensions.",
                      location=lc.location, test="extension.extendedKeyUsage.present",
                      assertion_id="tng.cert.extended_key_usage")
        return
    present = {u.dotted_string for u in eku}
    for oid, label in (requirement.get("oids") or {}).items():
        if str(oid) not in present:
            yield Finding(
                ERROR, f"TLS (AUTH) certificates must allow {label} ({oid}).",
                location=lc.location, test=f"extendedKeyUsage.{label}",
                assertion_id="tng.cert.extended_key_usage")


def check_group_and_domain(lc: LoadedCert) -> Iterator[Finding]:
    """groups_domains.py — the group must be known, the domain should be."""
    if not lc.material.group:
        yield Finding(ERROR, "Certificate at incorrect location: no group folder.",
                      location=lc.location, test="path.group.present",
                      assertion_id="tng.folder.group")
    elif lc.group not in VALID_GROUPS:
        yield Finding(ERROR, f"Invalid group: {lc.material.group}. Expected one of {list(VALID_GROUPS)}.",
                      location=lc.location, test="path.group.valid",
                      assertion_id="tng.folder.group")
    # Domain is a warning, not an error — upstream's hard assert is commented out
    # in favour of assert_to_warning.
    if not lc.material.domain:
        yield Finding(ERROR, "Certificate at incorrect location: no domain folder.",
                      location=lc.location, test="path.domain.present",
                      assertion_id="tng.folder.domain")
    elif lc.material.domain.upper() not in VALID_DOMAINS:
        severity = WARNING if _FOLDER.get("invalid_domain_severity") == "warning" else ERROR
        yield Finding(severity, f"Invalid domain: {lc.material.domain}.",
                      location=lc.location, test="path.domain.valid",
                      assertion_id="tng.folder.domain")


# ---------------------------------------------------------------------------
# country_flag — the subject country must match the folder
# ---------------------------------------------------------------------------
# Upstream reaches into pycountry's private index (`db._is_loaded`, `db.objects`,
# `db.indices`, `db.no_index`) to inject test countries, in three divergent
# copies: country_flag.py hardcodes ~30, delivery.py hardcodes a slightly
# different ~30, and scripts/tests/testing_countries.json — the only one
# conftest.py actually loads — holds three and does NOT include XXR.
#
# Here the test codes are a plain lookup table consulted BEFORE pycountry, which
# needs no private API and so cannot break on a pycountry upgrade. The set is
# country_flag.py's, that being the copy in force during the certificate checks.
# Override with TNG_TEST_COUNTRIES=<path to JSON {"XX": "XXX", ...}>.

_DEFAULT_TEST_COUNTRIES: dict[str, str] = {
    "XA": "XXA", "XB": "XXB", "XY": "XXY", "XX": "XXX", "XL": "XCL", "XO": "XXO",
    "XM": "XML", "XC": "XXC", "JA": "XJA", "XD": "XXD", "XE": "XXE", "XG": "XXG",
    "XH": "XXH", "XF": "XXF", "XJ": "XXJ", "XK": "XXK", "XI": "XXI", "XQ": "XXQ",
    "XN": "XXN", "XP": "XXP", "XS": "XXS", "XT": "XXT", "XU": "XXU", "XV": "XXV",
    "XW": "XXW", "YK": "XYK", "IO": "IOM", "XR": "XXR",
}


def _load_test_countries() -> dict[str, str]:
    """alpha-2 AND alpha-3 -> alpha-3, so either spelling resolves."""
    table = dict(_DEFAULT_TEST_COUNTRIES)
    override = os.getenv("TNG_TEST_COUNTRIES", "")
    if override:
        try:
            table = {str(k).upper(): str(v).upper()
                     for k, v in json.loads(Path(override).read_text()).items()}
        except Exception:  # pragma: no cover - config error, not a cert problem
            pass
    return {**{a3: a3 for a3 in table.values()}, **table}


TEST_COUNTRIES = _load_test_countries()


def resolve_country(value: str) -> Optional[str]:
    """Resolve a subject C value to an ISO-3166 alpha-3 code, or None."""
    v = (value or "").strip()
    if not v:
        return None
    if v.upper() in TEST_COUNTRIES:
        return TEST_COUNTRIES[v.upper()]
    if _PYCOUNTRY:
        try:
            return pycountry.countries.lookup(v).alpha_3
        except LookupError:
            return None
    return None


def check_country_flag(lc: LoadedCert) -> Iterator[Finding]:
    """country_flag.py — the C value must be a real country and match the folder.

    Upstream gates this behind `--country-mode` and pytest.skips otherwise, which
    means that in a participant repo the check silently does not run. Here a
    missing country code is reported as an explicit INFO: a check that could not
    run must be distinguishable from one that passed.
    """
    attrs = lc.cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if not attrs:
        yield Finding(ERROR, "No country attribute found.", location=lc.location,
                      test="subject.country.present", assertion_id="tng.cert.country_flag")
        return

    value = str(attrs[0].value)
    resolved = resolve_country(value)
    if resolved is None:
        if not _PYCOUNTRY:
            yield Finding(
                INFO, "pycountry is unavailable on this instance; the subject country "
                      f"'{value}' could not be checked against ISO-3166.",
                location=lc.location, test="runtime.pycountry.present",
                assertion_id="tng.engine.unavailable")
            return
        yield Finding(
            ERROR, f"Subject country '{value}' is not a known ISO-3166 country.",
            location=lc.location, test="subject.country.known",
            assertion_id="tng.cert.country_flag")
        return

    if lc.material.country is None:
        yield Finding(
            INFO, f"Subject country is '{resolved}'. The folder does not carry a country "
                  "code and none was supplied, so the two could not be compared.",
            location=lc.location, test="subject.country.matches.folder",
            assertion_id="tng.cert.country_flag")
        return

    if resolved != lc.material.country:
        yield Finding(
            ERROR, f"Subject country does not match the folder: {lc.material.country} != {resolved}.",
            location=lc.location, test="subject.country.matches.folder",
            assertion_id="tng.cert.country_flag")


# Rules needing a successfully parsed certificate, in report order.
CERT_RULES = (
    check_group_and_domain,
    check_signature_algorithm,
    check_key_length,
    check_subject_format,
    check_country_flag,
    check_validity,
    check_validity_range,
    check_extended_key_usage,
    check_key_usage,
    check_basic_constraints,
)


# ---------------------------------------------------------------------------
# Folder-scoped rules
# ---------------------------------------------------------------------------


def check_tls_without_chain(materials: list[MaterialFile], domain: str) -> Iterator[Finding]:
    """tls_pem_without_chain.py — a TLS leaf file holds EXACTLY ONE certificate.

    Exactly one, so an empty file fails too: upstream asserts `count_begin == 1`,
    not `<= 1`.
    """
    for m in materials:
        if m.domain != domain or (m.group or "").upper() != "TLS":
            continue
        if not m.filename.upper().startswith("TLS"):
            continue
        expected = int(_FOLDER.get("tls_leaf_certificate_count", 1))
        n = count_certificates(m)
        if n != expected:
            yield Finding(
                ERROR, f"{m.filename} must contain EXACTLY {'ONE' if expected == 1 else expected} "
                       f"certificate (found {n}); the CA chain belongs in CA.pem.",
                location=m.location, test="tls.single.certificate",
                assertion_id="tng.cert.tls_no_chain")


def _verify_signed_by(child, ca_public_key) -> bool:
    """Raw signature verification of `child` against a CA public key.

    This is upstream's chain_check: a signature check, NOT full RFC 5280 path
    validation (no name chaining, no time nesting, no basicConstraints walk).
    Named accordingly so the report does not overstate what was proven.
    """
    if isinstance(ca_public_key, dsa.DSAPublicKey):
        ca_public_key.verify(child.signature, child.tbs_certificate_bytes,
                             child.signature_hash_algorithm)
    elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
        ca_public_key.verify(child.signature, child.tbs_certificate_bytes,
                             ec.ECDSA(child.signature_hash_algorithm))
    elif isinstance(ca_public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        # DIVERGENCE: upstream falls through to the RSA branch here and dies with a
        # TypeError, because Ed25519 verify() takes two arguments. Handled instead.
        ca_public_key.verify(child.signature, child.tbs_certificate_bytes)
    else:
        ca_public_key.verify(child.signature, child.tbs_certificate_bytes,
                             padding.PKCS1v15(), child.signature_hash_algorithm)
    return True


def check_chain(loaded: list[LoadedCert], domain: str) -> Iterator[Finding]:
    """chain_check.py — every TLS leaf must be signed by one of the CAs present.

    All certificates from every .pem in the domain's TLS folder form the
    candidate store; each TLS*-named certificate must verify against at least one
    CA*-named certificate.
    """
    in_tls = [lc for lc in loaded
              if lc.material.domain == domain and lc.group == "TLS"
              and lc.cert is not None and lc.material.filename.lower().endswith(".pem")]
    leaves = [lc for lc in in_tls if lc.filename.startswith("TLS")]
    cas = [lc for lc in in_tls if lc.filename.startswith("CA")]

    for leaf in leaves:
        if not cas:
            yield Finding(
                ERROR, f"Could not find a signing CA for {leaf.material.filename}: "
                       f"no CA*.pem certificate present in {domain}/TLS.",
                location=leaf.location, test="chain.ca.present",
                assertion_id="tng.cert.chain")
            continue
        verified_by = None
        for ca in cas:
            try:
                if _verify_signed_by(leaf.cert, ca.cert.public_key()):
                    verified_by = ca
                    break
            except InvalidSignature:
                continue  # not this CA; keep looking
            except (UnsupportedAlgorithm, TypeError, ValueError) as exc:
                # DIVERGENCE: upstream re-raises, which turns one odd key into a
                # test error. In a validator that has to return a report, an
                # unusable CA is reported and the search continues.
                yield Finding(
                    WARNING,
                    f"Could not use {ca.material.filename} as a signing CA for "
                    f"{leaf.material.filename}: {exc}",
                    location=ca.location, test="chain.verify",
                    assertion_id="tng.cert.chain")
                continue
        if verified_by is None:
            yield Finding(
                ERROR, f"Could not find a signing CA for {leaf.material.filename}.",
                location=leaf.location, test="chain.verify",
                assertion_id="tng.cert.chain")
        else:
            yield Finding(
                INFO, f"{leaf.material.filename} signature verified against "
                      f"{verified_by.material.filename}. Note: this is a signature check, "
                      "not full RFC 5280 path validation.",
                location=leaf.location, test="chain.verify",
                assertion_id="tng.cert.chain")


def check_mandatory_files(materials: list[MaterialFile], domain: str) -> Iterator[Finding]:
    """folder_mandatory_files.py — TLS/TLS.pem, TLS/CA.pem and UP/UP.pem must exist.

    DIVERGENCE, and the significant one in this module: upstream wraps its own
    assertions in `try/except AssertionError: print(e)`, so this check can never
    fail a PR — a domain missing every mandatory file passes green. Here the
    findings are real errors. SCA/SCA.pem is commented out upstream and stays out.
    """
    present = {((m.group or "").upper(), m.filename.upper())
               for m in materials if m.domain == domain}
    for group, filename in MANDATORY_FILES:
        if (group, filename.upper()) not in present:
            yield Finding(
                ERROR, f"{group}/{filename} is missing in domain {domain}.",
                location=f"{domain}/{group}/{filename}", test="folder.mandatory.files",
                assertion_id="tng.folder.mandatory")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Inspection — the facts, separate from the verdict
# ---------------------------------------------------------------------------
# The rules above answer "does this pass?". A Gherkin step like
# `Then "cert" keyUsage "cRLSign" must be false` asks something different: what
# IS the value? Exposing the facts lets a test harness assert against them
# directly, instead of every new assertion needing a new rule in this module.


def _key_facts(cert) -> dict:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "bits": pub.key_size, "curve": None}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"algorithm": "EC", "bits": pub.curve.key_size, "curve": pub.curve.name}
    if isinstance(pub, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "bits": pub.key_size, "curve": None}
    return {"algorithm": type(pub).__name__, "bits": None, "curve": None}


def describe_cert(lc: "LoadedCert") -> dict:
    """Everything a test harness might want to assert about one certificate."""
    if lc.cert is None:
        return {"location": lc.location, "readable": False, "error": lc.error,
                "group": lc.material.group, "filename": lc.material.filename,
                "domain": lc.material.domain, "country": lc.material.country}

    c = lc.cert
    ku = _extension(c, ExtensionOID.KEY_USAGE)
    bc = _extension(c, ExtensionOID.BASIC_CONSTRAINTS)
    eku = _extension(c, ExtensionOID.EXTENDED_KEY_USAGE)

    # Keys are the RFC 5280 spelling, not cryptography's snake_case, so that a
    # caller with a simple expression language can address one directly —
    # /keyUsage/cRLSign — instead of transforming the name first.
    key_usage = None
    if ku is not None:
        key_usage = {}
        for attribute, rfc in (("digital_signature", "digitalSignature"),
                               ("content_commitment", "contentCommitment"),
                               ("key_encipherment", "keyEncipherment"),
                               ("data_encipherment", "dataEncipherment"),
                               ("key_agreement", "keyAgreement"),
                               ("key_cert_sign", "keyCertSign"),
                               ("crl_sign", "cRLSign")):
            key_usage[rfc] = bool(getattr(ku, attribute, False))
        # encipherOnly/decipherOnly raise unless keyAgreement is set.
        for attribute, rfc in (("encipher_only", "encipherOnly"),
                               ("decipher_only", "decipherOnly")):
            try:
                key_usage[rfc] = bool(getattr(ku, attribute))
            except ValueError:
                key_usage[rfc] = False

    not_before, not_after = _not_valid_before(c), _not_valid_after(c)
    subject_country = c.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    subject_cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

    return {
        "location": lc.location,
        "readable": True,
        "index": lc.index,
        "group": lc.material.group,
        "filename": lc.material.filename,
        "domain": lc.material.domain,
        "country": lc.material.country,
        "subject": {
            "rfc4514": c.subject.rfc4514_string(),
            "commonName": str(subject_cn[0].value) if subject_cn else None,
            "commonNamePresent": bool(subject_cn and str(subject_cn[0].value).strip()),
            "country": str(subject_country[0].value) if subject_country else None,
            "countryAttributeCount": len(subject_country),
            "resolvedCountry": resolve_country(str(subject_country[0].value))
                               if subject_country else None,
        },
        "issuer": {"rfc4514": c.issuer.rfc4514_string()},
        "serialNumber": format(c.serial_number, "x"),
        "publicKey": _key_facts(c),
        "signatureAlgorithm": {
            "oid": c.signature_algorithm_oid.dotted_string,
            "name": c.signature_algorithm_oid._name,
            "allowed": c.signature_algorithm_oid.dotted_string in ALLOWED_SIGNATURE_OIDS,
        },
        "validity": {
            "notBefore": not_before.isoformat(),
            "notAfter": not_after.isoformat(),
            "days": (not_after - not_before).days,
            "daysRemaining": (not_after - datetime.now(timezone.utc)).days,
        },
        "extensions": sorted(e.oid.dotted_string for e in c.extensions),
        # The same information keyed by OID. JSON Pointer cannot search an array,
        # so a caller holding only pointer expressions — a GITB TDL step — needs
        # a map to ask "is this present?" in a single hop.
        "extensionsByOid": {e.oid.dotted_string: True for e in c.extensions},
        "keyUsage": key_usage,
        "extendedKeyUsage": sorted(u.dotted_string for u in eku) if eku is not None else None,
        "extendedKeyUsageByOid": ({u.dotted_string: True for u in eku}
                                  if eku is not None else {}),
        "basicConstraints": ({
            "ca": bool(bc.ca),
            "pathLength": bc.path_length,
            # Precomputed: "0 or absent" is two conditions, and a pointer
            # expression can only fetch one value.
            "pathLengthOk": bc.path_length in (None, 0),
        } if bc is not None else None),
    }


def inspect_folder(folder: Path, country: Optional[str] = None) -> list[dict]:
    """Describe every certificate in a country folder."""
    materials, _ = collect_material(folder, country)
    out: list[dict] = []
    for m in materials:
        for lc in load_certs(m):
            out.append(describe_cert(lc))
    return out


def facts_for_bytes(data: bytes, *, framework: str = "any", material: str = "up",
                    country: Optional[str] = None) -> list[dict]:
    """Describe certificates supplied as bytes rather than read from a folder."""
    mat = synthetic_material(framework, material, data, country)
    if mat is None:
        raise ValueError(f"unsupported material kind {material!r}")
    return [describe_cert(lc) for lc in load_certs(mat)]


# ---------------------------------------------------------------------------
# Artefact-scoped entry point
# ---------------------------------------------------------------------------
# A GITB validationType is "<framework>.<material>", e.g. dcc.tls. Upstream's
# rules key off the GROUP FOLDER and the FILENAME, not off a content type, so a
# validationType maps cleanly onto the path identity the rules expect:
#
#     dcc.tls  ->  DCC/TLS/TLS.pem      dcc.up   ->  DCC/UP/UP.pem
#     dcc.ca   ->  DCC/TLS/CA.pem       dcc.sca  ->  DCC/SCA/SCA.pem
#
# Note `ca` maps into the TLS group: upstream treats CA.pem as a file inside the
# TLS folder, and several rules (validity_range, key_usage, extended_key_usage)
# branch on exactly that.

MATERIAL_TO_PATH: dict[str, tuple[str, str]] = {
    "tls": ("TLS", "TLS.pem"),
    "ca": ("TLS", "CA.pem"),
    "up": ("UP", "UP.pem"),
    "sca": ("SCA", "SCA.pem"),
    "deca": ("DECA", "DECA.pem"),
}


def synthetic_material(framework: str, material: str, data: bytes,
                       country: Optional[str] = None) -> Optional[MaterialFile]:
    """Describe posted bytes as though they sat at their canonical path."""
    entry = MATERIAL_TO_PATH.get(material.lower())
    if entry is None:
        return None
    group, filename = entry
    return MaterialFile(domain=framework.upper(), group=group, filename=filename,
                        country=country, data=data)


def validate_artifact(data: bytes, framework: str, material: str, *,
                      country: Optional[str] = None,
                      ca_material: Optional[list[bytes]] = None) -> list[Finding]:
    """Run the certificate rules over one posted artefact.

    Deliberately the SAME rule functions the folder path uses. There is no second
    implementation to keep in step, so /validate and the folder endpoints cannot
    disagree about what the governance rules say.

    Folder-scoped rules degrade honestly rather than silently:
      * mandatory-files cannot be evaluated at all and is simply absent
      * country_flag emits an INFO when no country is supplied
      * chain is checked when CA material is supplied and reported as unverifiable
        when it is not
    """
    mat = synthetic_material(framework, material, data, country)
    if mat is None:
        return [Finding(ERROR, f"Unsupported material kind '{material}'.",
                        test="validationType.material", assertion_id="tng.engine.error")]

    findings: list[Finding] = []
    if not _CRYPTO:
        return [Finding(
            INFO, "Certificate parsing library (cryptography) unavailable on this instance; "
                  "structural checks were skipped.",
            test="runtime.cryptography.present", assertion_id="tng.engine.unavailable")]

    loaded = load_certs(mat)
    for lc in loaded:
        if lc.error is not None or lc.cert is None:
            findings.extend(check_pem_parses(lc))
            continue
        for rule in CERT_RULES:
            try:
                findings.extend(rule(lc))
            except Exception as exc:
                findings.append(Finding(
                    ERROR, f"Check '{rule.__name__}' failed to evaluate: {exc}",
                    location=lc.location, test=rule.__name__, assertion_id="tng.engine.error"))

    # TLS leaves must be a single certificate.
    if mat.group == "TLS" and mat.filename.upper().startswith("TLS"):
        findings.extend(check_tls_without_chain([mat], mat.domain))

        cas = [MaterialFile(domain=mat.domain, group="TLS", filename=f"CA{i or ''}.pem",
                            country=country, data=blob)
               for i, blob in enumerate(ca_material or [])]
        if not cas:
            findings.append(Finding(
                WARNING, "No CA material supplied (externalRules); the chain could not be verified.",
                location=mat.location, test="chain.material.present",
                assertion_id="tng.cert.chain"))
        else:
            pool = list(loaded)
            for ca in cas:
                pool.extend(load_certs(ca))
            findings.extend(check_chain(pool, mat.domain))

    return findings


def validate_folder(
    folder: Path, country: Optional[str], allowed_domains: Optional[list[str]] = None,
) -> FolderReport:
    """Run every rule over one country folder."""
    report = FolderReport(country=country, root=str(folder))

    materials, layout_findings = collect_material(folder, country)
    report.findings.extend(layout_findings)
    if not materials:
        if not any(f.severity == ERROR for f in layout_findings):
            report.findings.append(Finding(
                ERROR, f"No certificate material (*.pem, *.crt) found under {folder.name}/{ONBOARDING}.",
                location=folder.name, test="folder.material.present",
                assertion_id="tng.folder.mandatory"))
        return report

    report.files_examined = [m.location for m in materials]
    report.domains = sorted({m.domain for m in materials})

    if not _CRYPTO:
        report.findings.append(Finding(
            INFO, "Certificate parsing library (cryptography) unavailable on this instance; "
                  "certificate checks were skipped.",
            test="runtime.cryptography.present", assertion_id="tng.engine.unavailable"))
        return report

    # --- per-certificate ---------------------------------------------------
    loaded: list[LoadedCert] = []
    for m in materials:
        for lc in load_certs(m):
            loaded.append(lc)
            if lc.error is not None or lc.cert is None:
                report.findings.extend(check_pem_parses(lc))
                continue
            for rule in CERT_RULES:
                try:
                    report.findings.extend(rule(lc))
                except Exception as exc:  # a rule must never take the request down
                    report.findings.append(Finding(
                        ERROR, f"Check '{rule.__name__}' failed to evaluate: {exc}",
                        location=lc.location, test=rule.__name__,
                        assertion_id="tng.engine.error"))

    # --- per-domain --------------------------------------------------------
    # An empty allowedDomains means "check every domain found". Upstream's
    # read_allowed_domain_from_env() returns ('',) when ALLOWED_DOMAINS is unset,
    # which matches no domain and silently disables the mandatory-file check
    # entirely; checking nothing must not be the default.
    allow = {d.strip().upper() for d in (allowed_domains or []) if d.strip()}
    if not allow:
        report.findings.append(Finding(
            INFO, "No allowedDomains supplied; mandatory-file checks were applied to every "
                  f"domain found ({', '.join(report.domains)}).",
            test="folder.mandatory.scope", assertion_id="tng.folder.mandatory"))

    for domain in report.domains:
        report.findings.extend(check_tls_without_chain(materials, domain))
        report.findings.extend(check_chain(loaded, domain))
        if allow and domain.upper() not in allow:
            report.findings.append(Finding(
                INFO, f"Domain '{domain}' is not in allowedDomains; its mandatory-file "
                      "check was skipped.",
                location=domain, test="folder.mandatory.scope",
                assertion_id="tng.folder.mandatory"))
            continue
        report.findings.extend(check_mandatory_files(materials, domain))

    return report


def validate_folders(
    root: Path, layout: str = LAYOUT_AUTO, countries: Optional[list[str]] = None,
    country: Optional[str] = None, allowed_domains: Optional[list[str]] = None,
) -> tuple[list[FolderReport], str]:
    """Discover and validate every requested country folder under `root`."""
    folders, resolved, findings = discover_country_folders(root, layout, countries, country)
    reports = [validate_folder(f, code, allowed_domains) for f, code in folders]

    if findings:
        # Discovery problems belong to no single country; carry them in their own
        # report so they cannot be lost.
        discovery = FolderReport(country=None, root=str(root), findings=findings)
        reports.insert(0, discovery)
    return reports, resolved
