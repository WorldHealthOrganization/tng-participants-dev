"""
tng_certificate_dialect.py
==========================

The **certificate dialect**: the Gherkin step language for WHO GDHCN certificate
governance. Vocabulary and semantics only — bring your own parser.

This deliberately contains no Feature/Scenario/Rule parsing. It takes a step's
*text* (and its data table, if any) and evaluates it against certificate facts.
Bind it to whatever produces those: your ITB base parser, behave, pytest-bdd, or
a hand-rolled loop.

    from tng_certificate_dialect import evaluate, facts_for_folder, Bindings

    subjects = facts_for_folder(Path("."), country="XXR")
    b = Bindings(subject=subjects[0], all_subjects=subjects, country="XXR")

    r = evaluate('"cert" keyUsage "digitalSignature" must be true', b)
    r.outcome     # PASSED | FAILED | SKIPPED | UNKNOWN
    r.message     # why, when it is not PASSED

Three outcomes matter, and conflating any two of them breaks the spec
--------------------------------------------------------------------
    PASSED   the assertion held
    FAILED   the assertion did not hold
    SKIPPED  a guard did not match this certificate — the scenario does not
             apply to it. NOT a pass.
    UNKNOWN  no step definition matched the text at all

`SKIPPED` is the one people get wrong. A step like

    Given "cert" group is "TLS" and filename starts with "TLS"

is a **guard**, not an assertion: when the bound certificate is a UP cert, the
scenario simply does not apply. Treating that as a pass would report that every
UP certificate satisfies every TLS rule.

`UNKNOWN` never silently passes either. The source feature file criticises
"assertions that don't yet check anything", and a dialect that shrugged at
unrecognised text would reintroduce exactly that.

The binding model
-----------------
The feature's Background reads

    Given certificate "cert" is loaded from the participant material

so `cert` denotes *every* certificate in the material, not one. The harness is
expected to run each scenario once per certificate, binding `subject` to each in
turn. `Bindings.all_subjects` is there for the steps that need siblings — the
chain scenarios reach for the CA in the same TLS folder.

Vocabulary
----------
`VOCABULARY` lists every supported step with a description and an example, so a
harness can introspect or document the dialect rather than hard-coding a list.
Every step in `check_certificate_quality.feature` is covered; see
docs/procedure-mapping.md for which of those the *rule engine* also enforces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

import tng_folder_validation as fv

# Facts come from the same module the rules use, so a step and a rule can never
# disagree about what a certificate contains.
describe_cert = fv.describe_cert


def facts_for_folder(folder: Path, country: Optional[str] = None) -> list[dict]:
    """Describe every certificate under a participant folder."""
    return fv.inspect_folder(folder, country)


def facts_for_pem(data: bytes, *, framework: str = "any", material: str = "up",
                  country: Optional[str] = None) -> list[dict]:
    """Describe certificates supplied as bytes rather than read from a folder."""
    mat = fv.synthetic_material(framework, material, data, country)
    if mat is None:
        raise ValueError(f"unsupported material kind {material!r}")
    return [fv.describe_cert(lc) for lc in fv.load_certs(mat)]


# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------


class Outcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


@dataclass
class Result:
    outcome: Outcome
    message: str = ""
    step: str = ""

    def __bool__(self) -> bool:
        return self.outcome is Outcome.PASSED


class _Failure(AssertionError):
    """Internal: the assertion did not hold."""


class _Skip(Exception):
    """Internal: a guard did not match this subject."""


@dataclass
class Bindings:
    """State the harness supplies for one step evaluation.

    `subject`      facts for the certificate this scenario run is bound to
    `all_subjects` every certificate in the material, for sibling lookups
    `country`      the participant's ISO-3166 alpha-3 code, if known
    `names`        variables bound by earlier steps ("tlsCert", "caCert", ...);
                   steps mutate this, so reuse one Bindings across a scenario
    """

    subject: dict
    all_subjects: list[dict] = field(default_factory=list)
    country: Optional[str] = None
    names: dict[str, dict] = field(default_factory=dict)

    def resolve(self, name: str) -> dict:
        return self.names.get(name, self.subject)

    def tls_siblings(self, of: dict) -> list[dict]:
        return [f for f in self.all_subjects
                if f.get("domain") == of.get("domain")
                and (f.get("group") or "").upper() == "TLS"
                and f.get("readable")]


Table = Optional[list[dict[str, str]]]
Handler = Callable[[re.Match, Bindings, Table], None]

_STEPS: list[tuple[re.Pattern, Handler, str, str]] = []


def _step(pattern: str, description: str, example: str) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        _STEPS.append((re.compile(pattern, re.IGNORECASE), fn, description, example))
        return fn
    return register


def _readable(facts: dict) -> None:
    if not facts.get("readable"):
        raise _Failure(f"certificate could not be parsed: {facts.get('error')}")


# ---------------------------------------------------------------------------
# Binding and guards
# ---------------------------------------------------------------------------


@_step(r'^certificate "([^"]+)" is loaded from the participant material$',
       "Bind a name to the certificate this run is about.",
       'Given certificate "cert" is loaded from the participant material')
def _bind(m: re.Match, b: Bindings, _t: Table) -> None:
    b.names[m.group(1)] = b.subject
    _readable(b.subject)


@_step(r'^its group and filename prefix are known$',
       "Assert the certificate sits at <domain>/<group>/<file> so role rules apply.",
       "And its group and filename prefix are known")
def _identity(_m: re.Match, b: Bindings, _t: Table) -> None:
    if not b.subject.get("group") or not b.subject.get("filename"):
        raise _Failure("certificate is not at <domain>/<group>/<file>; its role is unknown")


@_step(r'^"([^"]+)" group is "([^"]+)" and filename starts with "([^"]+)"$',
       "GUARD: narrow the scenario to one group and filename prefix.",
       'Given "cert" group is "TLS" and filename starts with "TLS"')
def _guard_group_prefix(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    if (f.get("group") or "").upper() != m.group(2).upper() or \
       not (f.get("filename") or "").upper().startswith(m.group(3).upper()):
        raise _Skip()
    b.names[m.group(1)] = f


@_step(r'^"([^"]+)" group is "([^"]+)"$',
       "GUARD: narrow the scenario to one group.",
       'Given "cert" group is "UP"')
def _guard_group(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    if (f.get("group") or "").upper() != m.group(2).upper():
        raise _Skip()
    b.names[m.group(1)] = f


@_step(r'^"([^"]+)" is an? (TLS end-entity|SCA|DSC|UP|DECA|CA) certificate$',
       "GUARD: narrow to a role, and bind a name to it.",
       'Given "tlsCert" is a TLS end-entity certificate')
def _guard_role(m: re.Match, b: Bindings, _t: Table) -> None:
    role = m.group(2).upper()
    f = b.subject
    group = (f.get("group") or "").upper()
    fname = (f.get("filename") or "").upper()
    if role == "TLS END-ENTITY":
        ok = group == "TLS" and fname.startswith("TLS")
    elif role == "CA":
        ok = group == "TLS" and fname.startswith("CA")
    else:
        ok = group == role
    if not ok:
        raise _Skip()
    b.names[m.group(1)] = f


@_step(r'^"([^"]+)" is the CA certificate in the same TLS group$',
       "Bind the CA sitting beside a TLS end-entity certificate.",
       'And "caCert" is the CA certificate in the same TLS group')
def _bind_ca(m: re.Match, b: Bindings, _t: Table) -> None:
    subject = b.names.get("tlsCert", b.subject)
    cas = [f for f in b.tls_siblings(subject)
           if (f.get("filename") or "").upper().startswith("CA")]
    if not cas:
        raise _Skip()   # the "no signing CA" scenario is the one that applies
    b.names[m.group(1)] = cas[0]


@_step(r'^no CA certificate in its TLS group verifies it$',
       "GUARD: only applies when nothing in the TLS folder signs this certificate.",
       "And no CA certificate in its TLS group verifies it")
def _guard_no_ca(_m: re.Match, b: Bindings, _t: Table) -> None:
    subject = b.names.get("tlsCert", b.subject)
    if _signing_ca(b, subject) is not None:
        raise _Skip()


@_step(r'^"([^"]+)" is a DSC issued by "([^"]+)"$',
       "Bind a DSC whose issuer matches the named SCA.",
       'And "dsc" is a DSC issued by "sca"')
def _bind_dsc(m: re.Match, b: Bindings, _t: Table) -> None:
    issuer = b.names.get(m.group(2))
    if not issuer:
        raise _Skip()
    issuer_dn = issuer.get("subject", {}).get("rfc4514")
    found = [f for f in b.all_subjects
             if (f.get("group") or "").upper() == "DSC" and f.get("readable")
             and f.get("issuer", {}).get("rfc4514") == issuer_dn]
    if not found:
        raise _Skip()
    b.names[m.group(1)] = found[0]


# ---------------------------------------------------------------------------
# Key strength
# ---------------------------------------------------------------------------


@_step(r'^"([^"]+)" public key must satisfy the minimum size:?$',
       "Table of | algorithm | minBits |. Fails if the key's algorithm is absent "
       "from the table — an unlisted algorithm is unreviewed, not permitted.",
       'Then "cert" public key must satisfy the minimum size:')
def _key_minimum(m: re.Match, b: Bindings, table: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    if not table:
        raise _Failure("this step needs a table of | algorithm | minBits |")
    limits = {r["algorithm"].upper(): int(r["minBits"]) for r in table}
    key = f["publicKey"]
    algorithm = (key.get("algorithm") or "").upper()
    if algorithm not in limits:
        raise _Failure(f"no minimum defined for {algorithm} (table covers {sorted(limits)})")
    if key.get("bits") is None or key["bits"] < limits[algorithm]:
        raise _Failure(f"{algorithm} key is {key.get('bits')} bits, minimum {limits[algorithm]}")


@_step(r'^"([^"]+)" public key algorithm must be one of "([^"]+)"$',
       "Allow-list of algorithms. An entry may constrain the curve, e.g. EC(P-256).",
       'Then "cert" public key algorithm must be one of "RSA, EC(P-256)"')
def _key_allowed(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    key = f["publicKey"]
    algorithm = (key.get("algorithm") or "").upper()
    curve = (key.get("curve") or "").upper()
    for entry in (e.strip().upper() for e in m.group(2).split(",")):
        spec = re.match(r"^([A-Z0-9]+)\(([^)]+)\)$", entry)
        if spec:
            if algorithm == spec.group(1) and _same_curve(curve, spec.group(2)):
                return
        elif algorithm == entry:
            return
    described = f"{algorithm}({key.get('curve')})" if curve else algorithm
    raise _Failure(f"public key algorithm {described} is not one of {m.group(2)}")


def _same_curve(actual: str, expected: str) -> bool:
    """P-256, secp256r1 and prime256v1 all name the same curve."""
    aliases = {
        "P-256": {"P-256", "SECP256R1", "PRIME256V1"},
        "P-384": {"P-384", "SECP384R1"},
        "P-521": {"P-521", "SECP521R1"},
    }
    expected = expected.strip().upper()
    return actual.upper() in aliases.get(expected, {expected})


# ---------------------------------------------------------------------------
# Extensions
# ---------------------------------------------------------------------------


@_step(r'^"([^"]+)" must contain extension "([^"]+)"$',
       "Assert an extension is present, by dotted OID.",
       'Then "cert" must contain extension "2.5.29.15"')
def _has_extension(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    if m.group(2) not in f.get("extensions", []):
        raise _Failure(f"extension {m.group(2)} is absent")


@_step(r'^"([^"]+)" keyUsage "([^"]+)" must be (true|false)$',
       "Assert one keyUsage bit. Flag names are camelCase as in RFC 5280.",
       'Then "cert" keyUsage "cRLSign" must be false')
def _key_usage(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    usages = f.get("keyUsage")
    if usages is None:
        raise _Failure("keyUsage extension is absent")
    # Fact keys are already the RFC 5280 spelling the step text uses, so there is
    # no name transformation here to get wrong.
    flag = m.group(2)
    if flag not in usages:
        raise _Failure(f"unknown keyUsage flag {flag!r}; known: {sorted(usages)}")
    expected = m.group(3).lower() == "true"
    if usages[flag] is not expected:
        raise _Failure(f"keyUsage {flag} is {usages[flag]}, expected {expected}")


@_step(r'^"([^"]+)" EKU must include "([^"]+)"$',
       "Assert an extendedKeyUsage OID is present.",
       'And "cert" EKU must include "1.3.6.1.5.5.7.3.2"')
def _eku_includes(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    eku = f.get("extendedKeyUsage")
    if eku is None:
        raise _Failure("extendedKeyUsage extension is absent")
    if m.group(2) not in eku:
        raise _Failure(f"extendedKeyUsage does not include {m.group(2)}; has {eku}")


@_step(r'^"([^"]+)" EKU requirement is waived for groups "([^"]+)"$',
       "Documentation-only waiver. Passes for the named groups and SKIPS otherwise, "
       "so it can never read as evidence that a TLS leaf's EKU was checked.",
       'Then "cert" EKU requirement is waived for groups "CA, SCA, UP, DECA"')
def _eku_waived(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    waived = {g.strip().upper() for g in m.group(2).split(",")}
    group = (f.get("group") or "").upper()
    fname = (f.get("filename") or "").upper()
    if group in waived or (group == "TLS" and fname.startswith("CA") and "CA" in waived):
        return
    raise _Skip()


# ---------------------------------------------------------------------------
# Basic constraints
# ---------------------------------------------------------------------------


@_step(r'^"([^"]+)" basicConstraints CA must be (true|false)$',
       "Assert the CA boolean. An absent extension counts as CA:false.",
       'Then "cert" basicConstraints CA must be true')
def _bc_ca(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    expected = m.group(2).lower() == "true"
    bc = f.get("basicConstraints")
    actual = bool(bc and bc.get("ca"))
    if actual is not expected:
        where = "absent" if bc is None else f"CA:{actual}"
        raise _Failure(f"basicConstraints is {where}, expected CA:{expected}")


@_step(r'^"([^"]+)" basicConstraints CA must be false for groups:?$',
       "Table of | group |. Applies only to end-entities: within TLS it skips the "
       "CA file, which is a CA by definition.",
       'Then "cert" basicConstraints CA must be false for groups:')
def _bc_ca_false(m: re.Match, b: Bindings, table: Table) -> None:
    f = b.resolve(m.group(1))
    if not table:
        raise _Failure("this step needs a table with a | group | column")
    groups = {r["group"].strip().upper() for r in table}
    group = (f.get("group") or "").upper()
    fname = (f.get("filename") or "").upper()
    if group not in groups or (group == "TLS" and fname.startswith("CA")):
        raise _Skip()
    _readable(f)
    bc = f.get("basicConstraints")
    if bc and bc.get("ca"):
        raise _Failure("end-entity certificate asserts basicConstraints CA:TRUE")


@_step(r'^"([^"]+)" basicConstraints pathLen must be "0 or absent"$',
       "Assert the path length constraint is 0 or not present.",
       'And "cert" basicConstraints pathLen must be "0 or absent"')
def _bc_pathlen(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    bc = f.get("basicConstraints")
    if bc is None:
        raise _Failure("basicConstraints is absent")
    if bc.get("pathLength") not in (None, 0):
        raise _Failure(f"pathLen is {bc['pathLength']}, expected 0 or absent")


# ---------------------------------------------------------------------------
# Chain
# ---------------------------------------------------------------------------


def _signing_ca(b: Bindings, subject: dict) -> Optional[dict]:
    """The CA in the same TLS folder whose subject matches this issuer.

    Name matching, not signature verification — the dialect asserts over facts.
    `tng_folder_validation.check_chain` does the cryptographic check, and both
    run against the same material.
    """
    for candidate in b.tls_siblings(subject):
        if not (candidate.get("filename") or "").upper().startswith("CA"):
            continue
        if subject.get("issuer", {}).get("rfc4514") == candidate.get("subject", {}).get("rfc4514"):
            return candidate
    return None


@_step(r'^"([^"]+)" must be signed by "([^"]+)"$',
       "Assert the issuer DN matches the named CA's subject DN.",
       'Then "tlsCert" must be signed by "caCert"')
def _signed_by(m: re.Match, b: Bindings, _t: Table) -> None:
    child, ca = b.resolve(m.group(1)), b.resolve(m.group(2))
    _readable(child)
    _readable(ca)
    if child.get("issuer", {}).get("rfc4514") != ca.get("subject", {}).get("rfc4514"):
        raise _Failure(f"{child.get('filename')} issuer does not match "
                       f"{ca.get('filename')} subject")


@_step(r'^"([^"]+)" must be rejected$',
       "Assert nothing in the TLS folder signs this certificate.",
       'Then "tlsCert" must be rejected')
def _rejected(m: re.Match, b: Bindings, _t: Table) -> None:
    subject = b.resolve(m.group(1))
    found = _signing_ca(b, subject)
    if found is not None:
        raise _Failure(f"{subject.get('filename')} was not rejected — "
                       f"{found.get('filename')} verifies it")


# ---------------------------------------------------------------------------
# Subject
# ---------------------------------------------------------------------------


@_step(r'^"([^"]+)" subject CN must be non-empty$',
       "Assert the subject carries a non-empty common name.",
       'Then "cert" subject CN must be non-empty')
def _cn(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    cn = f.get("subject", {}).get("commonName")
    if not cn or not str(cn).strip():
        raise _Failure("subject has no non-empty common name")


@_step(r'^"([^"]+)" subject country must equal the participant country$',
       "Assert the subject C resolves to the participant's alpha-3 code. SKIPS "
       "when no participant country is known, rather than passing.",
       'And "cert" subject country must equal the participant country')
def _country(m: re.Match, b: Bindings, _t: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    expected = b.country or f.get("country")
    if not expected:
        raise _Skip()
    resolved = f.get("subject", {}).get("resolvedCountry")
    if resolved is None:
        raise _Failure(f"subject country {f['subject'].get('country')!r} "
                       "is not a known ISO-3166 country")
    if resolved != expected:
        raise _Failure(f"subject country {resolved} != participant {expected}")


# ---------------------------------------------------------------------------
# Validity
# ---------------------------------------------------------------------------


@_step(r'^"([^"]+)" validity must not exceed the limit for its group:?$',
       "Table of | group | maxYears |. Uses upstream's arithmetic: strictly less "
       "than maxYears * 366 days. SKIPS for a group the table does not cover.",
       'Then "cert" validity must not exceed the limit for its group:')
def _validity(m: re.Match, b: Bindings, table: Table) -> None:
    f = b.resolve(m.group(1))
    _readable(f)
    if not table:
        raise _Failure("this step needs a table of | group | maxYears |")
    limits = {r["group"].upper(): int(r["maxYears"]) for r in table}
    group = (f.get("group") or "").upper()
    if group not in limits:
        raise _Skip()
    days = f["validity"]["days"]
    ceiling = limits[group] * 366
    if days >= ceiling:
        raise _Failure(f"{group} validity is {days} days; limit is "
                       f"{limits[group]} years ({ceiling} days)")


@_step(r'^"([^"]+)" notAfter must not exceed "([^"]+)" notAfter$',
       "Assert an issued certificate does not outlive its issuer.",
       'Then "dsc" notAfter must not exceed "sca" notAfter')
def _nested_validity(m: re.Match, b: Bindings, _t: Table) -> None:
    child, parent = b.resolve(m.group(1)), b.resolve(m.group(2))
    _readable(child)
    _readable(parent)
    if child["validity"]["notAfter"] > parent["validity"]["notAfter"]:
        raise _Failure(f"{child.get('filename')} outlives its issuer: "
                       f"{child['validity']['notAfter']} > {parent['validity']['notAfter']}")


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(text: str, bindings: Bindings, table: Table = None) -> Result:
    """Evaluate one Gherkin step against the bound certificate facts.

    `text` is the step WITHOUT its keyword — pass `'"cert" group is "UP"'`, not
    `'Given "cert" group is "UP"'`. Strip the keyword in your parser, where the
    Given/When/Then/And distinction already lives.

    Never raises for an ordinary failure: the outcome is in the Result, so a
    harness maps it to its own reporting without exception handling.
    """
    step_text = strip_keyword(text)
    for pattern, handler, _desc, _example in _STEPS:
        found = pattern.match(step_text)
        if not found:
            continue
        try:
            handler(found, bindings, table)
            return Result(Outcome.PASSED, step=step_text)
        except _Skip:
            return Result(Outcome.SKIPPED, "guard does not match this certificate",
                          step=step_text)
        except _Failure as exc:
            return Result(Outcome.FAILED, str(exc), step=step_text)
        except Exception as exc:   # a broken step must not take the harness down
            return Result(Outcome.FAILED, f"{type(exc).__name__}: {exc}", step=step_text)
    return Result(Outcome.UNKNOWN, f"no step definition matches: {step_text}", step=step_text)


_KEYWORDS = ("given", "when", "then", "and", "but", "*")


def strip_keyword(text: str) -> str:
    """Remove a leading Gherkin keyword, if the caller left one on."""
    stripped = text.strip()
    first, _, rest = stripped.partition(" ")
    if first.lower() in _KEYWORDS:
        return rest.strip()
    return stripped


#: Every supported step: (pattern, description, example). For introspection and
#: documentation — a harness should not hard-code this list.
VOCABULARY: list[dict[str, str]] = [
    {"pattern": pattern.pattern, "description": desc, "example": example}
    for pattern, _fn, desc, example in _STEPS
]


def supports(text: str) -> bool:
    """Is this step text in the dialect?"""
    step_text = strip_keyword(text)
    return any(p.match(step_text) for p, _f, _d, _e in _STEPS)
