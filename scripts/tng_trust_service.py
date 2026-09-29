"""
tng_trust_service.py
====================

REST services for the WHO Trust Network Gateway (TNG) participant pipeline,
covering the full path

        upload  ->  verification  ->  processing

for a participant's key material, expressed in the endpoint idiom of the
EC Interoperability Test Bed (ITB) / GITB validator services so that the
verification core is a drop-in for anything that already speaks ITB — Gazelle's
GITB REST client, a Test Bed TDL `verify` step, or a plain curl.

Origin: this replaces the opaque hourly job
    WorldHealthOrganization/tng-participants-dev
    .github/workflows/sys-on-cron-delivery-ext.yml
whose real work (pull key material -> apply the QA rules from the repo README ->
sign -> commit to the trust list) is here split into addressable services.

--------------------------------------------------------------------------------
ITB / GITB endpoint convention (this is the part that must stay faithful)
--------------------------------------------------------------------------------
Verification is environment-agnostic (the governance rules are identical across
dev/uat/prod), so there is a single validation *domain* (`tng`). Environment is a
parameter on the stateful `process` step only, where it selects the trust list:

    GET  /{domain}/api/info               -> module definition: the validation
                                             types this domain supports and the
                                             inputs each expects (getModuleDefinition)
    POST /{domain}/api/validate           -> validate ONE input, return a GITB TAR
    POST /{domain}/api/validateMultiple   -> validate an ARRAY of inputs, array of TARs

Request body (GITB REST `ValidateRequest`):
    {
      "contentToValidate": "<base64 | url | inline string>",
      "embeddingMethod":   "BASE64" | "URL" | "STRING",
      "validationType":    "dcc.tls",        # <framework>.<material-kind>
      "contentSyntax":     "application/x-pem-file",   # optional
      "externalRules":     [ { "ruleSet": "...", "embeddingMethod": "BASE64" } ],  # e.g. CA chain
      "reportSyntax":      "application/json" | "application/xml",  # optional; Accept also honoured
      "locale":            "en",
      "addInputToReport":  false
    }

Response: a GITB TAR (Test Assertion Report) — `result`, `counts`
{nrOfAssertions,nrOfErrors,nrOfWarnings}, `reports` (typed BAR items),
`overview` (validationServiceName/Version/profileID), `context`, `date`.

TNG-specific extensions (upload + processing) sit alongside, in the same
`/{domain}/api/...` style but clearly outside the ITB validator contract:

    POST /{domain}/api/submissions              -> upload key material, get a submission
    GET  /{domain}/api/submissions/{id}         -> submission + latest verification TAR
    POST /{domain}/api/submissions/{id}/sign    -> body {environment}; sign + self-verify
    POST /{domain}/api/submissions/{id}/deploy  -> body {dry_run}; commit to the trust list

Run:
    uvicorn tng_trust_service:app --host 127.0.0.1 --port 8080

Requires: fastapi, uvicorn, pydantic>=2.  `cryptography` is used for the real
certificate checks when present; the service degrades honestly (UNDEFINED result
with an info finding) when it is not, rather than crashing.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import uuid
import xml.sax.saxutils as sax
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path as FsPath          # `Path` is FastAPI's path-param helper here
from typing import Any, Callable, Optional

from fastapi import (APIRouter, Body, FastAPI, Header, HTTPException, Path as PathParam, Query,
                     Request, Response, status)
from pydantic import BaseModel, Field

import tng_folder_validation as fv
from tng_delivery_policy import DeliveryMode, PolicyError
from tng_delivery_policy import resolve as resolve_delivery_policy

log = logging.getLogger("tng.trust")

# Load .env before any module-level os.getenv below. `.env.example` has always
# told people to "copy to .env and edit"; until this existed, nothing read it.
#
# override=False so a real environment variable always beats the file — the
# deployed shape sets variables directly, and a stale .env left in a working
# directory must never silently win over them. Set TNG_SKIP_DOTENV=1 to disable
# (the test suite does, so a developer's local .env cannot change test outcomes).
if not os.getenv("TNG_SKIP_DOTENV"):
    try:
        from dotenv import load_dotenv

        load_dotenv(override=False)
    except ImportError:  # pragma: no cover - python-dotenv is optional
        pass

SERVICE_NAME = "WHO TNG Trust Material Validator"
SERVICE_VERSION = "1.0.0"
PARTICIPANT_CODE_RE = re.compile(r"^[A-Z]{3}$")

# Optional heavy dependency — checks that need it declare so.
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False


# ---------------------------------------------------------------------------
# GITB core types (subset of the GITB TRL / TAR model, JSON + XML renderable)
# ---------------------------------------------------------------------------


class EmbeddingMethod(str, Enum):
    BASE64 = "BASE64"
    STRING = "STRING"
    URL = "URL"


class TestResult(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    WARNING = "WARNING"
    UNDEFINED = "UNDEFINED"


class ItemType(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ReportItem(BaseModel):
    """A GITB BAR (BasicAssertionReport) item."""

    type: ItemType
    description: str
    location: Optional[str] = None          # e.g. "TLS.pem", "subject", "content:2:0"
    test: Optional[str] = None              # the rule that produced the finding
    assertionID: Optional[str] = None       # stable rule id, e.g. "tng.cert.validity"


class ValidationCounters(BaseModel):
    nrOfAssertions: int = 0
    nrOfErrors: int = 0
    nrOfWarnings: int = 0


class Overview(BaseModel):
    validationServiceName: str = SERVICE_NAME
    validationServiceVersion: str = SERVICE_VERSION
    profileID: Optional[str] = None         # the applied validationType
    customizationID: Optional[str] = None
    # WHICH rules produced this verdict. A report that says only "passed" cannot
    # be reconciled later against a different instance; this makes a disagreement
    # between repo A, a participant's repo B and an ITB run diagnosable.
    ruleSetVersion: str = fv.RULESET_VERSION


class TAR(BaseModel):
    """GITB Test Assertion Report."""

    date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    result: TestResult = TestResult.UNDEFINED
    counts: ValidationCounters = Field(default_factory=ValidationCounters)
    reports: list[ReportItem] = Field(default_factory=list)
    overview: Overview = Field(default_factory=Overview)
    context: dict[str, Any] = Field(default_factory=dict)
    name: Optional[str] = None
    id: Optional[str] = None

    @classmethod
    def from_items(cls, items: list[ReportItem], *, profile: str, name: str,
                   context: Optional[dict] = None) -> "TAR":
        errors = sum(1 for i in items if i.type == ItemType.ERROR)
        warnings = sum(1 for i in items if i.type == ItemType.WARNING)
        undefined = any(i.assertionID == "tng.engine.unavailable" for i in items)
        if undefined:
            result = TestResult.UNDEFINED
        elif errors:
            result = TestResult.FAILURE
        elif warnings:
            result = TestResult.WARNING
        else:
            result = TestResult.SUCCESS
        return cls(
            result=result,
            counts=ValidationCounters(nrOfAssertions=len(items), nrOfErrors=errors, nrOfWarnings=warnings),
            reports=items,
            overview=Overview(profileID=profile),
            context=context or {},
            name=name,
            id=str(uuid.uuid4()),
        )


def tar_to_xml(tar: TAR) -> str:
    """Render a TAR as GITB TRL XML (namespaces per the gitb tr/core schemas)."""

    def esc(v: Any) -> str:
        return sax.escape(str(v))

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<tr:TestStepReport xmlns:tr="http://www.gitb.com/tr/v1/"'
        ' xmlns:trs="http://www.gitb.com/core/v1/"'
        ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        ' xsi:type="tr:TAR">',
        f"  <tr:date>{esc(tar.date.isoformat())}</tr:date>",
        f"  <tr:result>{esc(tar.result.value)}</tr:result>",
        "  <tr:counts>",
        f"    <tr:nrOfAssertions>{tar.counts.nrOfAssertions}</tr:nrOfAssertions>",
        f"    <tr:nrOfErrors>{tar.counts.nrOfErrors}</tr:nrOfErrors>",
        f"    <tr:nrOfWarnings>{tar.counts.nrOfWarnings}</tr:nrOfWarnings>",
        "  </tr:counts>",
        "  <tr:overview>",
        f"    <tr:validationServiceName>{esc(tar.overview.validationServiceName)}</tr:validationServiceName>",
        f"    <tr:validationServiceVersion>{esc(tar.overview.validationServiceVersion)}</tr:validationServiceVersion>",
    ]
    if tar.overview.profileID:
        lines.append(f"    <tr:profileID>{esc(tar.overview.profileID)}</tr:profileID>")
    if tar.overview.ruleSetVersion:
        lines.append(f"    <tr:customizationID>{esc(tar.overview.ruleSetVersion)}</tr:customizationID>")
    lines.append("  </tr:overview>")
    lines.append("  <tr:reports>")
    for it in tar.reports:
        tag = {"error": "tr:error", "warning": "tr:warning", "info": "tr:info"}[it.type.value]
        lines.append(f'    <{tag} xsi:type="tr:BAR">')
        lines.append(f"      <tr:description>{esc(it.description)}</tr:description>")
        if it.location:
            lines.append(f"      <tr:location>{esc(it.location)}</tr:location>")
        if it.test:
            lines.append(f"      <tr:test>{esc(it.test)}</tr:test>")
        if it.assertionID:
            lines.append(f"      <tr:assertionID>{esc(it.assertionID)}</tr:assertionID>")
        lines.append(f"    </{tag}>")
    lines.append("  </tr:reports>")
    lines.append("</tr:TestStepReport>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Request models (GITB REST ValidateRequest)
# ---------------------------------------------------------------------------


class RuleSet(BaseModel):
    ruleSet: str
    embeddingMethod: EmbeddingMethod = EmbeddingMethod.BASE64
    contentSyntax: Optional[str] = None


class ValidateRequest(BaseModel):
    contentToValidate: str
    embeddingMethod: EmbeddingMethod = EmbeddingMethod.BASE64
    validationType: str
    contentSyntax: Optional[str] = None
    externalRules: Optional[list[RuleSet]] = None   # e.g. the CA chain for a chain check
    reportSyntax: Optional[str] = None
    locale: str = "en"
    addInputToReport: bool = False
    country: Optional[str] = None                   # ISO-3166 alpha-3; enables the
                                                    # subject-country match check, which
                                                    # otherwise reports that it could not run


def resolve_content(value: str, method: EmbeddingMethod) -> bytes:
    if method == EmbeddingMethod.BASE64:
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"contentToValidate is not valid base64: {exc}")
    if method == EmbeddingMethod.STRING:
        return value.encode()
    # URL: deliberately not auto-fetched here. Pulling arbitrary URLs server-side in a
    # trust component is an SSRF surface; wire it to an allow-listed fetcher before enabling.
    raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED,
                        "embeddingMethod URL is disabled in this deployment; send BASE64 or STRING")


# ---------------------------------------------------------------------------
# Verification engine
# ---------------------------------------------------------------------------
# A validationType is "<framework>.<material>", e.g. dcc.tls / ph4h.up / any.did.
# Each maps to an ordered list of assertions. An assertion inspects the resolved
# bytes (+ any externalRules) and appends ReportItems. This is the REST surface of
# every scripts/tests/*.py rule in the participants repo README.


AssertionFn = Callable[[bytes, ValidateRequest, list["ReportItem"]], None]


def _engine_unavailable(items: list[ReportItem]) -> None:
    items.append(ReportItem(
        type=ItemType.INFO,
        description="Certificate parsing library unavailable on this instance; "
                    "structural checks were skipped.",
        assertionID="tng.engine.unavailable",
        test="runtime.cryptography.present",
    ))


def to_report_item(finding: fv.Finding) -> ReportItem:
    """Map a rules-engine Finding onto a GITB BAR item."""
    return ReportItem(
        type=ItemType(finding.severity), description=finding.description,
        location=finding.location, test=finding.test, assertionID=finding.assertion_id)


def a_did(data: bytes, req: ValidateRequest, items: list[ReportItem]) -> None:
    items.append(ReportItem(
        type=ItemType.INFO, location="content",
        description="DID checks (resolvable, domain linkage, JWK form, unique keys, no private JWK) "
                    "are not yet implemented in this instance.",
        assertionID="tng.did", test="did.suite"))


def a_jwks(data: bytes, req: ValidateRequest, items: list[ReportItem]) -> None:
    items.append(ReportItem(
        type=ItemType.INFO, location="content",
        description="JWKS checks (resolvable, secure URI, valid format, unique keys, no private JWK) "
                    "are not yet implemented in this instance.",
        assertionID="tng.jwks", test="jwks.suite"))


# material-kind -> how it is validated.
#
# `None` means "a certificate": route it to the shared rule set in
# tng_folder_validation, which is the SAME code the folder-scoped endpoints run.
# There is deliberately no second implementation of the governance rules here —
# an earlier one existed, written from the public README before upstream's
# scripts/tests/ could be read, and it disagreed with them on key length,
# subject cardinality and the chain check. See docs/validation-rules.md.
MATERIAL_SUITES: dict[str, Optional[list[AssertionFn]]] = {
    "tls": None,
    "ca": None,
    "up": None,
    "sca": None,
    "deca": None,
    "did": [a_did],
    "jwks": [a_jwks],
}
# frameworks (trust domains) recognised as the validationType prefix
FRAMEWORKS = {"dcc", "ph4h", "ddcc", "racsel", "any"}


def parse_validation_type(validation_type: str) -> tuple[str, str]:
    parts = validation_type.lower().split(".", 1)
    if len(parts) != 2 or parts[0] not in FRAMEWORKS or parts[1] not in MATERIAL_SUITES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"unknown validationType '{validation_type}'. Expected <framework>.<material> "
            f"with framework in {sorted(FRAMEWORKS)} and material in {sorted(MATERIAL_SUITES)}.",
        )
    return parts[0], parts[1]


def run_validation(req: ValidateRequest) -> TAR:
    framework, material = parse_validation_type(req.validationType)
    data = resolve_content(req.contentToValidate, req.embeddingMethod)
    suite = MATERIAL_SUITES[material]
    items: list[ReportItem] = []
    if suite is None:
        cas = [resolve_content(r.ruleSet, r.embeddingMethod) for r in (req.externalRules or [])]
        items = [to_report_item(f) for f in fv.validate_artifact(
            data, framework, material, country=req.country, ca_material=cas or None)]
    else:
        for assertion in suite:
            assertion(data, req, items)
    context: dict[str, Any] = {}
    if req.addInputToReport:
        context["input"] = {"embeddingMethod": req.embeddingMethod.value, "value": req.contentToValidate}
    return TAR.from_items(items, profile=req.validationType,
                          name=f"TNG verification report ({req.validationType})", context=context)


# ---------------------------------------------------------------------------
# Folder-scoped validation
# ---------------------------------------------------------------------------
# Four governance rules cannot be answered from one artefact's bytes: the chain
# needs the sibling CA, country_flag needs the country from the path, the
# mandatory-file check needs to know what is ABSENT, and tls_no_chain needs to
# know the file is a TLS leaf. So there is a folder-shaped surface alongside the
# artefact-shaped one. Both run the same rules.
#
# It holds no keys and creates nothing: this validates, it does not deliver.

#: Filesystem root that folder validation may read. Everything is resolved inside
#: it and anything escaping is refused — a server-side path parameter is an
#: arbitrary-file-read surface otherwise.
VALIDATION_ROOT = FsPath(os.getenv("TNG_VALIDATION_ROOT", os.getcwd())).resolve()


class ValidateFoldersRequest(BaseModel):
    root: Optional[str] = Field(
        default=None,
        description="Directory to validate, relative to TNG_VALIDATION_ROOT. "
                    "Omit for the root itself.")
    countries: Optional[list[str]] = Field(
        default=None,
        description="ISO-3166 alpha-3 subset (hub layout). Omit to validate every "
                    "country folder found.")
    country: Optional[str] = Field(
        default=None,
        description="The country a participant-layout folder belongs to. Without it the "
                    "subject-country match cannot run and says so.")
    layout: str = Field(default="auto", description="auto | hub | participant")
    allowedDomains: Optional[list[str]] = Field(
        default=None,
        description="Domains subject to the mandatory-file check. Omit to check every "
                    "domain found.")
    reportSyntax: Optional[str] = None


def resolve_validation_path(relative: Optional[str]) -> FsPath:
    candidate = (VALIDATION_ROOT / (relative or "")).resolve()
    if candidate != VALIDATION_ROOT and VALIDATION_ROOT not in candidate.parents:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"root '{relative}' resolves outside TNG_VALIDATION_ROOT")
    if not candidate.is_dir():
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such directory: '{relative or '.'}'")
    return candidate


def folder_report_to_tar(report: fv.FolderReport, profile: str) -> TAR:
    items = [to_report_item(f) for f in report.findings]
    name = (f"TNG folder verification report ({report.country})" if report.country
            else "TNG folder verification report")
    return TAR.from_items(items, profile=profile, name=name, context={
        "country": report.country,
        "domains": report.domains,
        "filesExamined": report.files_examined,
    })


def run_folder_validation(req: ValidateFoldersRequest) -> list[TAR]:
    root = resolve_validation_path(req.root)
    if req.layout not in (fv.LAYOUT_AUTO, fv.LAYOUT_HUB, fv.LAYOUT_PARTICIPANT):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"unknown layout '{req.layout}'; expected auto | hub | participant")
    try:
        reports, resolved = fv.validate_folders(
            root, layout=req.layout, countries=req.countries, country=req.country,
            allowed_domains=req.allowedDomains)
    except OSError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"could not read {root}: {exc}")
    return [folder_report_to_tar(r, f"tng.folder.{resolved}") for r in reports]


class InspectRequest(BaseModel):
    """Ask what a certificate IS, rather than whether it passes.

    Accepts either posted content or a folder plus a selector. The selector
    exists so a caller with a simple expression language — a GITB TDL test step
    using JsonPointer, say — can address one certificate without having to
    filter a list itself.
    """

    # artefact form
    contentToValidate: Optional[str] = None
    embeddingMethod: EmbeddingMethod = EmbeddingMethod.BASE64
    validationType: Optional[str] = Field(
        default=None, description="<framework>.<material>, e.g. ph4h.tls")
    # folder form
    root: Optional[str] = Field(default=None,
                                description="Directory relative to TNG_VALIDATION_ROOT")
    layout: str = "auto"
    country: Optional[str] = None
    # selection, applied to the folder form
    materialDomain: Optional[str] = Field(default=None, description="e.g. PH4H")
    group: Optional[str] = Field(default=None, description="TLS | UP | SCA | DECA")
    filename: Optional[str] = Field(default=None, description="e.g. TLS.pem")


class InspectResponse(BaseModel):
    count: int
    #: Present when the selection matched exactly one certificate, so a caller
    #: can point straight at /certificate/... instead of indexing a list.
    certificate: Optional[dict[str, Any]] = None
    certificates: list[dict[str, Any]] = Field(default_factory=list)


def run_inspection(req: InspectRequest) -> InspectResponse:
    if req.contentToValidate is not None:
        if not req.validationType:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "validationType is required when inspecting posted content")
        framework, material = parse_validation_type(req.validationType)
        data = resolve_content(req.contentToValidate, req.embeddingMethod)
        found = fv.facts_for_bytes(data, framework=framework, material=material,
                                   country=req.country)
    else:
        root = resolve_validation_path(req.root)
        found = fv.inspect_folder(root, req.country)
        if req.layout != "auto" and req.layout not in (fv.LAYOUT_HUB, fv.LAYOUT_PARTICIPANT):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown layout '{req.layout}'")

    def keep(c: dict) -> bool:
        for wanted, key in ((req.materialDomain, "domain"), (req.group, "group"),
                            (req.filename, "filename")):
            if wanted and str(c.get(key) or "").upper() != wanted.upper():
                return False
        return True

    found = [c for c in found if keep(c)]
    return InspectResponse(count=len(found),
                           certificate=found[0] if len(found) == 1 else None,
                           certificates=found)


class ValidationRun(BaseModel):
    """One validation of a set of country folders.

    Aggregated for a CI caller that wants a single verdict, while still carrying
    the per-country GITB TARs.
    """

    id: str
    created_at: datetime
    result: TestResult
    counts: ValidationCounters
    countries: list[str] = Field(default_factory=list)
    reports: list[TAR] = Field(default_factory=list)
    #: assertionID -> how many error/warning findings carried it. A caller with
    #: only pointer expressions can then ask "was tng.cert.chain reported?"
    #: without searching a nested array.
    assertions: dict[str, int] = Field(default_factory=dict)


_VALIDATION_RUNS: dict[str, ValidationRun] = {}
_VALIDATION_RUN_LIMIT = 200


def _assertion_counts(tars: list[TAR]) -> dict[str, int]:
    """Which rules actually reported a problem, and how often.

    Info items are excluded: they record that something was checked or could not
    run, so counting them here would make "was this reported?" answer yes for
    every rule that merely ran.
    """
    counts: dict[str, int] = {}
    for tar in tars:
        for item in tar.reports:
            if item.type is ItemType.INFO or not item.assertionID:
                continue
            counts[item.assertionID] = counts.get(item.assertionID, 0) + 1
    return counts


def aggregate_run(tars: list[TAR]) -> ValidationRun:
    order = {TestResult.SUCCESS: 0, TestResult.WARNING: 1,
             TestResult.UNDEFINED: 2, TestResult.FAILURE: 3}
    worst = TestResult.SUCCESS
    for t in tars:
        if order[t.result] > order[worst]:
            worst = t.result
    run = ValidationRun(
        id=str(uuid.uuid4()), created_at=datetime.now(timezone.utc), result=worst,
        counts=ValidationCounters(
            nrOfAssertions=sum(t.counts.nrOfAssertions for t in tars),
            nrOfErrors=sum(t.counts.nrOfErrors for t in tars),
            nrOfWarnings=sum(t.counts.nrOfWarnings for t in tars)),
        countries=[c for c in (t.context.get("country") for t in tars) if c],
        reports=tars,
        assertions=_assertion_counts(tars))
    if len(_VALIDATION_RUNS) >= _VALIDATION_RUN_LIMIT:
        for stale in sorted(_VALIDATION_RUNS, key=lambda k: _VALIDATION_RUNS[k].created_at)[:20]:
            _VALIDATION_RUNS.pop(stale, None)
    _VALIDATION_RUNS[run.id] = run
    return run


def negotiate_report(tar: TAR, report_syntax: Optional[str], accept: str) -> Response:
    wants_xml = (report_syntax and "xml" in report_syntax.lower()) or \
                (not report_syntax and "xml" in (accept or "").lower() and "json" not in (accept or "").lower())
    if wants_xml:
        return Response(content=tar_to_xml(tar), media_type="application/xml")
    return Response(content=tar.model_dump_json(), media_type="application/json")


# ---------------------------------------------------------------------------
# Submissions (upload) + processing — TNG extensions
# ---------------------------------------------------------------------------


class ArtifactIn(BaseModel):
    """One uploaded key-material file within a submission."""
    filename: str = Field(description="e.g. 'onboarding/DCC/TLS/TLS.pem'")
    validationType: str = Field(description="<framework>.<material>, e.g. 'dcc.tls'")
    content: str
    embeddingMethod: EmbeddingMethod = EmbeddingMethod.BASE64
    externalRules: Optional[list[RuleSet]] = None


class SubmissionIn(BaseModel):
    participant: str = Field(description="ISO-3166 alpha-3 participant code")
    artifacts: list[ArtifactIn]
    run_id: Optional[str] = Field(
        default=None,
        description="Correlation id grouping submissions made by one batch/cron tick, "
                    "e.g. the GitHub Actions run id. Lets you retrieve a whole run.")
    delivery_mode: Optional[str] = Field(
        default=None,
        description="What the participant's own .tng/delivery.yml says: "
                    "'full' | 'no-push' | 'no-commit'. Read from the participant checkout by "
                    "the client (the service holds no checkouts) and carried here. It can only "
                    "ever make delivery MORE restrictive — see tng_delivery_policy.")


class ArtifactResult(BaseModel):
    filename: str
    validationType: str
    report: TAR
    digest: Optional[str] = None    # sha256 of the submitted bytes — what was actually checked


# ---------------------------------------------------------------------------
# Audit trail — the accumulated "checked ok by X at T" record
# ---------------------------------------------------------------------------
# Every step appends an attestation. Three properties make this evidential
# rather than decorative:
#   1. FAILURES ARE RECORDED TOO. A trail that only logs successes cannot answer
#      "did the deploy have issues?" — which is the whole point of asking.
#   2. HASH-CHAINED. Each entry commits to the previous entry's hash, so an entry
#      cannot be altered or removed without breaking the chain (verify_chain()).
#   3. THE ACTOR CARRIES ITS OWN TRUSTWORTHINESS. `authenticated` is false when the
#      actor was merely self-declared by the caller, so the report never implies
#      more assurance than it has.
# Timestamps are stored as UTC ISO 8601; render them ddmmyy at presentation time.


class ActorKind(str, Enum):
    SERVICE = "service"      # this service instance did it automatically
    USER = "user"            # a human principal
    WORKFLOW = "workflow"    # a CI job / scheduler


class AuditActor(BaseModel):
    kind: ActorKind
    id: str                              # service name+version, or principal identity
    authenticated: bool = False          # false == self-declared, not proven


class AuditEvent(str, Enum):
    MATERIAL_CHECKED = "material_checked"
    SIGNATURE_PRODUCED = "signature_produced"
    SIGNATURE_CHECKED = "signature_checked"
    DEPLOY_ATTEMPTED = "deploy_attempted"
    DEPLOYED = "deployed"


class Outcome(str, Enum):
    OK = "ok"
    FAILED = "failed"


class AuditEntry(BaseModel):
    seq: int
    event: AuditEvent
    outcome: Outcome
    at: datetime
    actor: AuditActor
    summary: str                                   # human-readable one-liner
    detail: dict[str, Any] = Field(default_factory=dict)
    prev_hash: Optional[str] = None
    hash: Optional[str] = None

    def compute_hash(self) -> str:
        body = {
            "seq": self.seq, "event": self.event.value, "outcome": self.outcome.value,
            "at": self.at.isoformat(), "actor": self.actor.model_dump(),
            "summary": self.summary, "detail": self.detail, "prev_hash": self.prev_hash,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


SERVICE_ACTOR = AuditActor(kind=ActorKind.SERVICE, id=f"{SERVICE_NAME} {SERVICE_VERSION}", authenticated=True)


def append_audit(sub: "Submission", event: AuditEvent, outcome: Outcome, summary: str,
                 actor: Optional[AuditActor] = None, **detail: Any) -> AuditEntry:
    prev = sub.audit[-1] if sub.audit else None
    entry = AuditEntry(
        seq=len(sub.audit) + 1, event=event, outcome=outcome,
        at=datetime.now(timezone.utc), actor=actor or SERVICE_ACTOR,
        summary=summary, detail=detail, prev_hash=prev.hash if prev else None)
    entry.hash = entry.compute_hash()
    sub.audit.append(entry)
    return entry


def verify_chain(sub: "Submission") -> tuple[bool, Optional[str]]:
    """Recompute the chain. Returns (intact, first_broken_seq_description)."""
    prev_hash = None
    for e in sub.audit:
        if e.prev_hash != prev_hash:
            return False, f"entry {e.seq} does not link to entry {e.seq - 1}"
        if e.hash != e.compute_hash():
            return False, f"entry {e.seq} content does not match its hash"
        prev_hash = e.hash
    return True, None


def render_audit(sub: "Submission") -> list[str]:
    """The report as readable lines, dates as ddmmyy."""
    lines = []
    for e in sub.audit:
        mark = "ok" if e.outcome == Outcome.OK else "FAILED"
        stamp = e.at.strftime("%d%m%y")
        trust = "" if e.actor.authenticated else " (self-declared)"
        lines.append(f"{e.seq}. {e.summary} — {mark} by {e.actor.id}{trust} at {stamp}")
    return lines


class SignatureInfo(BaseModel):
    """Result of signing ONE artefact. `self_verified` is the point of splitting
    sign from deploy: the service checks its own output before anything is pushed."""
    algorithm: str = "CMS/SHA-256 detached"
    signature_b64: Optional[str] = None
    signer_subject: Optional[str] = None
    self_verified: bool = False
    detail: Optional[str] = None


class ArtifactSignature(BaseModel):
    filename: str
    signature: SignatureInfo


class DeployResult(BaseModel):
    target: str                              # e.g. "prod/AND"
    mode: str = DeliveryMode.NO_COMMIT.value  # the delivery mode actually applied
    dry_run: bool = False                    # retained for compatibility: true when mode != full
    committed: bool = False                  # material actually LANDED in the trust list
    pushed: bool = False                     # reached the remote
    ok: bool = False                         # the deploy step itself succeeded
    commit_sha: Optional[str] = None
    detail: Optional[str] = None
    policy: dict[str, str] = Field(default_factory=dict)   # which layer chose the mode


class ProcessState(str, Enum):
    UPLOADED = "uploaded"        # received, not yet verified
    VERIFIED = "verified"        # all artefacts SUCCESS/WARNING — may be signed
    REJECTED = "rejected"        # at least one artefact FAILURE — terminal
    SIGNED = "signed"            # trust-anchor signature produced and self-verified
    DELIVERED = "delivered"      # committed to the trust list
    FAILED = "failed"            # sign or deploy attempted and failed


class Submission(BaseModel):
    id: str
    participant: str
    state: ProcessState
    created_at: datetime
    aggregate_result: TestResult
    artifacts: list[ArtifactResult]
    run_id: Optional[str] = None            # correlates submissions from one batch
    environment: Optional[str] = None       # fixed at SIGN time — the TA key used
    delivery_mode: Optional[str] = None     # what the participant repo asked for, if anything
    signatures: list[ArtifactSignature] = Field(default_factory=list)
    deployment: Optional[DeployResult] = None
    audit: list[AuditEntry] = Field(default_factory=list)


_SUBMISSIONS: dict[str, Submission] = {}
# Artefact bytes, kept out of the API/journal payloads but needed to sign and
# deploy the real material. Keyed by submission id, dropped when it closes.
_MATERIAL: dict[str, dict[str, bytes]] = {}


def verify_submission(body: SubmissionIn, actor: Optional[AuditActor] = None) -> Submission:
    if not PARTICIPANT_CODE_RE.match(body.participant):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"participant '{body.participant}' is not ISO-3166 alpha-3")
    # Reject an unreadable delivery mode at ingest rather than at deploy: a typo in
    # a safety switch must surface before anything has been signed.
    if body.delivery_mode:
        try:
            resolve_delivery_policy(participant=body.delivery_mode)
        except PolicyError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    results: list[ArtifactResult] = []
    material: dict[str, bytes] = {}
    worst = TestResult.SUCCESS
    order = {TestResult.SUCCESS: 0, TestResult.WARNING: 1, TestResult.UNDEFINED: 2, TestResult.FAILURE: 3}
    for art in body.artifacts:
        tar = run_validation(ValidateRequest(
            contentToValidate=art.content, embeddingMethod=art.embeddingMethod,
            validationType=art.validationType, externalRules=art.externalRules))
        raw = resolve_content(art.content, art.embeddingMethod)
        material[art.filename] = raw
        digest = hashlib.sha256(raw).hexdigest()
        results.append(ArtifactResult(filename=art.filename, validationType=art.validationType,
                                      report=tar, digest=digest))
        if order[tar.result] > order[worst]:
            worst = tar.result
    state = ProcessState.REJECTED if worst == TestResult.FAILURE else ProcessState.VERIFIED
    sub = Submission(
        id=str(uuid.uuid4()), participant=body.participant, state=state,
        created_at=datetime.now(timezone.utc), aggregate_result=worst, artifacts=results,
        run_id=body.run_id, delivery_mode=body.delivery_mode)
    errors = sum(a.report.counts.nrOfErrors for a in results)
    warnings = sum(a.report.counts.nrOfWarnings for a in results)
    append_audit(
        sub, AuditEvent.MATERIAL_CHECKED,
        Outcome.OK if state == ProcessState.VERIFIED else Outcome.FAILED,
        f"Key material checked for {body.participant} ({len(results)} artefact(s))",
        actor=actor, aggregate=worst.value, errors=errors, warnings=warnings,
        validationTypes=[a.validationType for a in results])
    _SUBMISSIONS[sub.id] = sub
    _MATERIAL[sub.id] = material
    if state == ProcessState.REJECTED:
        close_submission(sub)          # terminal: never signed, never merged
    return sub


# --- signing service (INTERNAL) --------------------------------------------
# The trust-anchor private key lives behind this boundary only. Swap the body
# for a KMS/HSM call; the workflow injected this key straight into a script env.
#
# Signing and deploying are SEPARATE operations on purpose:
#   * sign   — cryptographic, local, reversible (nothing leaves the service).
#              Self-verifies its own output so a bad key/cert pair is caught here.
#   * deploy — I/O against the trust-list repo, and the only irreversible step.
# That means a broken key and a broken git push produce different failures at
# different endpoints, instead of one opaque "delivery failed".


class SignerError(RuntimeError):
    pass


class Signer:
    """CMS signer over the openssl CLI. Environment-scoped: each trust environment
    has its own trust anchor, so the key is selected by environment and recorded on
    the submission — you cannot sign with the dev TA and deploy to prod."""

    def __init__(self, key_pem: str, cert_pem: str):
        self._key, self._cert = key_pem, cert_pem

    @property
    def configured(self) -> bool:
        return bool(self._key and self._cert)

    def sign(self, payload: bytes) -> SignatureInfo:
        if not self.configured:
            raise SignerError("no trust-anchor key/certificate configured")
        import subprocess
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "key.pem").write_text(self._key)
            (d / "cert.pem").write_text(self._cert)
            (d / "in.bin").write_bytes(payload)
            try:
                subprocess.run(
                    ["openssl", "cms", "-sign", "-binary", "-outform", "DER",
                     "-in", str(d / "in.bin"), "-out", str(d / "sig.der"),
                     "-signer", str(d / "cert.pem"), "-inkey", str(d / "key.pem")],
                    check=True, capture_output=True)
            except FileNotFoundError:
                raise SignerError("openssl not available on this instance")
            except subprocess.CalledProcessError as exc:
                raise SignerError(f"signing failed: {exc.stderr.decode(errors='replace')[:300]}")

            sig = (d / "sig.der").read_bytes()

            # Self-verify: prove the signature validates against its own signer cert
            # before the caller is told signing succeeded.
            verified, detail = False, None
            try:
                subprocess.run(
                    ["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                     "-in", str(d / "sig.der"), "-content", str(d / "in.bin"),
                     "-certfile", str(d / "cert.pem"), "-noverify",
                     "-out", os.devnull],
                    check=True, capture_output=True)
                verified = True
            except subprocess.CalledProcessError as exc:
                detail = f"self-verification failed: {exc.stderr.decode(errors='replace')[:300]}"

            subject = None
            if _CRYPTO:
                try:
                    subject = x509.load_pem_x509_certificate(self._cert.encode()).subject.rfc4514_string()
                except Exception:
                    pass
            return SignatureInfo(signature_b64=base64.b64encode(sig).decode(),
                                 signer_subject=subject, self_verified=verified, detail=detail)


def env_or_file(name: str) -> str:
    """Read a setting from `NAME`, or from the file named by `NAME_FILE`.

    The `_FILE` form is the one to prefer for key material. A PEM in an
    environment variable is multi-line, awkward to set from a shell, and visible
    to anything that can read the process environment — `docker inspect`, `ps -e`,
    a crash reporter. Pointing at a file keeps the bytes out of all of those, and
    is how Docker and Kubernetes secrets are normally surfaced anyway.
    """
    direct = os.getenv(name)
    if direct:
        return direct
    path = os.getenv(f"{name}_FILE")
    if not path:
        return ""
    try:
        return FsPath(path).read_text(encoding="utf-8")
    except OSError as exc:
        # Loud, because the alternative is a confusing 503 that looks like
        # "no key configured" when a key WAS configured and could not be read.
        log.error("%s_FILE points at %s which could not be read: %s", name, path, exc)
        return ""


def signer_for(environment: str) -> Signer:
    """Per-environment trust anchor: TNG_TA_PRIVATE_KEY_<ENV> / TNG_TA_CA_<ENV>,
    falling back to the unsuffixed pair. Both accept the `_FILE` indirection."""
    suffix = environment.upper()
    key = env_or_file(f"TNG_TA_PRIVATE_KEY_{suffix}") or env_or_file("TNG_TA_PRIVATE_KEY")
    cert = env_or_file(f"TNG_TA_CA_{suffix}") or env_or_file("TNG_TA_CA")
    return Signer(key, cert)


# --- deployment service (INTERNAL) -----------------------------------------


class DeployerError(RuntimeError):
    pass


class Deployer:
    """Commits signed material to an environment's trust list."""

    @property
    def configured(self) -> bool:
        return False

    def deploy(self, sub: "Submission", environment: str, mode: DeliveryMode,
               material: dict[str, bytes]) -> DeployResult:
        raise NotImplementedError


class GitTrustListDeployer(Deployer):
    """Writes the material and its detached signature into the environment's trust
    list repository, commits, and pushes.

    `dry_run` performs the clone, write and local commit but does NOT push — so it
    exercises everything that can realistically fail (auth, checkout, path layout,
    conflicting state) without mutating the published trust list.

    Layout written per participant:
        <environment>/<PARTICIPANT>/<filename>
        <environment>/<PARTICIPANT>/<filename>.p7s     (detached CMS signature)
        <environment>/<PARTICIPANT>/manifest.json      (digests, run, audit head)
    """

    def __init__(self, repo_template: str, token: str, branch: str = "main",
                 author: str = "TNG Trust Service", email: str = "tng-bot@who.int"):
        self._repo_template, self._token = repo_template, token
        self._branch, self._author, self._email = branch, author, email

    @property
    def configured(self) -> bool:
        return bool(self._repo_template)

    def repo_for(self, environment: str) -> str:
        return self._repo_template.replace("{env}", environment)

    def _run(self, args: list[str], cwd: Optional[str] = None) -> str:
        import subprocess
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0",
               "GIT_AUTHOR_NAME": self._author, "GIT_AUTHOR_EMAIL": self._email,
               "GIT_COMMITTER_NAME": self._author, "GIT_COMMITTER_EMAIL": self._email}
        if self._token:
            # Token via askpass, never in the URL or argv — URLs leak into reflogs.
            env["GIT_ASKPASS"] = self._askpass
            env["TNG_GIT_TOKEN"] = self._token
        proc = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True)
        if proc.returncode != 0:
            raise DeployerError(f"git {args[0]}: {proc.stderr.decode(errors='replace')[:300]}")
        return proc.stdout.decode(errors="replace").strip()

    @property
    def _askpass(self) -> str:
        import stat
        import tempfile
        from pathlib import Path as _P
        path = _P(tempfile.gettempdir()) / "tng-askpass.sh"
        if not path.exists():
            path.write_text('#!/bin/sh\ncase "$1" in *[Uu]sername*) echo x-access-token;; '
                            '*) echo "$TNG_GIT_TOKEN";; esac\n')
            path.chmod(stat.S_IRWXU)
        return str(path)

    def _render(self, sub: "Submission", environment: str, material: dict[str, bytes],
                into) -> list[str]:
        """Materialise the participant's files and manifest under `into`.

        Separated from deploy() so `no-commit` can prove the material renders
        without writing anything into the trust list's working tree.
        """
        from pathlib import Path as _P
        into.mkdir(parents=True, exist_ok=True)
        manifest: dict[str, Any] = {
            "participant": sub.participant, "environment": environment,
            "submission": sub.id, "run_id": sub.run_id,
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "audit_chain_head": sub.audit[-1].hash if sub.audit else None,
            "artifacts": [],
        }
        written: list[str] = []
        sig_by_file = {s.filename: s.signature for s in sub.signatures}
        for art in sub.artifacts:
            raw = material.get(art.filename)
            if raw is None:
                raise DeployerError(f"artefact bytes for {art.filename} not held")
            name = _P(art.filename).name
            (into / name).write_bytes(raw)
            written.append(name)
            entry = {"file": name, "validationType": art.validationType, "digest": art.digest}
            sig = sig_by_file.get(art.filename)
            if sig and sig.signature_b64:
                (into / f"{name}.p7s").write_bytes(base64.b64decode(sig.signature_b64))
                written.append(f"{name}.p7s")
                entry["signature"] = f"{name}.p7s"
                entry["signer"] = sig.signer_subject
            manifest["artifacts"].append(entry)
        (into / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        written.append("manifest.json")
        return written

    def deploy(self, sub: "Submission", environment: str, mode: DeliveryMode,
               material: dict[str, bytes]) -> DeployResult:
        import tempfile
        from pathlib import Path as _P
        target = f"{environment}/{sub.participant}"
        if not self.configured:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "deployer not configured (set TRUST_LIST_REPO); nothing was written")
        repo = self.repo_for(environment)
        base: dict[str, Any] = {"target": target, "mode": mode.value,
                                "dry_run": mode is not DeliveryMode.FULL}
        try:
            with tempfile.TemporaryDirectory(prefix="tng-deploy-") as td:
                # The clone happens in every mode: it is what proves the remote is
                # reachable, the credentials work and the branch exists. Those are
                # the failures worth surfacing before anyone flips the switch to full.
                self._run(["clone", "--depth", "1", "--branch", self._branch, repo, td])

                if mode is DeliveryMode.NO_COMMIT:
                    # Render OUTSIDE the clone. Nothing reaches the trust list's
                    # working tree, so there is no local commit and nothing a later
                    # `git add -A` could sweep up.
                    with tempfile.TemporaryDirectory(prefix="tng-preview-") as pd:
                        files = self._render(sub, environment, material, _P(pd))
                    return DeployResult(
                        **base, committed=False, pushed=False, ok=True,
                        detail=f"no-commit: {repo} reachable and {len(files)} file(s) "
                               "rendered successfully; nothing was committed")

                dest = _P(td) / environment / sub.participant
                self._render(sub, environment, material, dest)

                self._run(["add", "-A", f"{environment}/{sub.participant}"], cwd=td)
                if not self._run(["status", "--porcelain"], cwd=td):
                    return DeployResult(**base, committed=False, pushed=False, ok=True,
                                        detail="no changes — trust list already up to date")
                self._run(["commit", "-m",
                           f"TNG: {sub.participant} trust material ({environment})"
                           + (f" [run {sub.run_id}]" if sub.run_id else "")], cwd=td)
                sha = self._run(["rev-parse", "HEAD"], cwd=td)
                if mode is DeliveryMode.NO_PUSH:
                    return DeployResult(**base, committed=False, pushed=False, ok=True,
                                        commit_sha=sha,
                                        detail="no-push: committed locally, not pushed")
                self._run(["push", "origin", self._branch], cwd=td)
                return DeployResult(**base, committed=True, pushed=True, ok=True,
                                    commit_sha=sha, detail=f"pushed to {repo}")
        except DeployerError as exc:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"deploy to {target} failed: {exc}")


deployer: Deployer = (
    GitTrustListDeployer(os.getenv("TRUST_LIST_REPO", ""), os.getenv("TRUST_LIST_TOKEN", ""),
                         os.getenv("TRUST_LIST_BRANCH", "main"))
    if os.getenv("TRUST_LIST_REPO") else Deployer())


# --- the two steps ---------------------------------------------------------


def sign_submission(sub: Submission, environment: str, actor: Optional[AuditActor] = None) -> Submission:
    """Step 1: sign every artefact with the environment's trust anchor and
    self-verify. Local and repeatable — safe to call while testing."""
    require_environment(environment)
    if sub.state == ProcessState.REJECTED:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "submission failed verification; it will not be signed")
    if sub.state not in (ProcessState.VERIFIED, ProcessState.SIGNED):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"submission in state '{sub.state.value}' cannot be signed")
    signer = signer_for(environment)
    signatures: list[ArtifactSignature] = []
    for art in sub.artifacts:
        payload = _MATERIAL.get(sub.id, {}).get(art.filename)
        if payload is None:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"artefact bytes for {art.filename} are no longer held; resubmit")
        try:
            info = signer.sign(payload)
        except SignerError as exc:
            sub.state = ProcessState.FAILED
            sub.signatures = signatures
            append_audit(sub, AuditEvent.SIGNATURE_PRODUCED, Outcome.FAILED,
                         f"Signature for {sub.participant} could not be produced",
                         actor=actor, environment=environment, artifact=art.filename, error=str(exc))
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
        if not info.self_verified:
            sub.state = ProcessState.FAILED
            append_audit(sub, AuditEvent.SIGNATURE_CHECKED, Outcome.FAILED,
                         f"Signature for {sub.participant} did not verify",
                         actor=actor, environment=environment, artifact=art.filename,
                         error=info.detail)
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                                f"signature for {art.filename} did not self-verify: {info.detail}")
        signatures.append(ArtifactSignature(filename=art.filename, signature=info))
    sub.signatures = signatures
    sub.environment = environment
    sub.state = ProcessState.SIGNED
    subject = signatures[0].signature.signer_subject if signatures else None
    append_audit(sub, AuditEvent.SIGNATURE_PRODUCED, Outcome.OK,
                 f"Signature produced for {sub.participant} ({len(signatures)} artefact(s))",
                 actor=actor, environment=environment, signer=subject,
                 algorithm=signatures[0].signature.algorithm if signatures else None)
    append_audit(sub, AuditEvent.SIGNATURE_CHECKED, Outcome.OK,
                 f"Signature checked for {sub.participant}",
                 actor=actor, environment=environment, method="CMS self-verification", signer=subject)
    return sub


def deploy_submission(sub: Submission, requested_mode: Optional[str] = None,
                      dry_run: Optional[bool] = None,
                      actor: Optional[AuditActor] = None) -> Submission:
    """Step 2: commit the signed material to the trust list. The environment is
    inherited from the signature — not re-specified — so dev-signed material can
    never be deployed to prod.

    Whether anything is actually committed is decided by `tng_delivery_policy`
    across four layers — this request, the participant's own `.tng/delivery.yml`,
    `TNG_DELIVERY_MODE`, and a safe built-in default — of which the MOST
    RESTRICTIVE wins. A participant that marks its material `no-commit` cannot
    have that overridden here.
    """
    if sub.state not in (ProcessState.SIGNED, ProcessState.DELIVERED):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"submission in state '{sub.state.value}' is not signed; sign it first")
    if not sub.environment:
        raise HTTPException(status.HTTP_409_CONFLICT, "signed submission has no environment recorded")

    # `dry_run: true` is the older boolean spelling of no-push. It can only ever
    # restrict, so it is folded in as a requested mode rather than a separate flag.
    if dry_run and not requested_mode:
        requested_mode = DeliveryMode.NO_PUSH.value
    try:
        policy = resolve_delivery_policy(
            requested=requested_mode, participant=sub.delivery_mode,
            environment=sub.environment)
    except PolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    if sub.state == ProcessState.DELIVERED and policy.pushes:
        raise HTTPException(status.HTTP_409_CONFLICT, "submission is already delivered")

    append_audit(sub, AuditEvent.DEPLOY_ATTEMPTED, Outcome.OK,
                 f"Deployment attempted for {sub.participant} to {sub.environment}",
                 actor=actor, environment=sub.environment, mode=policy.mode.value,
                 policy=policy.sources, dry_run=not policy.pushes)
    try:
        # Missing config is a 503, not an uncaught NotImplementedError — mirrors the
        # signer's "not configured" path. Raised inside the try so the failure is
        # recorded in the audit trail rather than vanishing (no false silence).
        if not deployer.configured:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "no trust list repository configured for deployment")
        result = deployer.deploy(sub, sub.environment, policy.mode, _MATERIAL.get(sub.id, {}))
    except HTTPException as exc:
        append_audit(sub, AuditEvent.DEPLOYED, Outcome.FAILED,
                     f"Deployment of {sub.participant} to {sub.environment} failed",
                     actor=actor, environment=sub.environment, mode=policy.mode.value,
                     dry_run=not policy.pushes, status=exc.status_code, error=str(exc.detail))
        raise
    result.policy = policy.sources
    sub.deployment = result
    if result.committed and policy.pushes:
        sub.state = ProcessState.DELIVERED
    # The audit says WHY nothing was written, not merely that nothing was — a trail
    # that records "deployed" for a run which committed nothing is worse than silent.
    append_audit(sub, AuditEvent.DEPLOYED,
                 Outcome.OK if result.ok else Outcome.FAILED,
                 f"Deployed {sub.participant} to {sub.environment}"
                 if policy.pushes else
                 f"Deployment of {sub.participant} to {sub.environment} withheld — "
                 f"{policy.explain()}",
                 actor=actor, environment=sub.environment, mode=policy.mode.value,
                 policy=policy.sources, dry_run=not policy.pushes,
                 target=result.target, commit=result.commit_sha)
    if sub.state == ProcessState.DELIVERED:
        close_submission(sub)          # merged — this is what search will find
    return sub


# ---------------------------------------------------------------------------
# Domains / configuration
# ---------------------------------------------------------------------------
# Verification is environment-agnostic: the governance rules (PEM, validity, key
# length, subject, chain) are identical across dev/uat/prod, so there is ONE
# validation domain. Environment is not structural here — it only matters at the
# stateful `process` step, where it selects the target trust list, and is passed
# as a parameter there.

DOMAIN = os.getenv("TNG_DOMAIN", "tng")
ENVIRONMENTS = {e.strip() for e in os.getenv("TNG_ENVIRONMENTS", "dev,uat,prod").split(",") if e.strip()}


def require_domain(domain: str) -> str:
    if domain != DOMAIN:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown domain '{domain}'. Known: ['{DOMAIN}']")
    return domain


def require_environment(environment: str) -> str:
    if environment not in ENVIRONMENTS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"unknown environment '{environment}'. Known: {sorted(ENVIRONMENTS)}")
    return environment


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="TNG Trust Material Services",
    version=SERVICE_VERSION,
    summary="ITB/GITB-aligned upload, verification and processing for WHO TNG key material",
)

api = APIRouter(prefix="/{domain}/api", tags=["validation"])


@api.get("/info")
async def module_definition(domain: str = PathParam(...)) -> dict[str, Any]:
    """GITB getModuleDefinition: what this domain validates and the inputs expected."""
    require_domain(domain)
    types = [f"{fw}.{mat}" for fw in sorted(FRAMEWORKS) for mat in sorted(MATERIAL_SUITES)]
    return {
        "service": {"name": SERVICE_NAME, "version": SERVICE_VERSION},
        "domain": domain,
        # The governance rule set applied, independent of the service version.
        # Quote this when reporting a verdict: it is what makes a result reproducible.
        "ruleSet": {"version": fv.RULESET_VERSION, "source": str(fv.RULES_PATH.name)},
        "validationTypes": types,
        "inputs": {
            "contentToValidate": {"required": True},
            "embeddingMethod": {"required": False, "values": [e.value for e in EmbeddingMethod]},
            "validationType": {"required": True, "values": types},
            "externalRules": {"required": False, "note": "CA chain for <framework>.tls chain checks"},
            "country": {"required": False,
                        "note": "ISO-3166 alpha-3; enables the subject-country match check"},
            "reportSyntax": {"required": False, "values": ["application/json", "application/xml"]},
        },
        # Folder-scoped validation is not part of the ITB validator contract, so it
        # is advertised separately rather than smuggled into validationTypes.
        "folderValidation": {
            "endpoint": f"/{domain}/api/validateFolders",
            "layouts": [fv.LAYOUT_AUTO, fv.LAYOUT_HUB, fv.LAYOUT_PARTICIPANT],
            "root": str(VALIDATION_ROOT),
            "note": "For the rules that need more than one artefact: chain, "
                    "subject-country match, TLS-without-chain, mandatory files.",
        },
        "assertions": sorted({
            "tng.cert.pem", "tng.cert.x509", "tng.cert.validity", "tng.cert.validity_range",
            "tng.crypto.keylength", "tng.cert.subject", "tng.cert.country_flag",
            "tng.cert.key_usage", "tng.cert.extended_key_usage", "tng.cert.basic_constraints",
            "tng.cert.signature_algorithm", "tng.cert.tls_no_chain", "tng.cert.chain",
            "tng.folder.mandatory", "tng.folder.group", "tng.folder.domain", "tng.folder.layout",
        }),
    }


@api.post("/validate")
async def validate(
    request: Request,
    domain: str = PathParam(...),
    body: ValidateRequest = Body(...),
    accept: str = Header(default="application/json"),
) -> Response:
    require_domain(domain)
    tar = run_validation(body)
    return negotiate_report(tar, body.reportSyntax, accept)


@api.post("/validateMultiple")
async def validate_multiple(
    domain: str = PathParam(...),
    body: list[ValidateRequest] = Body(...),
    accept: str = Header(default="application/json"),
) -> Response:
    require_domain(domain)
    tars = [run_validation(item) for item in body]
    # Bulk always returns JSON array of TARs (matches ITB restValidateMultiple).
    payload = "[" + ",".join(t.model_dump_json() for t in tars) + "]"
    return Response(content=payload, media_type="application/json")


@api.post("/inspect", response_model=InspectResponse)
async def inspect(
    domain: str = PathParam(...),
    body: InspectRequest = Body(default=InspectRequest()),
) -> InspectResponse:
    """Report what a certificate IS — key, extensions, subject, validity, path.

    The rules answer "does this pass?". A test step such as
    `keyUsage "cRLSign" must be false` asks something different, and needs the
    value. Exposing the facts means a harness can assert against them without
    every new assertion requiring a new rule.

    Holds no keys and creates nothing.
    """
    require_domain(domain)
    return run_inspection(body)


@api.post("/validateFolders")
async def validate_folders_endpoint(
    domain: str = PathParam(...),
    body: ValidateFoldersRequest = Body(default=ValidateFoldersRequest()),
    accept: str = Header(default="application/json"),
) -> Response:
    """Validate country onboarding folders, one GITB TAR per country.

    The folder-shaped counterpart to /validate, for the four rules that need more
    than one artefact's bytes. Requires no keys, no token and no signing material.
    """
    require_domain(domain)
    tars = run_folder_validation(body)
    if len(tars) == 1 and (body.reportSyntax or "xml" in (accept or "").lower()):
        return negotiate_report(tars[0], body.reportSyntax, accept)
    payload = "[" + ",".join(t.model_dump_json() for t in tars) + "]"
    return Response(content=payload, media_type="application/json")


# --- validation runs: the CI-shaped view over the same engine ----------------
# Outside the /{domain}/api/ prefix on purpose. Those endpoints follow the ITB
# validator contract and return TARs; this one exists for a PR check that wants a
# single verdict and an exit code, and is free to have a shape ITB does not
# define. It creates nothing beyond an in-memory record and needs no credentials.

validation_api = APIRouter(prefix="/v1/validation", tags=["validation runs (CI)"])


@validation_api.post("/runs", response_model=ValidationRun)
async def create_validation_run(
    response: Response,
    body: ValidateFoldersRequest = Body(default=ValidateFoldersRequest()),
    fail_on_error: bool = Query(
        default=False,
        description="Return 422 instead of 200 when the run failed, so a CI step "
                    "fails on the status code alone."),
) -> ValidationRun:
    """Validate a set of country folders and return one aggregated verdict.

    Synchronous: this is PEM parsing over a handful of files, and a check that
    returned 202 would have to be polled — a caller that forgot would pass every
    time. `result` is SUCCESS, WARNING or FAILURE; `reports` holds the per-country
    GITB TARs.
    """
    run = aggregate_run(run_folder_validation(body))
    response.headers["Location"] = f"/v1/validation/runs/{run.id}"
    if fail_on_error and run.result == TestResult.FAILURE:
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    return run


@validation_api.get("/runs/{run_id}", response_model=ValidationRun)
async def get_validation_run(run_id: str = PathParam(...)) -> ValidationRun:
    run = _VALIDATION_RUNS.get(run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown validation run")
    return run


def _require_run(run_id: str) -> ValidationRun:
    run = _VALIDATION_RUNS.get(run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown validation run")
    return run


@validation_api.get("/runs/{run_id}/countries")
async def list_run_countries(run_id: str = PathParam(...)) -> list[dict[str, Any]]:
    """One line per country in this run — verdict, counts and where to read it.

    A hub run covers many participants at once. Aggregating them into a single
    verdict is what a CI gate wants; it is not what an operator chasing one
    country's failure wants, nor what that country should be handed.
    """
    run = _require_run(run_id)
    return [{
        "country": tar.context.get("country"),
        "result": tar.result.value,
        "counts": tar.counts.model_dump(),
        "filesExamined": len(tar.context.get("filesExamined") or []),
        "report": f"/v1/validation/runs/{run.id}/countries/{tar.context.get('country')}",
    } for tar in run.reports if tar.context.get("country")]


@validation_api.get("/runs/{run_id}/countries/{country}")
async def get_run_country_report(
    run_id: str = PathParam(...),
    country: str = PathParam(..., description="ISO-3166 alpha-3"),
    reportSyntax: Optional[str] = Query(default=None),
    accept: str = Header(default="application/json"),
) -> Response:
    """That one country's GITB TAR, as JSON or TRL XML.

    The same report the run already holds, addressable on its own — so a hub
    operator can hand a participant their result without also handing them
    every other country's.
    """
    run = _require_run(run_id)
    wanted = country.upper()
    for tar in run.reports:
        if str(tar.context.get("country") or "").upper() == wanted:
            return negotiate_report(tar, reportSyntax, accept)
    known = sorted({str(t.context.get("country")) for t in run.reports
                    if t.context.get("country")})
    raise HTTPException(status.HTTP_404_NOT_FOUND,
                        f"run {run_id} has no report for '{country}'. Known: {known}")


# --- submissions (upload) + processing -------------------------------------

sub_api = APIRouter(prefix="/{domain}/api/submissions", tags=["submissions (TNG)"])


def resolve_actor(x_actor: Optional[str], kind: ActorKind = ActorKind.WORKFLOW) -> Optional[AuditActor]:
    """Identify who is performing the step.

    In production this MUST come from the authenticated principal — an mTLS client
    certificate subject or a verified token identity. Until that exists, an actor
    supplied via X-Actor is recorded with authenticated=false so the audit report
    never implies assurance it does not have. No header == the service itself.
    """
    if not x_actor:
        return None
    return AuditActor(kind=kind, id=x_actor, authenticated=False)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------
# NOTE ON DURABILITY: _SUBMISSIONS is an in-memory dict, so search only covers
# this process's lifetime. In the "service inside the CI job" deployment that
# means a single job — search is precisely the capability that only becomes real
# with a persistent store behind a deployed service. The filter logic below is
# storage-agnostic on purpose: swap _all_submissions() for a DB query and the
# endpoints do not change.


class JournalPage(BaseModel):
    total: int                       # matches before paging
    limit: int
    offset: int
    items: list["JournalRecord"]


class RunSummary(BaseModel):
    run_id: str
    started_at: datetime
    last_activity_at: datetime
    participants: list[str]
    outcomes: dict[str, int]
    merged: int
    any_failure: bool


class InFlight(BaseModel):
    """A submission still being worked on — not yet in the journal."""
    id: str
    participant: str
    state: ProcessState
    aggregate_result: TestResult
    created_at: datetime
    run_id: Optional[str] = None
    environment: Optional[str] = None
    last_event: Optional[str] = None
    last_event_at: Optional[datetime] = None


def parse_when(value: str, *, end_of_day: bool) -> datetime:
    """Accept a plain date (2026-07-25) or a full ISO timestamp. A plain date means
    the whole UTC day, so from=2026-07-25&to=2026-07-25 returns that day."""
    try:
        if len(value) == 10:
            d = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return d.replace(hour=23, minute=59, second=59, microsecond=999999) if end_of_day else d
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"cannot parse date '{value}'; use YYYY-MM-DD or an ISO timestamp")


def search_journal(
    *, participant: Optional[list[str]] = None, outcome: Optional[ProcessState] = None,
    environment: Optional[str] = None, run_id: Optional[str] = None,
    merged: Optional[bool] = None, failed_only: bool = False,
    since: Optional[datetime] = None, until: Optional[datetime] = None,
    date_field: str = "closed_at",
    sort: str = "closed_at", order: str = "desc", limit: int = 50, offset: int = 0,
) -> "JournalPage":
    """Search the accumulated record.

    Dates match `closed_at` by default — when the delivery actually concluded and
    was merged — because that is the date on which a delivery 'happened'. Pass
    date_field=opened_at to search by when the material was submitted instead;
    the two differ whenever a submission sat around or was retried.
    """
    codes = {c.upper() for c in participant} if participant else None
    if codes:
        bad = [c for c in codes if not PARTICIPANT_CODE_RE.match(c)]
        if bad:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"not ISO-3166 alpha-3 codes: {sorted(bad)}")
    if date_field not in ("closed_at", "opened_at"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "date_field must be closed_at or opened_at")

    rows = journal.all()
    if codes:
        rows = [r for r in rows if r.participant in codes]
    if outcome:
        rows = [r for r in rows if r.outcome == outcome]
    if environment:
        rows = [r for r in rows if r.environment == environment]
    if run_id:
        rows = [r for r in rows if r.run_id == run_id]
    if merged is not None:
        rows = [r for r in rows if r.merged == merged]
    if failed_only:
        # Never merged, OR merged only after something failed along the way.
        rows = [r for r in rows
                if not r.merged or any(e.outcome == Outcome.FAILED for e in r.audit)]
    if since:
        rows = [r for r in rows if getattr(r, date_field) >= since]
    if until:
        rows = [r for r in rows if getattr(r, date_field) <= until]

    keys = {"closed_at": lambda r: r.closed_at, "opened_at": lambda r: r.opened_at,
            "participant": lambda r: r.participant, "seq": lambda r: r.seq}
    if sort not in keys:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"cannot sort by '{sort}'; use {sorted(keys)}")
    rows.sort(key=keys[sort], reverse=(order == "desc"))

    return JournalPage(total=len(rows), limit=limit, offset=offset,
                       items=rows[offset:offset + limit])


def list_in_flight() -> list["InFlight"]:
    """Submissions not yet closed into the journal — the live working set."""
    closed = {r.submission_id for r in journal.all()}
    out = []
    for s in _SUBMISSIONS.values():
        if s.id in closed:
            continue
        last = s.audit[-1] if s.audit else None
        out.append(InFlight(
            id=s.id, participant=s.participant, state=s.state,
            aggregate_result=s.aggregate_result, created_at=s.created_at,
            run_id=s.run_id, environment=s.environment,
            last_event=last.event.value if last else None,
            last_event_at=last.at if last else None))
    out.sort(key=lambda x: x.created_at, reverse=True)
    return out


def summarise_runs(limit: int = 50) -> list[RunSummary]:
    """Runs, from the accumulated record."""
    grouped: dict[str, list["JournalRecord"]] = {}
    for r in journal.all():
        if r.run_id:
            grouped.setdefault(r.run_id, []).append(r)
    runs: list[RunSummary] = []
    for rid, recs in grouped.items():
        outcomes: dict[str, int] = {}
        for r in recs:
            outcomes[r.outcome.value] = outcomes.get(r.outcome.value, 0) + 1
        runs.append(RunSummary(
            run_id=rid,
            started_at=min(r.opened_at for r in recs),
            last_activity_at=max(r.closed_at for r in recs),
            participants=sorted(r.participant for r in recs),
            outcomes=outcomes,
            merged=sum(1 for r in recs if r.merged),
            any_failure=any(not r.merged or any(e.outcome == Outcome.FAILED for e in r.audit)
                            for r in recs)))
    runs.sort(key=lambda r: r.started_at, reverse=True)
    return runs[:limit]


# ---------------------------------------------------------------------------
# The journal — the accumulated record, written at merge
# ---------------------------------------------------------------------------
# Two different things were being conflated before:
#
#   in-flight submissions  — a participant's material being checked/signed right
#                            now. Minutes old. Ephemeral by nature.
#   the journal            — what actually happened, closed and merged. Retained
#                            for years. THIS is what date/country search is for.
#
# A journal record is written when a submission reaches a terminal state: merged
# into the trust list, rejected at verification, or explicitly closed after
# failing. It carries the WHOLE accumulated audit chain, so the failed attempts
# that preceded a successful merge are inside the record, not lost with the
# working set.
#
# The backend is pluggable because the natural home for this is the trust-list
# repo itself — append a JSONL line beside the merged material and the journal
# inherits git's replication, history and signing. JOURNAL_PATH selects that;
# unset means in-memory (tests only, and search will be empty after a restart).


class JournalRecord(BaseModel):
    seq: int
    submission_id: str
    participant: str
    outcome: ProcessState                    # delivered | rejected | failed
    merged: bool                             # did the material actually land in the trust list
    opened_at: datetime                      # submission created
    closed_at: datetime                      # reached terminal state — what date search matches
    run_id: Optional[str] = None
    environment: Optional[str] = None
    aggregate_result: TestResult = TestResult.UNDEFINED
    errors: int = 0
    warnings: int = 0
    artifacts: list[dict[str, Any]] = Field(default_factory=list)   # filename, type, digest
    commit_sha: Optional[str] = None
    audit: list[AuditEntry] = Field(default_factory=list)           # the full accumulated trail
    chain_head: Optional[str] = None         # last audit hash — ties record to its trail


class Journal:
    """Append-only accumulated record. Subclass for a real store."""

    def append(self, record: JournalRecord) -> JournalRecord:
        raise NotImplementedError

    def all(self) -> list[JournalRecord]:
        raise NotImplementedError

    @property
    def backend(self) -> str:
        return type(self).__name__


class InMemoryJournal(Journal):
    def __init__(self) -> None:
        self._records: list[JournalRecord] = []

    def append(self, record: JournalRecord) -> JournalRecord:
        self._records.append(record)
        return record

    def all(self) -> list[JournalRecord]:
        return list(self._records)


class FileJournal(Journal):
    """JSONL, one record per line. Append-only, greppable, and safe to commit
    alongside the trust list so the record travels with the material."""

    def __init__(self, path: str) -> None:
        from pathlib import Path as _P
        self._path = _P(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[JournalRecord] = []
        self.unreadable: list[int] = []          # line numbers we could not parse
        if self._path.exists():
            for n, line in enumerate(self._path.read_text().splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    self._records.append(JournalRecord(**json.loads(line)))
                except Exception:
                    # Never silently drop an audit record. Surfaced via /healthz so a
                    # corrupted journal is visible rather than quietly shrinking.
                    self.unreadable.append(n)
                    log.error("journal line %d in %s is unreadable", n, self._path)

    def append(self, record: JournalRecord) -> JournalRecord:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")
        self._records.append(record)
        return record

    def all(self) -> list[JournalRecord]:
        return list(self._records)


_journal_path = os.getenv("JOURNAL_PATH", "")
journal: Journal = FileJournal(_journal_path) if _journal_path else InMemoryJournal()


def close_submission(sub: "Submission", outcome: Optional[ProcessState] = None) -> JournalRecord:
    """Write the accumulated record. Idempotent per submission."""
    existing = next((r for r in journal.all() if r.submission_id == sub.id), None)
    if existing:
        return existing
    final = outcome or sub.state
    record = JournalRecord(
        seq=len(journal.all()) + 1,
        submission_id=sub.id, participant=sub.participant, outcome=final,
        merged=(final == ProcessState.DELIVERED),
        opened_at=sub.created_at,
        closed_at=(sub.audit[-1].at if sub.audit else datetime.now(timezone.utc)),
        run_id=sub.run_id, environment=sub.environment,
        aggregate_result=sub.aggregate_result,
        errors=sum(a.report.counts.nrOfErrors for a in sub.artifacts),
        warnings=sum(a.report.counts.nrOfWarnings for a in sub.artifacts),
        artifacts=[{"filename": a.filename, "validationType": a.validationType, "digest": a.digest}
                   for a in sub.artifacts],
        commit_sha=sub.deployment.commit_sha if sub.deployment else None,
        audit=list(sub.audit),
        chain_head=sub.audit[-1].hash if sub.audit else None)
    _MATERIAL.pop(sub.id, None)      # material is in the trust list now, or was rejected
    return journal.append(record)


class SignRequest(BaseModel):
    environment: str = Field(description="Selects the trust anchor, e.g. 'dev' | 'uat' | 'prod'")


class DeployRequest(BaseModel):
    mode: Optional[str] = Field(
        default=None,
        description="'full' | 'no-push' | 'no-commit'. This can only make delivery MORE "
                    "restrictive — the participant's own .tng/delivery.yml and "
                    "TNG_DELIVERY_MODE are also consulted and the strictest of the three wins. "
                    "Omit to let those decide.")
    dry_run: Optional[bool] = Field(
        default=None,
        description="Deprecated spelling of mode='no-push'. Ignored when mode is given.")


@sub_api.post("/{submission_id}/sign", response_model=Submission)
async def sign(
    domain: str = PathParam(...),
    submission_id: str = PathParam(...),
    body: SignRequest = Body(...),
    x_actor: Optional[str] = Header(default=None, alias="X-Actor"),
) -> Submission:
    """Step 1 — sign with the environment's trust anchor and self-verify the result.
    Nothing leaves the service. Safe to call repeatedly while testing keys."""
    require_domain(domain)
    return sign_submission(_lookup(submission_id), body.environment, resolve_actor(x_actor))


@sub_api.post("/{submission_id}/deploy", response_model=Submission)
async def deploy(
    domain: str = PathParam(...),
    submission_id: str = PathParam(...),
    body: DeployRequest = Body(default=DeployRequest()),
    x_actor: Optional[str] = Header(default=None, alias="X-Actor"),
) -> Submission:
    """Step 2 — commit signed material to the trust list. Environment is inherited
    from the signature, so dev-signed material cannot reach prod.

    Whether anything is committed depends on the delivery mode, which defaults to
    `no-commit`. See docs/delivery-policy.md."""
    require_domain(domain)
    return deploy_submission(_lookup(submission_id), body.mode, body.dry_run,
                             resolve_actor(x_actor))


@sub_api.post("/{submission_id}/close", response_model=JournalRecord)
async def close(
    domain: str = PathParam(...),
    submission_id: str = PathParam(...),
    x_actor: Optional[str] = Header(default=None, alias="X-Actor"),
) -> JournalRecord:
    """Close a submission that will not proceed — a failed sign, an abandoned
    retry — so it still enters the accumulated record instead of vanishing with
    the working set. Delivered and rejected submissions close themselves."""
    require_domain(domain)
    sub = _lookup(submission_id)
    if sub.state in (ProcessState.DELIVERED, ProcessState.REJECTED):
        return close_submission(sub)
    return close_submission(sub, ProcessState.FAILED)


@sub_api.get("/{submission_id}/audit")
async def audit_report(
    domain: str = PathParam(...),
    submission_id: str = PathParam(...),
    accept: str = Header(default="application/json"),
) -> Response:
    """The accumulated attestation record: what was checked, by whom, when, and
    whether it passed — successes and failures alike. `chain_intact` tells you the
    trail has not been altered since it was written."""
    require_domain(domain)
    sub = _lookup(submission_id)
    intact, problem = verify_chain(sub)
    if "text/plain" in (accept or ""):
        body = "\n".join(render_audit(sub)) or "(no entries)"
        if not intact:
            body += f"\n\nWARNING: audit chain broken — {problem}"
        return Response(content=body + "\n", media_type="text/plain")
    return Response(
        content=json.dumps({
            "submission": sub.id,
            "participant": sub.participant,
            "state": sub.state.value,
            "environment": sub.environment,
            "chain_intact": intact,
            "chain_problem": problem,
            "entries": [json.loads(e.model_dump_json()) for e in sub.audit],
            "rendered": render_audit(sub),
        }, indent=2),
        media_type="application/json")


def _lookup(submission_id: str) -> Submission:
    sub = _SUBMISSIONS.get(submission_id)
    if not sub:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such submission")
    return sub


@sub_api.get("", response_model=list[InFlight])
async def list_in_flight_submissions(domain: str = PathParam(...)) -> list[InFlight]:
    """The live working set: submissions not yet closed into the journal.

    This is deliberately NOT the search endpoint. Use GET /{domain}/api/journal to
    search history by country or date — in-flight submissions are minutes old and
    disappear once they close, so searching them by date would answer the wrong
    question.
    """
    require_domain(domain)
    return list_in_flight()


@sub_api.post("", status_code=status.HTTP_201_CREATED, response_model=Submission)
async def create_submission(
    domain: str = PathParam(...),
    body: SubmissionIn = Body(...),
    x_actor: Optional[str] = Header(default=None, alias="X-Actor"),
) -> Submission:
    """Upload a participant's key material; every artefact is verified on ingest.
    Verification is environment-agnostic, so no environment is supplied here."""
    require_domain(domain)
    return verify_submission(body, resolve_actor(x_actor))


@sub_api.get("/{submission_id}", response_model=Submission)
async def get_submission(domain: str = PathParam(...), submission_id: str = PathParam(...)) -> Submission:
    require_domain(domain)
    return _lookup(submission_id)


# --- ops -------------------------------------------------------------------

ops = APIRouter(tags=["ops"])


@ops.get("/healthz")
async def healthz() -> dict[str, Any]:
    # The effective delivery mode per environment, with nothing else supplied.
    # Operators need to see at a glance whether this instance can write anywhere.
    defaults = {}
    for e in sorted(ENVIRONMENTS):
        try:
            defaults[e] = resolve_delivery_policy(environment=e).mode.value
        except PolicyError as exc:
            defaults[e] = f"misconfigured: {exc}"
    return {"status": "ok", "cryptography": _CRYPTO, "domain": DOMAIN,
            "environments": sorted(ENVIRONMENTS),
            "signers": {e: signer_for(e).configured for e in sorted(ENVIRONMENTS)},
            "deployer": deployer.configured,
            "delivery_mode": defaults,
            "journal": {"backend": journal.backend, "records": len(journal.all()),
                        "durable": not isinstance(journal, InMemoryJournal),
                        "unreadable_lines": getattr(journal, "unreadable", [])}}


# --- journal: the accumulated record, and what date/country search queries ----

journal_api = APIRouter(prefix="/{domain}/api/journal", tags=["journal (TNG)"])


@journal_api.get("", response_model=JournalPage)
async def search_journal_endpoint(
    domain: str = PathParam(...),
    participant: Optional[list[str]] = Query(default=None,
        description="Repeatable. ISO-3166 alpha-3, e.g. participant=PRT&participant=BEL"),
    outcome: Optional[ProcessState] = Query(default=None, description="delivered | rejected | failed"),
    environment: Optional[str] = Query(default=None),
    run_id: Optional[str] = Query(default=None),
    merged: Optional[bool] = Query(default=None, description="Only material that did / did not land"),
    failed_only: bool = Query(default=False,
        description="Never merged, or merged only after a failure along the way"),
    since: Optional[str] = Query(default=None, alias="from",
        description="YYYY-MM-DD (whole UTC day) or ISO timestamp"),
    until: Optional[str] = Query(default=None, alias="to"),
    date_field: str = Query(default="closed_at", description="closed_at (default) | opened_at"),
    sort: str = Query(default="closed_at"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> JournalPage:
    """Search the accumulated record by country, date, environment, run or outcome.

    Examples:
        ?participant=PRT
        ?from=2026-07-01&to=2026-07-25
        ?participant=BEL&failed_only=true
        ?environment=prod&merged=true
        ?run_id=gh-4711
    """
    require_domain(domain)
    if environment:
        require_environment(environment)
    return search_journal(
        participant=participant, outcome=outcome, environment=environment, run_id=run_id,
        merged=merged, failed_only=failed_only,
        since=parse_when(since, end_of_day=False) if since else None,
        until=parse_when(until, end_of_day=True) if until else None,
        date_field=date_field, sort=sort, order=order, limit=limit, offset=offset)


@journal_api.get("/{seq}", response_model=JournalRecord)
async def get_journal_record(domain: str = PathParam(...), seq: int = PathParam(...)) -> JournalRecord:
    """One accumulated record, including its full merged audit trail."""
    require_domain(domain)
    rec = next((r for r in journal.all() if r.seq == seq), None)
    if not rec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no journal record {seq}")
    return rec


runs_api = APIRouter(prefix="/{domain}/api/runs", tags=["runs (TNG)"])


@runs_api.get("", response_model=list[RunSummary])
async def list_runs(
    domain: str = PathParam(...),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[RunSummary]:
    """Batch view over the journal, grouped by run_id.
    `any_failure` is the field to scan when asking "which runs had problems?"."""
    require_domain(domain)
    return summarise_runs(limit)


@runs_api.get("/{run_id}", response_model=JournalPage)
async def get_run(
    domain: str = PathParam(...),
    run_id: str = PathParam(...),
    limit: int = Query(default=200, ge=1, le=500),
) -> JournalPage:
    """Every accumulated record belonging to one run."""
    require_domain(domain)
    page = search_journal(run_id=run_id, limit=limit)
    if page.total == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no journal records for run '{run_id}'")
    return page


for r in (api, validation_api, sub_api, journal_api, runs_api, ops):
    app.include_router(r)


def main() -> None:
    """Console entry point (`tng-trust-service`) and `python tng_trust_service.py`."""
    import uvicorn

    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    log.info("governance rule set %s from %s", fv.RULESET_VERSION, fv.RULES_PATH)
    uvicorn.run(app, host=os.getenv("BIND", "127.0.0.1"), port=int(os.getenv("PORT", "8080")))


if __name__ == "__main__":
    main()
