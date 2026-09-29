#!/usr/bin/env python3
"""tng_cli.py
=========

A command line over the same procedure the REST service exposes — one
subcommand per endpoint, same request shapes, same JSON out.

    python -m tng_cli healthz
    python -m tng_cli info
    python -m tng_cli validate onboarding/PH4H/UP/UP.pem --type ph4h.up --country XXR
    python -m tng_cli validate-folders --country XXR --layout participant
    python -m tng_cli inspect --group TLS --filename TLS.pem --country XXR
    python -m tng_cli run --country XXR --layout participant --fail-on-error

Two transports, one contract
---------------------------
By default the commands run **in process**: they call the very functions the
FastAPI routes call, so there is no server to start and no port to hold. Pass
``--url`` to send the same request to a **running service** instead:

    python -m tng_cli --url http://127.0.0.1:8080 run --country XXR

Both produce identical JSON, because both go through one implementation. That
is the point: a CI check, an ITB session and a developer at a terminal cannot
end up disagreeing about what "passing" means.

The stateful half of the procedure — submit, sign, deploy, audit, close and the
journal — needs ``--url``. Those endpoints accumulate state across calls, and a
fresh process per invocation has nowhere to keep it; the CLI says so rather
than quietly starting from an empty working set each time.

Exit codes
----------
    0   the command succeeded (for `run`: SUCCESS or WARNING)
    1   a governance verdict of FAILURE, with --fail-on-error
    2   the command could not be performed — bad usage, or the service is
        unreachable. Never a verdict.

1 and 2 are distinct on purpose. A service that failed to start must not read
as "your certificates are bad", nor as "your certificates are fine".
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

EXIT_OK, EXIT_VERDICT, EXIT_USAGE = 0, 1, 2
DEFAULT_DOMAIN = os.getenv("TNG_DOMAIN", "tng")


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------

class Remote:
    """Talk to a running service."""

    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def call(self, method: str, path: str, body: Any = None,
             accept: str = "application/json") -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": accept}
        if data:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(f"{self.url}{path}", data=data,
                                         method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=120) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        except urllib.error.URLError as exc:
            die(f"could not reach {self.url}: {exc.reason}")
        text = raw.decode("utf-8", errors="replace")
        try:
            return status, json.loads(text)
        except json.JSONDecodeError:
            return status, text


class InProcess:
    """Call the functions the routes call. No server, no port."""

    def __init__(self) -> None:
        try:
            import tng_trust_service as svc
        except Exception as exc:                      # noqa: BLE001 - report, don't crash
            die(f"could not load the service module: {exc}")
        self.svc = svc

    def healthz(self) -> Any:
        return _run_async(self.svc.healthz())

    def info(self, domain: str) -> Any:
        return _run_async(self.svc.module_definition(domain=domain))

    def validate(self, req: dict) -> Any:
        return _dump(self.svc.run_validation(self.svc.ValidateRequest(**req)))

    def validate_folders(self, req: dict) -> Any:
        return [_dump(t) for t in
                self.svc.run_folder_validation(self.svc.ValidateFoldersRequest(**req))]

    def inspect(self, req: dict) -> Any:
        return _dump(self.svc.run_inspection(self.svc.InspectRequest(**req)))

    def run(self, req: dict) -> Any:
        body = self.svc.ValidateFoldersRequest(**req)
        return _dump(self.svc.aggregate_run(self.svc.run_folder_validation(body)))


def _run_async(coro: Any) -> Any:
    import asyncio
    return asyncio.run(coro) if hasattr(coro, "__await__") else coro


def _dump(model: Any) -> Any:
    """Pydantic model -> the same JSON the endpoint would return."""
    if hasattr(model, "model_dump"):
        return json.loads(model.model_dump_json())
    return model


def die(message: str, code: int = EXIT_USAGE) -> None:
    annotate("error", message)
    raise SystemExit(code)


def annotate(level: str, message: str) -> None:
    if os.getenv("GITHUB_ACTIONS"):
        print(f"::{level}::{message}")
    else:
        print(f"{level}: {message}", file=sys.stderr)


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def resolve_country(value: str | None) -> str | None:
    """`--country auto` resolves from PARTICIPANT_COUNTRY or the repository name."""
    if value != "auto":
        return value
    code = (os.getenv("PARTICIPANT_COUNTRY") or "").strip().upper()
    if not code:
        repo = (os.getenv("GITHUB_REPOSITORY") or ROOT.name).rsplit("/", 1)[-1]
        match = re.search(r"([A-Za-z]{3})$", repo)
        code = match.group(1).upper() if match else ""
    if not re.fullmatch(r"[A-Z]{3}", code):
        die("could not resolve --country auto. Set PARTICIPANT_COUNTRY to an "
            "ISO-3166 alpha-3 code, or pass --country explicitly.")
    return code


def emit(payload: Any, out: str | None) -> None:
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    print(text)


def read_content(path: str, embedding: str) -> str:
    raw = sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()
    return raw.decode("utf-8") if embedding == "STRING" else base64.b64encode(raw).decode()


def requires_url(args: argparse.Namespace, command: str) -> Remote:
    if not args.url:
        die(f"`{command}` needs a running service: pass --url http://127.0.0.1:8080. "
            "It accumulates state across calls, which a fresh process cannot keep.")
    return Remote(args.url)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_healthz(args: argparse.Namespace) -> int:
    if args.url:
        _, body = Remote(args.url).call("GET", "/healthz")
    else:
        body = InProcess().healthz()
    emit(body, args.out)
    return EXIT_OK


def cmd_info(args: argparse.Namespace) -> int:
    if args.url:
        _, body = Remote(args.url).call("GET", f"/{args.domain}/api/info")
    else:
        body = InProcess().info(args.domain)
    emit(body, args.out)
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    req: dict[str, Any] = {
        "contentToValidate": read_content(args.file, args.embedding),
        "embeddingMethod": args.embedding,
        "validationType": args.type,
    }
    if args.country:
        req["country"] = resolve_country(args.country)
    if args.external_rules:
        req["externalRules"] = [
            {"ruleSet": read_content(p, "BASE64"), "embeddingMethod": "BASE64"}
            for p in args.external_rules]

    if args.url:
        _, body = Remote(args.url).call("POST", f"/{args.domain}/api/validate", req)
    else:
        body = InProcess().validate(req)
    emit(body, args.out)
    return verdict_exit(body, args.fail_on_error)


def cmd_validate_folders(args: argparse.Namespace) -> int:
    req = folder_request(args)
    if args.url:
        _, body = Remote(args.url).call("POST", f"/{args.domain}/api/validateFolders", req)
    else:
        body = InProcess().validate_folders(req)
    emit(body, args.out)
    worst = worst_result(body if isinstance(body, list) else [body])
    return EXIT_VERDICT if (args.fail_on_error and worst == "FAILURE") else EXIT_OK


def cmd_inspect(args: argparse.Namespace) -> int:
    req: dict[str, Any] = {"layout": args.layout}
    for key, value in (("country", resolve_country(args.country) if args.country else None),
                       ("root", args.root), ("group", args.group),
                       ("materialDomain", args.material_domain),
                       ("filename", args.filename)):
        if value:
            req[key] = value
    if args.file:
        req["contentToValidate"] = read_content(args.file, "BASE64")
        req["embeddingMethod"] = "BASE64"
        req["validationType"] = args.type

    if args.url:
        _, body = Remote(args.url).call("POST", f"/{args.domain}/api/inspect", req)
    else:
        body = InProcess().inspect(req)
    emit(body, args.out)
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    req = folder_request(args)
    if args.url:
        query = "?fail_on_error=true" if args.fail_on_error else ""
        _, body = Remote(args.url).call("POST", f"/v1/validation/runs{query}", req)
    else:
        body = InProcess().run(req)

    emit(body, args.out)

    if args.report:
        from report_markdown import render
        markdown = render(body)
        Path(args.report).write_text(markdown, encoding="utf-8")
        step_summary = os.getenv("GITHUB_STEP_SUMMARY")
        if step_summary:
            with open(step_summary, "a", encoding="utf-8") as handle:
                handle.write(markdown)

    return verdict_exit(body, args.fail_on_error)


def cmd_passthrough(args: argparse.Namespace) -> int:
    """submit / sign / deploy / audit / close / journal — service required."""
    remote = requires_url(args, args.command)
    domain = args.domain
    method, path, body = "GET", "", None

    if args.command == "submit":
        method, path = "POST", f"/{domain}/api/submissions"
        body = json.loads(Path(args.body).read_text(encoding="utf-8"))
    elif args.command == "sign":
        method, path = "POST", f"/{domain}/api/submissions/{args.id}/sign"
        body = {"environment": args.environment}
    elif args.command == "deploy":
        method, path = "POST", f"/{domain}/api/submissions/{args.id}/deploy"
        body = {"mode": args.mode} if args.mode else {}
    elif args.command == "close":
        method, path = "POST", f"/{domain}/api/submissions/{args.id}/close"
    elif args.command == "audit":
        path = f"/{domain}/api/submissions/{args.id}/audit"
        status, text = remote.call("GET", path,
                                   accept="text/plain" if args.text else "application/json")
        emit(text, args.out)
        return EXIT_OK if status == 200 else EXIT_USAGE
    elif args.command == "journal":
        query = urllib.parse.urlencode({"participant": args.participant} if args.participant else {})
        path = f"/{domain}/api/journal" + (f"?{query}" if query else "")

    status, payload = remote.call(method, path, body)
    emit(payload, args.out)
    if status >= 500:
        return EXIT_USAGE
    return EXIT_OK


# --------------------------------------------------------------------------

def folder_request(args: argparse.Namespace) -> dict[str, Any]:
    req: dict[str, Any] = {"layout": args.layout}
    country = resolve_country(args.country) if args.country else None
    if country:
        req["country"] = country
    if getattr(args, "root", None):
        req["root"] = args.root
    if getattr(args, "allowed_domains", None):
        req["allowedDomains"] = args.allowed_domains
    return req


def worst_result(reports: list[dict]) -> str:
    order = {"SUCCESS": 0, "UNDEFINED": 1, "WARNING": 2, "FAILURE": 3}
    worst = "SUCCESS"
    for report in reports:
        result = (report or {}).get("result", "UNDEFINED")
        if order.get(result, 1) > order.get(worst, 0):
            worst = result
    return worst


def verdict_exit(body: Any, fail_on_error: bool) -> int:
    if not fail_on_error:
        return EXIT_OK
    result = body.get("result") if isinstance(body, dict) else worst_result(body)
    if result == "FAILURE":
        annotate("error", "governance rules were violated")
        return EXIT_VERDICT
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tng_cli", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", help="talk to a running service instead of "
                                      "calling in process, e.g. http://127.0.0.1:8080")
    parser.add_argument("--domain", default=DEFAULT_DOMAIN, help="validation domain")
    parser.add_argument("--out", help="also write the JSON to this file")

    # The same three options after the subcommand, because
    # `tng_cli run --out run.json` is what anyone will type first.
    # SUPPRESS keeps an unused option from clobbering the value given before it.
    common = argparse.ArgumentParser(add_help=False)
    for flag, helptext in (("--url", "service URL"), ("--domain", "validation domain"),
                           ("--out", "also write the JSON to this file")):
        common.add_argument(flag, default=argparse.SUPPRESS, help=helptext)

    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, **kwargs: Any) -> argparse.ArgumentParser:
        return sub.add_parser(name, parents=[common], **kwargs)

    add("healthz", help="GET /healthz").set_defaults(func=cmd_healthz)
    add("info", help="GET /{domain}/api/info").set_defaults(func=cmd_info)

    p = add("validate", help="POST /{domain}/api/validate")
    p.add_argument("file", help="PEM file, or - for stdin")
    p.add_argument("--type", required=True, help="<framework>.<material>, e.g. ph4h.up")
    p.add_argument("--country", help="alpha-3, or 'auto'")
    p.add_argument("--embedding", default="BASE64", choices=["BASE64", "STRING"])
    p.add_argument("--external-rules", nargs="*", help="CA chain PEM(s) for TLS checks")
    p.add_argument("--fail-on-error", action="store_true")
    p.set_defaults(func=cmd_validate)

    p = add("validate-folders", help="POST /{domain}/api/validateFolders")
    add_folder_args(p)
    p.set_defaults(func=cmd_validate_folders)

    p = add("run", help="POST /v1/validation/runs — one aggregated verdict")
    add_folder_args(p)
    p.add_argument("--report", metavar="FILE",
                   help="also render the markdown report here, and append it to "
                        "$GITHUB_STEP_SUMMARY when that is set")
    p.set_defaults(func=cmd_run)

    p = add("inspect", help="POST /{domain}/api/inspect — facts, not verdicts")
    p.add_argument("--file", help="PEM file to inspect instead of a folder")
    p.add_argument("--type", help="validationType, required with --file")
    p.add_argument("--country", help="alpha-3, or 'auto'")
    p.add_argument("--layout", default="participant", choices=["auto", "hub", "participant"])
    p.add_argument("--root")
    p.add_argument("--group", help="select by group, e.g. TLS")
    p.add_argument("--filename", help="select by filename, e.g. TLS.pem")
    p.add_argument("--material-domain", help="select by domain, e.g. PH4H")
    p.set_defaults(func=cmd_inspect)

    for name, help_text in (("submit", "POST /{domain}/api/submissions"),
                            ("sign", "POST .../{id}/sign"),
                            ("deploy", "POST .../{id}/deploy"),
                            ("close", "POST .../{id}/close"),
                            ("audit", "GET .../{id}/audit"),
                            ("journal", "GET /{domain}/api/journal")):
        p = add(name, help=help_text + "  (needs --url)")
        if name == "submit":
            p.add_argument("body", help="JSON file holding the submission")
        if name in ("sign", "deploy", "close", "audit"):
            p.add_argument("id", help="submission id")
        if name == "sign":
            p.add_argument("--environment", default="dev")
        if name == "deploy":
            p.add_argument("--mode", choices=["full", "no-push", "no-commit"])
        if name == "audit":
            p.add_argument("--text", action="store_true", help="human-readable trail")
        if name == "journal":
            p.add_argument("--participant")
        p.set_defaults(func=cmd_passthrough)

    return parser


def add_folder_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--country", help="alpha-3, or 'auto' to resolve from the repository")
    p.add_argument("--layout", default="participant", choices=["auto", "hub", "participant"])
    p.add_argument("--root", help="directory relative to TNG_VALIDATION_ROOT")
    p.add_argument("--allowed-domains", nargs="*")
    p.add_argument("--fail-on-error", action="store_true",
                   help="exit 1 when the verdict is FAILURE")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
