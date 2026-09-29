"""
tng_delivery_policy.py
======================

Controls whether the last step — committing a participant's key material to a
trust list — actually runs.

Everything before deployment is reversible: verification touches no keys, signing
is local and repeatable. Deployment is the one step that writes to a published
trust list, and it is the one step you cannot take back. This module decides
whether it is allowed to, and records why.

Three modes
-----------
    full        write, commit, push.  The live path.
    no-push     write and commit into a throwaway clone, never push.  Exercises
                path layout, auth and conflict handling without publishing.
    no-commit   verify the target is reachable and writable, then stop before any
                commit.  Nothing enters the working tree, so there is no local
                commit that a later push could pick up.

Where the setting comes from
----------------------------
Four layers, in order of specificity:

    1. the deploy request          {"mode": "no-push"}
    2. the participant repo        .tng/delivery.yml
    3. the service environment     TNG_DELIVERY_MODE[_<ENV>]
    4. the built-in default        no-commit

**The most restrictive layer wins, not the most specific.** A participant that
marks its own material `no-commit` cannot have that overridden by an API caller
or by an operator's environment default. The setting exists so the owner of the
key material can withhold it; a precedence rule that let someone else override it
would defeat the point.

The consequence worth knowing: to deploy a participant whose repository says
`no-commit`, you change that repository. There is deliberately no force flag.

Safe by default, and the environment is a ceiling
-------------------------------------------------
With nothing configured anywhere the mode is `no-commit`. An unconfigured or
misconfigured deployment cannot write to a trust list.

More than that: **an unset `TNG_DELIVERY_MODE` contributes the safe default
rather than abstaining.** So a deploy request asking for `full` against a service
whose environment says nothing still resolves to `no-commit`. Enabling delivery
requires an operator with access to the service environment; it is not something
an API caller can do alone. Layers 1 and 2 can then only restrict further.

The participant-repo file
-------------------------
`.tng/delivery.yml`, either spelling:

    delivery:
      mode: no-commit          # full | no-push | no-commit

    no-commit: true            # shorthand; false means "no objection", and is
                               # still clamped by the other layers

Parsed with `yaml.safe_load`, which also accepts JSON — YAML 1.2 is a JSON
superset — so `.tng/delivery.yml` may contain either syntax.

Reading the file is a separate step from applying it, because the service does
not hold participant checkouts: the client that builds a submission reads the
file and passes the result along. For that, this module is runnable:

    python -m tng_delivery_policy /path/to/participant/repo
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

try:
    import yaml

    _YAML = True
except Exception:  # pragma: no cover
    _YAML = False


CONFIG_RELPATH = Path(".tng") / "delivery.yml"
ENV_VAR = "TNG_DELIVERY_MODE"


class DeliveryMode(str, Enum):
    FULL = "full"
    NO_PUSH = "no-push"
    NO_COMMIT = "no-commit"


#: Higher is more restrictive. Used by most_restrictive(); do not reorder.
RESTRICTIVENESS: dict[DeliveryMode, int] = {
    DeliveryMode.FULL: 0,
    DeliveryMode.NO_PUSH: 1,
    DeliveryMode.NO_COMMIT: 2,
}

DEFAULT_MODE = DeliveryMode.NO_COMMIT

_ALIASES = {
    "full": DeliveryMode.FULL,
    "commit": DeliveryMode.FULL,
    "live": DeliveryMode.FULL,
    "no-push": DeliveryMode.NO_PUSH,
    "no_push": DeliveryMode.NO_PUSH,
    "nopush": DeliveryMode.NO_PUSH,
    "dry-run": DeliveryMode.NO_PUSH,
    "dry_run": DeliveryMode.NO_PUSH,
    "no-commit": DeliveryMode.NO_COMMIT,
    "no_commit": DeliveryMode.NO_COMMIT,
    "nocommit": DeliveryMode.NO_COMMIT,
    "off": DeliveryMode.NO_COMMIT,
}


class PolicyError(ValueError):
    """A configured value could not be understood.

    Never silently downgraded to the default: a typo in a safety switch must be
    loud, not quietly permissive OR quietly restrictive.
    """


def parse_mode(value: object) -> Optional[DeliveryMode]:
    """Parse a configured value. None means 'this layer expresses no opinion'."""
    if value is None:
        return None
    if isinstance(value, DeliveryMode):
        return value
    if isinstance(value, bool):
        # Only reachable via the `no-commit: true` shorthand, handled by caller.
        return DeliveryMode.NO_COMMIT if value else DeliveryMode.FULL
    text = str(value).strip().lower()
    if not text:
        return None
    if text not in _ALIASES:
        raise PolicyError(
            f"unknown delivery mode {value!r}; expected one of "
            f"{[m.value for m in DeliveryMode]}")
    return _ALIASES[text]


def most_restrictive(*modes: Optional[DeliveryMode]) -> DeliveryMode:
    """The strictest opinion expressed, or the safe default if none was."""
    present = [m for m in modes if m is not None]
    if not present:
        return DEFAULT_MODE
    return max(present, key=lambda m: RESTRICTIVENESS[m])


@dataclass
class Resolution:
    """The decision, and enough provenance to explain it in an audit entry."""

    mode: DeliveryMode
    sources: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def commits(self) -> bool:
        return self.mode in (DeliveryMode.FULL, DeliveryMode.NO_PUSH)

    @property
    def pushes(self) -> bool:
        return self.mode == DeliveryMode.FULL

    @property
    def decided_by(self) -> str:
        """Which layer(s) set the winning value — what to put in the audit."""
        winners = [k for k, v in self.sources.items() if v == self.mode.value]
        return ", ".join(winners) if winners else "default"

    def explain(self) -> str:
        if self.mode == DeliveryMode.FULL:
            what = "material will be committed and pushed"
        elif self.mode == DeliveryMode.NO_PUSH:
            what = "material will be committed locally but not pushed"
        else:
            what = "nothing will be committed"
        return f"delivery mode '{self.mode.value}' set by {self.decided_by}: {what}"


def env_mode(environ: Optional[dict] = None) -> Optional[DeliveryMode]:
    """The service-wide default, from TNG_DELIVERY_MODE.

    A per-environment override TNG_DELIVERY_MODE_<ENV> takes precedence, so one
    deployment can run dev live while prod stays at no-commit.
    """
    env = environ if environ is not None else os.environ
    return parse_mode(env.get(ENV_VAR))


def env_mode_for(environment: str, environ: Optional[dict] = None) -> Optional[DeliveryMode]:
    env = environ if environ is not None else os.environ
    specific = env.get(f"{ENV_VAR}_{environment.upper()}")
    if specific:
        return parse_mode(specific)
    return env_mode(env)


def read_repo_config(repo_root: Path) -> tuple[Optional[DeliveryMode], list[str]]:
    """Read `.tng/delivery.yml` from a participant checkout.

    Returns (mode, notes). A missing file is not an error — it means the
    participant expressed no opinion, and the remaining layers decide. A file
    that exists but cannot be understood IS an error, because a safety switch
    that silently fails open (or closed) is worse than no switch.
    """
    notes: list[str] = []
    path = Path(repo_root) / CONFIG_RELPATH
    if not path.is_file():
        return None, [f"no {CONFIG_RELPATH.as_posix()} in {Path(repo_root).name}"]

    if not _YAML:  # pragma: no cover
        raise PolicyError(
            f"{path} exists but PyYAML is not installed, so the delivery policy "
            "cannot be read. Refusing to guess.")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyError(f"{path} is not valid YAML/JSON: {exc}")

    if raw is None:
        return None, [f"{path} is empty"]
    if not isinstance(raw, dict):
        raise PolicyError(f"{path} must contain a mapping, found {type(raw).__name__}")

    # Long form: delivery.mode
    section = raw.get("delivery")
    if isinstance(section, dict) and "mode" in section:
        mode = parse_mode(section.get("mode"))
        notes.append(f"{CONFIG_RELPATH.as_posix()}: delivery.mode = {section.get('mode')}")
        return mode, notes

    # Shorthand: no-commit / no_commit
    for key in ("no-commit", "no_commit"):
        if key in raw:
            value = raw[key]
            if not isinstance(value, bool):
                raise PolicyError(f"{path}: '{key}' must be true or false, found {value!r}")
            notes.append(f"{CONFIG_RELPATH.as_posix()}: {key} = {value}")
            return (DeliveryMode.NO_COMMIT if value else DeliveryMode.FULL), notes

    return None, [f"{path} sets no delivery mode"]


def resolve(
    *, requested: object = None, participant: object = None,
    environment: Optional[str] = None, environ: Optional[dict] = None,
) -> Resolution:
    """Combine every layer. The most restrictive opinion wins."""
    sources: dict[str, str] = {}
    notes: list[str] = []

    req = parse_mode(requested)
    if req is not None:
        sources["request"] = req.value

    part = parse_mode(participant)
    if part is not None:
        sources["participant repo"] = part.value

    # The environment is a CEILING, not just another opinion. When it is unset it
    # contributes the safe default, so no request and no participant file can
    # enable delivery on its own — going live takes an operator with access to the
    # service environment. That is what makes "explicit opt-in per environment"
    # true rather than merely the default.
    envm = env_mode_for(environment, environ) if environment else env_mode(environ)
    if envm is None:
        envm = DEFAULT_MODE
        notes.append(f"{ENV_VAR} is unset; delivery is not enabled for this environment")
        sources["default"] = envm.value
    else:
        sources[ENV_VAR] = envm.value

    mode = most_restrictive(req, part, envm)
    return Resolution(mode=mode, sources=sources, notes=notes)


def _main(argv: list[str]) -> int:  # pragma: no cover - thin CLI wrapper
    """Print the mode a participant checkout declares, for CI to pass along."""
    root = Path(argv[1]) if len(argv) > 1 else Path.cwd()
    try:
        mode, notes = read_repo_config(root)
    except PolicyError as exc:
        print(f"error: {exc}", flush=True)
        return 2
    for n in notes:
        print(f"# {n}", flush=True)
    print(mode.value if mode else "")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(_main(sys.argv))
