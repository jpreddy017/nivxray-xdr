"""NivXRay v2 · Feature-Flag Registry (3-state).

Per /app/memory/GOVERNANCE.md §12 (Feature-Flag Contract) with the
Round-5 amendment introducing tri-state semantics:

    DISABLED  →  code path is off. Zero runtime cost. Byte-identical
                 RC5 behaviour required.

    SHADOW    →  code path runs SIDE-BY-SIDE with the RC5 pipeline
                 but MUST NOT influence any output. Used for
                 collecting evidence, dual-write validation, and
                 quality-gate measurement before promotion.

    ENABLED   →  code path is authoritative. Only reached after the
                 shadow phase closes its regression gate.

Boot-time source of truth: environment variables prefixed with
`NIVX_FLAG_`. Values are case-insensitive. Unknown values fall back
to `disabled`.

Example:
    NIVX_FLAG_CASE_ENGINE=shadow
    NIVX_FLAG_TIMELINE_V2=disabled

Runtime toggles are Phase-4+ (admin API). Until then, flags are
read once at process start.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Final


class FlagState(str, Enum):
    """Tri-state feature flag."""
    DISABLED = "disabled"
    SHADOW = "shadow"
    ENABLED = "enabled"

    @classmethod
    def parse(cls, raw: str | None) -> "FlagState":
        if not raw:
            return cls.DISABLED
        v = raw.strip().lower()
        if v in ("on", "true", "1", "enabled"):
            return cls.ENABLED
        if v in ("shadow", "sidecar", "observe"):
            return cls.SHADOW
        return cls.DISABLED


# ─── Registered flags ────────────────────────────────────────────────
# The keys below are the ONLY recognised v2 capability switches.
# Adding a new capability requires a governance amendment.
FLAG_NAMES: Final[tuple[str, ...]] = (
    "CASE_ENGINE",
    "GRAPH_ENGINE",
    "TIMELINE_V2",
    "TRAJECTORY_ENGINE",
    "ADAPTERS",
    "REPLAY",
    "NOTEBOOK",
    "ARTIFACT_STORE",
    "KNOWLEDGE_LAYER",
    "NEGATIVE_EVIDENCE",
    "COPILOT",
    "VERDICT_ENGINE_V3",
)


@dataclass(frozen=True)
class FeatureFlag:
    name: str
    state: FlagState
    env_key: str

    def disabled(self) -> bool: return self.state is FlagState.DISABLED
    def shadow(self)   -> bool: return self.state is FlagState.SHADOW
    def enabled(self)  -> bool: return self.state is FlagState.ENABLED

    def observable(self) -> bool:
        """True when the code path may run (shadow or enabled)."""
        return self.state is not FlagState.DISABLED


def _read(name: str) -> FeatureFlag:
    env_key = f"NIVX_FLAG_{name}"
    return FeatureFlag(name=name, env_key=env_key,
                       state=FlagState.parse(os.environ.get(env_key)))


# Snapshot captured at process start. Kept ONLY for back-compat with
# `summary()` and `all_disabled()` — `get()` re-reads env every call.
# See DYNAMIC_FLAGS below for the rationale.
FLAGS: Final[dict[str, FeatureFlag]] = {n: _read(n) for n in FLAG_NAMES}


# ─── Dynamic flag reads ──────────────────────────────────────────────
# Historically `FLAGS` was a frozen import-time snapshot and every
# consumer (routers, tests, admin API) had to trip over the fact that
# env vars set AFTER import were invisible. Every fork-agent handoff
# has re-discovered this the hard way (CI cold-cache runs, module-
# scope fixtures, admin runtime toggles, notebook re-runs).
#
# We now resolve every `get(name)` from the LIVE environment. Cost is
# a single dict lookup + string parse — well under a microsecond per
# call and dominated by the FastAPI request itself. In exchange we
# get:
#   • CI env vars set at any point work identically to `.env` files.
#   • Test fixtures can flip a flag mid-suite without importlib.reload.
#   • The future admin API can just call `os.environ[...] = "shadow"`.
#   • `all_disabled()` stays semantically stable — it now reflects
#     current env, not a stale import snapshot.
#
# `FLAGS` is preserved so any pre-existing `from v2.flags import FLAGS`
# consumer keeps working; it's simply no longer the authoritative
# source of truth.
def get(name: str) -> FeatureFlag:
    """Return the current state of a registered flag.

    Reads `os.environ` on every call — see the module docstring for
    the rationale (permanent fix for the CI cold-cache class of bugs).
    """
    if name not in FLAGS:
        return FeatureFlag(name=name, env_key=f"NIVX_FLAG_{name}",
                           state=FlagState.DISABLED)
    return _read(name)


def all_disabled() -> bool:
    """True iff every registered flag is currently DISABLED.

    Reads env live (see `get`). Governance contract §12 still holds:
    when this returns True, the process MUST behave byte-identically
    to the frozen RC5 release.
    """
    return all(_read(n).state is FlagState.DISABLED for n in FLAG_NAMES)


def summary() -> dict[str, str]:
    """Live summary of every registered flag."""
    return {n: _read(n).state.value for n in FLAG_NAMES}


__all__ = [
    "FlagState", "FeatureFlag", "FLAG_NAMES", "FLAGS",
    "get", "all_disabled", "summary",
]
