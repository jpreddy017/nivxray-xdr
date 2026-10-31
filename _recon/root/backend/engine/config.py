"""Feature-flag helpers for the Phase A orchestrator.

Env vars (backend/.env)
-----------------------
NIVX_ENGINE                     "legacy" | "orchestrator"   (default: "legacy")
NIVX_ENGINE_BUDGET_DEPTH        int                          (default: 12)
NIVX_ENGINE_BUDGET_WALLTIME_MS  int                          (default: 5000)
NIVX_ENGINE_BUDGET_BRANCHES     int                          (default: 3)

Contract
--------
Until Phase G validates the new engine end-to-end, routers should call
`engine_mode()` and dispatch to the legacy pipeline when it returns "legacy".
The new orchestrator remains fully usable in tests and dev regardless of flag.
"""
from __future__ import annotations

import os
from typing import Literal

from .models import Budget

EngineMode = Literal["legacy", "orchestrator"]


def engine_mode() -> EngineMode:
    v = (os.environ.get("NIVX_ENGINE") or "legacy").strip().lower()
    return "orchestrator" if v == "orchestrator" else "legacy"


def new_budget() -> Budget:
    def _int(name: str, default: int) -> int:
        try:
            return int(os.environ.get(name, "").strip() or default)
        except ValueError:
            return default
    return Budget(
        max_depth=_int("NIVX_ENGINE_BUDGET_DEPTH", 12),
        max_branches=_int("NIVX_ENGINE_BUDGET_BRANCHES", 3),
        wall_time_ms=_int("NIVX_ENGINE_BUDGET_WALLTIME_MS", 5000),
    )
