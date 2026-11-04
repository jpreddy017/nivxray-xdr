"""Executor budget (D6-r recursion + wall-time bounds)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ExecutorBudget:
    max_depth: int = 3
    max_children: int = 16
    max_wall_time_ms: int = 5000
    enrichers_enabled: bool = True   # INV-2 gate
