"""Canonical Executor — Phase 3.

Runs an IUEDecision plan against a capability registry; writes results
to AuthoritativeSSOT with mandatory Provenance. INV-1: no capability
plug-in becomes an alternative SSOT.
"""
from .executor import Executor, ExecutorResult
from .registry import CAPABILITY_REGISTRY, register_capability, CapabilityRole
from .budget import ExecutorBudget

# Import capabilities package to auto-register built-ins.
from . import capabilities as _cap  # noqa: F401

__all__ = ["Executor", "ExecutorResult", "ExecutorBudget",
           "CAPABILITY_REGISTRY", "register_capability", "CapabilityRole"]
