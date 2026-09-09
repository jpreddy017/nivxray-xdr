"""Command Reconstruction Engine (CRE).

A first-class Workspace pipeline stage that reconstructs the *effective
executable payload* the operating system will eventually run from any
nested Windows command-line invocation. Runs BEFORE decoder dispatch
and semantic analysis, making the reconstructed payload the
authoritative input for every downstream engine.

Public surface:
    reconstruct(cmdline) -> CommandReconstruction

The CRE is:
    · deterministic  — no execution, no external calls, same input = same output
    · recursive      — peels nested wrappers until the effective payload is bare
    · table-driven   — every wrapper is a parser module registered in
                        `wrappers/__init__.py`; adding a new wrapper is a
                        one-file change with no engine modifications
    · extensible     — parsers only need to implement the WrapperParser protocol
    · evidence-preserving — every peel emits a WrapperChainStep that becomes
                             the single source of truth for the analyst-facing
                             execution flow, process tree, timeline, attack
                             story, and investigation report
"""
from .engine import reconstruct
from .models import (
    CommandReconstruction,
    DispatchHint,
    WrapperChainStep,
)

__all__ = [
    "reconstruct",
    "CommandReconstruction",
    "DispatchHint",
    "WrapperChainStep",
]
