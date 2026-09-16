"""Canonical CRE data model.

Every wrapper peel emits a `WrapperChainStep`. The full recursive
reconstruction emits a `CommandReconstruction` that carries the
original invocation, the effective (innermost) payload, the ordered
wrapper chain, and a dispatch hint telling downstream engines which
analyzer should handle the effective payload.

Every downstream Workspace surface (Analyst Execution Flow, Process
Tree, Timeline, Attack Story, Investigation Report) should be
generated from THIS object — one source of truth.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class DispatchHint(str, Enum):
    """Which downstream analyzer should own the effective payload."""
    POWERSHELL = "powershell"
    LOLBAS = "lolbas"
    CMD_BATCH = "cmd_batch"
    WSCRIPT = "wscript"
    CSCRIPT = "cscript"
    BASH = "bash"
    PYTHON = "python"
    UNKNOWN = "unknown"


@dataclass
class WrapperChainStep:
    """One layer in the invocation chain.

    Fields (canonical — analyst-facing surfaces MUST read from here):
        wrapper           — canonical wrapper name (e.g. "wmic", "cmd",
                            "powershell", "schtasks"). Always lowercase.
        command           — the wrapper-specific sub-command / verb
                            (e.g. "process call create" for wmic,
                            "/c" for cmd, "-Command" for powershell).
        inner_command     — the raw inner command line extracted from
                            the wrapper's argument (may itself still be
                            wrapped — the CRE recurses on this value).
        normalized_command— the inner command with wrapper-specific
                            quoting / escaping / continuation syntax
                            resolved away, ready for the next peel.
                            Identical to `inner_command` when no
                            normalization was required.
        evidence          — free-form analyst-facing string explaining
                            EXACTLY what was matched and what rule was
                            applied. Kept short and truthful — the
                            analyst reads this to audit the peel.
        confidence        — 0-100. 100 means the wrapper's own grammar
                            proves the extraction (e.g. WMIC's own
                            argument syntax); lower values reflect
                            heuristic / lossy peels.
    """
    wrapper: str
    command: str
    inner_command: str
    normalized_command: str
    evidence: str
    confidence: int = 100

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CommandReconstruction:
    """The complete CRE output for a single command line.

    Fields:
        original          — verbatim input the analyst / EDR captured.
        effective_payload — the innermost recovered command, i.e. what
                            the OS will actually run once every wrapper
                            has been resolved.
        chain             — ordered list of WrapperChainSteps from
                            outermost wrapper to innermost. Length 0
                            means the original was already the
                            effective payload (no wrapping detected).
        dispatch_hint     — which downstream analyzer should own the
                            effective payload (see DispatchHint).
        stopped_reason    — populated ONLY when the engine bails out
                            early (recursion cap, unresolved quoting,
                            unknown wrapper). Empty on a clean peel.
        determinism_hash  — SHA-256 of the concatenated canonical
                            step dicts + effective payload. Enables the
                            regression harness to prove that the same
                            input yields byte-identical reconstruction
                            across runs.
    """
    original: str
    effective_payload: str
    chain: list[WrapperChainStep] = field(default_factory=list)
    dispatch_hint: DispatchHint = DispatchHint.UNKNOWN
    stopped_reason: str = ""
    determinism_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "original":          self.original,
            "effective_payload": self.effective_payload,
            "chain":             [s.to_dict() for s in self.chain],
            "dispatch_hint":     self.dispatch_hint.value,
            "stopped_reason":    self.stopped_reason,
            "determinism_hash":  self.determinism_hash,
        }

    # ── Analyst-facing helpers ──────────────────────────────────
    def execution_flow(self) -> list[str]:
        """Produce the human-readable execution flow the Analyst
        Execution Flow section renders (Issue #4 from the Runtime
        Dependency P0). Reads directly from the chain — no separate
        derivation logic, no risk of drift."""
        if not self.chain:
            return [self.effective_payload]
        flow: list[str] = []
        for step in self.chain:
            flow.append(step.wrapper)
        # Terminal token derived from the dispatch hint
        if self.dispatch_hint == DispatchHint.POWERSHELL:
            flow.append("powershell")
        elif self.dispatch_hint == DispatchHint.LOLBAS:
            flow.append("lolbas")
        else:
            flow.append(self.dispatch_hint.value)
        # Deduplicate consecutive tokens (e.g. cmd → cmd chain
        # collapses to a single node).
        collapsed: list[str] = []
        for tok in flow:
            if not collapsed or collapsed[-1] != tok:
                collapsed.append(tok)
        return collapsed
