"""IEDDE Stage 3 · Recipe Planner (discovery-driven, Rule 26).

The planner ties Stages 1–2 into a single decision loop:

    Stage 1 (Interpreter ID)  →  Stage 2 (Technique inventory)  →
        Stage 3 chooses ONE transformation from the L0 registry
        that has objective evidence  →  L0 executes it  →
        Stage 3 re-identifies + re-inventories  →  Repeat
        until no evidence justifies another stage → Stability Gate.

Rule contract:
    * Rule 23 · Stability Gate — stops when no further deterministic
      progress can be proven; returns a reasoned stop message.
    * Rule 24 · Understand-First — no plugin runs "just to try".
    * Rule 26 · Discovery-Driven — re-inspects after every stage.
    * Rule 21 · Deterministic — identical input → identical trace.

Non-goals:
    * Does NOT modify L0 execution semantics.
    * Does NOT hallucinate outputs when no primitive applies.
    * Does NOT choose non-deterministic candidates (e.g. AES without a
      known key → stability gate with `key_unavailable` reason).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from workspace.convergence.artifact import Artifact
from workspace.convergence.content import run as _run_content
from workspace.convergence.decoder import run as _run_decoder
from workspace.convergence.semantic import run as _run_semantic
from workspace.convergence.structural import run as _run_structural

from .interpreter_identifier import IdentificationResult, identify
from .technique_detector import (
    DetectionContext,
    TechniqueInventory,
    detect_techniques,
)


# ---------------------------------------------------------------------------
# Technique → L0 pass mapping.
# ---------------------------------------------------------------------------
#
# Each entry answers: "when this technique is present with sufficient
# evidence, which L0 pass is the correct next executor?"
#
# The mapping is intentionally sparse. If a technique has no mapping,
# the planner does NOT invent one — it advances to the next-highest
# technique or trips the stability gate.
#
_TECHNIQUE_TO_PASS: dict[str, str] = {
    "ps_invocation_wrapper": "structural",
    "ps_launcher_wrapper":   "structural",
    "string_concat":         "structural",
    "char_array":            "structural",
    "reverse":               "structural",
    "env_var_assembly":      "content",
    "ps_backtick":           "content",
    "cmd_caret":              "content",
    "unicode_escape":        "content",
    "url_encoding":          "content",
    "base64":                "decoder",
    "hex":                   "decoder",
    "utf16le":               "decoder",
    "gzip":                  "decoder",
    "zlib":                  "decoder",
}

_PASS_RUNNERS = {
    "structural": _run_structural,
    "content":    _run_content,
    "decoder":    _run_decoder,
    "semantic":   _run_semantic,
}

# Techniques that require deterministic-only external data. If detected
# they trip the stability gate with a specific reason, never a guess.
_KEY_REQUIRED = {"aes_wrapper", "rc4_wrapper", "xor"}


# ---------------------------------------------------------------------------
# Recipe / execution records
# ---------------------------------------------------------------------------


@dataclass
class PlannerDecision:
    """Explains WHY the planner chose a particular technique this
    iteration (or why it tripped the stability gate)."""
    selected: str | None                # technique name, or None if stability gate
    selected_pass: str | None           # L0 pass to execute, or None
    reason: str                          # human-readable justification
    confidence: float                    # confidence of the selected technique
    remaining_candidates: list[str]     # other techniques present, not chosen this iter
    key_required_deferred: list[str]    # techniques deferred because a secret is unavailable

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected": self.selected,
            "selected_pass": self.selected_pass,
            "reason": self.reason,
            "confidence": round(self.confidence, 4),
            "remaining_candidates": self.remaining_candidates,
            "key_required_deferred": self.key_required_deferred,
        }


@dataclass
class Stage:
    """One iteration of the planner loop."""
    iteration: int
    interpreter: str
    interpreter_confidence: float
    techniques_present: list[str]
    decision: PlannerDecision            # NEW · Rule 24 traceability
    chosen_pass: str | None              # None → stability gate reached this iter
    fired_transformations: list[str]
    changed: bool
    content_len_before: int
    content_len_after: int
    canonicality_delta: float            # NEW · %-shrink toward canonical (0..1)
    stop_reason: str | None              # populated when chosen_pass is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration": self.iteration,
            "interpreter": self.interpreter,
            "interpreter_confidence": round(self.interpreter_confidence, 4),
            "techniques_present": self.techniques_present,
            "decision": self.decision.to_dict(),
            "chosen_pass": self.chosen_pass,
            "fired_transformations": self.fired_transformations,
            "changed": self.changed,
            "content_len_before": self.content_len_before,
            "content_len_after": self.content_len_after,
            "canonicality_delta": round(self.canonicality_delta, 4),
            "stop_reason": self.stop_reason,
        }


@dataclass
class PlanResult:
    canonical_output: str
    stages: list[Stage]
    terminal_state: str            # "canonical" | "stability_gate"
    stop_reason: str
    iterations_executed: int
    final_interpreter: str
    final_techniques: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_output": self.canonical_output,
            "iterations_executed": self.iterations_executed,
            "terminal_state": self.terminal_state,
            "stop_reason": self.stop_reason,
            "final_interpreter": self.final_interpreter,
            "final_techniques": self.final_techniques,
            "stages": [s.to_dict() for s in self.stages],
        }


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


_MAX_ITERATIONS = 32  # hard ceiling — the stability gate should trip well before this


def plan_and_execute(content: str, max_iterations: int = _MAX_ITERATIONS) -> PlanResult:
    """Discovery-driven IEDDE loop.

    Args:
        content: initial artifact text.
        max_iterations: safety ceiling; the stability gate should
            terminate the loop well before this bound.

    Returns:
        PlanResult with the canonical output + full stage-by-stage
        reasoning trace.
    """
    if not isinstance(content, str):
        return PlanResult(
            canonical_output="",
            stages=[],
            terminal_state="stability_gate",
            stop_reason="non_string_input",
            iterations_executed=0,
            final_interpreter="unknown",
            final_techniques=[],
        )

    stages: list[Stage] = []
    current = content
    prev_hash: str | None = None

    for i in range(max_iterations):
        ident = identify(current)
        ctx = DetectionContext(
            primary_interpreter=ident.primary_interpreter,
            interpreters=tuple(m.interpreter for m in ident.interpreters),
        )
        inventory = detect_techniques(current, ctx)
        present = inventory.names()

        # ── Discovery-driven selection ─────────────────────────────
        # 1. Skip techniques we know require external secrets.
        # 2. Pick the highest-confidence technique that has a pass mapping.
        chosen_pass: str | None = None
        chosen_tech: str | None = None
        chosen_conf: float = 0.0
        blocking_key_required: str | None = None
        key_required_list: list[str] = []
        remaining_candidates: list[str] = []

        for sig in inventory.techniques:
            if sig.name in _KEY_REQUIRED and sig.confidence >= 0.60:
                blocking_key_required = blocking_key_required or sig.name
                key_required_list.append(sig.name)
                continue
            mapped = _TECHNIQUE_TO_PASS.get(sig.name)
            if mapped:
                if chosen_pass is None:
                    chosen_pass = mapped
                    chosen_tech = sig.name
                    chosen_conf = sig.confidence
                else:
                    remaining_candidates.append(sig.name)

        # Build the decision object.
        if chosen_pass is not None:
            decision = PlannerDecision(
                selected=chosen_tech,
                selected_pass=chosen_pass,
                reason=(
                    f"highest-confidence deterministic technique with an L0 primitive; "
                    f"selected {chosen_tech!r} → {chosen_pass!r} pass "
                    f"(confidence={chosen_conf:.2f})"
                ),
                confidence=chosen_conf,
                remaining_candidates=remaining_candidates,
                key_required_deferred=key_required_list,
            )
        else:
            decision = PlannerDecision(
                selected=None,
                selected_pass=None,
                reason=_stability_gate_reason(
                    present=present,
                    blocking_key_required=blocking_key_required,
                    ident=ident,
                ),
                confidence=0.0,
                remaining_candidates=[t for t in present],
                key_required_deferred=key_required_list,
            )

        # ── Stability Gate ─────────────────────────────────────────
        # If nothing to run, stop with a reasoned message.
        if chosen_pass is None:
            reason = decision.reason
            stages.append(Stage(
                iteration=i,
                interpreter=ident.primary_interpreter,
                interpreter_confidence=ident.confidence,
                techniques_present=present,
                decision=decision,
                chosen_pass=None,
                fired_transformations=[],
                changed=False,
                content_len_before=len(current),
                content_len_after=len(current),
                canonicality_delta=0.0,
                stop_reason=reason,
            ))
            return PlanResult(
                canonical_output=current,
                stages=stages,
                terminal_state="canonical" if not present else "stability_gate",
                stop_reason=reason,
                iterations_executed=i,
                final_interpreter=ident.primary_interpreter,
                final_techniques=present,
            )

        # ── Execute one pass ───────────────────────────────────────
        artifact = Artifact.from_input(current, interpreter=ident.primary_interpreter or None)
        runner = _PASS_RUNNERS[chosen_pass]
        try:
            new_artifact, record = runner(artifact)
        except Exception as e:
            stages.append(Stage(
                iteration=i,
                interpreter=ident.primary_interpreter,
                interpreter_confidence=ident.confidence,
                techniques_present=present,
                decision=decision,
                chosen_pass=chosen_pass,
                fired_transformations=[],
                changed=False,
                content_len_before=len(current),
                content_len_after=len(current),
                canonicality_delta=0.0,
                stop_reason=f"pass_execution_error:{chosen_pass}:{type(e).__name__}",
            ))
            return PlanResult(
                canonical_output=current,
                stages=stages,
                terminal_state="stability_gate",
                stop_reason=f"pass_execution_error:{chosen_pass}",
                iterations_executed=i,
                final_interpreter=ident.primary_interpreter,
                final_techniques=present,
            )

        len_before = len(current)
        len_after = len(new_artifact.content)
        delta = (len_before - len_after) / len_before if len_before else 0.0
        stage = Stage(
            iteration=i,
            interpreter=ident.primary_interpreter,
            interpreter_confidence=ident.confidence,
            techniques_present=present,
            decision=decision,
            chosen_pass=chosen_pass,
            fired_transformations=list(record.transformations),
            changed=record.changed,
            content_len_before=len_before,
            content_len_after=len_after,
            canonicality_delta=delta,
            stop_reason=None,
        )
        stages.append(stage)

        # If the pass didn't actually change anything, we're spinning.
        # Stop with a reasoned message to preserve Rule 23 (never guess).
        if not record.changed:
            reason = (
                f"chosen_pass_produced_no_change:{chosen_pass}:{chosen_tech};"
                f" no further deterministic recovery justified"
            )
            stages[-1].stop_reason = reason
            return PlanResult(
                canonical_output=current,
                stages=stages,
                terminal_state="stability_gate",
                stop_reason=reason,
                iterations_executed=i + 1,
                final_interpreter=ident.primary_interpreter,
                final_techniques=present,
            )

        current = new_artifact.content

        # Rule 23 stability: identical hash for two consecutive
        # iterations means no progress — bail out.
        this_hash = new_artifact.content_hash
        if prev_hash == this_hash:
            reason = "duplicate_fingerprint:no_deterministic_progress"
            stages[-1].stop_reason = reason
            return PlanResult(
                canonical_output=current,
                stages=stages,
                terminal_state="stability_gate",
                stop_reason=reason,
                iterations_executed=i + 1,
                final_interpreter=ident.primary_interpreter,
                final_techniques=present,
            )
        prev_hash = this_hash

    # Safety ceiling hit — should be rare.
    return PlanResult(
        canonical_output=current,
        stages=stages,
        terminal_state="stability_gate",
        stop_reason=f"max_iterations_reached:{max_iterations}",
        iterations_executed=max_iterations,
        final_interpreter=stages[-1].interpreter if stages else "unknown",
        final_techniques=stages[-1].techniques_present if stages else [],
    )


def _stability_gate_reason(
    *,
    present: list[str],
    blocking_key_required: str | None,
    ident: IdentificationResult,
) -> str:
    """Human-readable reasoned stop message (Rule 24 §4 contract)."""
    if blocking_key_required:
        pretty = {
            "aes_wrapper": "AES encrypted; decryption key unavailable",
            "rc4_wrapper": "RC4 wrapper; key unavailable",
            "xor":         "XOR obfuscation; key unavailable",
        }.get(blocking_key_required, f"{blocking_key_required}; secret unavailable")
        return f"remaining_layer:{pretty};canonical_deterministic_recovery_completed"
    if not present:
        return "canonical_reached:no_further_techniques_detected"
    unmapped = [t for t in present if t not in _TECHNIQUE_TO_PASS and t not in _KEY_REQUIRED]
    if unmapped:
        return (
            f"remaining_layer:{','.join(sorted(unmapped))};"
            f"no_deterministic_primitive_registered;"
            f"canonical_deterministic_recovery_completed"
        )
    # All detected techniques already tried this iteration but nothing
    # applied.
    return "no_deterministic_primitive_available_for_detected_techniques"


__all__ = ["Stage", "PlanResult", "plan_and_execute"]
