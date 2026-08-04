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
class BinaryArtifact:
    """When decoding recovers a binary executable, this describes it."""
    kind: str                      # "PE" | "ELF" | "Mach-O" | "unknown_binary"
    magic: str                     # bytes as hex
    subtype: str                   # ".exe/.dll" | "shared object" | "Mach-O bundle"
    recovered_by: list[str]        # ordered technique chain
    # ▲ 2026-02 · Phase-1 PE Static Analysis (owner-approved bundle).
    #   Attached when kind == "PE" and `services.pe_analyzer.is_available()`.
    #   Consumed by the Workspace `PEAnalysisPanel` to keep analysts inside
    #   NivXRay instead of exporting the payload to PEStudio / DIE / PE-bear.
    pe_analysis: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "magic": self.magic,
            "subtype": self.subtype,
            "recovered_by": self.recovered_by,
            "pe_analysis": self.pe_analysis,
            "next_actions": [
                "Parse PE Header" if self.kind == "PE" else f"Parse {self.kind} Header",
                "Extract Imports",
                "Calculate Hashes",
                "Detect Packers",
                "Extract Strings",
                "YARA Scan",
                "Static Analysis",
            ],
        }


@dataclass
class PlanResult:
    canonical_output: str
    stages: list[Stage]
    terminal_state: str            # "canonical" | "stability_gate" | "binary_artifact_recovered"
    stop_reason: str
    iterations_executed: int
    final_interpreter: str
    final_techniques: list[str]
    binary_artifact: BinaryArtifact | None = None
    # ▲ 2026-02 · Phase 2 · Broken Payload Diagnostics.
    # Structured, human-readable explanations of *why* the deterministic
    # recovery stopped. Populated for every non-canonical terminal state.
    # Rule 23 anchor — the engine surfaces the specific layer, offset,
    # and recommendation instead of a silent failure.
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_output": self.canonical_output,
            "iterations_executed": self.iterations_executed,
            "terminal_state": self.terminal_state,
            "stop_reason": self.stop_reason,
            "final_interpreter": self.final_interpreter,
            "final_techniques": self.final_techniques,
            "binary_artifact": self.binary_artifact.to_dict() if self.binary_artifact else None,
            "diagnostics": list(self.diagnostics),
            "stages": [s.to_dict() for s in self.stages],
        }


# ─── Broken Payload Diagnostics (2026-02 · Phase 2) ───────────────────
#
# Rule 23 (Stability Gate) mandates that the engine NEVER guesses when
# recovery cannot proceed deterministically. But a raw "stop_reason"
# string like `pass_execution_error:decoder:UnicodeDecodeError` is not
# what an analyst wants to see. `_diagnose` translates the engine's
# internal signals into a structured analyst-facing explanation:
#
#     {
#       "layer":          "gzip" | "aes" | "base64" | "utf16le" | ...
#       "reason":         short human-readable description
#       "recommendation": what the analyst should do next
#       "code":           machine-parseable label
#       "severity":       "critical" | "high" | "medium" | "info"
#       "hex_snippet":    optional 32-byte hex peek of the offending bytes
#       "offset":         optional file offset where the failure hit
#     }
#
# Every non-canonical PlanResult carries at least one diagnostic. The
# frontend (`IEDDEDecisionTrace`) renders them as amber cards.
def _hex_snippet(data: str | bytes, limit: int = 32) -> str | None:
    """Return the first `limit` bytes of `data` as space-separated hex."""
    try:
        if isinstance(data, str):
            data = data.encode("latin-1", errors="replace")
        return " ".join(f"{b:02x}" for b in data[:limit]) if data else None
    except Exception:
        return None


def _diagnose(
    result_terminal_state: str,
    stop_reason: str,
    stages: list["Stage"],
    current_content: str,
) -> list[dict[str, Any]]:
    """Deterministically translate engine signals into analyst diagnostics.

    Never raises. Returns [] when the recovery reached canonical.
    """
    if result_terminal_state == "canonical":
        return []
    if result_terminal_state == "binary_artifact_recovered":
        # Binary handoff is not a failure — nothing to diagnose.
        return []

    diagnostics: list[dict[str, Any]] = []
    reason = stop_reason or ""
    last_stage = stages[-1] if stages else None
    last_pass = last_stage.chosen_pass if last_stage else None
    fired = last_stage.fired_transformations if last_stage else []

    # ── Pass-execution errors → surface the exception class ───────────
    if reason.startswith("pass_execution_error:"):
        parts = reason.split(":")
        pass_name = parts[1] if len(parts) > 1 else last_pass or "unknown"
        exc_name = parts[2] if len(parts) > 2 else "Exception"
        layer = _layer_for_pass(pass_name, fired)
        rec_msg = _recommendation_for_exception(exc_name, layer)
        diagnostics.append({
            "layer": layer,
            "code":  f"pass_execution_error:{exc_name}",
            "severity": "high",
            "reason": f"The {layer} pass raised {exc_name} while transforming the artifact.",
            "recommendation": rec_msg,
            "hex_snippet": _hex_snippet(current_content),
            "offset": None,
        })

    # ── "chosen_pass_produced_no_change" → planner detected a technique
    #    but the corresponding L0 primitive couldn't materially decode ─
    elif reason.startswith("chosen_pass_produced_no_change:"):
        # reason format: chosen_pass_produced_no_change:<pass>:<tech>; ...
        try:
            head = reason.split(";", 1)[0]
            _, pass_name, tech = head.split(":", 2)
        except Exception:
            pass_name, tech = last_pass or "unknown", "unknown"
        layer = tech if tech and tech != "unknown" else _layer_for_pass(pass_name, fired)
        diagnostics.append({
            "layer": layer,
            "code":  f"stalled:{pass_name}:{tech}",
            "severity": "medium",
            "reason": (
                f"The {tech} primitive was detected but produced no change. "
                "This usually means the encoded payload is malformed, truncated, "
                "or requires a key the engine does not have."
            ),
            "recommendation": _recommendation_for_stalled(layer),
            "hex_snippet": _hex_snippet(current_content),
            "offset": None,
        })

    # ── "no_deterministic_primitive_registered" → planner detected an
    #    unmapped technique (typically a keyed cipher: AES/RC4/XOR) ────
    elif "no_deterministic_primitive_registered" in reason:
        head = reason.split("no_deterministic_primitive_registered:", 1)[-1]
        tech = head.split(";", 1)[0] or "unknown"
        diagnostics.append({
            "layer": tech,
            "code":  f"key_required:{tech}",
            "severity": "high",
            "reason": (
                f"Recovery reached a {tech.upper()} layer that requires a key "
                "which is not present in the payload. The engine refused to "
                "brute-force (Rule 23 — never guess)."
            ),
            "recommendation": (
                f"Locate the {tech.upper()} key material in the surrounding script "
                "or memory dump, then re-run with the key supplied."
            ),
            "hex_snippet": _hex_snippet(current_content),
            "offset": None,
        })

    # ── "duplicate_fingerprint:no_deterministic_progress" ────────────
    elif "duplicate_fingerprint" in reason:
        diagnostics.append({
            "layer": last_pass or "decoder",
            "code":  "duplicate_fingerprint",
            "severity": "medium",
            "reason": (
                "Two consecutive iterations produced identical output — the "
                "planner is spinning without progress."
            ),
            "recommendation": (
                "The remaining layer may need a manual recipe step. Inspect the "
                "current content and add a targeted decoder in the Recipe panel."
            ),
            "hex_snippet": _hex_snippet(current_content),
            "offset": None,
        })

    # ── Fallback (shouldn't be reached in practice) ───────────────────
    else:
        diagnostics.append({
            "layer": "unknown",
            "code":  "unknown_stability_gate",
            "severity": "info",
            "reason": reason or "The deterministic recovery stopped without a specific cause.",
            "recommendation": "Inspect the IEDDE Decision Trace for the last executed pass.",
            "hex_snippet": _hex_snippet(current_content),
            "offset": None,
        })

    return diagnostics


def _layer_for_pass(pass_name: str, fired_transformations: list[str]) -> str:
    """Best-effort mapping of an L0 pass name into an analyst-facing layer."""
    txt = " ".join(fired_transformations or []) + " " + (pass_name or "")
    for token, layer in (
        ("gzip",    "gzip"),
        ("deflate", "deflate"),
        ("zlib",    "zlib"),
        ("base64",  "base64"),
        ("utf16",   "utf16le"),
        ("aes",     "aes"),
        ("rc4",     "rc4"),
        ("xor",     "xor"),
    ):
        if token in txt.lower():
            return layer
    return pass_name or "unknown"


def _recommendation_for_exception(exc_name: str, layer: str) -> str:
    """Map the exception class → specific analyst-friendly recommendation."""
    mapping = {
        "UnicodeDecodeError":     f"The {layer} decoder found an invalid surrogate. Check for a truncated payload or byte-order mismatch.",
        "binascii.Error":         f"The base64 decoder found invalid padding. Verify the entire base64 blob was captured and re-run.",
        "Error":                  f"The {layer} step raised a low-level error. Verify the payload is complete.",
        "BadZipFile":             f"The archive is corrupt. Re-capture the original file and re-run.",
        "zlib.error":             f"The {layer} stream is malformed. This often indicates a partial capture or wrong offset.",
        "PEFormatError":          f"The recovered PE headers are truncated or damaged. Verify the base64 blob is complete.",
        "MemoryError":            f"The payload was too large for the {layer} pass. Try running the decoder on a slice of the payload.",
    }
    return mapping.get(exc_name, f"The {layer} pass failed with {exc_name}. Verify the payload is complete.")


def _recommendation_for_stalled(layer: str) -> str:
    """What to tell the analyst when a detected primitive produced no change."""
    mapping = {
        "gzip":    "The GZip header was detected but decompression failed. The DEFLATE stream is likely corrupt or truncated — re-capture the payload.",
        "deflate": "The DEFLATE stream is malformed. Check that the payload wasn't chunked or split across multiple lines.",
        "base64":  "Base64 detection fired but decoding produced no change. The blob may be double-wrapped or contain invalid characters.",
        "utf16le": "UTF-16LE detection fired but decoding produced no change. The byte-order mark may be missing or the payload uses BE.",
        "aes":     "AES layer detected — the key is unknown. Provide the key or capture it from the surrounding script.",
        "rc4":     "RC4 layer detected — the key is unknown. Provide the key or capture it from the surrounding script.",
        "xor":     "XOR layer detected — the key is unknown. Try a known-plaintext attack or supply the key.",
    }
    return mapping.get(layer.lower(),
                        f"The {layer} primitive detected the payload but couldn't recover it. Inspect the raw bytes for corruption.")



_BINARY_MAGIC = (
    (b"MZ",           "PE",       "Executable (.exe/.dll)"),
    (b"\x7fELF",      "ELF",      "Linux executable / shared object"),
    (b"\xcf\xfa\xed\xfe", "Mach-O", "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe", "Mach-O", "Mach-O 32-bit"),
    (b"\xca\xfe\xba\xbe", "Mach-O", "Universal binary"),
    (b"PK\x03\x04",   "ZIP",      "ZIP / JAR / OOXML container"),
    (b"\x1f\x8b\x08", "GZIP",     "raw gzip stream"),
)


def _detect_binary_artifact(content: str, recovered_by: list[str]) -> BinaryArtifact | None:
    """Return a BinaryArtifact iff the recovered content is (or contains
    inside an SQ literal) a known executable / container magic.

    Only fires when the artifact is predominantly non-printable OR the
    magic sits inside a SQ literal that itself is mostly non-printable
    (avoids labelling `MZ is the CEO of Meta.` as a PE).
    """
    if not isinstance(content, str) or len(content) < 4:
        return None
    try:
        raw = content.encode("latin-1", errors="ignore")
    except Exception:
        return None

    # Case A: bare binary at the start.
    printable_ratio = _printable_ratio(raw[:512])
    for sig, kind, subtype in _BINARY_MAGIC:
        if raw.startswith(sig) and printable_ratio < 0.85:
            pe = _attach_pe_analysis(kind, raw)
            return BinaryArtifact(
                kind=kind, magic=sig.hex(),
                subtype=subtype, recovered_by=list(recovered_by),
                pe_analysis=pe,
            )

    # Case B: SQ-literal-wrapped binary (e.g. after base64→SQ inline).
    # Extract every SQ literal and check its bytes.
    import re
    for m in re.finditer(r"'([^'\r\n]{16,})'", content):
        inner = m.group(1).encode("latin-1", errors="ignore")
        ir = _printable_ratio(inner[:512])
        for sig, kind, subtype in _BINARY_MAGIC:
            if inner.startswith(sig) and ir < 0.85:
                pe = _attach_pe_analysis(kind, inner)
                return BinaryArtifact(
                    kind=kind, magic=sig.hex(),
                    subtype=subtype, recovered_by=list(recovered_by),
                    pe_analysis=pe,
                )

    # Case C: binary magic appears at ANY offset in the raw content
    # (real-world PE payloads contain \r and \n which break the SQ regex).
    # Guardrail — the 512-byte window AFTER the magic must be predominantly
    # non-printable, so we don't false-fire on a text mention of "MZ".
    for sig, kind, subtype in _BINARY_MAGIC:
        idx = raw.find(sig)
        if idx < 0:
            continue
        window = raw[idx: idx + 1024]
        if len(window) < 64:
            continue
        if _printable_ratio(window) < 0.55:
            payload_bytes = raw[idx:]
            pe = _attach_pe_analysis(kind, payload_bytes)
            return BinaryArtifact(
                kind=kind, magic=sig.hex(),
                subtype=subtype, recovered_by=list(recovered_by),
                pe_analysis=pe,
            )
    return None


def _attach_pe_analysis(kind: str, raw: bytes) -> dict | None:
    """Deterministically produce a PE static-analysis report for PE
    artifacts. Returns None for non-PE binaries; returns the analyzer
    diagnostic dict (with `available: False`) if pefile isn't installed —
    the caller renders "PE analysis capability unavailable" in that case.
    """
    if kind != "PE":
        return None
    try:
        from services.pe_analyzer import analyze_pe
        return analyze_pe(raw)
    except Exception:
        return None


def _printable_ratio(chunk: bytes) -> float:
    if not chunk:
        return 1.0
    p = sum(1 for b in chunk if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d))
    return p / len(chunk)


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


_MAX_ITERATIONS = 32  # hard ceiling — the stability gate should trip well before this


def plan_and_execute(content: str, max_iterations: int = _MAX_ITERATIONS) -> PlanResult:
    """Discovery-driven IEDDE loop.

    Wraps `_plan_and_execute_core` and post-processes every non-canonical
    result to attach analyst-facing `diagnostics` (2026-02 · Phase 2 ·
    Broken Payload Diagnostics).
    """
    result = _plan_and_execute_core(content, max_iterations=max_iterations)
    if result.terminal_state not in ("canonical", "binary_artifact_recovered"):
        try:
            result.diagnostics = _diagnose(
                result.terminal_state,
                result.stop_reason,
                result.stages,
                result.canonical_output,
            )
        except Exception:
            # Never let a diagnostic-builder bug crash the pipeline.
            result.diagnostics = []
    return result


def _plan_and_execute_core(content: str, max_iterations: int = _MAX_ITERATIONS) -> PlanResult:
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
        # 2. Prefer decoder-pass techniques (base64/hex/gzip/utf16le/zlib)
        #    over structural-pass techniques — because outer structural
        #    wrappers (launcher, invocation) are often *hiding* an
        #    inner encoding layer that must peel first.
        # 3. Fall back to highest-confidence technique with a pass mapping.
        chosen_pass: str | None = None
        chosen_tech: str | None = None
        chosen_conf: float = 0.0
        blocking_key_required: str | None = None
        key_required_list: list[str] = []
        remaining_candidates: list[str] = []

        # First pass: prefer decoder-pass techniques (encoding layers)
        # when the current artifact contains any of them.
        _DECODER_TECHS = {"base64", "utf16le", "hex", "gzip", "zlib"}
        _decoder_pick: tuple[str, str, float] | None = None
        _structural_pick: tuple[str, str, float] | None = None
        _content_pick: tuple[str, str, float] | None = None

        for sig in inventory.techniques:
            if sig.name in _KEY_REQUIRED and sig.confidence >= 0.60:
                blocking_key_required = blocking_key_required or sig.name
                key_required_list.append(sig.name)
                continue
            mapped = _TECHNIQUE_TO_PASS.get(sig.name)
            if not mapped:
                continue
            if sig.name in _DECODER_TECHS and _decoder_pick is None:
                _decoder_pick = (sig.name, mapped, sig.confidence)
            elif mapped == "structural" and _structural_pick is None:
                _structural_pick = (sig.name, mapped, sig.confidence)
            elif mapped == "content" and _content_pick is None:
                _content_pick = (sig.name, mapped, sig.confidence)
            remaining_candidates.append(sig.name)

        # Priority: decoder > structural > content.
        picked = _decoder_pick or _structural_pick or _content_pick
        if picked:
            chosen_tech, chosen_pass, chosen_conf = picked
            remaining_candidates = [t for t in remaining_candidates if t != chosen_tech]

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
            # Check for binary artifact — if the recovered content is
            # an executable/container, the *decoding* problem is done
            # even though it isn't ASCII text (IEDDE §5.1 canonical
            # artifact contract).
            bin_art = _detect_binary_artifact(
                current,
                recovered_by=[t for s in stages for t in s.fired_transformations],
            )
            if bin_art:
                return PlanResult(
                    canonical_output=current,
                    stages=stages,
                    terminal_state="binary_artifact_recovered",
                    stop_reason=(
                        f"canonical_binary_recovered:{bin_art.kind};"
                        f"decoding_complete_switch_to_binary_analysis"
                    ),
                    iterations_executed=i,
                    final_interpreter=ident.primary_interpreter,
                    final_techniques=present,
                    binary_artifact=bin_art,
                )
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
            # Binary artifact check on this exit path too.
            bin_art = _detect_binary_artifact(
                current,
                recovered_by=[t for s in stages for t in s.fired_transformations],
            )
            if bin_art:
                return PlanResult(
                    canonical_output=current,
                    stages=stages,
                    terminal_state="binary_artifact_recovered",
                    stop_reason=(
                        f"canonical_binary_recovered:{bin_art.kind};"
                        f"decoding_complete_switch_to_binary_analysis"
                    ),
                    iterations_executed=i + 1,
                    final_interpreter=ident.primary_interpreter,
                    final_techniques=present,
                    binary_artifact=bin_art,
                )
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
