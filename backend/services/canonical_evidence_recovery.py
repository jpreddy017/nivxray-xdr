"""Canonical Evidence Recovery Service (ARB PR-2.1.2 · Phase A)

Single, shared entry point for deterministic evidence recovery. Both
``/api/decode/smart`` (sync) and ``/api/analyze/async`` (async) MUST
invoke this service — not each other — before any downstream
investigation, verdict projection, or reporting begins.

Architectural contract
----------------------
- **Investigation First**: engine owns the workflow. This service
  performs only the *recovery* half (Parse → Normalize → Aggregate).
  Post-recovery IOC / MITRE / verdict projection belongs to callers.
- **Interpreter Ownership**: normalization only fires when the active
  interpreter (PowerShell, cmd, JS, VBS, etc.) is *positively*
  identified. Token heuristics never trigger normalization.
- **Canonical Artifact**: once produced, every consumer reads from this
  object. Callers must not re-derive decoded output by re-running the
  chain.
- **Terminal Output**: the artifact is terminal. Callers must never feed
  ``decoded_output`` back into the recovery pipeline.

Stability gates
---------------
- **Recursive Safety**: ``input_hash`` and ``output_hash`` are exposed on
  the artifact. Callers that attempt further transformation MUST assert
  ``input_hash != output_hash`` before doing so. This service itself
  never re-processes its own output.
- **Decoder Stability Gate**: when the deterministic pipeline cannot
  produce new evidence, the artifact terminates with
  ``terminal_state == "stability_gate"`` and ``stability_gate_reached
  is True``. Callers should present this as *"Decoder Stability Gate
  reached. No further deterministic progress possible."*
- **Deterministic Fallback**: static-only stages (AES/OpenSSL/runtime
  decryptor branches) surface as ``terminal_state == "runtime_dependent"``
  or as notes on the artifact. Callers should render an explanatory
  fallback message rather than fabricate a verdict.

Terminal states
---------------
- ``atomic_ioc`` — input is a bare filename / URL / IP / hash. No
  decoding applicable; ``decoded_output == raw_input``.
- ``decode_error`` — PowerShell ``-EncodedCommand`` recovery chain
  exhausted. ``decode_error`` payload populated on the artifact.
- ``partial_recovery`` — ADR-0012 progressive partial recovery kicked
  in. ``partial_recovery`` payload populated.
- ``multi_fragment`` — input contains multiple independently decodable
  fragments. The router remains responsible for the multi-fragment
  fan-out (Phase A scope): the service tags the terminal state and the
  fragments list, and callers handle fan-out.
- ``recovered`` — deterministic best-decode succeeded and produced a
  canonical decoded output. ``det_result`` carries the raw pipeline
  return value for callers that need engine metadata.
- ``stability_gate`` — deterministic pipeline exhausted with no new
  evidence recovered.
- ``passthrough`` — input already plaintext / no obfuscation. Decoded
  output equals raw input; chain is empty.

Non-goals (Phase A)
-------------------
- Verdict card construction, IOC extraction, MITRE / LOLBAS mapping,
  layer-360 aggregation, TI enrichment, semantic overlay — these
  remain caller responsibilities. Phase B extends the service to
  optionally expose them once ``/api/analyze/async`` is on the same
  path.
- L0 convergence engine is FROZEN — this module strictly consumes it.
"""
from __future__ import annotations
import hashlib
import logging
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("nivx.services.canonical_evidence_recovery")


# ─── Public artifact type ────────────────────────────────────────────────
TerminalState = str  # Literal enum (kept as str for JSON portability):
# "recovered" · "stability_gate" · "passthrough" ·
# "atomic_ioc" · "decode_error" · "partial_recovery" · "multi_fragment"


def _sha256_str(text: str) -> str:
    """Stable content hash used for recursive-safety checks."""
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


@dataclass
class CanonicalArtifact:
    """Immutable canonical evidence recovery result.

    Both sync (`/decode/smart`) and async (`/analyze/async`) surfaces
    consume the same instance shape. Callers MUST NOT re-derive
    ``decoded_output``; they MUST read it from this artifact.
    """

    # Input side --------------------------------------------------------
    raw_input: str
    input_hash: str

    # Terminal state ----------------------------------------------------
    terminal_state: TerminalState
    stability_gate_reached: bool = False

    # Recovered canonical evidence -------------------------------------
    decoded_output: str = ""
    output_hash: str = ""

    # Chain / trace (canonical, drawn from the L0 deterministic run) ---
    chain_steps: List[Dict[str, Any]] = field(default_factory=list)
    chain_ids: List[str] = field(default_factory=list)

    # Engine metadata --------------------------------------------------
    engine: Optional[str] = None
    reached_shellcode: bool = False
    confidence: Optional[int] = None
    detected_type: Optional[Dict[str, Any]] = None
    notes: List[str] = field(default_factory=list)

    # Ingress gate provenance (ADR-0014) -------------------------------
    ingress_normalised_via: Optional[str] = None
    original_raw_input: Optional[str] = None

    # Optional terminal payloads (populated per terminal_state) --------
    atomic_ioc: Optional[Dict[str, Any]] = None
    decode_error: Optional[Dict[str, Any]] = None
    partial_recovery: Optional[Dict[str, Any]] = None
    multi_fragment: Optional[Dict[str, Any]] = None  # {"fragments": [...]}

    # Full deterministic engine return (for callers that need the raw
    # `det` dict — corrupted_container, reasoning, layer_trace, etc.).
    # NOT part of the canonical contract; provided as an escape hatch
    # so `/decode/smart`'s legacy response shape can be preserved
    # without duplicating the L0 call.
    det_result: Optional[Dict[str, Any]] = None

    # ─── Recursive safety helpers ─────────────────────────────────
    def assert_no_recursion(self) -> None:
        """Guard: callers must never feed decoded_output back through
        the recovery pipeline. Raises if input_hash == output_hash on
        a non-passthrough artifact."""
        if self.terminal_state == "passthrough":
            return
        if not self.output_hash:
            return
        if self.input_hash == self.output_hash:
            raise RuntimeError(
                "Recursive-safety violation: attempted to re-process a "
                "canonical artifact whose decoded_output is byte-identical "
                "to its raw_input. Callers must not re-invoke the recovery "
                "pipeline on stability-gate output."
            )

    def to_dict(self) -> Dict[str, Any]:
        """Portable dict — omits ``det_result`` (which is internal-only)."""
        d = asdict(self)
        d.pop("det_result", None)
        return d


# ─── Atomic IOC guard ────────────────────────────────────────────────────
def _atomic_ioc_kind_safe(text: str) -> Optional[str]:
    try:
        from v2.investigation.pipeline import _atomic_ioc_kind
        return _atomic_ioc_kind(text or "")
    except Exception:
        return None


# ─── Ingress normalisation gate (ADR-0014) ───────────────────────────────
def _apply_ingress_gate_safe(text: str) -> Tuple[str, Optional[str]]:
    """Return (normalised_text, provenance_or_None). Never raises."""
    try:
        from nivxforge.investigation.ingress_gate import apply_ingress_gate as _apply_gate
        gate = _apply_gate(text or "")
        if gate.was_vendor_json:
            return gate.text, gate.normalised_via
        return text, None
    except Exception:
        log.exception("Ingress gate failed (safe — raw input preserved)")
        return text, None


# ─── PowerShell -EncodedCommand short-circuit ───────────────────────────
_PS_ENC_RE = re.compile(
    r"powershell(?:\.exe)?[^\n]*?\-e(?:nc|c|ncodedcommand)?\s+"
    r"([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)


def _try_ps_encoded_short_circuit(text: str) -> Optional[Dict[str, Any]]:
    """Return a dict describing decode_error / partial_recovery when the
    PS ``-EncodedCommand`` blob fails the deterministic recovery chain.
    Returns None when no short-circuit applies (normal path continues).
    """
    m = _PS_ENC_RE.search(text or "")
    if not m:
        return None
    try:
        from v2.semantic.ps_recovery import recover_powershell_from_b64
        blob = m.group(1).strip("= ").rstrip("=")
        blob = blob + "=" * ((-len(blob)) % 4)
        rep = recover_powershell_from_b64(blob)
        if rep.status != "decode_error":
            return None
        return {"report": rep, "blob": blob}
    except Exception:
        return None


# ─── Multi-fragment detection ────────────────────────────────────────────
def _detect_multi_fragment(text: str) -> Optional[List[str]]:
    raw = text or ""
    has_br = bool(re.search(r"(?i)<\s*br\s*/?\s*>", raw))
    norm = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n\n", raw)
    enc_count = len(re.findall(r"(?i)-\s*e(?:c|nc|ncoded(?:command)?)\b", norm))
    if not (has_br or enc_count >= 2):
        return None
    fragments = [p.strip() for p in re.split(r"\n\s*\n+", norm.strip()) if p.strip()]
    return fragments if len(fragments) >= 2 else None


# ─── Public API ─────────────────────────────────────────────────────────
def recover_canonical_evidence(
    input_text: str,
    analysis_mode: str = "balanced",
) -> CanonicalArtifact:
    """Produce the canonical evidence recovery artifact for ``input_text``.

    Both ``/api/decode/smart`` and ``/api/analyze/async`` (and any future
    surface that needs canonical evidence) MUST invoke this function.
    No caller may re-derive ``decoded_output`` by re-running the L0
    convergence pipeline or by cross-endpoint HTTP calls.

    Parameters
    ----------
    input_text : str
        Raw analyst-supplied payload.
    analysis_mode : {"fast", "balanced", "deep"}
        Passed through to ``deterministic_best_decode``. Deep mode adds
        the linguistic hypothesis pass. Defaults to "balanced" (same as
        `/api/decode/smart` when the client doesn't override).

    Returns
    -------
    CanonicalArtifact
        Immutable canonical recovery result. See module docstring.

    Notes
    -----
    - Synchronous. Callers that need to avoid blocking the asyncio event
      loop should offload the whole call through ``run_offloaded`` (the
      same helper `/decode/smart` uses today for `deterministic_best_decode`).
    - Never raises: unexpected failures collapse to a ``passthrough``
      artifact with a diagnostic note. The router still gets a valid
      artifact to render.
    """
    original_raw = input_text or ""
    input_hash = _sha256_str(original_raw)

    # 1) Ingress normalisation gate (ADR-0014) --------------------------
    gated_text, ingress_via = _apply_ingress_gate_safe(original_raw)

    # 2) Atomic-IOC guard ----------------------------------------------
    atomic_kind = _atomic_ioc_kind_safe(gated_text)
    if atomic_kind is not None:
        art = CanonicalArtifact(
            raw_input=gated_text,
            input_hash=_sha256_str(gated_text),
            terminal_state="atomic_ioc",
            decoded_output=gated_text,
            output_hash=_sha256_str(gated_text),
            chain_steps=[{"op": "atomic-ioc-passthrough", "args": {}}],
            chain_ids=["atomic-ioc-passthrough"],
            engine="atomic_ioc_guard",
            reached_shellcode=False,
            confidence=100,
            detected_type={"type": "atomic_ioc", "label": f"Atomic {atomic_kind}"},
            notes=[
                f"Input classified as bare {atomic_kind}. "
                "Legacy chain-decode skipped — atomic IOCs are surfaced "
                "as-is and cannot be brute-forced into meaningful plaintext."
            ],
            ingress_normalised_via=ingress_via,
            original_raw_input=original_raw if ingress_via else None,
            atomic_ioc={"kind": atomic_kind, "value": (gated_text or "").strip()},
            stability_gate_reached=True,
        )
        return art

    # 3) PowerShell -EncodedCommand short-circuit ----------------------
    ps_short = _try_ps_encoded_short_circuit(gated_text)
    if ps_short is not None:
        rep = ps_short["report"]
        blob = ps_short["blob"]
        # ADR-0012 progressive partial recovery — if the decoder pulled a
        # readable prefix, mark terminal_state=partial_recovery so the
        # router can run the ADR-0012 pipeline. Otherwise it's a plain
        # decode_error.
        pr = dict(getattr(rep, "partial_recovery", {}) or {})
        if pr and pr.get("prefix_text"):
            terminal = "partial_recovery"
        else:
            terminal = "decode_error"
        art = CanonicalArtifact(
            raw_input=gated_text,
            input_hash=_sha256_str(gated_text),
            terminal_state=terminal,
            decoded_output="",  # never leak binary garbage
            output_hash=_sha256_str(""),
            chain_steps=[{"op": "ps-encodedcommand-recovery", "args": {}}],
            chain_ids=["ps-encodedcommand-recovery"],
            engine="ps-encodedcommand-recovery",
            reached_shellcode=False,
            confidence=None,
            detected_type={
                "type": "powershell_encoded_decode_error",
                "label": ("PowerShell -EncodedCommand blob detected — "
                          "recovery chain failed"),
            },
            notes=[
                "PowerShell -EncodedCommand blob detected — deterministic "
                "recovery chain executed.",
                (f"Base64 decoded ({rep.b64_bytes} bytes) but UTF-16LE "
                 f"strict validation failed at byte offset "
                 f"{rep.first_invalid_offset}: {rep.invalid_reason}."),
                "Downstream decoders (xor-brute, etc.) intentionally skipped.",
            ],
            ingress_normalised_via=ingress_via,
            original_raw_input=original_raw if ingress_via else None,
            decode_error={
                "status":               rep.status,
                "b64_bytes":            rep.b64_bytes,
                "b64_status":           rep.b64_status,
                "b64_reason":           rep.b64_reason,
                "first_invalid_offset": rep.first_invalid_offset,
                "invalid_reason":       rep.invalid_reason,
                "hex_preview":          rep.hex_preview,
                "possible_causes":      list(rep.possible_causes),
                "attempts":             [a.to_dict() for a in rep.attempts],
                "blob_length":          len(blob),
                "partial_recovery":     pr,
                "confidence_band":      rep.confidence_band,
                "confidence_reason":    rep.confidence_reason,
                "recovered_layers":     rep.recovered_layers,
            },
            partial_recovery=pr if terminal == "partial_recovery" else None,
            stability_gate_reached=True,
        )
        return art

    # 4) Multi-fragment fan-out signal ---------------------------------
    frags = _detect_multi_fragment(gated_text)
    if frags:
        art = CanonicalArtifact(
            raw_input=gated_text,
            input_hash=_sha256_str(gated_text),
            terminal_state="multi_fragment",
            decoded_output="",  # router fans out per-fragment
            output_hash=_sha256_str(""),
            engine="multi-fragment-split",
            detected_type={"type": "multi_fragment", "label": "Multi-fragment payload"},
            notes=[f"Detected {len(frags)} decodable fragments — router fan-out required."],
            ingress_normalised_via=ingress_via,
            original_raw_input=original_raw if ingress_via else None,
            multi_fragment={"fragments": frags, "count": len(frags)},
        )
        return art

    # 5) Deterministic best-decode (L0 convergence race) ---------------
    try:
        from analysis_core import deterministic_best_decode
        det = deterministic_best_decode(gated_text, analysis_mode=analysis_mode or "balanced")
    except Exception as e:
        log.exception("Canonical recovery: deterministic_best_decode raised")
        # Safe passthrough so callers still receive a valid artifact.
        return CanonicalArtifact(
            raw_input=gated_text,
            input_hash=_sha256_str(gated_text),
            terminal_state="passthrough",
            decoded_output=gated_text,
            output_hash=_sha256_str(gated_text),
            chain_steps=[],
            chain_ids=[],
            engine=None,
            confidence=0,
            detected_type=None,
            notes=[f"Recovery pipeline failed safely — passthrough. ({type(e).__name__})"],
            ingress_normalised_via=ingress_via,
            original_raw_input=original_raw if ingress_via else None,
            stability_gate_reached=True,
        )

    # 6) Post-decode enrichment applied inside `deterministic_best_decode`
    # (crypto API annotator etc.) already lives in the det dict. Build the
    # canonical artifact from `det`.
    decoded = det.get("output") or ""
    steps = det.get("steps") or []
    chain_ids = [s.get("op") for s in steps if s.get("op")]

    # Stability-gate detection: no steps produced OR output equals input.
    output_hash = _sha256_str(decoded)
    if not steps or decoded == "" or output_hash == _sha256_str(gated_text):
        # Passthrough / stability-gate — no new evidence recovered.
        terminal = "passthrough" if not steps else "stability_gate"
        art = CanonicalArtifact(
            raw_input=gated_text,
            input_hash=_sha256_str(gated_text),
            terminal_state=terminal,
            decoded_output=decoded or gated_text,
            output_hash=_sha256_str(decoded or gated_text),
            chain_steps=steps,
            chain_ids=chain_ids,
            engine=det.get("engine"),
            reached_shellcode=bool(det.get("reached_shellcode")),
            confidence=int(round(min(1.0, det.get("score", 0.0)) * 100)),
            detected_type=None,   # caller re-detects on decoded_output
            notes=list(det.get("notes") or []),
            ingress_normalised_via=ingress_via,
            original_raw_input=original_raw if ingress_via else None,
            det_result=det,
            stability_gate_reached=True,
        )
        return art

    art = CanonicalArtifact(
        raw_input=gated_text,
        input_hash=_sha256_str(gated_text),
        terminal_state="recovered",
        decoded_output=decoded,
        output_hash=output_hash,
        chain_steps=steps,
        chain_ids=chain_ids,
        engine=det.get("engine"),
        reached_shellcode=bool(det.get("reached_shellcode")),
        confidence=int(round(min(1.0, det.get("score", 0.0)) * 100)),
        detected_type=None,   # caller re-detects on decoded_output
        notes=list(det.get("notes") or []),
        ingress_normalised_via=ingress_via,
        original_raw_input=original_raw if ingress_via else None,
        det_result=det,
        stability_gate_reached=False,
    )
    return art


# ─── Convenience async wrapper ──────────────────────────────────────────
async def recover_canonical_evidence_async(
    input_text: str,
    analysis_mode: str = "balanced",
) -> CanonicalArtifact:
    """Async wrapper that offloads the synchronous recovery call to a
    worker thread — same offloading helper `/decode/smart` uses.

    Prefer this from asyncio request handlers so the event loop stays
    responsive during heavy decodes (xor-brute, L3 dispatch).
    """
    from routers.helpers.decode_offload import run_offloaded
    return await run_offloaded(
        recover_canonical_evidence, input_text, analysis_mode=analysis_mode,
    )


__all__ = [
    "CanonicalArtifact",
    "recover_canonical_evidence",
    "recover_canonical_evidence_async",
]
