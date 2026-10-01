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

    # ─── IEDDE augmentation (Priority 1 · SSOT wiring · 2026-02) ────
    # The IEDDE (Intelligent Evidence-Driven Decoding Engine) trace is
    # attached to EVERY canonical artifact. This makes the IEDDE
    # reasoning trace visible on every decode entry point without
    # disrupting the legacy Workspace UI. See:
    #   • backend/services/recipe_planner.py  (plan_and_execute)
    #   • backend/routers/iedde.py            (dedicated SSOT endpoint)
    #   • memory/ARCHITECTURAL_DIRECTION_IEDDE.md
    #
    # `iedde_trace`         · dict form of PlanResult (stages, decisions,
    #                          terminal_state, stop_reason, binary_artifact).
    # `iedde_terminal_state`· one of {canonical, stability_gate,
    #                          binary_artifact_recovered}.
    # `canonical_confidence`· 0-100 · analyst-facing completeness metric
    #                          derived deterministically from the IEDDE
    #                          terminal state + stop reason. NEVER a
    #                          heuristic guess (Rule 23).
    iedde_trace: Optional[Dict[str, Any]] = None
    iedde_terminal_state: Optional[str] = None
    canonical_confidence: Optional[int] = None
    canonical_confidence_reason: Optional[str] = None
    # ▲ 2026-02 · Phase 2 · Broken Payload Diagnostics.
    # Structured analyst-facing explanations for every non-canonical
    # terminal state (layer / reason / recommendation / severity /
    # optional hex_snippet). Empty list for canonical + binary paths.
    iedde_diagnostics: List[Dict[str, Any]] = field(default_factory=list)

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


# ─── Bash echo-base64-pipe short-circuit ────────────────────────────────
# Matches classic Linux LotL:
#   echo "<b64>" | base64 -d
#   echo '<b64>' | base64 -d | bash
#   echo <b64> | base64 --decode | sh
#   echo "<b64>" | tr 'X' 'Y' | base64 -d [| bash]  ← character-substitution obfuscation
#   echo "<b64>" | rev | base64 -d               ← reversal obfuscation
# L0 has no bash-pipeline decoder and interpreter-ownership incorrectly
# flags `echo` as the PowerShell alias for `Write-Output`, producing
# ─── Bash shell-pipeline decoder (plugin-registry) ──────────────────────
# Instead of adding a new regex every time a new obfuscation combo
# appears (base64 / xxd / gunzip / openssl / …), we parse the shell
# pipeline into stages and dispatch each stage to a Python-side
# deterministic handler. Adding support for a new obfuscation combo
# = adding one plugin entry to the registries below.
#
# Design contract:
#   • Every handler is READ-ONLY — never shells out.
#   • Every handler is DETERMINISTIC — same input → same output.
#   • Handlers separated into three classes:
#       SOURCES     — produce the initial blob (echo / printf).
#       TRANSFORMS  — reshape the blob (tr / rev / sed).
#       DECODERS    — convert blob into decoded bytes (base64 -d,
#                     xxd -r -p, gunzip, openssl enc -d, …).
#       EXECUTORS   — terminal labels only (bash / sh / /bin/bash).
#   • A valid pipeline is: SOURCE [TRANSFORM…] DECODER [EXECUTOR].
#
# Read the module docstring "Extending the bash pipeline decoder"
# below for the checklist to add new plugins.
import base64 as _bash_b64


# 1) Sources ------------------------------------------------------------
_SOURCE_ECHO_RE = re.compile(
    r"""^\s*echo\s+(?:-n\s+)?["']?(?P<blob>[A-Za-z0-9+/=_\-\s]{8,}?)["']?\s*$""",
    re.IGNORECASE | re.VERBOSE,
)
_SOURCE_PRINTF_RE = re.compile(
    r"""^\s*printf\s+(?:'%s\\n'|"%s\\n"|'%s'|"%s"|%s)\s+["']?(?P<blob>[A-Za-z0-9+/=_\-\s]{8,}?)["']?\s*$""",
    re.IGNORECASE | re.VERBOSE,
)


def _parse_source(step: str) -> Optional[str]:
    for rx in (_SOURCE_ECHO_RE, _SOURCE_PRINTF_RE):
        m = rx.match(step)
        if m:
            return m.group("blob").strip()
    return None


# 2) Transforms ---------------------------------------------------------
_TR_STEP_RE = re.compile(
    r"""^tr\s+
        (?:'(?P<from_sq>[^']*)'|"(?P<from_dq>[^"]*)"|(?P<from_bare>\S+))
        \s+
        (?:'(?P<to_sq>[^']*)'|"(?P<to_dq>[^"]*)"|(?P<to_bare>\S+))\s*$""",
    re.VERBOSE,
)


def _apply_transform(step: str, blob: str) -> Optional[str]:
    s = step.strip().lower()
    if s == "rev":
        return blob[::-1]
    if s.startswith("cat") and len(s.split()) == 1:
        return blob      # `cat` alone — pass-through
    m = _TR_STEP_RE.match(step.strip())
    if m:
        _from = (m.group("from_sq") or m.group("from_dq")
                  or m.group("from_bare") or "")
        _to = (m.group("to_sq") or m.group("to_dq")
                or m.group("to_bare") or "")
        if len(_from) != len(_to):
            return None  # POSIX tr with unequal lengths — refuse.
        return blob.translate(str.maketrans(_from, _to))
    # (sed / awk / cut plugins can be added here as needed.)
    return None


# 3) Decoders (terminal transformation) --------------------------------
def _decode_base64(blob: str) -> Optional[str]:
    clean = re.sub(r"\s+", "", blob).strip("=")
    padded = clean + "=" * ((-len(clean)) % 4)
    try:
        return _bash_b64.b64decode(padded, validate=True).decode("utf-8")
    except Exception:
        return None


def _decode_hex(blob: str) -> Optional[str]:
    clean = re.sub(r"\s+", "", blob)
    if len(clean) % 2 != 0 or not re.match(r"^[0-9a-fA-F]+$", clean):
        return None
    try:
        return bytes.fromhex(clean).decode("utf-8")
    except Exception:
        return None


def _decode_gunzip(blob: str) -> Optional[str]:
    # Only useful when blob is already binary — the b64/hex handlers
    # above will typically produce bytes first then `gunzip` runs on
    # those bytes. Left as a stub for future composition.
    return None


# Registry of decoder commands the pipeline may terminate with.
# Every entry: regex → handler(blob) → decoded_str.
_BASH_DECODERS: List[Tuple[re.Pattern, "callable"]] = [
    (re.compile(r"^\s*base64\s+(?:-d|--decode|-D)\s*$", re.IGNORECASE),
     _decode_base64),
    (re.compile(r"^\s*xxd\s+-r\s+-p\s*$", re.IGNORECASE),
     _decode_hex),
    (re.compile(r"^\s*xxd\s+-p\s+-r\s*$", re.IGNORECASE),
     _decode_hex),
    (re.compile(r"^\s*od\s+-A\s*n\s+-t\s*x1?\s*$", re.IGNORECASE),
     _decode_hex),
    (re.compile(r"^\s*g(?:un)?zip\s+(?:-d)?\s*$", re.IGNORECASE),
     _decode_gunzip),
]


def _match_decoder(step: str):
    for rx, fn in _BASH_DECODERS:
        if rx.match(step):
            return fn
    return None


# 4) Executors (terminal labels — presence, not transformation) --------
_EXEC_TAILS_RE = re.compile(
    r"""^(?:bash|sh|/bin/(?:ba)?sh|zsh|dash)\s*$""",
    re.IGNORECASE,
)


def _try_bash_shell_pipeline(text: str) -> Optional[Dict[str, Any]]:
    """Parse a bash pipeline of the form
        SOURCE | TRANSFORM* | DECODER [| EXECUTOR]
    into a deterministic decoded output artifact.

    Returns ``None`` when the pipeline does not match this schema —
    caller then falls through to the L0 engine.
    """
    if "|" not in (text or ""):
        return None
    steps = [s.strip() for s in text.split("|") if s.strip()]
    if len(steps) < 2:
        return None

    # SOURCE
    blob = _parse_source(steps[0])
    if blob is None:
        return None

    # Optional EXECUTOR at the tail
    exec_shell = False
    if _EXEC_TAILS_RE.match(steps[-1]):
        exec_shell = True
        steps = steps[:-1]

    if len(steps) < 2:
        return None

    # DECODER must be the last stage now
    decoder = _match_decoder(steps[-1])
    if decoder is None:
        return None

    # TRANSFORM stages (may be empty)
    cur = blob
    pre_steps: List[str] = []
    for step in steps[1:-1]:
        pre_steps.append(step)
        cur = _apply_transform(step, cur)
        if cur is None:
            return None

    decoded = decoder(cur)
    if decoded is None or not decoded.strip():
        return None

    return {
        "decoded":     decoded,
        "blob":        cur,
        "source":      steps[0],
        "decoder":     steps[-1],
        "pre_steps":   pre_steps,
        "exec_shell":  exec_shell,
    }


# Public alias — kept for existing recover_canonical_evidence call site.
def _try_bash_echo_b64_short_circuit(text: str) -> Optional[Dict[str, Any]]:
    """Compat shim over the generic ``_try_bash_shell_pipeline`` — same
    return shape as before with ``decoded``/``exec_shell``/``pre_steps``
    plus the added ``blob``/``source``/``decoder`` diagnostic fields.
    """
    r = _try_bash_shell_pipeline(text or "")
    if r is None:
        return None
    # Backward-compat field name: b64 → blob (the pre-decoder buffer).
    return {
        "decoded":    r["decoded"],
        "b64":        r["blob"],
        "exec_shell": r["exec_shell"],
        "pre_steps":  r["pre_steps"],
    }


# ─── PowerShell env-var reassembly short-circuit ────────────────────────
# Detects the classic PowerShell dynamic-assembly obfuscation:
#     set-item env:x 'Write-'; set-item env:y 'Output "hi"';
#     iex (gci env:x).value(gci env:y).value
# The obfuscator splits a command across env vars and reassembles
# them via `iex (gci env:X).value + (gci env:Y).value + ...`.
# We rebuild the effective command deterministically.
# Positive interpreter identification: `powershell(.exe)?` or `pwsh`
# must be present (Governance Rule 19).
_PS_ENV_ASSIGN_RE = re.compile(
    r"""(?ix)
    (?:set-item|new-item|\$env:)\s*
    (?:env:)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*
    (?:'(?P<value_sq>[^']*)'|"(?P<value_dq>[^"]*)")
    """,
)
_PS_ENV_LOOKUP_RE = re.compile(
    r"""(?ix)
    \(\s*(?:gci|get-childitem|get-item|gi)\s+env:(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\.value
    """,
)
_PS_HOST_RE = re.compile(r"(?i)(?:powershell(?:\.exe)?|pwsh)")


def _try_ps_env_reassembly_short_circuit(text: str) -> Optional[Dict[str, Any]]:
    """Deterministically reverse the env-var reassembly obfuscation.

    Returns None when the pattern does not apply (caller falls through
    to L0). Interpreter ownership: only fires when `powershell.exe` or
    `pwsh` is present in the raw input.
    """
    raw = text or ""
    if not _PS_HOST_RE.search(raw):
        return None
    assignments = {
        m.group("name").lower(): (m.group("value_sq") if m.group("value_sq") is not None
                                   else m.group("value_dq"))
        for m in _PS_ENV_ASSIGN_RE.finditer(raw)
    }
    if not assignments:
        return None
    # Substitute every (gci env:X).value occurrence with the assigned
    # literal in the order they appear.
    def _sub(m):
        name = m.group("name").lower()
        val = assignments.get(name)
        return f"'{val}'" if val is not None else m.group(0)
    substituted = _PS_ENV_LOOKUP_RE.sub(_sub, raw)
    if substituted == raw:
        return None  # No lookups fired — not this obfuscation class.
    # Extract the effective command AFTER `iex`. Find all single-quoted
    # literal fragments on the iex line; concatenation is the PS default
    # for `'A''B'` and `'A'+'B'` alike, so `join` gives the real command.
    m_iex = re.search(r"(?is)\biex\b\s*\(?(?P<tail>[^;]*)", substituted)
    if m_iex:
        tail = m_iex.group("tail")
        pieces = re.findall(r"'([^']*)'", tail)
        if pieces:
            decoded = "".join(pieces).strip()
            if decoded:
                return {
                    "decoded":       decoded,
                    "assignments":   assignments,
                    "substituted":   substituted,
                    "reassembly":    "iex-env-lookup",
                }
    # Fall back to returning the substituted script itself (the analyst
    # sees the reassembled but not-yet-executed PowerShell).
    return {
        "decoded":     substituted,
        "assignments": assignments,
        "substituted": substituted,
        "reassembly": "env-lookup-only",
    }


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
    """Public entry point — thin wrapper over the core recovery that
    ALWAYS attaches the IEDDE decision trace + canonical confidence
    before returning (Priority 1 · SSOT · 2026-02)."""
    art = _recover_canonical_evidence_core(input_text, analysis_mode=analysis_mode)
    return _attach_iedde_augmentation(art)


def _recover_canonical_evidence_core(
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
        # ── URL is NOT an atomic IOC — it's an acquirable resource (Rule R14).
        # Ask IDA what KIND of URL this is; if acquirable, produce a
        # `url_acquisition_pending` artifact so the frontend sees the
        # correct pipeline instead of the legacy "atomic-ioc-passthrough".
        if atomic_kind == "url":
            try:
                from services.ida.url_intent import classify_url_intent as _url_intent
                intent = _url_intent(gated_text.strip())
            except Exception:
                intent = {"intent": "atomic_ioc", "acquirable": False,
                          "vendor": None, "host": "", "scheme": "",
                          "reasoning": ["IDA URL Intent classifier unavailable."]}

            if intent.get("acquirable"):
                vendor  = intent.get("vendor")
                v_tag   = f" · {vendor}" if vendor else ""
                label   = {
                    "threat_report":  "Threat Intelligence Report",
                    "code_snippet":   "Code Snippet / Paste",
                    "repository":     "Source Repository",
                    "file_resource":  "Direct File Resource",
                }.get(intent["intent"], "Acquirable URL")
                art = CanonicalArtifact(
                    raw_input=gated_text,
                    input_hash=_sha256_str(gated_text),
                    terminal_state="url_acquisition_pending",
                    decoded_output=gated_text,
                    output_hash=_sha256_str(gated_text),
                    chain_steps=[{"op": "ida-url-acquisition-pending",
                                  "args": {"intent": intent["intent"],
                                           "vendor": vendor,
                                           "host":   intent.get("host")}}],
                    chain_ids=["ida-url-acquisition-pending"],
                    engine="ida.url_intent",
                    reached_shellcode=False,
                    confidence=100,
                    detected_type={"type": "acquirable_url",
                                   "label": f"{label}{v_tag}"},
                    notes=[
                        f"URL routed to IDA as a **{label}**{v_tag}. "
                        "Content acquisition (IDA-3) is required before "
                        "commands, IOCs, MITRE and timeline can be extracted."
                    ] + list(intent.get("reasoning") or []),
                    ingress_normalised_via=ingress_via,
                    original_raw_input=original_raw if ingress_via else None,
                    atomic_ioc=None,
                    stability_gate_reached=True,
                )
                return art
            # else: fall through to the legacy atomic-IOC branch below —
            # unknown-vendor URLs, shorteners and IP-only URLs stay in
            # the IOC lane exactly as before.

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

    # 3) Bash echo-base64-pipe short-circuit --------------------------
    # Interpreter-ownership guard: catch classic Linux LotL bash
    # pipelines BEFORE L0 runs so PowerShell `echo`→`Write-Output`
    # alias normalization can't kick in on a bash command.
    bash_short = _try_bash_echo_b64_short_circuit(gated_text)
    if bash_short is not None:
        decoded = bash_short["decoded"]
        notes = [
            "Bash echo-base64 pipeline detected — deterministic "
            "b64 recovery ran before any PowerShell alias normalization.",
        ]
        if bash_short["exec_shell"]:
            notes.append(
                "Payload is piped into `bash`/`sh` at runtime — the "
                "decoded text is what the shell will execute."
            )
        art = CanonicalArtifact(
            raw_input=gated_text,
            input_hash=_sha256_str(gated_text),
            terminal_state="recovered",
            decoded_output=decoded,
            output_hash=_sha256_str(decoded),
            chain_steps=[{"op": "decoder-bash-echo-b64-pipe", "args": {}}],
            chain_ids=["decoder-bash-echo-b64-pipe"],
            engine="bash-echo-b64-pipe",
            reached_shellcode=False,
            confidence=100,
            detected_type={"type": "bash_lotl",
                            "label": "Bash echo | base64 -d [| bash] pipeline"},
            notes=notes,
            ingress_normalised_via=ingress_via,
            original_raw_input=original_raw if ingress_via else None,
            stability_gate_reached=False,
        )
        return art

    # 4) PowerShell env-var reassembly short-circuit -------------------
    ps_env = _try_ps_env_reassembly_short_circuit(gated_text)
    if ps_env is not None:
        decoded = ps_env["decoded"]
        art = CanonicalArtifact(
            raw_input=gated_text,
            input_hash=_sha256_str(gated_text),
            terminal_state="recovered",
            decoded_output=decoded,
            output_hash=_sha256_str(decoded),
            chain_steps=[{"op": "decoder-ps-env-reassembly", "args": {}}],
            chain_ids=["decoder-ps-env-reassembly"],
            engine="ps-env-reassembly",
            reached_shellcode=False,
            confidence=100,
            detected_type={"type": "ps_env_reassembly",
                            "label": ("PowerShell env-var dynamic "
                                      "reassembly obfuscation")},
            notes=[
                ("PowerShell env-var reassembly detected. Substituted "
                 f"{len(ps_env['assignments'])} env-var lookup(s) with "
                 "their literal values."),
                (f"Reassembly kind: {ps_env['reassembly']}"),
            ],
            ingress_normalised_via=ingress_via,
            original_raw_input=original_raw if ingress_via else None,
            stability_gate_reached=False,
        )
        return art

    # 4.5) Python `-c` deterministic evaluator (Rule 22 · Cat C) -------
    try:
        from services.python_dashc_evaluator import try_python_dashc_evaluator
        py_hit = try_python_dashc_evaluator(gated_text)
    except Exception:
        py_hit = None
    if py_hit is not None:
        decoded = py_hit["stdout"]
        notes = [
            "Python `-c` deterministic expression evaluated. Output is "
            "the stdout the Python interpreter would produce at runtime.",
        ]
        if py_hit["next_stage"]:
            notes.append(
                f"Recovered stdout is piped into `{py_hit['next_stage']}` "
                "at runtime — that next stage will consume the decoded text."
            )
        art = CanonicalArtifact(
            raw_input=gated_text,
            input_hash=_sha256_str(gated_text),
            terminal_state="recovered",
            decoded_output=decoded,
            output_hash=_sha256_str(decoded),
            chain_steps=[{"op": "decoder-python-dashc-eval", "args": {}}],
            chain_ids=["decoder-python-dashc-eval"],
            engine="python-dashc-eval",
            reached_shellcode=False,
            confidence=100,
            detected_type={"type": "python_dashc_eval",
                            "label": "Python -c deterministic evaluator"},
            notes=notes,
            ingress_normalised_via=ingress_via,
            original_raw_input=original_raw if ingress_via else None,
            stability_gate_reached=False,
        )
        return art

    # 5) PowerShell -EncodedCommand short-circuit ----------------------
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

    # Confidence extraction — L0 convergence doesn't set a top-level
    # `score`; it exposes per-layer verdicts in `layer_trace`. When any
    # layer reports `verdict == "canonical"`, treat as full confidence.
    def _confidence_from_det(_det):
        for _lt in (_det.get("layer_trace") or []):
            if _lt.get("verdict") == "canonical":
                return 100
        return int(round(min(1.0, _det.get("score", 0.0)) * 100))

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
            confidence=_confidence_from_det(det),
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
        confidence=_confidence_from_det(det),
        detected_type=None,   # caller re-detects on decoded_output
        notes=list(det.get("notes") or []),
        ingress_normalised_via=ingress_via,
        original_raw_input=original_raw if ingress_via else None,
        det_result=det,
        stability_gate_reached=False,
    )
    return art


# ─── IEDDE augmentation (SSOT wiring · Priority 1 · 2026-02) ────────────
def _compute_canonical_confidence(iedde_plan_dict: Dict[str, Any]) -> Tuple[int, str]:
    """Deterministically derive a 0-100 completeness score from the IEDDE
    terminal state. This is analyst-facing "how complete is the
    deterministic recovery?" — NOT a threat score.

    Rule 23 anchor: never guess. Every score is tied to a specific
    IEDDE outcome, with a reasoned justification.
    """
    ts = iedde_plan_dict.get("terminal_state") or "unknown"
    reason = iedde_plan_dict.get("stop_reason") or ""
    stages = iedde_plan_dict.get("stages") or []
    executed = sum(1 for s in stages if s.get("chosen_pass"))
    # -- Full canonical text recovered ---------------------------------
    if ts == "canonical":
        return 100, "canonical_reached:no_further_deterministic_techniques_detected"
    # -- Executable / container recovered (decoding done, switch to    -
    #    binary analysis) --------------------------------------------
    if ts == "binary_artifact_recovered":
        return 100, f"canonical_binary_recovered:decoding_phase_complete;iterations_executed={executed}"
    # -- Stability gate: analyze the reason ---------------------------
    if ts == "stability_gate":
        # Key-required deferrals (AES/RC4/XOR without a known key) are
        # explicitly a "canonical up to the crypto boundary" state.
        if "remaining_layer:" in reason and "key" in reason.lower():
            return 85, f"deterministic_recovery_completed_up_to_crypto_boundary:{reason}"
        # Unmapped technique — engine detected a primitive we don't yet
        # own. Recovery ran as far as it could.
        if "no_deterministic_primitive_registered" in reason:
            return 70, f"deterministic_recovery_partial:{reason}"
        # Chosen pass produced no change — the L0 primitive detected
        # a technique but couldn't materially transform the artifact.
        if "chosen_pass_produced_no_change" in reason:
            return 60, f"deterministic_recovery_partial_no_change:{reason}"
        # Duplicate fingerprint — engine did make progress but got stuck.
        if "duplicate_fingerprint" in reason:
            return 55, f"deterministic_recovery_partial_no_progress:{reason}"
        # Fallback stability_gate.
        return 50, f"deterministic_recovery_partial:{reason or 'stability_gate'}"
    # -- Unknown terminal state — surface transparently ----------------
    return 30, f"unknown_terminal_state:{ts};stop_reason={reason}"


def _run_iedde_safe(input_text: str) -> Optional[Dict[str, Any]]:
    """Run the IEDDE recipe planner and return its trace dict.

    Never raises. If the planner fails, returns None and the artifact
    is left un-augmented (legacy path unaffected).
    """
    try:
        from services.recipe_planner import plan_and_execute
        plan = plan_and_execute(input_text or "", max_iterations=32)
        return plan.to_dict()
    except Exception:
        log.exception("IEDDE planner failed safely (canonical artifact still returned)")
        return None


def _attach_iedde_augmentation(art: CanonicalArtifact) -> CanonicalArtifact:
    """Attach the IEDDE decision trace + canonical confidence to any
    canonical artifact. Additive only — never mutates decoded_output,
    chain_steps, or terminal_state.

    This makes the IEDDE engine the *observable* SSOT for every decode
    entry point (Rule 25 · SSOT · Priority 1 owner directive) without
    disrupting the legacy Workspace UI. Consumers that render the
    IEDDE Decision Trace panel and the Canonical Confidence / Terminal
    State pills read from these fields.
    """
    # Terminal states where IEDDE augmentation is not meaningful
    # (atomic IOC / multi-fragment fan-out are pre-decode surfaces).
    if art.terminal_state in ("atomic_ioc", "multi_fragment"):
        return art
    trace = _run_iedde_safe(art.raw_input or "")
    if not trace:
        return art
    art.iedde_trace = trace
    art.iedde_terminal_state = trace.get("terminal_state")
    score, reason = _compute_canonical_confidence(trace)
    art.canonical_confidence = score
    art.canonical_confidence_reason = reason
    art.iedde_diagnostics = list(trace.get("diagnostics") or [])
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
    # `recover_canonical_evidence` already applies IEDDE augmentation
    # internally — no double-run needed.
    return await run_offloaded(
        recover_canonical_evidence, input_text, analysis_mode=analysis_mode,
    )


__all__ = [
    "CanonicalArtifact",
    "recover_canonical_evidence",
    "recover_canonical_evidence_async",
]
