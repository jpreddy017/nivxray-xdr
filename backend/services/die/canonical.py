"""
DIE · Canonical Investigation Object (SSOT)
────────────────────────────────────────────
Frozen 2026-03-01 as part of IUE v2.0 / Rule R11.

The Canonical Investigation Object is the **single source of truth**
every Workspace surface must consume.  Once emitted by the IUE, no
UI panel, engine, filter, export, or API endpoint is allowed to
re-parse the raw input.  See:

    · /app/memory/IUE_ARCHITECTURE_V2.md
    · /app/memory/WORKSPACE_ARCHITECTURE_RULES.md (R9, R10, R11)

The dataclass below fixes the wire shape; the emitter in
``investigation_results.render()`` populates it deterministically
from the health check + IUE + preprocessor + analyze envelope +
intent classifier.

Design principles
-----------------
1. Deterministic — same input → identical object.
2. Additive — new fields are always safe (JSON-friendly); no
   consumer should ever break because a new key appeared.
3. Evidence-first — every conclusion carries the concrete signals
   that produced it.
4. Backwards-compatible — existing frontend code that reads
   ``analyze.result.preprocessor`` etc. is treated as consuming a
   projection of this object.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


# ── Confidence Breakdown ──────────────────────────────────────────
@dataclass
class ConfidenceSignal:
    """One row in the "how did we get to N%" breakdown."""
    id:      str           # stable identifier ("decoder", "parser", …)
    label:   str           # analyst-facing label
    status:  str           # "passed" | "partial" | "missing" | "skipped"
    detail:  Optional[str] = None


@dataclass
class ConfidenceBreakdown:
    """Aggregate confidence with the categorical trail that produced
    it — every score displayed in the Workspace must be explainable
    via one of these objects (Rule R10 · "every decision is
    analyst-visible")."""
    overall:      int                                # 0–100
    label:        str                                # "Low" · "Medium" · "High"
    ai_inference: bool = False                       # was any LLM inference used?
    signals:      List[ConfidenceSignal] = field(default_factory=list)


# ── Investigation Plan Step ───────────────────────────────────────
@dataclass
class PlanStep:
    engine:   str
    action:   str
    reason:   str
    required: bool = True
    status:   str = "pending"


# ── Canonical Investigation Object ────────────────────────────────
@dataclass
class Canonical:
    """The single object every Workspace surface consumes."""
    metadata:              Dict[str, Any] = field(default_factory=dict)
    input:                 Dict[str, Any] = field(default_factory=dict)
    health:                Dict[str, Any] = field(default_factory=dict)
    profiling:             Dict[str, Any] = field(default_factory=dict)
    understanding:         Dict[str, Any] = field(default_factory=dict)
    plan:                  List[Dict[str, Any]] = field(default_factory=list)

    # Content decomposition
    commands:              List[Dict[str, Any]] = field(default_factory=list)
    iocs:                  Dict[str, List[str]] = field(default_factory=dict)
    lolbas:                List[Dict[str, Any]] = field(default_factory=list)
    mitre:                 List[Dict[str, Any]] = field(default_factory=list)
    dkp:                   List[Dict[str, Any]] = field(default_factory=list)

    # IDA · Intelligent Document Analyzer (Rule R14)
    # ── Slice 1 (IDA-1 + IDA-2): artifact splitter output ──
    # `artifacts[]`         — every typed artifact split from the paste
    # `artifact_summary{}`  — {type: count} snapshot for quick projection
    # `ida{}`               — verdict object: {ida_class, confidence, reasoning}
    artifacts:             List[Dict[str, Any]] = field(default_factory=list)
    artifact_summary:      Dict[str, int] = field(default_factory=dict)
    ida:                   Dict[str, Any] = field(default_factory=dict)

    # Structured downstream views
    preprocessor:          Dict[str, Any] = field(default_factory=dict)
    intent:                Dict[str, Any] = field(default_factory=dict)
    confidence:            Dict[str, Any] = field(default_factory=dict)

    # Engine routing
    engines_selected:      List[str] = field(default_factory=list)
    engines_skipped:       List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Deterministic Confidence Breakdown builder ────────────────────
def build_confidence_breakdown(
    *,
    health:        Dict[str, Any],
    understanding: Dict[str, Any],
    preprocessor:  Dict[str, Any],
    lolbas:        List[Dict[str, Any]],
    mitre:         List[Dict[str, Any]],
    dkp:           List[Dict[str, Any]],
    iocs:          Dict[str, List[str]],
    intent:        Dict[str, Any],
) -> ConfidenceBreakdown:
    """Assemble a categorical confidence breakdown from the SSOT
    inputs.  Every category maps a boolean data-completeness signal
    to an analyst-facing status.  No AI, no heuristics beyond the
    presence of concrete evidence.
    """
    signals: List[ConfidenceSignal] = []

    # 1) Input Health
    has_errors = any(i.get("severity") == "error" for i in (health.get("issues") or []))
    has_warns  = any(i.get("severity") == "warn"  for i in (health.get("issues") or []))
    signals.append(ConfidenceSignal(
        id="health",
        label="Input Health",
        status="passed" if not has_errors and not has_warns
                else ("partial" if not has_errors else "missing"),
        detail=(f"{len(health.get('issues') or [])} issue(s) reported"
                if health.get('issues') else "No corruption detected"),
    ))

    # 2) Decoder
    dec_req = bool(understanding.get("decode_required"))
    signals.append(ConfidenceSignal(
        id="decoder",
        label="Decoder",
        status="skipped" if not dec_req else "passed",
        detail=understanding.get("decode_reason") or
               ("Encoded input decoded" if dec_req else "Skipped — input already plain"),
    ))

    # 3) Parser
    stage_count = len(preprocessor.get("stages") or [])
    signals.append(ConfidenceSignal(
        id="parser",
        label="Parser",
        status="passed" if stage_count >= 1 else "missing",
        detail=f"{stage_count} stage(s) built" if stage_count else "No commands parsed",
    ))

    # 4) MITRE
    signals.append(ConfidenceSignal(
        id="mitre",
        label="MITRE Mapping",
        status="passed" if mitre else "missing",
        detail=f"{len(mitre)} technique(s) mapped" if mitre else "No techniques identified",
    ))

    # 5) LOLBAS
    unique_bins = {(lb.get("binary") or "").lower() for lb in lolbas if lb.get("binary")}
    signals.append(ConfidenceSignal(
        id="lolbas",
        label="LOLBAS Mapping",
        status="passed" if unique_bins else "missing",
        detail=f"{len(unique_bins)} LOLBAS binary(s) matched" if unique_bins else "No LOLBAS observed",
    ))

    # 6) IOC Extraction
    total_iocs = sum(len(v) for v in (iocs or {}).values())
    signals.append(ConfidenceSignal(
        id="ioc",
        label="IOC Extraction",
        status="passed" if total_iocs else "missing",
        detail=f"{total_iocs} IOC(s) extracted" if total_iocs else "No IOCs found",
    ))

    # 7) DKP
    signals.append(ConfidenceSignal(
        id="dkp",
        label="DKP Match",
        status="passed" if dkp else "missing",
        detail=f"{len(dkp)} DKP family(s) matched" if dkp else "No DKP family match",
    ))

    # 8) Evidence — evidence bundles live on preprocessor stages
    evidence_count = sum(len(s.get("evidence") or []) for s in (preprocessor.get("stages") or []))
    signals.append(ConfidenceSignal(
        id="evidence",
        label="Evidence",
        status="passed" if evidence_count else "missing",
        detail=f"{evidence_count} evidence excerpt(s)" if evidence_count else "No evidence excerpts",
    ))

    # 9) AI Inference — deterministic pipeline never uses it here.
    signals.append(ConfidenceSignal(
        id="ai",
        label="AI Inference",
        status="skipped",           # always skipped in deterministic path
        detail="Not used — deterministic pipeline",
    ))

    # Overall confidence — take the intent classifier's number when
    # present, else fall back to a signals-weighted average.
    raw_conf = intent.get("confidence")
    if isinstance(raw_conf, (int, float)):
        overall = int(round(raw_conf * 100)) if raw_conf <= 1.0 else int(raw_conf)
    else:
        passed = sum(1 for s in signals if s.status == "passed")
        overall = int(round(passed / max(1, len(signals) - 1) * 100))   # exclude "ai" from denom
    label = "Low" if overall < 40 else ("Medium" if overall < 75 else "High")
    return ConfidenceBreakdown(
        overall=overall,
        label=label,
        ai_inference=False,
        signals=signals,
    )


# ── Deterministic Plan builder ────────────────────────────────────
def build_plan(
    *,
    understanding: Dict[str, Any],
    preprocessor:  Dict[str, Any],
    health:        Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Materialise the IUE's engine plan as a list of PlanStep dicts
    the frontend can render as a checklist / trace."""
    steps: List[PlanStep] = []
    if not health.get("ready", True):
        steps.append(PlanStep(
            engine="stage-0",
            action="input-health-check",
            reason="Structural problems detected — surfacing before analysis",
            required=True,
            status="failed",
        ))
    steps.append(PlanStep(
        engine="iue",
        action="classify-input",
        reason="Determine input type + language + encoding",
        status="done",
    ))
    if understanding.get("decode_required"):
        steps.append(PlanStep(
            engine="die",
            action="decode-input",
            reason=understanding.get("decode_reason") or "Encoded payload detected",
            status="done",
        ))
    else:
        steps.append(PlanStep(
            engine="die",
            action="decode-skip",
            reason=understanding.get("decode_reason") or "Already plain — no decoding required",
            required=False,
            status="skipped",
        ))
    stage_count = len(preprocessor.get("stages") or [])
    steps.append(PlanStep(
        engine="preprocessor",
        action="extract-stages",
        reason=f"Deterministic decomposition into command stages ({stage_count} built)",
        status="done" if stage_count else "empty",
    ))
    for engine in (understanding.get("engines_selected") or []):
        if engine in {"iue", "die", "preprocessor"}:
            continue
        steps.append(PlanStep(
            engine=engine.lower(),
            action=f"run-{engine.lower()}",
            reason="Requested by IUE routing plan",
            status="done",
        ))
    return [asdict(s) for s in steps]
