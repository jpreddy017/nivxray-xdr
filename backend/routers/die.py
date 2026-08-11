"""
DIE · HTTP router
─────────────────
Analyst-facing endpoints so the frontend (and curl / tests) can query
the Decoder Intelligence Engine directly.  Read-only — DIE never
mutates state.  Every endpoint returns the standard analyze envelope
so consumers can switch languages without changing shape.
"""
from __future__ import annotations
from typing import Optional, Dict, Any
from fastapi import APIRouter
from pydantic import BaseModel, Field

from services.die import (
    analyze,
    analyze_powershell,
    lolbas_lookup,
    LOLBAS_REGISTRY,
    extract_iocs,
    archive_recover,
    archive_recover_recursive,
    archive_detect_kind,
)
from services.die.chain import analyze_chain, looks_like_chain
from services.die.api import _analyze_single
from services.die.intent import classify_intent, classify_intent_from_analyze
from services.die.confidence import score_investigation
from services.die.narrative import generate_report
from services.die.dkp import load_patterns as dkp_load_patterns, pattern_by_id as dkp_pattern_by_id
from deps import db
import base64 as _b64

router = APIRouter(prefix="/die", tags=["die"])


class AnalyzeBody(BaseModel):
    input: str = Field(..., description="Raw command line or script to analyze.")
    language: Optional[str] = Field(
        None, description="Optional force ('powershell'|'cmd'|'javascript'|'vbscript'|'bash').")


@router.post("/analyze")
def die_analyze(body: AnalyzeBody):
    """Single-entry semantic analysis over any command-line input.

    Phase 5.W (2026-08-10): when NIVX_CANONICAL_DIE_ANALYZE=on, the
    canonical narrative MITRE evidence is ADDED (never replaces) to
    the legacy result so the Workspace attack-chain graph populates
    for DOCX / narrative vendor-report inputs.
    """
    result = analyze(body.input, language=body.language)
    from services.die.canonical_bridge import augment_die_result
    result = augment_die_result(result, body.input)
    return {"result": result}


class UnderstandBody(BaseModel):
    input: str = Field(..., description="Raw analyst paste to understand.")
    execute: bool = Field(True, description="When true, run the plan and record the execution trace.")


@router.post("/understand")
def die_understand(body: UnderstandBody):
    """Input Understanding Engine — classify the input, build the
    investigation plan, execute it (unless disabled) and return the
    analyst-visible trace."""
    from services.die import understand_input
    u = understand_input(body.input, execute=body.execute)
    return {"understanding": u.to_dict()}


class NarrateBody(BaseModel):
    input: str = Field(..., description="Raw analyst paste to narrate.")


@router.post("/narrate")
def die_narrate(body: NarrateBody):
    """Deterministic Analyst Narrative — Executive Summary, Analyst
    Summary, Recommended Actions, Sigma / YARA ideas and Threat-actor
    context.  Zero LLM.

    Phase 5.W (2026-08-10): when the legacy stage-based generator
    produces empty summary/actions (URL/DOCX/vendor-narrative input
    that has no command-line stages), the canonical narrative rules
    fill the empty fields deterministically from detected MITRE
    techniques + IOCs.
    """
    from services.die.preprocessor import preprocess as _pp
    from services.die.analyst_narrative import generate as _gen
    from services.die.canonical_bridge import (
        canonical_die_flag_enabled, _canonical_techniques_from_text,
    )
    from services.die.canonical_narrative_enrichment import enrich_narrative
    from canonical.projections.attck import _TECHNIQUE_META

    pre = _pp(body.input or "")
    narrative = _gen(pre.to_dict()) or {}

    # ── Phase 5.W enrichment · additive only ──────────────────────
    if canonical_die_flag_enabled():
        canonical_techs = _canonical_techniques_from_text(body.input or "")
        # Also lift MITRE ids already in `narrative.mitre_matrix` so
        # the enricher has the full set to reason over.
        mitre_full: list = []
        seen_ids: set = set()
        for m in canonical_techs:
            if m.get("id") and m["id"] not in seen_ids:
                meta = _TECHNIQUE_META.get(m["id"], {})
                mitre_full.append({
                    "id": m["id"], "name": m.get("name", ""),
                    "tactic": meta.get("tactic", "unknown"),
                    "kill_chain": meta.get("kill_chain", "unknown"),
                })
                seen_ids.add(m["id"])
        for row in (narrative.get("mitre_matrix") or []):
            if isinstance(row, dict) and row.get("id") and row["id"] not in seen_ids:
                meta = _TECHNIQUE_META.get(row["id"], {})
                mitre_full.append({
                    "id": row["id"], "name": row.get("name", ""),
                    "tactic": row.get("tactic") or meta.get("tactic", "unknown"),
                    "kill_chain": meta.get("kill_chain", "unknown"),
                })
                seen_ids.add(row["id"])
        # Phase 5.W.3 · CSV/EDR analyzer feed (2026-08-10)
        # For tabular endpoint-security exports the prose narrative
        # rules match nothing → mitre_full stays empty → enrichment
        # doesn't fire → analyst gets the legacy canned exec_summary.
        # Run the same csv_edr_analyzer used by /investigation-results
        # so `/narrate` produces the same enriched shape.
        try:
            from services.die.csv_edr_analyzer import analyse_csv_edr
            csv_r = analyse_csv_edr(body.input or "")
            if csv_r:
                for t in (csv_r.get("mitre") or []):
                    tid = t.get("id")
                    if tid and tid not in seen_ids:
                        meta = _TECHNIQUE_META.get(tid, {})
                        mitre_full.append({
                            "id":         tid,
                            "name":       t.get("name") or meta.get("tactic"),
                            "tactic":     t.get("tactic") or meta.get("tactic") or "unknown",
                            "kill_chain": meta.get("kill_chain") or "unknown",
                        })
                        seen_ids.add(tid)
                # Also feed the tactic-grouped progression + mitre_matrix
                # so the enricher sees the same evidence surface. Overwrite
                # the legacy per-file "Stage N — <filename>" progression
                # (whose mitre[] is empty) since the CSV/EDR analyzer's
                # tactic-grouped view carries real technique evidence.
                _legacy_prog = narrative.get("attack_progression") or []
                _prog_has_evidence = any(
                    (s.get("mitre") or []) for s in _legacy_prog if isinstance(s, dict)
                )
                if not _prog_has_evidence:
                    narrative["attack_progression"] = csv_r.get("attack_progression") or []
                if not narrative.get("mitre_matrix"):
                    narrative["mitre_matrix"] = csv_r.get("mitre") or []
                if not narrative.get("kill_chain_coverage"):
                    narrative["kill_chain_coverage"] = csv_r.get("kill_chain_coverage") or []
        except Exception:
            pass
        if mitre_full:
            narrative = enrich_narrative(narrative, mitre_full)

    return {"narrative": narrative}


class InvestigationResultsBody(BaseModel):
    input: str = Field(..., description="Raw analyst paste to investigate.")


@router.post("/investigation-results")
def die_investigation_results(body: InvestigationResultsBody):
    """Return the deterministic Investigation Results view for a paste.

    This is the SSOT for the Workspace "INVESTIGATION RESULTS" pane
    (formerly "OUTPUT").  Whenever the IUE decides no decoding is
    required — plain PowerShell / CMD / Bash / vendor report / IOC
    list — the Workspace displays the ``output`` field of this
    response instead of echoing the input.  The ``object`` field is
    the Canonical Investigation Object (SSOT) downstream engines
    consume in IUE v2.1.

    Phase 5.W (2026-08-10): when NIVX_CANONICAL_DIE_ANALYZE=on, the
    canonical narrative MITRE rules populate `object.mitre`,
    `object.narrative.mitre_matrix`, `object.narrative.kill_chain_coverage`,
    `object.narrative.attack_progression`, and
    `object.ice.incident.summary.tactics_observed` so the Workspace
    attack-chain graph renders on DOCX / vendor-narrative inputs.
    """
    from services.die.investigation_results import render as _render
    from services.die.canonical_bridge import augment_investigation_results
    result = _render(body.input or "")
    result = augment_investigation_results(result, body.input or "")
    return result


class TimelineBody(BaseModel):
    input: str = Field(..., description="Raw analyst paste to project into a timeline.")


@router.post("/timeline")
def die_timeline(body: TimelineBody):
    """Workspace Timeline Graph · read-only projection (2026-08-11).

    Returns a chronologically ordered event list assembled from the
    existing canonical investigation evidence.  ONLY events that
    carry a real timestamp are emitted.  Narrative-only MITRE
    mentions (no timestamp) intentionally do NOT appear.

    Contract guarantees:
      · Does NOT mutate `/api/die/investigation-results` payload
        or shape — this endpoint is a pure projection built OVER
        the same pipeline.
      · Every emitted event carries the same `evidence_ref` from
        the P0.2 evidence-chain gate that the Workspace MITRE
        panels already display.
      · No fabricated events / relationships / evidence.

    Response envelope:

        {
          "events":       [ {timestamp, source, event_type, host, user,
                             process, parent_process, command_line,
                             file_context, network_context,
                             registry_context, event_or_rule,
                             evidence_ref, mitre[], confidence}, … ],
          "event_count":  int,
          "span_start":   ISO ts | null,
          "span_end":     ISO ts | null,
          "hosts":        [ … ],
          "users":        [ … ],
          "sources":      [ … ],
          "meta":         { projection, note }
        }
    """
    from services.die.investigation_results import render as _render
    from services.die.canonical_bridge import augment_investigation_results
    from services.die.timeline_projection import project_timeline
    text = body.input or ""
    result = _render(text)
    result = augment_investigation_results(result, text)
    obj = result.get("object") if isinstance(result, dict) else None
    return project_timeline(text, obj or {})


class QueryHuntBody(BaseModel):
    input:   str            = Field(..., description="Raw analyst paste (same shape as investigation-results).")
    filters: Dict[str, Any] = Field(default_factory=dict,
                                    description="Optional filter dictionary (host, user, action, category, "
                                                "process, parent, file_path, file_hash, mitre, event_type, "
                                                "date_from, date_to, confidence). Values are strings.")


@router.post("/query")
def die_query(body: QueryHuntBody):
    """Workspace Query/Hunt · read-only scoped sub-view (2026-08-11).

    Returns the subset of the canonical investigation events that
    satisfy the supplied filter dictionary.  Result row shape is
    identical to a Timeline event so Timeline / Table / (future)
    Process Tree / Graph views can consume the same records.

    Contract guarantees:
      · Does NOT mutate `/api/die/investigation-results` or
        `/api/die/timeline` payloads — this is a strict projection.
      · Every returned row carries the same `evidence_ref` from
        the P0.2 evidence-chain gate.
      · Empty / prose / narrative-only inputs → empty results (no
        fabrication).
      · Empty filter dict → returns every event the Timeline would
        show (Query is a filter over Timeline, not a re-analysis).

    Response envelope: see services/die/query_hunt.run_query.
    """
    from services.die.investigation_results import render as _render
    from services.die.canonical_bridge import augment_investigation_results
    from services.die.query_hunt import run_query
    text = body.input or ""
    result = _render(text)
    result = augment_investigation_results(result, text)
    obj = result.get("object") if isinstance(result, dict) else None
    return run_query(text, obj or {}, body.filters or {})


class HealthBody(BaseModel):
    input: str = Field(..., description="Raw analyst paste to health-check.")


@router.post("/health-check")
def die_health_check(body: HealthBody):
    """Stage-0 · Input Health Check (IUE v2.0 · Layer 0).

    Before the Input Understanding Engine classifies the paste, we
    surface any structural problems: empty input, oversized input,
    binary-magic detection, malformed / truncated Base64,
    non-UTF-16LE ``-EncodedCommand`` payloads, high control-character
    ratios, and password references.  This is deterministic and
    non-blocking — the pipeline continues even when errors are
    reported so analysts still receive a partial investigation.
    """
    from services.die.input_health import check_health as _hc
    return {"health": _hc(body.input or "").to_dict()}


class SSOTBody(BaseModel):
    input: str = Field(..., description="Raw analyst paste to canonicalise.")


@router.post("/investigation")
def die_canonical_investigation(body: SSOTBody):
    """Return the **Canonical Investigation Object** (SSOT) for a paste.

    This is the single source of truth per Rule R11.  Every Workspace
    surface, engine, filter, export, and API endpoint downstream of
    the IUE consumes THIS object — never the raw input.  See
    ``services/die/canonical.py`` for the schema and
    ``services/die/investigation_results.py`` for the emitter.
    """
    from services.die.investigation_results import render as _render
    result = _render(body.input or "")
    return {"investigation": result["object"]}





@router.post("/powershell/ast")
def die_powershell_ast(body: AnalyzeBody):
    """Force the PowerShell semantic AST parser."""
    return {"result": analyze_powershell(body.input)}


class IocBody(BaseModel):
    input: str
    source: str = "raw"


@router.post("/iocs")
def die_iocs(body: IocBody):
    return {"iocs": extract_iocs(body.input, source=body.source)}


@router.get("/lolbas")
def die_lolbas_all():
    """List every LOLBAS entry (built-in + JSON overlay)."""
    return {
        "count": len(LOLBAS_REGISTRY),
        "entries": [{"binary": k, **v} for k, v in
                    sorted(LOLBAS_REGISTRY.items())],
    }


@router.get("/lolbas/{binary}")
def die_lolbas_one(binary: str):
    entry = lolbas_lookup(binary)
    return {"binary": binary, "entry": entry}


# ── DIE Cycle B · archive recovery ────────────────────────────────
class ArchiveBody(BaseModel):
    """Body carries base64-encoded raw bytes so archives can be posted
    over JSON without multipart plumbing."""
    b64: str = Field(..., description="Base64-encoded archive bytes.")
    name: Optional[str] = Field(None, description="Optional container name.")
    recursive: bool = Field(False, description="Descend nested archives.")
    max_depth: int = Field(3, ge=1, le=8)
    max_children: int = Field(200, ge=1, le=2000)


@router.post("/archive/recover")
def die_archive_recover(body: ArchiveBody):
    try:
        blob = _b64.b64decode(body.b64, validate=False)
    except Exception as e:
        return {"error": f"invalid base64: {e}"}
    if body.recursive:
        return {"result": archive_recover_recursive(
            blob, name=body.name,
            max_depth=body.max_depth,
            max_children=body.max_children)}
    return {"result": archive_recover(blob, name=body.name)}


@router.post("/detect-kind")
def die_detect_kind(body: ArchiveBody):
    try:
        blob = _b64.b64decode(body.b64, validate=False)
    except Exception as e:
        return {"error": f"invalid base64: {e}"}
    return {"kind": archive_detect_kind(blob), "size": len(blob)}


# ── DKP · Decoder Knowledge Pack (Phase B.2 · 2026-02-16) ─────────
@router.get("/dkp/patterns")
def die_dkp_patterns():
    """List every seeded DKP pattern (including JSON overlay)."""
    patterns = [p.to_dict() for p in dkp_load_patterns()]
    return {"count": len(patterns), "patterns": patterns}


@router.get("/dkp/patterns/{pattern_id}")
def die_dkp_pattern(pattern_id: str):
    p = dkp_pattern_by_id(pattern_id)
    return {"pattern": p.to_dict() if p else None}


# ── Chain analyzer (Phase B.2 · 2026-02-16 pm) ────────────────────
@router.post("/chain")
def die_chain(body: AnalyzeBody):
    """Explicit chain-analysis endpoint.

    Returns the full per-step walk (Discovery → Defense Evasion →
    Persistence → C2 → Impact) with each step's own AST, MITRE,
    IOCs, and DKP matches — even when the analyst wants the chain
    view for a single-step input.
    """
    return {"result": analyze_chain(body.input, analyze_fn=_analyze_single)}


# ── Attack Intent Engine (Phase B.7 · 2026-02-16 pm-late) ─────────
@router.post("/intent")
def die_intent(body: AnalyzeBody):
    """Return the Attack Intent for a raw input.

    Deterministic synthesis over the chain envelope — Primary
    Objective + confidence + evidence + MITRE + observed vs missing
    ATT&CK phases + attack progress %.
    """
    env = analyze(body.input, language=body.language)
    intent = classify_intent_from_analyze(env)
    return {"intent": intent}


# ── Case-scoped DIE (workspace_cases.input → full analyze) ────────
@router.get("/case/{case_id}")
async def die_case(case_id: str):
    """Fetch a case's raw input from the case store and return the
    full DIE analyze envelope (chain + attack intent + DKP
    matches).  Powers the Attack Story panel on the Investigation
    Story tab.

    Cases can live in the ``investigations`` collection (the primary
    case store) or ``workspace_cases`` (legacy); we probe both.
    """
    from bson import ObjectId
    from bson.errors import InvalidId
    queries = [{"id": case_id}]
    try:
        queries.append({"_id": ObjectId(case_id)})
    except InvalidId:
        pass
    case = None
    for coll in ("investigations", "workspace_cases"):
        for q in queries:
            case = await db[coll].find_one(q)
            if case and case.get("input"):
                break
        if case and case.get("input"):
            break
    if not case or not case.get("input"):
        return {"error": "case not found or input missing",
                "case_id": case_id, "envelope": None}
    env = analyze(case["input"])
    return {"case_id":  case_id,
            "input_preview": (case["input"] or "")[:512],
            "envelope": env}


# ── Investigation Confidence + 12-section Report (Phase B.4 + B.6) ─
@router.post("/confidence")
def die_confidence(body: AnalyzeBody):
    env = analyze(body.input, language=body.language)
    return {"confidence": score_investigation(env)}


@router.get("/report/{case_id}")
async def die_report(case_id: str):
    """Return the 12-section deterministic investigation report for a
    case — Executive Summary through Confidence Summary."""
    from bson import ObjectId
    from bson.errors import InvalidId
    queries = [{"id": case_id}]
    try:
        queries.append({"_id": ObjectId(case_id)})
    except InvalidId:
        pass
    case = None
    for coll in ("investigations", "workspace_cases"):
        for q in queries:
            case = await db[coll].find_one(q)
            if case and case.get("input"):
                break
        if case and case.get("input"):
            break
    if not case or not case.get("input"):
        return {"error": "case not found or input missing",
                "case_id": case_id, "report": None}
    env = analyze(case["input"])
    return {"case_id": case_id,
            "report":  generate_report(env, case_id=case_id,
                                       input_preview=(case["input"] or "")[:512])}
