"""Phase 5.W · DIE canonical bridge (2026-08-10).

Owner directive: bring the Workspace's real /api/die/analyze path into
the canonical investigation architecture WITHOUT changing its external
contract or the Workspace UI behavior.

- Preserves legacy shape (`result.techniques[]`, `result.chain.steps[]`)
- Only ADDS canonical evidence (never removes or reshapes legacy)
- Feature-flag gated: NIVX_CANONICAL_DIE_ANALYZE (default OFF)
- Firewall: no import of new legacy modules; canonical-only.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

_FLAG_ENV = "NIVX_CANONICAL_DIE_ANALYZE"


def canonical_die_flag_enabled() -> bool:
    return os.environ.get(_FLAG_ENV, "off").strip().lower() == "on"


def _canonical_techniques_from_text(text: str) -> List[Dict[str, Any]]:
    """Run the canonical narrative MITRE rules on `text` and return a
    list of techniques in the LEGACY DIE shape:
        [{"id": "T1219", "name": "Remote Access Software",
          "evidence": "<snippet>"}, ...]
    Pure function; no I/O, no clock, no random.
    """
    if not text:
        return []
    # Import lazily to keep module import cheap when flag is OFF.
    from canonical.executor.capabilities import (
        _NARRATIVE_RULES,
        _match_narrative_rule,
    )
    out: List[Dict[str, Any]] = []
    lowered = text.lower()
    for tid, rule in _NARRATIVE_RULES.items():
        matched = _match_narrative_rule(lowered, rule)
        if not matched:
            continue
        first = matched[0]
        idx = lowered.find(first)
        start = max(0, idx - 80)
        end = min(len(lowered), idx + 160)
        snippet = lowered[start:end]
        out.append({
            "id": tid,
            "name": rule["name"],
            "evidence": snippet,
            "matched": matched,
            "rule_family": "canonical.narrative_vendor_report",
        })
    # Deterministic ordering.
    out.sort(key=lambda x: x["id"])
    return out


def augment_die_result(result: Dict[str, Any], raw_input: str) -> Dict[str, Any]:
    """Augment an existing legacy DIE `result` dict with canonical
    narrative MITRE evidence when the flag is on.

    Contract:
      - If legacy already produced a technique with the same id ⇒ keep
        legacy entry, don't duplicate.
      - Otherwise append the canonical technique to result.techniques.
      - If result has no chain, synthesise a single-step chain so
        the Workspace AttackChainView renders.
      - result.language, result.ast, result.lolbins, result.iocs
        remain untouched.
    """
    if not canonical_die_flag_enabled():
        return result
    if not isinstance(result, dict):
        return result

    canonical_techs = _canonical_techniques_from_text(raw_input or "")
    if not canonical_techs:
        return result

    # Merge into result.techniques (dedup by technique id).
    existing = result.get("techniques") or []
    if not isinstance(existing, list):
        existing = []
    existing_ids = {t.get("id") for t in existing if isinstance(t, dict)}
    added: List[Dict[str, Any]] = []
    for t in canonical_techs:
        if t["id"] in existing_ids:
            continue
        existing.append(t)
        added.append(t)
        existing_ids.add(t["id"])
    result["techniques"] = existing

    # Synthesize / augment chain so the Workspace attack-chain graph
    # renders. Legacy shape: {"steps": [{"techniques": [...], ...}]}.
    chain = result.get("chain")
    if not isinstance(chain, dict):
        chain = {}
    steps = chain.get("steps")
    if not isinstance(steps, list) or not steps:
        steps = [{
            "index": 0,
            "kind": "canonical.narrative",
            "source": "root",
            "artifact_type": "narrative",
            "verdict": "malicious",
            "techniques": canonical_techs,
            "evidence": "canonical narrative MITRE mapping",
        }]
    else:
        step0 = steps[0]
        if isinstance(step0, dict):
            step_techs = step0.get("techniques") or []
            if not isinstance(step_techs, list):
                step_techs = []
            step_ids = {t.get("id") for t in step_techs if isinstance(t, dict)}
            for t in added:
                if t["id"] not in step_ids:
                    step_techs.append(t)
                    step_ids.add(t["id"])
            step0["techniques"] = step_techs
    chain["steps"] = steps
    result["chain"] = chain

    # Attach canonical provenance marker (non-breaking additive field).
    result["canonical_augmented"] = {
        "wave": "5.W",
        "lifecycle": "canonical_bridge",
        "added_techniques": [t["id"] for t in added],
    }
    return result


def augment_investigation_results(result: Dict[str, Any], raw_input: str) -> Dict[str, Any]:
    """Augment /api/die/investigation-results with canonical narrative
    MITRE evidence so the Workspace attack-chain graph populates on
    DOCX / vendor-narrative inputs.

    Feature-flag gated (NIVX_CANONICAL_DIE_ANALYZE). Additive only.
    Existing populated fields are preserved; only empty ones are filled.
    """
    if not canonical_die_flag_enabled():
        return result
    if not isinstance(result, dict):
        return result

    # Map technique_id → tactic + kill_chain (single source of truth).
    from canonical.projections.attck import _TECHNIQUE_META
    def _meta(tid): return _TECHNIQUE_META.get(tid, {"tactic": "unknown",
                                                     "kill_chain": "unknown"})

    # Normalise any tactic string to canonical snake_case form so
    # legacy IDA's Title Case (e.g. "Defense Evasion") and the
    # canonical catalog's snake_case (e.g. "defense_evasion") agree.
    def _norm_tactic(s):
        if not s: return ""
        return s.strip().lower().replace(" ", "_").replace("-", "_")

    canonical_techs = _canonical_techniques_from_text(raw_input or "")

    obj = result.get("object")
    if not isinstance(obj, dict):
        obj = {}
        result["object"] = obj

    # ── object.mitre · merge canonical narrative techniques ───────────
    existing_mitre = obj.get("mitre") or []
    if not isinstance(existing_mitre, list):
        existing_mitre = []
    existing_ids = {t.get("id") for t in existing_mitre if isinstance(t, dict)}
    for t in canonical_techs:
        if t["id"] in existing_ids: continue
        meta = _meta(t["id"])
        existing_mitre.append({
            "id":         t["id"],
            "name":       t["name"],
            "tactic":     meta["tactic"],
            "kill_chain": meta["kill_chain"],
            "evidence":   t.get("evidence", ""),
            "matched":    t.get("matched", []),
            "rule_family": "canonical.narrative_vendor_report",
        })
        existing_ids.add(t["id"])

    # ── CSV / tabular EDR analyzer (Phase 5.W · 2026-08-10) ──────────
    # When the input is a vendor endpoint-security log (SEP, CrowdStrike,
    # Defender, …), the prose narrative rules match nothing. The CSV/EDR
    # analyzer walks the table deterministically and contributes MITRE
    # + LOLBAS + IOC evidence.  Additive: only fills gaps, never
    # overwrites existing findings.
    _csv_source_text = raw_input or ""
    csv_report = None
    try:
        from .csv_edr_analyzer import analyse_csv_edr
        csv_report = analyse_csv_edr(_csv_source_text)
    except Exception:
        csv_report = None
    if csv_report:
        # Merge MITRE techniques.
        for t in (csv_report.get("mitre") or []):
            tid = t.get("id")
            if not tid or tid in existing_ids:
                continue
            meta = _meta(tid)
            existing_mitre.append({
                "id":         tid,
                "name":       t.get("name") or meta.get("tactic"),
                "tactic":     t.get("tactic") or meta.get("tactic") or "unknown",
                "kill_chain": meta.get("kill_chain") or "unknown",
                "evidence":   t.get("evidence", ""),
                "rule_family": "canonical.csv_edr_analyzer",
            })
            existing_ids.add(tid)

        # Merge IOCs.
        existing_iocs = obj.get("iocs") if isinstance(obj.get("iocs"), dict) else {}
        for kind, values in (csv_report.get("iocs") or {}).items():
            bucket = existing_iocs.get(kind) or []
            if isinstance(bucket, list):
                seen_bucket = {b if isinstance(b, str) else b.get("value") for b in bucket}
                for v in values:
                    if v not in seen_bucket:
                        bucket.append(v)
                        seen_bucket.add(v)
                existing_iocs[kind] = bucket
        obj["iocs"] = existing_iocs

        # Merge LOLBAS (add binaries not already present).
        existing_lolbas = obj.get("lolbas") if isinstance(obj.get("lolbas"), list) else []
        existing_lolbas_names = {(l.get("binary") or "").lower() for l in existing_lolbas
                                  if isinstance(l, dict)}
        for lb in (csv_report.get("lolbas") or []):
            if (lb.get("binary") or "").lower() in existing_lolbas_names:
                continue
            existing_lolbas.append(lb)
            existing_lolbas_names.add((lb.get("binary") or "").lower())
        obj["lolbas"] = existing_lolbas

        # Attach the CSV report to a namespaced field so the UI (or
        # future capabilities) can surface the raw table view / event
        # count. Bounded to <200 KB by the analyzer's row cap + event
        # cap already applied.
        obj["csv_edr"] = {
            "source":                csv_report.get("source"),
            "total_rows":            csv_report.get("total_rows"),
            "action_distribution":   csv_report.get("action_distribution"),
            "category_distribution": csv_report.get("category_distribution"),
            "highconf_event_count":  len(csv_report.get("highconf_events") or []),
            "highconf_events":       (csv_report.get("highconf_events") or [])[:50],
        }

    # ── Backfill empty tactic/kill_chain on legacy techniques ─────────
    # Legacy IDA emits techniques with `tactic: ""` or Title Case. Fill
    # blanks from the canonical catalog and NORMALISE all tactic strings
    # so canonical (snake_case) and legacy (Title Case) agree.
    for t in existing_mitre:
        if not isinstance(t, dict): continue
        tid = t.get("id") or ""
        meta = _meta(tid)
        current = _norm_tactic(t.get("tactic"))
        if not current and meta["tactic"] != "unknown":
            current = meta["tactic"]
        t["tactic"] = current
        current_kc = _norm_tactic(t.get("kill_chain"))
        if not current_kc and meta["kill_chain"] != "unknown":
            current_kc = meta["kill_chain"]
        t["kill_chain"] = current_kc
    obj["mitre"] = existing_mitre

    # If no techniques ANYWHERE, bail out — nothing to project.
    if not existing_mitre:
        return result

    # ── ALWAYS mirror object.mitre → narrative.* so the Workspace
    # attack-chain graph renders whether techniques came from legacy
    # IDA (command-line inputs) or canonical narrative rules (DOCX).
    narrative = obj.get("narrative")
    if not isinstance(narrative, dict):
        narrative = {}
        obj["narrative"] = narrative

    # mitre_matrix — always populated from object.mitre
    mm = []
    for t in existing_mitre:
        if not isinstance(t, dict): continue
        tid = t.get("id"); nm = t.get("name")
        if not tid: continue
        tac = t.get("tactic") or _meta(tid)["tactic"]
        mm.append({"id": tid, "name": nm, "tactic": tac})
    narrative["mitre_matrix"] = mm

    # kill_chain_coverage — always list
    tactics_seen = sorted({t.get("tactic") for t in existing_mitre
                           if isinstance(t, dict) and t.get("tactic")
                           and t.get("tactic") != "unknown"})
    narrative["kill_chain_coverage"] = tactics_seen

    # attack_progression — always list of tactic-grouped stages
    by_tactic: Dict[str, List[Dict[str, Any]]] = {}
    for t in existing_mitre:
        if not isinstance(t, dict): continue
        tid = t.get("id"); nm = t.get("name")
        if not tid: continue
        tac = t.get("tactic") or _meta(tid)["tactic"]
        if tac == "unknown": continue
        by_tactic.setdefault(tac, []).append({
            "id": tid, "name": nm, "evidence": t.get("evidence", ""),
        })
    from canonical.projections.attack_chain import _STAGE_INDEX
    ap: List[Dict[str, Any]] = []
    for tac in sorted(by_tactic.keys(),
                      key=lambda x: _STAGE_INDEX.get(x, len(_STAGE_INDEX))):
        first_tid = by_tactic[tac][0]["id"]
        kc = _meta(first_tid)["kill_chain"]
        ap.append({
            "stage": tac,
            "tactic": tac,
            "kill_chain": kc.replace("_", " ").title(),
            "title": tac.replace("_", " ").title(),
            "mitre": by_tactic[tac],
            "narrative": (f"Observed {len(by_tactic[tac])} technique(s) in "
                          f"{tac.replace('_',' ')}: "
                          f"{', '.join(x['id'] for x in by_tactic[tac])}"),
        })
    narrative["attack_progression"] = ap

    # ── Phase 5.W · Deterministic narrative enrichment (2026-08-10) ───
    # Fill executive_summary / analyst_summary / recommended_actions /
    # behavior_summary / overall_assessment / likely_objective /
    # sigma_hunts / yara_ideas when the legacy stage-based generator
    # produced empty content (URL, DOCX, vendor-narrative inputs).
    from .canonical_narrative_enrichment import (
        enrich_narrative, synth_chain_steps_from_progression,
    )
    _iocs   = obj.get("iocs") if isinstance(obj.get("iocs"), dict) else {}
    _lolbas = obj.get("lolbas") if isinstance(obj.get("lolbas"), list) else []
    _src_url = None
    _ad = obj.get("acquired_document")
    if isinstance(_ad, dict):
        _src_url = _ad.get("url") or _ad.get("source_url")
    narrative = enrich_narrative(narrative, existing_mitre,
                                 iocs=_iocs, lolbas=_lolbas,
                                 source_url=_src_url)
    obj["narrative"] = narrative

    # ── Synthesise object.chain.steps[] from attack_progression so
    # the linear AttackChainView + ReportTab render on URL / DOCX
    # / narrative inputs where legacy analyze_chain() produced []. ─
    chain_obj = obj.get("chain")
    if not isinstance(chain_obj, dict):
        chain_obj = {}
    if not chain_obj.get("steps"):
        synth_steps = synth_chain_steps_from_progression(ap)
        if synth_steps:
            chain_obj["steps"] = synth_steps
            chain_obj["root"]  = synth_steps[0]["node_id"]
            chain_obj["total"] = len(synth_steps)
            chain_obj["source"] = "canonical.narrative_progression"
    obj["chain"] = chain_obj

    # ── LOLBAS enrichment · fill legit/abuse/detection from registry ─
    if isinstance(_lolbas, list) and _lolbas:
        try:
            from .lolbas import lolbas_lookup as _lolbas_lookup
            for lb in _lolbas:
                if not isinstance(lb, dict):
                    continue
                binary = lb.get("binary") or ""
                reg = _lolbas_lookup(binary) if binary else None
                if not reg:
                    continue
                if not (lb.get("legit") or "").strip() and reg.get("notes"):
                    lb["legit"] = reg["notes"]
                if not (lb.get("abuse") or "").strip():
                    cat = reg.get("category") or ""
                    mitre_ids = ", ".join(reg.get("mitre") or [])
                    lb["abuse"] = (
                        f"Category `{cat}` — abused for {mitre_ids} tradecraft."
                        if cat or mitre_ids else "Living-off-the-land abuse."
                    )
                if not (lb.get("detection") or []):
                    hints: List[str] = []
                    for tid in (reg.get("mitre") or []):
                        catalog = None
                        try:
                            from .canonical_narrative_enrichment import (
                                _TECHNIQUE_CATALOG as _CAT,
                            )
                            catalog = _CAT.get(tid)
                        except Exception:
                            catalog = None
                        if catalog and catalog.get("sigma"):
                            hints.append(catalog["sigma"])
                    if hints:
                        lb["detection"] = hints
        except Exception:
            # Never break the bridge on enrichment errors.
            pass

    # ── ice.incident.summary population ───────────────────────────────
    ice = obj.get("ice") or {}
    inc = ice.get("incident") if isinstance(ice, dict) else None
    if isinstance(inc, dict):
        sm = inc.get("summary") or {}
        if isinstance(sm, dict):
            sm["tactics_observed"] = tactics_seen
            sm["mitre_count"] = len(existing_mitre)
            inc["summary"] = sm
        ice["incident"] = inc
    obj["ice"] = ice

    # Provenance marker.
    result["canonical_augmented"] = {
        "wave": "5.W",
        "lifecycle": "canonical_bridge.investigation_results",
        "canonical_added": [t["id"] for t in canonical_techs],
        "total_mitre": len(existing_mitre),
        "tactics_observed": tactics_seen,
    }

    # ── Wire-response slimming (Phase 5.W · 2026-08-10) ──────────
    # /api/die/investigation-results was returning 400-500 KB of
    # internal analysis intermediates (preprocessor.stages,
    # preprocessor.artifacts, preprocessor.process_edges,
    # explanations, commands, acquired_document text, …) that the
    # Workspace UI never renders. Setting all that into React state
    # + persisting to localStorage blocks the main thread for 15 s+
    # and Chrome shows "Wait / Exit". The full SSOT remains in the
    # immutable store; we only slim the WIRE response.
    _slim_investigation_response(result)
    return result


# ── Fields the Workspace UI does not render — strip from wire ─────
_SLIM_STRIP_KEYS = (
    "preprocessor",           # 400 KB+ of internal state
    "commands",               # keep only summary via `command_lines`
    "artifacts",               # rebuild lightweight list from `mitre`
    "explanations",            # legacy debug
    "explanation_coverage",
    "acquired_document",       # raw fetched HTML / DOCX text
    "document_profile",
    "report_extraction",
    "artifact_summary",
    "profiling",
    "engines_selected",
    "engines_skipped",
    "understanding",           # covered by narrative + mitre
    "plan",
    "acquisition_plan",
    "dkp",
    "intent",
    "behaviour",               # 45 KB, superseded by narrative.behavior_summary
    "ice",                     # 100 KB, only tactics needed
    "incident",                # 90 KB, only summary needed
)

def _slim_investigation_response(result: Dict[str, Any]) -> None:
    """Mutate `result` in place, stripping fields the Workspace UI
    does not render. Preserves: narrative, mitre, iocs, lolbas,
    chain, csv_edr, confidence, metadata, input (truncated).
    """
    if not isinstance(result, dict):
        return
    obj = result.get("object")
    if not isinstance(obj, dict):
        return

    # Cap the input echo — some callers post multi-MB payloads.
    if isinstance(obj.get("input"), str) and len(obj["input"]) > 64 * 1024:
        obj["input"] = obj["input"][:64 * 1024] + f"\n... [{len(obj['input']) - 64*1024:,} more bytes truncated]"

    # Retain a compact summary of incident tactics if present (single
    # tiny list rather than the 90 KB `incident` block).
    inc = obj.get("incident")
    if isinstance(inc, dict):
        tactics = []
        for b in (inc.get("behaviors") or []):
            if isinstance(b, dict) and b.get("tactic") and b["tactic"] not in tactics:
                tactics.append(b["tactic"])
        obj["incident_tactics"] = tactics[:20]

    # Filter internal / non-routable domain IOCs — they pollute
    # dashboards for enterprise EDR logs (AD-joined hostnames).
    iocs = obj.get("iocs")
    if isinstance(iocs, dict):
        _INTERNAL_TLDS = (".local", ".corp", ".lan", ".internal",
                           ".arpa", ".home", ".localdomain")
        for kind in ("domain",):
            bucket = iocs.get(kind)
            if isinstance(bucket, list):
                filtered = [v for v in bucket
                            if isinstance(v, str)
                            and not any(v.lower().endswith(tld) for tld in _INTERNAL_TLDS)]
                if len(filtered) != len(bucket):
                    iocs[kind] = filtered

    for key in _SLIM_STRIP_KEYS:
        obj.pop(key, None)

    # Trailing `command_lines` (short list) is fine to keep — it's typically
    # a handful of extracted strings.


__all__ = [
    "canonical_die_flag_enabled",
    "augment_die_result",
    "augment_investigation_results",
]
