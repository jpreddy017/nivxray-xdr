"""One-off backfill: re-enrich existing workspace cases whose
analyst_narrative and investigation_object.narrative were captured
before Phase 5.W enrichment (executive_summary/analyst_summary/
recommended_actions/behavior_summary/overall_assessment/
likely_objective/sigma_hunts/yara_ideas empty, but mitre_matrix
already populated).

Governance rules honored:
- Sample1 (Sample.docx) row is NEVER touched.
- Only fills EMPTY narrative fields; never overwrites populated content.
- Only mutates cases whose ssot.investigation_object.mitre has ≥1
  technique — otherwise nothing to enrich from.

Usage:
    python3 /app/backend/scripts/backfill_narrative_enrichment.py [--apply]

Without --apply, the script performs a dry-run and prints the
affected case count. Pass --apply to persist changes to Mongo.
"""
from __future__ import annotations
import os
import sys
import json
from pathlib import Path

# ── path bootstrap ────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymongo import MongoClient

from services.die.canonical_narrative_enrichment import (
    enrich_narrative, synth_chain_steps_from_progression,
)


SAMPLE1_MARKERS = {
    "Sample.docx", "Sample1", "sample1",
    "3915b712", "3915b71257",  # SHA256 prefix
}


def _is_sample1(case: dict) -> bool:
    """Refuse to touch the Sample1 golden case."""
    name = (case.get("name") or "")
    inp  = (case.get("input") or "")
    if any(marker in name for marker in SAMPLE1_MARKERS):
        return True
    if any(marker in inp for marker in SAMPLE1_MARKERS):
        return True
    return False


def _needs_enrichment(narr: dict) -> bool:
    if not isinstance(narr, dict):
        return False
    exec_empty = not (narr.get("executive_summary") or "").strip()
    actions_empty = not (narr.get("recommended_actions") or [])
    assessment_empty = not narr.get("overall_assessment")
    # If ANY of the enrichable fields is empty AND mitre_matrix has data → enrich.
    if not (narr.get("mitre_matrix") or narr.get("attack_progression")):
        return False
    return exec_empty or actions_empty or assessment_empty


def _build_mitre_list_from_narrative(narr: dict, obj: dict | None) -> list:
    """Coalesce a MITRE technique list from either object.mitre or
    narrative.mitre_matrix / attack_progression."""
    from canonical.projections.attck import _TECHNIQUE_META

    seen: dict = {}

    def _add(tid: str, name: str = "", tactic: str = ""):
        if not tid or tid in seen:
            return
        meta = _TECHNIQUE_META.get(tid, {})
        seen[tid] = {
            "id":         tid,
            "name":       name or "",
            "tactic":     tactic or meta.get("tactic") or "unknown",
            "kill_chain": meta.get("kill_chain") or "unknown",
        }

    if isinstance(obj, dict):
        for t in obj.get("mitre") or []:
            if isinstance(t, dict):
                _add(t.get("id"), t.get("name") or "", t.get("tactic") or "")

    for row in narr.get("mitre_matrix") or []:
        if isinstance(row, dict):
            _add(row.get("id"), row.get("name") or "", row.get("tactic") or "")

    for stage in narr.get("attack_progression") or []:
        if not isinstance(stage, dict):
            continue
        tac = stage.get("tactic") or stage.get("stage") or ""
        for m in stage.get("mitre") or []:
            if isinstance(m, dict):
                _add(m.get("id"), m.get("name") or "", tac)
            elif isinstance(m, str):
                _add(m, "", tac)

    return list(seen.values())


def main():
    apply_mode = "--apply" in sys.argv
    mongo_url = os.environ["MONGO_URL"]
    db_name = os.environ["DB_NAME"]
    client = MongoClient(mongo_url)
    db = client[db_name]

    touched = 0
    skipped_sample = 0
    skipped_no_mitre = 0
    total = 0

    cursor = db["workspace_cases"].find({})
    for case in cursor:
        total += 1
        if _is_sample1(case):
            skipped_sample += 1
            continue
        ssot = case.get("ssot") or {}
        an = ssot.get("analyst_narrative") or {}
        obj = (ssot.get("investigation_object") or {})
        obj_narr = obj.get("narrative") or {}

        # Determine mitre list (source of truth for enrichment).
        mitre_list = _build_mitre_list_from_narrative(an, obj)
        if not mitre_list:
            skipped_no_mitre += 1
            continue

        # Enrich both `analyst_narrative` (top-level, drives Workspace)
        # and `investigation_object.narrative` (drives per-view panels).
        an_changed = False
        obj_changed = False

        if _needs_enrichment(an):
            iocs = obj.get("iocs") if isinstance(obj.get("iocs"), dict) else {}
            src_url = None
            ad = obj.get("acquired_document") or {}
            if isinstance(ad, dict):
                src_url = ad.get("url") or ad.get("source_url")
            enrich_narrative(an, mitre_list, iocs=iocs, source_url=src_url or case.get("input"))
            an_changed = True

        if _needs_enrichment(obj_narr):
            iocs = obj.get("iocs") if isinstance(obj.get("iocs"), dict) else {}
            src_url = None
            ad = obj.get("acquired_document") or {}
            if isinstance(ad, dict):
                src_url = ad.get("url") or ad.get("source_url")
            enrich_narrative(obj_narr, mitre_list, iocs=iocs, source_url=src_url or case.get("input"))
            obj_changed = True

        # Synthesise chain.steps if legacy chain empty and progression exists.
        chain = obj.get("chain")
        if not isinstance(chain, dict):
            chain = {}
        if not chain.get("steps"):
            steps = synth_chain_steps_from_progression(obj_narr.get("attack_progression") or [])
            if steps:
                chain["steps"] = steps
                chain["root"]  = steps[0]["node_id"]
                chain["total"] = len(steps)
                chain["source"] = "canonical.narrative_progression"
                obj["chain"] = chain
                obj_changed = True

        # LOLBAS enrichment from registry.
        lolbas_list = obj.get("lolbas") or []
        if isinstance(lolbas_list, list) and lolbas_list:
            try:
                from services.die.lolbas import lolbas_lookup as _lolbas_lookup
                from services.die.canonical_narrative_enrichment import _TECHNIQUE_CATALOG
                for lb in lolbas_list:
                    if not isinstance(lb, dict):
                        continue
                    binary = lb.get("binary") or ""
                    reg = _lolbas_lookup(binary) if binary else None
                    if not reg:
                        continue
                    if not (lb.get("legit") or "").strip() and reg.get("notes"):
                        lb["legit"] = reg["notes"]
                        obj_changed = True
                    if not (lb.get("abuse") or "").strip():
                        cat = reg.get("category") or ""
                        mitre_ids = ", ".join(reg.get("mitre") or [])
                        lb["abuse"] = (
                            f"Category `{cat}` — abused for {mitre_ids} tradecraft."
                            if cat or mitre_ids else "Living-off-the-land abuse."
                        )
                        obj_changed = True
                    if not (lb.get("detection") or []):
                        hints = []
                        for tid in (reg.get("mitre") or []):
                            catalog = _TECHNIQUE_CATALOG.get(tid)
                            if catalog and catalog.get("sigma"):
                                hints.append(catalog["sigma"])
                        if hints:
                            lb["detection"] = hints
                            obj_changed = True
                obj["lolbas"] = lolbas_list
            except Exception:
                pass

        if not (an_changed or obj_changed):
            continue

        touched += 1
        if apply_mode:
            update = {}
            if an_changed:
                update["ssot.analyst_narrative"] = an
            if obj_changed:
                update["ssot.investigation_object.narrative"] = obj_narr
                update["ssot.investigation_object.chain"] = obj.get("chain") or {}
                update["ssot.investigation_object.lolbas"] = obj.get("lolbas") or []
            db["workspace_cases"].update_one({"_id": case["_id"]},
                                             {"$set": update})

            # Also mirror into the immutable ssot store (R28.1) so
            # /api/cases/{id} (which prefers ssot_ref → load_ssot)
            # serves the enriched narrative.
            ref = case.get("ssot_ref") or {}
            if isinstance(ref, dict) and ref.get("id"):
                store_update = {}
                if an_changed:
                    store_update["ssot.analyst_narrative"] = an
                if obj_changed:
                    store_update["ssot.investigation_object.narrative"] = obj_narr
                    store_update["ssot.investigation_object.chain"] = obj.get("chain") or {}
                    store_update["ssot.investigation_object.lolbas"] = obj.get("lolbas") or []
                if store_update:
                    db["investigation_ssot"].update_one(
                        {"investigation_id": ref["id"]},
                        {"$set": store_update},
                    )

    print(f"total workspace_cases scanned : {total}")
    print(f"skipped (Sample1 golden)      : {skipped_sample}")
    print(f"skipped (no MITRE evidence)   : {skipped_no_mitre}")
    print(f"cases enriched                : {touched}")
    print(f"mode                          : {'APPLY' if apply_mode else 'DRY-RUN'}")


if __name__ == "__main__":
    main()
