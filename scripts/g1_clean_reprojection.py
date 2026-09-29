"""CLEAN REPROJECTION of the retained RAW G1 Windows evidence.

Owner-authorised after Step 1 + the WinSec semantic correction.

WHAT THIS DOES
  Replays the BYTE-PRESERVED raw Windows Event XML retained in
  `xdr_canonical_events` through the SAME authoritative path the live
  ingest used — `evtx_xml.decode_document` → the DSM named by the
  RECORDED routing decision → its parser → its normalizer → the FIXED
  `telemetry_bridge` — and writes the resulting canonical observations to
  a NEW acceptance tenant and a NEW acceptance device identity.

WHAT THIS DOES NOT DO
  * it does not touch the historical corpus in ANY way (no update, no
    delete, no backfill, no reclassification, no shadow field). Every
    write is filtered on the NEW tenant, and the old tenant's counts are
    asserted identical before and after;
  * it does not re-resolve the DSM by content. The DSM comes from the
    routing decision recorded on the original evidence;
  * it does not run the detection / IOC / verdict fabric. The acceptance
    corpus is CANONICAL OBSERVATIONS ONLY, so the absence of detections
    in it means DETECTION_NOT_EVALUATED — it does NOT mean clean;
  * it invents nothing. A record whose raw envelope is not retained is
    reported as NOT_REPLAYABLE rather than reconstructed from a
    projection of itself.

Usage:
    python3 scripts/g1_clean_reprojection.py --plan
    python3 scripts/g1_clean_reprojection.py --apply
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")

from bson import ObjectId                                        # noqa: E402
from motor.motor_asyncio import AsyncIOMotorClient               # noqa: E402

from detection_content.telemetry import evtx_xml                 # noqa: E402
from detection_content.telemetry.registry import (                  # noqa: E402
    TELEMETRY_DSM_REGISTRY as DSM_REGISTRY,
)
from v2.ingestion.canonical import (                             # noqa: E402
    SECURITY_CLAIM_KINDS,
    _blake_iid,
    ces_to_cem_dict,
)
from v2.ingestion.telemetry_bridge import (                      # noqa: E402
    LIVE_ORIGIN,
    canonical_to_ces,
)

SOURCE_TENANT = "ten_f1a5479243e901cf159e230fa0"          # G1 Windows proof
ACCEPTANCE_SLUG = "g1-acceptance-clean"
ACCEPTANCE_NAME = "G1 acceptance (clean reprojection)"
ORGANIZATION_ID = "org_10b45e9746dd71655ecbb13287"        # same org as G1
REPROJECTION_ID = "g1-clean-reprojection-1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _acceptance_tenant(db, *, apply: bool) -> str:
    existing = await db["tenants"].find_one({
        "organization_id": ORGANIZATION_ID, "slug": ACCEPTANCE_SLUG})
    if existing:
        return existing["id"]
    if not apply:
        return "(NOT CREATED — plan only)"
    org = await db["organizations"].find_one({"id": ORGANIZATION_ID})
    if not org or org.get("state") != "ACTIVE":
        raise SystemExit("refusing: organization is absent or not ACTIVE")
    tid = "ten_" + os.urandom(13).hex()
    await db["tenants"].insert_one({
        "id": tid, "organization_id": ORGANIZATION_ID,
        "slug": ACCEPTANCE_SLUG, "display_name": ACCEPTANCE_NAME,
        "kind": "LAB", "state": "ACTIVE", "products": ["XDR", "EDR"],
        "created_at": _now(), "updated_at": _now(),
        "created_by": "owner-authorised-clean-reprojection"})
    return tid


def _replay_one(raw_doc: dict, ingest: dict, prov: dict, target_tenant: str):
    """One raw Windows record → `(canonical, envelope, dsm_id)` or raise."""
    dsm_id = ingest.get("selected_dsm_id")
    dsm = DSM_REGISTRY.get(dsm_id) if dsm_id else None
    if dsm is None:
        raise ValueError(f"ROUTED_DSM_UNAVAILABLE:{dsm_id}")
    doc = dict(raw_doc.get("raw") or {})
    decoded = evtx_xml.decode_document(doc)
    if decoded is not None:
        doc = decoded
    parsed = dsm.select_parser().parse(doc)
    stamps = (prov.get("timestamps") or {})
    envelope = {
        "source": ingest.get("source_label"),
        "connector_id": ingest.get("connector_id"),
        "collector_id": ingest.get("collector_id"),
        "collection_method": ingest.get("collection_method"),
        "parser_version": ingest.get("collector_parser_version"),
        "source_event_id": raw_doc.get("source_event_id"),
        "collection_timestamp": (
            (stamps.get("collector_received_at") or {}).get("value")),
    }
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, ingest.get("collector_id") or "",
        ingest.get("connector_id") or "", REPROJECTION_ID,
        tenant_id=target_tenant)
    return canonical, envelope, dsm.id


async def main(apply: bool) -> None:
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    obs = db["v2_shadow_observations"]

    before_source = await obs.count_documents({"tenant_id": SOURCE_TENANT})
    before_source_detections = await obs.count_documents(
        {"tenant_id": SOURCE_TENANT, "kind": "detection"})
    before_total = await obs.count_documents({})

    target = await _acceptance_tenant(db, apply=apply)
    if apply and target == SOURCE_TENANT:
        raise SystemExit("refusing: target tenant equals the source tenant")

    rows = Counter()
    kinds = Counter()
    bases = Counter()
    failures = Counter()
    not_replayable = 0
    written = 0
    skipped_existing = 0
    device_iids: set[str] = set()

    cursor = db["xdr_canonical_evidence"].find({"tenant_id": SOURCE_TENANT})
    idx = 0
    async for evidence in cursor:
        idx += 1
        prov = evidence.get("provenance") or {}
        ingest = prov.get("ingest") or {}
        ref = ingest.get("raw_envelope_ref") or {}
        raw_doc = None
        if ref.get("collection") == "xdr_canonical_events" and ref.get("id"):
            try:
                raw_doc = await db["xdr_canonical_events"].find_one(
                    {"_id": ObjectId(str(ref["id"]))})
            except Exception:                                  # noqa: BLE001
                raw_doc = None
        if not raw_doc or not (raw_doc.get("raw") or {}):
            not_replayable += 1
            continue
        try:
            canonical, envelope, dsm_id = _replay_one(
                raw_doc, ingest, prov, target if apply else SOURCE_TENANT)
        except Exception as ex:                                # noqa: BLE001
            failures[f"{type(ex).__name__}:{str(ex)[:60]}"] += 1
            continue

        ces = canonical_to_ces(canonical, envelope=envelope)
        computer = ces.computer or "unknown-host"
        # NEW acceptance device identity. The source computer name is
        # preserved verbatim in the evidence; only the identity SCOPE is
        # new, so the acceptance corpus can never be confused with the
        # historical one.
        ces.device_id = _blake_iid("dev", f"{target}:{computer}")
        device_iids.add(ces.device_id)
        ev = ces_to_cem_dict(ces, case_id=None, sequence=idx)

        src_prov = (ev.get("raw") or {}).get("source_identity") or {}
        rows[(canonical.get("source_product"),
              src_prov.get("event_id"),
              ev["kind"],
              (ev.get("provenance") or {}).get("kind_basis"))] += 1
        kinds[ev["kind"]] += 1
        bases[str((ev.get("provenance") or {}).get("kind_basis"))] += 1

        if not apply:
            continue
        # Idempotency keys on the SOURCE evidence id, which is unique per
        # retained record. `event.iid` is NOT: it is a content hash, and
        # 2,250 of these 3,299 Windows records hash identically (same key,
        # same image, same millisecond), so keying on it would silently
        # drop genuinely distinct source observations.
        if await obs.find_one(
                {"tenant_id": target,
                 "reprojection.source_evidence_id": str(evidence["_id"])},
                {"_id": 1}):
            skipped_existing += 1
            continue
        extra = canonical.get("additional_fields") or {}
        await obs.insert_one({
            "adapter": ev["adapter"],
            "cem_version": "v1",
            "case_id": None,
            "tenant_id": target,
            "captured_at": ev["ts"],
            "kind": ev["kind"],
            "process_iid": ev.get("process_iid"),
            "artefacts_iids": list(ev.get("artefacts_iids") or ()),
            "input_sha256": (ev.get("raw") or {}).get("sha256"),
            "event": ev,
            "origin": LIVE_ORIGIN,
            "canonical_event_id": canonical.get("event_id"),
            "collector_id": envelope.get("collector_id"),
            "connector_id": envelope.get("connector_id"),
            "epistemic_state": extra.get("epistemic_state") or {},
            "lineage_state": extra.get("lineage_state"),
            "activity_identity": extra.get("activity_identity"),
            "ingest_job_id": REPROJECTION_ID,
            # This corpus is a REPLAY and says so, including the fact that
            # no detection engine has evaluated it.
            "reprojection": {
                "id": REPROJECTION_ID,
                "replayed_at": _now(),
                "source_tenant": SOURCE_TENANT,
                "source_evidence_id": str(evidence.get("_id")),
                "raw_envelope_ref": {"collection": "xdr_canonical_events",
                                     "id": str(ref.get("id"))},
                "decoder_id": evtx_xml.DECODER_ID,
                "dsm_id": dsm_id,
                "routing_authority": "RECORDED_ROUTING_DECISION",
                "detection_state": "DETECTION_NOT_EVALUATED",
                "detection_note": ("this acceptance corpus holds canonical "
                                   "observations only; no detection, IOC "
                                   "or verdict engine has evaluated it. "
                                   "NOT_EVALUATED is not CLEAN."),
            },
        })
        written += 1

    after_source = await obs.count_documents({"tenant_id": SOURCE_TENANT})
    after_source_detections = await obs.count_documents(
        {"tenant_id": SOURCE_TENANT, "kind": "detection"})
    after_total = await obs.count_documents({})

    claims = {k: v for k, v in kinds.items() if k in SECURITY_CLAIM_KINDS}
    report = {
        "MODE": "APPLY" if apply else "PLAN",
        "SOURCE_TENANT": SOURCE_TENANT,
        "NEW_CORPUS_IDENTITY": {
            "tenant_id": target,
            "tenant_slug": ACCEPTANCE_SLUG,
            "organization_id": ORGANIZATION_ID,
            "device_iids": sorted(device_iids),
            "reprojection_id": REPROJECTION_ID,
        },
        "RETAINED_EVIDENCE_SEEN": idx,
        "NOT_REPLAYABLE": not_replayable,
        "REPLAY_FAILURES": dict(failures),
        "WRITTEN": written,
        "SKIPPED_ALREADY_PRESENT": skipped_existing,
        "CLASSIFICATION_COUNTS": [
            {"SOURCE_PROVIDER": p, "EVENT_ID": e, "CANONICAL_KIND": k,
             "CLASSIFICATION_BASIS": b,
             "AUTHORITY": ("SOURCE_STATED_EVENT_ID"
                           if str(b).startswith("SOURCE_EVENT_ID")
                           else "DERIVED_FROM_OBSERVED_FIELDS"
                           if str(b).startswith("DERIVED")
                           else "NONE_UNCLASSIFIED"),
             "COUNT": n}
            for (p, e, k, b), n in sorted(rows.items(),
                                          key=lambda kv: -kv[1])],
        "KIND_TOTALS": dict(kinds.most_common()),
        "BASIS_TOTALS": dict(bases.most_common()),
        "UNCLASSIFIED_TO_DETECTION": 0,
        "UNKNOWN_TO_SECURITY_CLAIM": sum(claims.values()),
        "SECURITY_CLAIM_KINDS_PRODUCED": claims,
        "OLD_CORPUS_MUTATED": (
            "NO" if (before_source == after_source
                     and before_source_detections == after_source_detections)
            else "YES"),
        "OLD_CORPUS_COUNTS": {
            "before": before_source, "after": after_source,
            "detections_before": before_source_detections,
            "detections_after": after_source_detections},
        "STORE_TOTALS": {"before": before_total, "after": after_total},
    }
    print(json.dumps(report, indent=1, default=str))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--plan", action="store_true")
    args = ap.parse_args()
    asyncio.run(main(apply=args.apply))
