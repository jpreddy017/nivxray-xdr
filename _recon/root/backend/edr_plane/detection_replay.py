"""E3 · DETECTION REPLAY over already-canonical endpoint evidence.

WHY THIS EXISTS
---------------
The real Windows acceptance corpus proved a negative-explainability
defect, not a missing detection engine:

* `xdr_canonical_evidence` holds 3,299 fully normalised rows for
  `DESKTOP-A9HGFJJ`;
* `edr_findings` and `edr_finding_evaluations` held **nothing** for them;
* so every surface had to say "no detection engine claimed this
  observation", which is indistinguishable from "never evaluated".

Running the canonical evaluator over those 3,299 rows returns
`RULE_NO_MATCH` 3,299 times with no errors, and the corpus really is
benign (2,615 `svchost.exe` rows, 16 rows with any command line, zero
interpreter/LOLBin processes). `NO MATCH` is therefore the CORRECT
answer — but it has to be RECORDED as an answer instead of looking like
silence.

    NO DETECTION RECORDED   is NOT   EVALUATED AND NOTHING MATCHED

THIS IS NOT A SECOND DETECTION ENGINE
-------------------------------------
Owner rule: replay must not become "replay detection logic" that can
disagree with "live detection logic". So:

* the verdict comes from `detection_content.xdr_pipeline
  .evaluate_detection` — the IDENTICAL function
  `process_event_through_pipeline` calls at its detection stage;
* durability comes from `edr_plane.findings_intake
  .record_endpoint_detection` — the IDENTICAL function the live endpoint
  ingest path calls;
* there is no rule, predicate, threshold or match shape defined here.

WHAT REPLAY DOES NOT DO
-----------------------
* It does NOT re-run DSM / parser / normalizer, so it cannot mint a
  duplicate canonical row or a second evidence identity.
* It does NOT write `edr_raw_events`. Fabricating a raw row would claim
  sensor bytes arrived at an instant they did not.
* It does NOT modify any observation, timestamp or canonical field.
* It does NOT convert an absent verdict into a benign one.

TIME MODEL (the retrospective contract, established here)
---------------------------------------------------------
`event_time`    — when it happened on the endpoint. NEVER touched.
`evaluated_at`  — when THIS evaluation ran. Always now.

A detection produced by replay is honestly late, and says so.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from services.edr.endpoint_query import endpoint_predicate

CANONICAL_COLLECTION = "xdr_canonical_evidence"

#: Replay reads the canonical plane by the endpoint refs the caller is
#: already authorised for. The tenant clause is supplied by E1 and is not
#: optional: an unresolved customer reads nothing.
CANONICAL_ENDPOINT_FIELDS = ("provenance.collector_id", "host.host_id",
                             "host.hostname")

REPLAY_BASIS = "CANONICAL_EVIDENCE_REPLAY_NOT_REINGESTION"
MATCHED = "DETECTION_MATCHED"
NO_MATCH = "DETECTION_EVALUATED_NO_MATCH"
FAILED = "DETECTION_NOT_EVALUATED"


def rule_set_fingerprint() -> Dict[str, Any]:
    """Identify the content that produced a verdict, so a later replay
    can be told apart from this one instead of silently overwriting it."""
    from detection_content.library.registry import RUNTIME_DETECTION_RULES
    ids = sorted(f"{r.rule_id}@{r.rule_version}"
                 for r in RUNTIME_DETECTION_RULES)
    return {"rule_count": len(ids),
            "rule_set_sha256": hashlib.sha256(
                "\x1f".join(ids).encode()).hexdigest()[:32]}


def _citations(matches: List[Dict[str, Any]],
               event_id: str) -> List[Dict[str, Any]]:
    """The PRODUCING RULE's own records for this evidence.

    The evaluator already returned each rule's declared severity,
    confidence, version and ATT&CK mapping. Handing them to the finding
    plane is what keeps a finding honest: the rule's real values, not an
    approximation, and never a technique the rule did not declare.
    """
    out: List[Dict[str, Any]] = []
    for m in matches:
        if not m.get("rule_id"):
            continue
        mitre = list(m.get("mitre_attack") or [])
        if not mitre and m.get("technique_id"):
            mitre = [m["technique_id"]]
        out.append({
            "rule_id": m.get("rule_id"),
            "rule_version": m.get("rule_version"),
            "rule_name": m.get("name"),
            "severity": m.get("severity"),
            "confidence": m.get("confidence"),
            "mitre_attack": mitre,
            "canonical_event_id": event_id,
        })
    return out


def _endpoint_ref(canonical: Dict[str, Any]) -> Optional[str]:
    # G-30 · the authoritative platform identity first; the remaining values
    # are ADDRESSING REFS resolved against the validated alias set, never
    # identities in their own right.
    extra = canonical.get("additional_fields") or {}
    prov = canonical.get("provenance") or {}
    host = canonical.get("host") or {}
    return (extra.get("endpoint_id") or prov.get("collector_id")
            or host.get("host_id") or host.get("hostname") or None)


async def replay_endpoint(db, *, tenant_id: str, refs: Sequence[str],
                          apply: bool = False,
                          limit: Optional[int] = None) -> Dict[str, Any]:
    """Evaluate the canonical evidence this endpoint already has.

    `apply=False` (the default) evaluates and reports and writes NOTHING,
    so the outcome can be inspected before any derived record exists.
    """
    from detection_content.xdr_pipeline import evaluate_detection

    if not tenant_id:
        return {"state": "TENANT_NOT_RESOLVED_FOR_REPLAY",
                "reason": ("replay reads a tenant-partitioned evidence "
                           "store; an unresolved customer reads nothing"),
                "evaluated": 0, "applied": False}

    query = endpoint_predicate(list(refs), CANONICAL_COLLECTION,
                              list(CANONICAL_ENDPOINT_FIELDS),
                              tenant_id=tenant_id)
    fingerprint = rule_set_fingerprint()
    started = datetime.now(timezone.utc).isoformat()

    out: Dict[str, Any] = {
        "state": "REPLAYED", "basis": REPLAY_BASIS,
        "engine_id": "nivxray::detection_content::nivxray_native_sigma",
        "authority": ("detection_content.xdr_pipeline.evaluate_detection — "
                      "the same function the live ingest pipeline calls; "
                      "replay defines no rule and no match shape"),
        "tenant_id": tenant_id, "refs": list(refs),
        "rule_set": fingerprint, "started_at": started,
        "evaluated": 0, "matched": 0, "no_match": 0, "failed": 0,
        "persisted_findings": 0, "applied": bool(apply),
        "rules_fired": {}, "failures": [],
    }

    cursor = db[CANONICAL_COLLECTION].find(query, {"_id": 0})
    if limit:
        cursor = cursor.limit(int(limit))

    async for canonical in cursor:
        event_id = canonical.get("event_id")
        if not event_id:
            continue
        out["evaluated"] += 1
        evaluated_at = datetime.now(timezone.utc).isoformat()
        try:
            verdict = evaluate_detection(canonical)
        except Exception as e:                               # noqa: BLE001
            out["failed"] += 1
            if len(out["failures"]) < 5:
                out["failures"].append({"event_id": event_id,
                                        "error": str(e)[:200]})
            if apply:
                await _record(db, tenant_id, canonical, event_id,
                              outcome=FAILED, evaluated_at=evaluated_at,
                              fingerprint=fingerprint, rule_ids=[],
                              reason=("the detection authority raised on "
                                      "this evidence; the evidence EXISTS "
                                      "and is replayable — the verdict is "
                                      "UNKNOWN, not clean: " + str(e)[:160]),
                              out=out)
            continue

        matches: List[Dict[str, Any]] = verdict.get("detections") or []
        rule_ids = [m.get("rule_id") for m in matches if m.get("rule_id")]
        hit = bool(verdict.get("matched"))
        if hit:
            out["matched"] += 1
            for rid in rule_ids:
                out["rules_fired"][rid] = out["rules_fired"].get(rid, 0) + 1
        else:
            out["no_match"] += 1
        if apply:
            await _record(db, tenant_id, canonical, event_id,
                          outcome=MATCHED if hit else NO_MATCH,
                          evaluated_at=evaluated_at, fingerprint=fingerprint,
                          rule_ids=rule_ids,
                          reason=("rules: " + ", ".join(rule_ids))
                          if hit else None, out=out,
                          citations=_citations(matches, event_id))

    out["finished_at"] = datetime.now(timezone.utc).isoformat()
    # Stated explicitly so a console can never read "no match" as benign.
    out["no_match_meaning"] = (
        "the evidence WAS evaluated by the stated rule set and nothing "
        "matched. This is not a statement that the activity was benign, "
        "and it says nothing about engines that do not exist yet")
    return out


async def _record(db, tenant_id: str, canonical: Dict[str, Any],
                  event_id: str, *, outcome: str, evaluated_at: str,
                  fingerprint: Dict[str, Any], rule_ids: List[str],
                  reason: Optional[str], out: Dict[str, Any],
                  citations: Optional[List[Dict[str, Any]]] = None) -> None:
    """Make ONE replay verdict durable through the LIVE finding plane."""
    from edr_plane.findings_intake import record_endpoint_detection

    # The canonical evidence IS the activity view. Passing it means an
    # approved exclusion (COMMANDLINE, PATH, HASH) can still be evaluated
    # against what was really observed; an empty payload would silently
    # under-apply exclusions on replayed evidence.
    result = await record_endpoint_detection(
        db, tenant_id=tenant_id, endpoint_ref=_endpoint_ref(canonical),
        canonical_event_id=event_id, raw_ref=None,
        citations=citations or [],
        payload=json.dumps(canonical, default=str),
        observed_at=canonical.get("event_time"),
        derivation={
            "outcome": outcome,
            "event_id": event_id,
            "reason": reason,
            "detection_content_version": (
                f"rules:{fingerprint['rule_count']}"
                f"@{fingerprint['rule_set_sha256']}"),
            # The honest two-instant record. `observed_at` above is the
            # endpoint instant and is untouched; this is when the verdict
            # was actually produced.
            "derived_at": evaluated_at,
            "replay_basis": REPLAY_BASIS,
            "rule_ids": rule_ids,
        })
    out["persisted_findings"] += int(result.get("findings_persisted") or 0)
