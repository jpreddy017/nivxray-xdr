#!/usr/bin/env python3
"""GATE 3 · run the fabric over REAL persisted detections. READ-ONLY.

The unit contracts prove the shape. This proves the fabric has a genuine
producer on the platform's own data: it reads real `edr_raw_events` rows
(the CALLER reads evidence — the fabric itself never opens an evidence
store, which is a structural test), evaluates them through the registered
deterministic analyzer, and reports the outcome distribution.

It writes NOTHING. No finding is persisted, no evidence row is touched.
"""
from __future__ import annotations

import json
import sys
from collections import Counter

sys.path.insert(0, "/app/backend")

from deps import sync_collection                              # noqa: E402
from edr_plane import fabric                                  # noqa: E402,F401
from edr_plane.fabric import registry                         # noqa: E402
from edr_plane.fabric.contracts import EvidenceUnit           # noqa: E402
from edr_plane.fabric.analyzers.deterministic_rule import ANALYZER  # noqa: E402

LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 500


def main() -> int:
    coll = sync_collection("edr_raw_events")
    # Sample across the outcome classes the ingest plane actually records,
    # so the report shows all three facts on real data instead of whatever
    # the first page of the collection happens to be.
    rows = []
    for outcome in ("DETECTION_MATCHED", "DETECTION_EVALUATED_NO_MATCH",
                    "DETECTION_NOT_EVALUATED", None):
        q = ({"derivations.outcome": outcome} if outcome
             else {"derivations": {"$exists": True, "$ne": []}})
        rows.extend(coll.find(q, {"_id": 0, "tenant_id": 1,
                                  "endpoint_ref": 1, "payload": 1,
                                  "derivations": 1, "ingest_time": 1}
                              ).limit(LIMIT))
    print(f"read {len(rows)} real raw events (read-only)")

    outcomes: Counter = Counter()
    findings = []
    for r in rows:
        try:
            activity = json.loads(r.get("payload") or "{}")
        except (ValueError, TypeError):
            activity = {}
        canonical = next((d.get("event_id") for d in r["derivations"]
                          if d.get("event_id")), None)
        if not canonical:
            outcomes["NO_CANONICAL_REFERENCE_SKIPPED"] += 1
            continue
        unit = EvidenceUnit(
            tenant_id=r.get("tenant_id") or "",
            evidence_ref=canonical,
            endpoint_ref=r.get("endpoint_ref"),
            observed_at=(activity.get("observed_at") or r.get("ingest_time")),
            activity=activity,
            derivations=r["derivations"])
        res = ANALYZER.evaluate(unit)
        outcomes[res.outcome] += 1
        findings.extend(res.findings)

    print("\noutcome distribution (three DIFFERENT facts, never merged):")
    for k, v in outcomes.most_common():
        print(f"  {k:32s} {v}")
    print(f"\nfindings produced: {len(findings)}")
    if findings:
        f = findings[0]
        print("\none finding, verbatim:")
        print(json.dumps(f.to_mongo(), indent=2, default=str))
        assert all(x.evidence_refs for x in findings)
        assert all(x.finding_id and x.finding_id.startswith("fnd_")
                   for x in findings)
        ids = {x.finding_id for x in findings}
        print(f"\ndistinct content-addressed ids: {len(ids)} of "
              f"{len(findings)} findings (repeats are the SAME evaluation of "
              f"the same evidence, recognised rather than duplicated)")

    print("\ndeclared capability of the fabric TODAY:")
    print(json.dumps(registry.declared_capabilities(), indent=2))
    print("\nNOTHING WAS WRITTEN. 0 findings persisted, 0 evidence rows "
          "touched.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
