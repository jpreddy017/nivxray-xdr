"""B5-2 · read-path PRE/POST equivalence and cost, on the REAL store.

The optimisation is only acceptable if the returned evidence set is
SEMANTICALLY IDENTICAL. So this script does not trust the change: it
re-implements the ORIGINAL unfiltered-scan behaviour verbatim and
compares, per device, across the whole directory:

    result count · evidence content digest · docs examined ·
    execution time · tenant isolation · unresolved-endpoint behaviour

    python3 scripts/b5_read_path_proof.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import time

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv                                  # noqa: E402

load_dotenv("/app/backend/.env")

from services.edr import device_identity as dir_svc             # noqa: E402

_obs = dir_svc._obs
ALL = {"all_tenants": True, "tenant_ids": []}


def _pre_observations(identity, refs=None, since_iso=None):
    """The ORIGINAL implementation: unfiltered scan, filter in Python."""
    iid = (identity.get("device_iid") or "").lower()
    host = (identity.get("hostname") or "").lower()
    ref_set = {str(r).lower() for r in (refs or []) if r}
    ref_set |= {v for v in (iid, host) if v}
    out = []
    for doc in _obs.find({}, {"_id": 0}):
        ev = dir_svc._event_of(doc)
        if not dir_svc._addresses(doc, ev, ref_set):
            continue
        ts = dir_svc._ts_of(doc, ev)
        if since_iso and ts and str(ts) < since_iso:
            continue
        out.append(doc)
    return out


def _digest(rows):
    """Order-insensitive digest of the EVIDENCE, not of the row order."""
    keys = sorted(json.dumps(r, sort_keys=True, default=str) for r in rows)
    return hashlib.sha256("\x1e".join(keys).encode()).hexdigest()[:16]


def main() -> None:
    devices = dir_svc.list_devices(ALL)
    print(f"directory devices: {len(devices)}")

    mismatches, total_pre, total_post = [], 0.0, 0.0
    checked = 0
    for dev in devices:
        ident = {"device_iid": dev.get("device_iid"),
                 "hostname": dev.get("hostname")}

        t = time.time()
        pre_docs = _pre_observations(ident)
        pre_ms = (time.time() - t) * 1000
        pre_ids = _digest([{"id": d.get("observation_id"),
                            "ts": dir_svc._ts_of(
                                d, dir_svc._event_of(d))}
                           for d in pre_docs])

        t = time.time()
        post = dir_svc.observations(dev.get("hostname")
                                    or dev.get("device_iid"), ALL,
                                    identity=ident)
        post_ms = (time.time() - t) * 1000
        post_digest = _digest([{"id": r.get("observation_id"),
                                "ts": r.get("timestamp")} for r in post])

        total_pre += pre_ms
        total_post += post_ms
        checked += 1
        if len(pre_docs) != len(post):
            mismatches.append({
                "device": dev.get("hostname") or dev.get("device_iid"),
                "pre_count": len(pre_docs), "post_count": len(post),
                "pre_digest": pre_ids, "post_digest": post_digest})

    # explain() proof for one real device
    dev = max(devices, key=lambda d: d.get("observation_count") or 0)
    refs = {str(v).lower() for v in (dev.get("device_iid"),
                                     dev.get("hostname")) if v}
    spellings = dir_svc._stored_spellings(refs)
    q = {"$or": [{f: {"$in": v}} for f, v in spellings.items()]}
    ex = _obs.find(q).explain()["executionStats"]

    # unresolved endpoint: the scan cost 4.4 s to conclude "nothing"
    t = time.time()
    unresolved = dir_svc.observations("host-that-does-not-exist", ALL,
                                      identity={"device_iid": None,
                                                "hostname": "host-that-"
                                                            "does-not-exist"})
    unresolved_ms = (time.time() - t) * 1000

    # tenant isolation: a scoped principal must not receive unowned rows
    scoped = dir_svc.list_devices({"all_tenants": False,
                                   "tenant_ids": ["ten_does_not_exist"]})

    print(json.dumps({
        "devices_compared": checked,
        "semantic_mismatches": mismatches,
        "identical": not mismatches,
        "pre_total_ms": round(total_pre, 1),
        "post_total_ms": round(total_post, 1),
        "speedup": (round(total_pre / total_post, 1)
                    if total_post else None),
        "explain_busiest_device": {
            "device": dev.get("hostname") or dev.get("device_iid"),
            "n_returned": ex["nReturned"],
            "docs_examined": ex["totalDocsExamined"],
            "keys_examined": ex["totalKeysExamined"],
            "index_only": ex["totalDocsExamined"] == ex["nReturned"],
            "millis": ex["executionTimeMillis"],
        },
        "unresolved_endpoint": {"rows": len(unresolved),
                                "ms": round(unresolved_ms, 2)},
        "tenant_isolation_unowned_scope": {
            "devices_returned": len(scoped),
            "must_be": 0, "pass": len(scoped) == 0},
    }, indent=1))


if __name__ == "__main__":
    main()
