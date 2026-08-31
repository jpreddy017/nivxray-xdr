"""
Admin Aggregations router — Phase A.2 · Platform Overview.

Three thin READ-ONLY aggregations over collections that already
exist. No engine is invoked; no data is fabricated.

  * GET /api/admin/ioc/composition
      → { total, items: [{ key, label, count, pct }] }
      Groups the `iocs` collection by canonical type
      (hash / ip / domain / url / other).

  * GET /api/admin/data-sources/summary
      → { total, adopted, enabled, connected, groups: [ … ] }
      Rolls up `xdr_data_sources` per `kind` with adoption /
      enablement / connectivity counts.  A source is only
      `connected` when it has received real telemetry
      (`events_received > 0`) — matches the SSOT rule that we
      never mark a source CONNECTED optimistically.

  * GET /api/admin/detection/summary
      → { total, active, disabled, categories: [ … ] }
      Rolls up `xdr_detection_rules` per category (content /
      network / endpoint / correlation / ioc / technique).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from deps import db, require_admin


router = APIRouter(prefix="/admin", tags=["admin-aggregations"])


# ── IOC composition ────────────────────────────────────────────────
_IOC_TYPE_MAP = {
    "sha256": "hash", "sha1": "hash", "md5": "hash",
    "ip":     "ip",
    "domain": "domain", "fqdn": "domain",
    "url":    "url",
}
_IOC_LABEL = {
    "hash":   "Hash",
    "ip":     "IP Address",
    "domain": "Domain",
    "url":    "URL",
    "other":  "Other",
}
_IOC_ORDER = ["hash", "domain", "ip", "url", "other"]


@router.get("/ioc/composition")
async def ioc_composition(user=Depends(require_admin)):
    pipeline = [{"$group": {"_id": "$kind", "n": {"$sum": 1}}}]
    cur = db.iocs.aggregate(pipeline)
    buckets: dict[str, int] = {k: 0 for k in _IOC_ORDER}
    async for row in cur:
        raw = (row.get("_id") or "").lower()
        buckets[_IOC_TYPE_MAP.get(raw, "other")] += int(row.get("n", 0))
    total = sum(buckets.values())
    items = [
        {
            "key":   k,
            "label": _IOC_LABEL[k],
            "count": buckets[k],
            "pct":   round((buckets[k] / total) * 100, 1) if total else 0.0,
        }
        for k in _IOC_ORDER
        if buckets[k] > 0
    ]
    return {"total": total, "items": items}


# ── Data-sources summary ───────────────────────────────────────────
@router.get("/data-sources/summary")
async def data_sources_summary(user=Depends(require_admin)):
    # xdr_data_sources uses the sync driver; still fine to read via
    # the shared async binding — motor exposes the same API.
    coll = db.xdr_data_sources
    rows: list[dict[str, Any]] = []
    async for d in coll.find({}, {"_id": 0}):
        rows.append(d)

    def _bucket(kind: str) -> tuple[str, str]:
        k = (kind or "").lower()
        if "syslog" in k:  return ("network", "Network")
        if "webhook" in k: return ("webhook", "Webhook / Integration")
        if "edr" in k:     return ("endpoint", "Endpoint")
        if "cloud" in k or "aws" in k or "gcp" in k or "azure" in k:
            return ("cloud", "Cloud")
        if "identity" in k or "idp" in k or "okta" in k:
            return ("identity", "Identity")
        if "ti" in k or "intel" in k:
            return ("threat_intel", "Threat Intelligence")
        return ("other", (kind or "Other").replace("_", " ").title())

    groups: dict[str, dict[str, Any]] = {}
    for d in rows:
        key, label = _bucket(d.get("kind", ""))
        g = groups.setdefault(key, {
            "key":       key,
            "label":     label,
            "configured": 0,
            "enabled":   0,
            "connected": 0,
            "last_telemetry_at": None,
        })
        g["configured"] += 1
        if d.get("enabled"):
            g["enabled"] += 1
        if int(d.get("events_received", 0)) > 0:
            g["connected"] += 1
        lt = d.get("last_telemetry_at")
        if lt and (g["last_telemetry_at"] is None or str(lt) > str(g["last_telemetry_at"])):
            g["last_telemetry_at"] = str(lt)

    ordered = sorted(groups.values(), key=lambda x: (-x["configured"], x["label"]))
    return {
        "total":       len(rows),
        "adopted":     sum(1 for d in rows if d.get("state") == "ADOPTED"),
        "enabled":     sum(1 for d in rows if d.get("enabled")),
        "connected":   sum(1 for d in rows if int(d.get("events_received", 0)) > 0),
        "groups":      ordered,
    }


# ── Detection content summary ──────────────────────────────────────
_DETECTION_CATEGORY_MAP = {
    "sigma": "content", "process_creation": "content",
    "parent_child": "content", "field_match": "content",
    "regex": "content", "registry": "content", "threshold": "content",
    "snort_signature": "network", "suricata_signature": "network",
    "yara": "endpoint",
    "correlation": "correlation",
    "ioc": "ioc",
    "attack_technique": "technique",
}
_CAT_LABEL = {
    "content":     "Content-Based",
    "network":     "Network-Based",
    "endpoint":    "Endpoint-Based",
    "correlation": "Correlation Rules",
    "ioc":         "IOC Rules",
    "technique":   "Technique Coverage",
    "other":       "Other",
}
_CAT_ORDER = ["content", "network", "endpoint", "correlation", "ioc", "technique", "other"]


@router.get("/detection/summary")
async def detection_summary(user=Depends(require_admin)):
    coll = db.xdr_detection_rules
    total = await coll.count_documents({})
    active = await coll.count_documents({"enabled": True})
    disabled = total - active

    pipe = [{
        "$group": {
            "_id":     "$rule_type",
            "total":   {"$sum": 1},
            "active":  {"$sum": {"$cond": [{"$eq": ["$enabled", True]}, 1, 0]}},
        },
    }]
    buckets: dict[str, dict[str, int]] = {k: {"total": 0, "active": 0} for k in _CAT_ORDER}
    async for row in coll.aggregate(pipe):
        raw = (row.get("_id") or "").lower()
        cat = _DETECTION_CATEGORY_MAP.get(raw, "other")
        buckets[cat]["total"]  += int(row.get("total", 0))
        buckets[cat]["active"] += int(row.get("active", 0))

    categories = []
    for k in _CAT_ORDER:
        b = buckets[k]
        if b["total"] == 0:
            continue
        categories.append({
            "key":      k,
            "label":    _CAT_LABEL[k],
            "total":    b["total"],
            "active":   b["active"],
            "disabled": b["total"] - b["active"],
        })
    return {
        "total":      total,
        "active":     active,
        "disabled":   disabled,
        "categories": categories,
    }
