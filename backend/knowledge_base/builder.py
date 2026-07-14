"""KB builder — orchestrates fingerprint → cluster → synthesise → upsert.

Idempotent: calling `rebuild_for_user` twice will refresh KB entries in place
rather than duplicating them.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from deps import db
from knowledge_base.schema import KBEntry, KBIocRollup, KBSampleRef
from knowledge_base.fingerprint import (
    compute_fingerprint, top_mitre_ids, verdict_bucket, slug_for,
)
from knowledge_base.synthesizer import synthesize


_MIN_BUCKET_SIZE = 1   # a single investigation still becomes a lonely archetype

# Known LOLBin process names — used for aggregation only, no hallucination risk
_LOLBIN_HINTS = {
    "certutil.exe","bitsadmin.exe","mshta.exe","rundll32.exe","regsvr32.exe",
    "msbuild.exe","installutil.exe","cmstp.exe","wmic.exe","msiexec.exe",
    "wscript.exe","cscript.exe","csc.exe","regasm.exe","regasm","schtasks.exe",
}


def _aggregate_bucket(bucket: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pure deterministic aggregation over a bucket of investigations."""
    engines: Counter = Counter()
    chains: Counter = Counter()
    urls: Counter = Counter()
    ips: Counter = Counter()
    domains: Counter = Counter()
    hashes: Counter = Counter()
    files: Counter = Counter()
    mitre_all: Counter = Counter()
    tactics_all: Counter = Counter()
    lolbins: Counter = Counter()
    verdicts: Counter = Counter()

    for inv in bucket:
        engines[inv.get("engine") or "unknown"] += 1
        chain_key = " → ".join(inv.get("chain") or []) or "(no-op)"
        chains[chain_key] += 1
        iocs = inv.get("iocs") or {}
        for u in iocs.get("urls", []) or []:  urls[str(u)] += 1
        for u in iocs.get("ips", []) or []:   ips[str(u)] += 1
        for u in iocs.get("domains", []) or []: domains[str(u)] += 1
        for k in ("md5", "sha1", "sha256"):
            for h in iocs.get(k, []) or []: hashes[str(h)] += 1
        for f in iocs.get("files", []) or []: files[str(f)] += 1
        for m in (inv.get("mitre") or []):
            if m.get("id"):     mitre_all[m["id"]] += 1
            if m.get("tactic"): tactics_all[m["tactic"]] += 1
        v = (inv.get("verdict") or {}).get("verdict")
        if v: verdicts[v] += 1
        # LOLBin heuristic — scan input+output for known LOLBin exe names
        blob = ((inv.get("input_preview") or "") + " " +
                (inv.get("output_preview") or "")).lower()
        for lb in _LOLBIN_HINTS:
            if lb in blob:
                lolbins[lb] += 1

    return {
        "engines": dict(engines),
        "common_chains": [k for k, _ in chains.most_common(5)],
        "iocs": {
            "urls":    dict(urls.most_common(10)),
            "ips":     dict(ips.most_common(10)),
            "domains": dict(domains.most_common(10)),
            "hashes":  dict(hashes.most_common(10)),
            "files":   dict(files.most_common(10)),
        },
        "mitre_ids": [k for k, _ in mitre_all.most_common(10)],
        "tactics":   [k for k, _ in tactics_all.most_common(10)],
        "lolbins":   [k for k, _ in lolbins.most_common(6)],
        "verdict":   verdicts.most_common(1)[0][0] if verdicts else "unknown",
    }


def _samples_of(bucket: List[Dict[str, Any]], k: int = 5) -> List[KBSampleRef]:
    # Newest first, cap at k
    bs = sorted(bucket, key=lambda x: x.get("ts") or "", reverse=True)[:k]
    out: List[KBSampleRef] = []
    for inv in bs:
        ts = inv.get("ts")
        if hasattr(ts, "isoformat"):
            ts_s = ts.isoformat()
        else:
            ts_s = str(ts) if ts else None
        out.append(KBSampleRef(
            investigation_id=str(inv.get("_id") or inv.get("id") or ""),
            input_preview=(inv.get("input_preview") or "")[:200],
            engine=inv.get("engine"),
            confidence=int(inv.get("confidence") or 0),
            verdict=(inv.get("verdict") or {}).get("verdict"),
            ts=ts_s,
        ))
    return out


async def _load_user_history(user_email: str, limit: int = 500) -> List[Dict[str, Any]]:
    cur = db.investigations.find({"user_email": user_email}).sort("ts", -1).limit(limit)
    return [d async for d in cur]


def _bucketize(invs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for inv in invs:
        fp = compute_fingerprint(inv)
        buckets[fp].append(inv)
    return buckets


async def _persist(entry: KBEntry) -> str:
    """Upsert one KB entry by (user_email, fingerprint). Returns the mongo id str."""
    payload = entry.model_dump()
    q = {"user_email": entry.user_email, "fingerprint": entry.fingerprint}
    now_iso = datetime.now(timezone.utc).isoformat()
    payload["refreshed_at"] = now_iso
    payload["last_seen"] = now_iso
    payload["iocs"] = entry.iocs.model_dump()
    payload["samples"] = [s.model_dump() for s in entry.samples]
    # Preserve first_seen if it already exists
    existing = await db.kb_entries.find_one(q, {"first_seen": 1})
    if existing and existing.get("first_seen"):
        payload["first_seen"] = existing["first_seen"]
    r = await db.kb_entries.update_one(q, {"$set": payload}, upsert=True)
    if r.upserted_id:
        return str(r.upserted_id)
    doc = await db.kb_entries.find_one(q, {"_id": 1})
    return str(doc["_id"]) if doc else ""


async def rebuild_for_user(user_email: str, limit: int = 500,
                            synth: bool = True) -> Dict[str, Any]:
    """Rebuild the KB for one user. Returns summary counts.

    `synth=False` skips the LLM synthesis step (faster; deterministic fallback used).
    """
    invs = await _load_user_history(user_email, limit=limit)
    if not invs:
        return {"buckets": 0, "entries": 0, "message": "no investigations to cluster"}

    buckets = _bucketize(invs)
    entries_written = 0
    per_bucket_warnings: List[str] = []

    for fp, bucket in buckets.items():
        if len(bucket) < _MIN_BUCKET_SIZE:
            continue
        agg = _aggregate_bucket(bucket)

        # LLM synth (or fallback)
        if synth:
            synth_data, warns = await synthesize(bucket)
        else:
            from knowledge_base.synthesizer import _deterministic_fallback
            synth_data, warns = _deterministic_fallback(bucket), ["synth disabled"]

        if warns:
            per_bucket_warnings.append(f"{fp}: {'; '.join(warns[:3])}")

        first_inv = bucket[0]
        entry = KBEntry(
            slug=slug_for(first_inv, fp),
            fingerprint=fp,
            title=synth_data.get("title", ""),
            summary=synth_data.get("summary", ""),
            severity=synth_data.get("severity", "medium"),
            verdict=agg["verdict"],
            mitre_ids=agg["mitre_ids"],
            tactics=agg["tactics"],
            engines=agg["engines"],
            common_chains=agg["common_chains"],
            iocs=KBIocRollup(**agg["iocs"]),
            lolbins=agg["lolbins"],
            samples=_samples_of(bucket, k=5),
            investigation_ids=[str(i.get("_id") or i.get("id") or "") for i in bucket],
            investigation_count=len(bucket),
            playbook_steps=synth_data.get("playbook_steps", []),
            hunt_queries=synth_data.get("hunt_queries", []),
            evidence_refs=synth_data.get("evidence_refs", []),
            warnings=warns,
            user_email=user_email,
        )
        await _persist(entry)
        entries_written += 1

    return {
        "buckets": len(buckets),
        "entries": entries_written,
        "investigations_scanned": len(invs),
        "warnings": per_bucket_warnings[:10],
    }
