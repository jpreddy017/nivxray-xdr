"""E3 PREVIEW-ONLY (E1: STRIP). Activity Details artifact enrichment over the E1-shaped page.
- e3_doc: fields E1's normalizer already holds on the observation doc but E1's projection drops (DERIVABLE in E1).
- SYNTHETIC fixtures (labelled): detection rule metadata + MITRE, TI fixture provider, dispositions with a
  retrospective change, enforcement outcomes. Nothing here is production evidence."""
from __future__ import annotations

from typing import Any

from . import prodshape as ps

TI_LABEL = "synthetic TI fixture"
ENF_LABEL = "synthetic enforcement fixture"
RAW_KEEP = ("process_image_hashes", "process_image_hash_state", "current_directory", "integrity_level", "parent_command_line",
            "parent_image_path", "process_start_time", "original_file_name", "dns", "dns_answer", "registry_key", "registry_value",
            "logon_type", "sid", "field_provenance", "source_identity")
RULES = {
    "E3-SEQ-OFFICE-SCRIPT-PS": {"engine": "Behavioral Protection", "engine_component": "edr_behavior", "rule_id": "BHV-OFFICE-CHAIN-001",
                                "rule_version": "1.3.0", "confidence": 0.86,
                                "mitre": [{"tactic": "Initial Access", "technique": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
                                          {"tactic": "Execution", "technique": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell"},
                                          {"tactic": "Command and Control", "technique": "T1105", "name": "Ingress Tool Transfer"}],
                                "mitre_source": "rule metadata (edr_behavior BHV-OFFICE-CHAIN-001)"},
    "EICAR-Test-Signature": {"engine": "File Reputation", "engine_component": "TI adapter (synthetic TI fixture)", "rule_id": "SIG-EICAR",
                             "rule_version": "2026.09.1", "confidence": 1.0, "mitre": [], "mitre_source": "rule metadata (no technique mapped)"},
}


async def seed(db, docs: list[dict[str, Any]], ref: int, dets: list[dict[str, Any]]) -> None:
    def find(pred):
        return next((d["observation_id"] for d in docs if pred(d["event"])), None)
    raw = lambda e: e.get("raw") or {}
    by_name = {d["name"]: d for d in dets}
    for d in dets:
        d.update(RULES.get(d["name"], {}))
    psh = by_name.get("E3-SEQ-OFFICE-SCRIPT-PS")
    if psh:
        keys = ("WINWORD.EXE", "wscript.exe", "-enc", "cdn-update-check.example", "upd.exe")
        chain = [d["observation_id"] for d in docs if any(k.lower() in " ".join(str(raw(d["event"]).get(f) or "") for f in
                 ("image_path", "command_line", "target")).lower() for k in keys)][:10]
        psh["evidence_refs"] = chain or [psh["observation_id"]]
    upd_file = find(lambda e: e["kind"] == "file_create" and raw(e).get("target", "").endswith("upd.exe"))
    eicar = by_name.get("EICAR-Test-Signature", {}).get("observation_id")
    ti = [{"type": "domain", "value": "cdn-update-check.example", "matched_field": "dns.query_name / network.dst_host", "status": "MATCH",
           "verdict": "MALICIOUS", "first_seen": ps._iso(ref - 9 * ps.D), "last_seen": ps._iso(ref - 2 * ps.H)},
          {"type": "ipv4", "value": "203.0.113.50", "matched_field": "network.dst_ip", "status": "MATCH", "verdict": "SUSPICIOUS",
           "first_seen": ps._iso(ref - 30 * ps.D), "last_seen": ps._iso(ref - ps.D)},
          {"type": "sha256", "value": ps.H_UPD, "matched_field": "process.hashes.sha256", "status": "MATCH", "verdict": "MALICIOUS",
           "first_seen": ps._iso(ref - 20 * ps.M), "last_seen": ps._iso(ref - 5 * ps.M)},
          {"type": "ipv4", "value": "198.51.100.23", "matched_field": "network.dst_ip", "status": "RATE_LIMITED", "verdict": None,
           "first_seen": None, "last_seen": None}]
    for t in ti:
        t.update({"source": TI_LABEL, "provenance": {"provider": TI_LABEL, "feed": "e3-fixture-feed", "synthetic": True}})
    disp = [{"sha256": ps.H_UPD, "state": "MALICIOUS", "source": TI_LABEL, "at": ps._iso(ref - 5 * ps.M),
             "provenance": {"provider": TI_LABEL, "basis": "TI fixture MATCH sha256", "synthetic": True},
             "history": [{"from": None, "to": "UNKNOWN", "at": ps._iso(ref - 50 * ps.M + 7 * ps.M), "source": TI_LABEL, "note": "first lookup: NO_HIT"},
                         {"from": "UNKNOWN", "to": "MALICIOUS", "at": ps._iso(ref - 5 * ps.M), "source": TI_LABEL,
                          "note": "retrospective change; the original observation is unchanged"}]}]
    enf = [d for d in [
        eicar and {"observation_id": eicar, "action": "QUARANTINE", "outcome": "QUARANTINED", "at": ps._iso(ref - 3 * ps.H + 6000),
                   "source": ENF_LABEL, "detail": "moved to quarantine store", "synthetic": True},
        upd_file and {"observation_id": upd_file, "action": "QUARANTINE", "outcome": "QUARANTINE_FAILED", "at": ps._iso(ref - 4 * ps.M),
                      "source": ENF_LABEL, "detail": "file in use by a running process (sharing violation)", "synthetic": True}] if d]
    for c, rows in (("e3_dt_ti", ti), ("e3_dt_dispositions", disp), ("e3_dt_enforcement", enf)):
        await db[c].delete_many({})
        if rows:
            await db[c].insert_many([dict(x) for x in rows])


async def enrich(db, events: list[dict[str, Any]], extra_obs: list[str]) -> dict[str, Any]:
    obs = [e.get("observation_id") for e in events]
    docs = {d["observation_id"]: d async for d in db["v2_shadow_observations"].find(
        {"observation_id": {"$in": obs + extra_obs}}, {"_id": 0, "observation_id": 1, "ingest_time": 1, "event.raw": 1, "event.artefacts": 1})}
    ti = [t async for t in db["e3_dt_ti"].find({}, {"_id": 0})]
    disp = {d["sha256"]: d async for d in db["e3_dt_dispositions"].find({}, {"_id": 0})}
    enf = {d["observation_id"]: d async for d in db["e3_dt_enforcement"].find({}, {"_id": 0})}
    for e in events:
        d = docs.get(e.get("observation_id")) or {}
        rw = (d.get("event") or {}).get("raw") or {}
        e["e3_ingested_at"] = d.get("ingest_time")
        e["e3_doc"] = {"basis": "E1 observation doc (normalizer) — not carried by E1's trajectory projection today",
                       "raw": {k: rw.get(k) for k in RAW_KEEP if rw.get(k) not in (None, "", {}, [])},
                       "artefacts": (d.get("event") or {}).get("artefacts") or {}}
        sha = (rw.get("process_image_hashes") or {}).get("sha256")
        net = ((e["e3_doc"]["artefacts"].get("network") or [{}])[0])
        vals = {sha, e.get("file_sha256"), net.get("dst_ip"), net.get("dns"), (rw.get("dns") or {}).get("query_name"), e.get("file")} - {None, ""}
        hits = [t for t in ti if t["value"] in vals]
        if hits:
            e["e3_ti"] = hits
        if sha and sha in disp:
            e["e3_disposition"] = disp[sha]
            if disp[sha]["state"] == "MALICIOUS":
                e["e3_assessment"] = {"state": "MALICIOUS", "evidence": [disp[sha]["provenance"]], "source": TI_LABEL}
        if e.get("observation_id") in enf:
            e["e3_enforcement"] = enf[e["observation_id"]]
    return docs


async def file_facts(db, sha256: str | None, path: str | None) -> dict[str, Any]:
    q = [c for c in ([{"event.raw.process_image_hashes.sha256": sha256}, {"event.artefacts.file.sha256": sha256}] if sha256 else [])
         + ([{"event.raw.image_path": path}, {"event.raw.target": path}] if path else [])]
    if not q:
        return {"state": "NO_KEY"}
    first = await db["v2_shadow_observations"].find_one({"$or": q}, {"_id": 0, "observation_id": 1, "event.ts": 1}, sort=[("event.ts", 1)])
    devs = {ps.ENDPOINT} if first else set()
    if sha256:
        rows = await db["e3_kushu_events"].aggregate([{"$match": {"event.file_sha256": sha256}}, {"$group": {"_id": "$device"}}]).to_list(None)
        devs |= {r["_id"] for r in rows if r["_id"]}
    return {"first_seen_on_device": first and first["event"]["ts"], "first_observation_id": first and first["observation_id"],
            "prevalence_devices": len(devs), "basis": "in retained evidence (preview DB: synthetic device + imports)"}
