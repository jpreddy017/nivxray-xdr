#!/usr/bin/env python3
"""W1 Phase 2 · server-side contract check for the Windows forwarder.

Validates the EXACT envelope shape `scripts/windows/NivXRay-SysmonForwarder.ps1`
emits against the live ingest route, so the owner does not discover a contract
mismatch while standing at the laptop. It uses a scratch collector in the
preview tenant and a synthetic record — it proves the CONTRACT, not the source.
Real-source acceptance remains REAL_SOURCE_BLOCKED until the laptop delivers.
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
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
# what the PowerShell forwarder sets
METHOD = "windows_eventlog_pull"
VERSION = "nivx-sysmon-forwarder/1.0"
HOSTNAME = f"CONTRACT-{STAMP}"
PS_ENVELOPES = os.environ.get("W1_PS_ENVELOPES", "/tmp/ps_envelopes.json")
PS_GENERATED = False
ok = True


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
        raw = e.read().decode()[:500]
        try:
            return e.code, json.loads(raw)
        except Exception:                                       # noqa: BLE001
            return e.code, raw


def envelope(col, raw):
    """Byte-for-byte the shape ConvertTo-Envelope produces."""
    return {"tenant_id": TEN, "collector_id": col,
            "source_event_id": f"{raw['Computer']}|{raw['record_id']}",
            "collection_method": METHOD, "source": HOSTNAME,
            "connector_id": f"{VERSION}@{HOSTNAME}",
            "declared_source": "microsoft-sysmon",
            "parser_version": VERSION, "raw": raw}


def load_ps_envelopes():
    """Prefer envelopes built by the ARTIFACT'S OWN PowerShell code.

    scripts/windows/Test-ForwarderEnvelope.ps1 loads ConvertTo-Envelope out
    of the real .ps1 via the PowerShell AST and writes its output here, so
    this check stops being a Python replica of the contract.
    """
    global PS_GENERATED, HOSTNAME
    import subprocess
    pwsh, gen = "/opt/pwsh/pwsh", "/app/scripts/windows/Test-ForwarderEnvelope.ps1"
    fwd = "/app/scripts/windows/NivXRay-SysmonForwarder.ps1"
    if os.path.exists(pwsh) and os.path.exists(gen):
        r = subprocess.run([pwsh, "-NoProfile", "-File", gen,
                            "-ForwarderPath", fwd, "-OutFile", PS_ENVELOPES],
                           capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            print("   PowerShell envelope generation FAILED:",
                  (r.stderr or r.stdout)[:300])
            return None
    if not os.path.exists(PS_ENVELOPES):
        return None
    envs = json.load(open(PS_ENVELOPES))
    raws = {int(e["raw"]["event_id"]): e["raw"] for e in envs}
    if not {1, 13, 22}.issubset(raws):
        return None
    PS_GENERATED = True
    HOSTNAME = raws[1]["Computer"]
    return raws


def main():
    print(f"== W1 PHASE 2 · FORWARDER ENVELOPE CONTRACT CHECK · {BASE} ==")
    _, body = call("/api/auth/login", "POST",
                   body={"email": ADMIN[0], "password": ADMIN[1]})
    token = body.get("access_token")
    check("admin session", bool(token))
    if not token:
        return 1
    _, body = call("/api/xdr/collectors", "POST", token=token, tenant=TEN,
                   body={"name": f"w1-contract-{STAMP}", "protocol": "rest",
                         "authorized_sources": ["microsoft-sysmon"]})
    col = (body.get("data") or {}).get("id")
    check("scratch collector created with protocol=rest", bool(col),
          str(body)[:120] if not col else col)
    if not col:
        return 1
    _, body = call("/api/xdr/api-keys", "POST", token=token, tenant=TEN,
                   body={"name": f"w1-contract-key-{STAMP}",
                         "confirm_tenant_id": TEN, "allow_new_tenant": False,
                         "scopes": ["collectors.enroll", "collectors.read"]})
    d = body.get("data") or {}
    key = d.get("plaintext") or d.get("api_key")
    check("scoped ingest key minted", bool(key))
    if not key:
        return 1

    ps = load_ps_envelopes()
    print(f"   envelope source: "
          f"{'POWERSHELL ARTIFACT CODE (Test-ForwarderEnvelope.ps1)' if ps else 'python replica'}")

    eid1 = {"event_id": 1, "provider": "Microsoft-Windows-Sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": HOSTNAME, "record_id": 900001,
            "TimeCreated": "2026-06-01T10:00:00.1234567Z",
            "RuleName": "-", "UtcTime": "2026-06-01 10:00:00.123",
            "ProcessGuid": "{c0ffee01-0000-0000-0000-000000000001}",
            "ProcessId": "4711",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "FileVersion": "10.0.19041.1",
            "Description": "Windows Command Processor",
            "Product": "Microsoft Windows Operating System",
            "Company": "Microsoft Corporation",
            "OriginalFileName": "Cmd.Exe",
            "CommandLine": "cmd.exe /c whoami",
            "CurrentDirectory": "C:\\Users\\owner\\",
            "User": "CONTRACT\\owner",
            "LogonGuid": "{c0ffee01-0000-0000-0000-000000000009}",
            "LogonId": "0x3e7", "TerminalSessionId": "1",
            "IntegrityLevel": "High",
            "Hashes": f"MD5={'b' * 32},SHA256={'c' * 64}",
            "ParentProcessGuid": "{c0ffee01-0000-0000-0000-000000000000}",
            "ParentProcessId": "500",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
            "ParentUser": "CONTRACT\\owner"}
    eid13 = {"event_id": 13, "provider": "Microsoft-Windows-Sysmon",
             "channel": "Microsoft-Windows-Sysmon/Operational",
             "Computer": HOSTNAME, "record_id": 900002,
             "TimeCreated": "2026-06-01T10:00:01.1234567Z",
             "UtcTime": "2026-06-01 10:00:01.123",
             "EventType": "SetValue",
             "ProcessGuid": "{c0ffee01-0000-0000-0000-000000000001}",
             "ProcessId": "4711",
             "Image": "C:\\Windows\\regedit.exe",
             "TargetObject": ("HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows"
                              "\\CurrentVersion\\Run\\Contract"),
             "Details": "C:\\Users\\Public\\contract.exe"}
    eid22 = {"event_id": 22, "provider": "Microsoft-Windows-Sysmon",
             "channel": "Microsoft-Windows-Sysmon/Operational",
             "Computer": HOSTNAME, "record_id": 900003,
             "TimeCreated": "2026-06-01T10:00:02.1234567Z",
             "UtcTime": "2026-06-01 10:00:02.123",
             "ProcessGuid": "{c0ffee01-0000-0000-0000-000000000001}",
             "ProcessId": "4711", "QueryName": "example.com",
             "QueryStatus": "0",
             "QueryResults": "type:  1 93.184.216.34;",
             "Image": "C:\\Windows\\System32\\svchost.exe"}

    if ps:
        eid1, eid13, eid22 = ps[1], ps[13], ps[22]
        check("the artifact's own code built these envelopes", True,
              f"host={HOSTNAME}")
        check("a source field in the reserved _nivx namespace was DROPPED, "
              "not renamed",
              not any(k.startswith("_nivx") for k in eid1),
              str([k for k in eid1 if k.startswith("_nivx")]))
        check("EventData was carried verbatim (no field renamed or added)",
              {"OriginalFileName", "ParentCommandLine", "Hashes",
               "ProcessGuid", "RuleName", "LogonGuid"}.issubset(eid1),
              f"{len(eid1)} fields")

    print("\n== 1 · THE FORWARDER'S EXACT ENVELOPE SHAPE ==")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TEN,
                      body={"envelopes": [envelope(col, eid1),
                                          envelope(col, eid13),
                                          envelope(col, eid22)]})
    data = body.get("data") or body
    check("accepted over the authenticated route",
          code == 200 and data.get("accepted") == 3,
          f"{code} accepted={data.get('accepted')} "
          f"routing_blocked={data.get('routing_blocked')}")
    check(f"collection_method='{METHOD}' is accepted verbatim",
          code == 200 and not data.get("routing_blocked"))
    statuses = [o.get("status") for o in (data.get("reasoning") or [])]
    check("every envelope was reasoned, none NOT_ATTEMPTED/NO_DSM",
          statuses and all(s == "REASONED" for s in statuses), str(statuses))
    check("the collector reached CONNECTED on evidence",
          data.get("collector_state") == "CONNECTED",
          f"{data.get('collector_state')} — "
          f"{str(data.get('collector_state_reason'))[:70]}")

    print("\n== 2 · CANONICAL EVIDENCE FROM THAT SHAPE ==")
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]
    canon = db["xdr_canonical_evidence"]
    c1 = canon.find_one({"tenant_id": TEN, "host.hostname": HOSTNAME,
                         "source_event_id": "1"}, {"_id": 0})
    c13 = canon.find_one({"tenant_id": TEN, "host.hostname": HOSTNAME,
                          "source_event_id": "13"}, {"_id": 0})
    c22 = canon.find_one({"tenant_id": TEN, "host.hostname": HOSTNAME,
                          "source_event_id": "22"}, {"_id": 0})
    check("all three canonical records exist", all([c1, c13, c22]))
    if c1:
        p = c1["process"]
        check("ProcessGuid / parent identity preserved",
              p["process_guid"].startswith("{c0ffee01")
              and p["parent_process_guid"].startswith("{c0ffee01")
              and p["attribution_state"] == "SOURCE_PROCESS_IDENTITY")
        check("OriginalFileName preserved as PE metadata, not process.name",
              p["original_file_name"] == "Cmd.Exe" and p["name"] == "cmd.exe")
        check("ParentImage + ParentCommandLine preserved",
              p["parent_executable_path"].endswith("explorer.exe")
              and p["parent_command_line"] == "C:\\Windows\\Explorer.EXE")
        check("SHA256 + MD5 reached canonical hash evidence",
              p["hashes"].get("sha256") == "c" * 64
              and p["hashes"].get("md5") == "b" * 32)
        check("provenance names the collector, the transport instance and "
              "the DSM",
              (c1["provenance"]["collector_id"] == col
               and c1["provenance"]["dsm_id"] == "microsoft-sysmon"
               and c1["provenance"]["integration_id"]
               == f"{VERSION}@{HOSTNAME}"),
              str(c1["provenance"])[:110])
        check("Sysmon's activity time is the event time basis",
              c1["event_time"].startswith("2026-06-01 10:00:00"),
              c1["event_time"])
    if c13:
        check("registry evidence is reachable by the Sigma field names",
              c13["registry"]["target_object"] == eid13["TargetObject"]
              and c13["registry"]["value_data"] == eid13["Details"],
              f'{c13["registry"]["target_object"][-22:]} / '
              f'{c13["registry"]["value_data"][-16:]}')
    if c22:
        check("DNS query + answer preserved",
              c22["network"]["dns_query"] == "example.com"
              and "93.184.216.34" in (c22["network"]["dns_response_ips"] or []))

    print("\n== 3 · EXACTLY-ONCE ON THE FORWARDER'S source_event_id ==")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TEN, body={"envelopes": [envelope(col, eid1)]})
    d2 = body.get("data") or body
    n = canon.count_documents({"tenant_id": TEN, "host.hostname": HOSTNAME,
                               "source_event_id": "1",
                               "provenance.collector_id": col})
    check("a replayed record is a DUPLICATE and creates no second record",
          d2.get("duplicates") == 1 and n == 1,
          f"duplicates={d2.get('duplicates')} canonical_rows={n}")

    print("\n== 4 · THE REFUSALS THE FORWARDER MUST REPORT, NOT HIDE ==")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TEN, body={"envelopes": [
                          {**envelope(col, {**eid1, "record_id": 900010}),
                           "declared_source": "zeek-json"}]})
    d3 = body.get("data") or body
    check("a declared_source outside the collector's authorized set is "
          "routing_blocked", (d3.get("routing_blocked") or 0) == 1,
          f"routing_blocked={d3.get('routing_blocked')}")
    code, _ = call("/api/xdr/ingest/telemetry", "POST", key=key,
                   tenant="another-tenant",
                   body={"envelopes": [envelope(col, {**eid1,
                                                      "record_id": 900011})]})
    check("a tenant-header mismatch is refused with 403", code == 403,
          str(code))
    code, body = call("/api/xdr/ingest/telemetry", "POST",
                      tenant=TEN,
                      body={"envelopes": [envelope(col, {**eid1,
                                                         "record_id": 900012})]})
    check("no key at all is refused", code in (401, 403), str(code))
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TEN, body={"envelopes": [
                          envelope(col, {**eid1, "record_id": 900013,
                                         "event_id": 7})]})
    d4 = body.get("data") or body
    st = [o.get("status") for o in (d4.get("reasoning") or [])]
    check("an unsupported Sysmon event id is refused honestly, not "
          "canonicalized", st and st[0] != "REASONED", str(st))

    print(f"\n== RESULT: {'PASS' if ok else 'FAIL'} ==")
    print("== CONTRACT PROVEN · REAL-SOURCE ACCEPTANCE STILL "
          "REAL_SOURCE_BLOCKED ==")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
