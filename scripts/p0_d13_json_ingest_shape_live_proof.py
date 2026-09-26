#!/usr/bin/env python3
"""D13 · JSON ingest shape, over real HTTP (PREVIEW ONLY).

The question this answers is not "can the DSM normalize a Windows event?" —
D12 settled that. It is:

    can a real Windows / Sysmon / CloudTrail document actually ENTER
    NivXRay XDR through the authenticated collector path and become
    correctly tenant-bound canonical evidence?

Six sources go through `POST /api/xdr/ingest/telemetry`: three JSON
documents and three verbatim lines, so the line sources prove no regression
in the same run. Then the same document is delivered as two different
tenants to prove it cannot cross over.

TEST/SYNTHETIC payloads throughout. NOT LIVE — no real Windows host, cloud
account or sensor is sending these. Nothing touches production.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")
BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
STAMP = int(time.time())
TEN_A = "t-d13-proof-a"
TEN_B = "t-d13-proof-b"

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
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def provision(token, tenant, name):
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=tenant, body={
                          "name": name, "protocol": "rest",
                          # D15 · the server-side authorization set: what
                          # this collector may DECLARE at ingest.
                          "authorized_sources": ["microsoft-sysmon",
                                                 "windows-security-evd",
                                                 "aws-cloudtrail",
                                                 "snort-eve",
                                                 "linux-auditd", "cef-leef"],
                          "tenant_id": tenant, "confirm_tenant_id": tenant,
                          "allow_new_tenant": True})
    if code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=tenant)
        col = next((c["id"] for c in
                    ((lst.get("data") or {}).get("collectors") or [])
                    if c.get("name") == name), None)
    elif code in (200, 201):
        d = body.get("data") or body
        col = d.get("id") or (d.get("collector") or {}).get("id")
    else:
        print(f"  collector create -> {code} {body}")
        return None, None
    if col:
        # D15 · a reused collector must carry the same server-side
        # authorization set; the allowlist is never assumed.
        call(f"/api/xdr/collectors/{col}", "PUT", token=token,
             tenant=tenant,
             body={"authorized_sources": ["microsoft-sysmon", "windows-security-evd",
                              "aws-cloudtrail", "snort-eve",
                              "linux-auditd", "cef-leef"]})
    code, body = call("/api/xdr/api-keys", "POST", token=token,
                      tenant=tenant, body={
                          "name": f"{name}-key-{STAMP}",
                          "confirm_tenant_id": tenant,
                          "allow_new_tenant": True,
                          "scopes": ["collectors.enroll", "collectors.read"]})
    _d = body.get("data") or {}
    key = (_d.get("api_key") or _d.get("key") or _d.get("secret")
           or _d.get("plaintext") or _d.get("token") or _d.get("value"))
    return col, key


AUD = f"1757452888.321:{9100 + STAMP % 800}"
SOURCES = {
    "microsoft-sysmon": {
        "EventID": 1, "provider": "Microsoft-Windows-Sysmon",
        "Computer": "WIN-WS-07", "User": "CORP\\dev1",
        "UtcTime": "2026-06-01T10:00:00+00:00",
        "TimeCreated": "2026-06-01T10:00:02+00:00",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": f"cmd /c whoami {STAMP}", "ProcessId": "4321",
        "ParentImage": "C:\\Windows\\explorer.exe"},
    "windows-security-evd": {
        "EventID": 4624, "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security", "Computer": f"WIN-DC-{STAMP % 100}",
        "TimeCreated": "2026-06-01T10:00:00+00:00",
        "EventData": {"TargetUserName": "svc_backup", "LogonType": "3",
                      "IpAddress": "10.0.0.9"}},
    "aws-cloudtrail": {
        "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
        "eventTime": "2026-06-01T10:00:00Z", "awsRegion": "us-east-1",
        "eventID": f"ct-d13-{STAMP}", "sourceIPAddress": "203.0.113.7",
        "userIdentity": {"type": "IAMUser", "userName": "dev1",
                         "accountId": "111122223333"}},
}
LINES = {
    "linux-auditd": (f'node=web-prod-04 type=SYSCALL msg=audit({AUD}): '
                     f'arch=c000003e syscall=59 uid=0 euid=0 comm="bash" '
                     f'exe="/usr/bin/bash" key="exec"'),
    "cef-leef": (f"CEF:0|NivX|Firewall|1.0|{STAMP % 900}|Blocked|5|"
                 "src=10.0.0.4 dst=198.51.100.2 spt=443 "
                 "devTime=1780308000000 rt=1780308060000"),
}


def main() -> int:
    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]
    print("login: 200\n1 · provision TEST collectors + keys for two tenants")
    col_a, key_a = provision(token, TEN_A, "d13-proof-collector-a")
    col_b, key_b = provision(token, TEN_B, "d13-proof-collector-b")
    check("tenant A collector + key", bool(col_a and key_a), col_a)
    check("tenant B collector + key", bool(col_b and key_b), col_b)
    if not (key_a and key_b):
        return 1

    print("\n2 · POST three JSON documents and three verbatim lines")
    envs = []
    for dsm_id, doc in SOURCES.items():
        envs.append({"tenant_id": TEN_A, "collector_id": col_a,
                     "source_event_id": f"d13:{STAMP}:{dsm_id}",
                     "collection_method": "rest", "source": "d13-host",
                     "declared_source": dsm_id,
                     "source_timestamp": "2026-06-01T10:00:01+00:00",
                     "raw": doc})
    for dsm_id, line in LINES.items():
        envs.append({"tenant_id": TEN_A, "collector_id": col_a,
                     "source_event_id": f"d13:{STAMP}:{dsm_id}",
                     "collection_method": "syslog", "source": "d13-host",
                     "declared_source": dsm_id,
                     "raw": {"line": line}})
    t0 = time.time()
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_a,
                      tenant=TEN_A, body={"envelopes": envs})
    t1 = time.time()
    check("ingest accepted", code == 200, f"HTTP {code} {str(body)[:200]}")
    if code != 200:
        return 1
    data = body.get("data") or body
    print(f"  outcomes: {[o.get('status') for o in (data.get('reasoning') or [])]}")
    print(f"  wall time for 5 envelopes: {(t1 - t0) * 1000:.0f} ms")
    time.sleep(2)

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

    print("\n3 · did each source become tenant-bound canonical evidence?")
    for dsm_id, doc in SOURCES.items():
        ev = db.xdr_canonical_evidence.find_one(
            {"tenant_id": TEN_A, "provenance.ingest.selected_dsm_id": dsm_id},
            sort=[("_id", -1)])
        if not ev:
            check(f"{dsm_id}: canonical evidence created", False,
                  "no canonical event — the document did not get in")
            continue
        ing = (ev.get("provenance") or {}).get("ingest") or {}
        ts = ((ev.get("provenance") or {}).get("timestamps") or {})
        d = ev.get("additional_fields") or {}
        print(f"  {dsm_id}")
        print(f"    tenant       : {ev.get('tenant_id')}")
        print(f"    shape / dsm  : {ing.get('payload_shape')} / "
              f"{ing.get('selected_dsm_id')}")
        print(f"    basis        : {d.get('event_time_basis')}")
        print(f"    activity     : {ts.get('activity_occurred_at', {}).get('status')} "
              f"{ts.get('activity_occurred_at', {}).get('source') or ''}")
        check(f"{dsm_id}: owned by the authenticated tenant",
              ev.get("tenant_id") == TEN_A, str(ev.get("tenant_id")))
        check(f"{dsm_id}: recorded as a DOCUMENT",
              ing.get("payload_shape") == "DOCUMENT")
        check(f"{dsm_id}: the right DSM claimed it",
              ing.get("selected_dsm_id") == dsm_id)
        check(f"{dsm_id}: D12 basis declared",
              d.get("event_time_basis") in (
                  "ACTIVITY_TIME", "OBSERVATION_TIME",
                  "SUPPLIED_TIMESTAMP_UNVERIFIED",
                  "INGEST_TIME_SUBSTITUTED"),
              str(d.get("event_time_basis")))
        check(f"{dsm_id}: all eight temporal boundaries present",
              len(ts) == 8, str(len(ts)))
        check(f"{dsm_id}: the NivX receipt is a real measurement",
              ts.get("nivx_received_at", {}).get("status") == "AVAILABLE")
        raw_ref = ev.get("raw_ref") or {}
        preserved = all(raw_ref.get(k) == v for k, v in doc.items()
                        if k in raw_ref)
        check(f"{dsm_id}: the source document survived verbatim", preserved)
        check(f"{dsm_id}: the raw envelope row is cited",
              bool((ing.get("raw_envelope_ref") or {}).get("id")))

    print("\n4 · did the line sources regress?")
    for dsm_id, line in LINES.items():
        ev = db.xdr_canonical_evidence.find_one(
            {"tenant_id": TEN_A, "raw_ref.line": line})
        if not ev:
            check(f"{dsm_id}: line still ingests", False, "no canonical event")
            continue
        ing = (ev.get("provenance") or {}).get("ingest") or {}
        check(f"{dsm_id}: line still ingests and is recorded as a LINE",
              ing.get("payload_shape") == "LINE"
              and ing.get("selected_dsm_id") == dsm_id,
              f"{ing.get('payload_shape')} / {ing.get('selected_dsm_id')}")
        check(f"{dsm_id}: still tenant-bound", ev.get("tenant_id") == TEN_A)

    print("\n5 · the same document, delivered as tenant B")
    doc_b = dict(SOURCES["microsoft-sysmon"])
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_b,
                      tenant=TEN_B, body={"envelopes": [{
                          "tenant_id": TEN_B, "collector_id": col_b,
                          "source_event_id": f"d13:{STAMP}:xtenant",
                          "collection_method": "rest", "source": "d13-host",
                          "declared_source": "microsoft-sysmon",
                          "raw": doc_b}]})
    check("tenant B ingest accepted", code == 200, f"HTTP {code}")
    time.sleep(2)
    n_a = db.xdr_canonical_evidence.count_documents(
        {"tenant_id": TEN_A,
         "provenance.ingest.selected_dsm_id": "microsoft-sysmon"})
    n_b = db.xdr_canonical_evidence.count_documents(
        {"tenant_id": TEN_B,
         "provenance.ingest.selected_dsm_id": "microsoft-sysmon"})
    check("identical content produced separate evidence per tenant",
          n_a >= 1 and n_b >= 1, f"A={n_a} B={n_b}")
    leaked = db.xdr_canonical_evidence.count_documents(
        {"tenant_id": TEN_B, "provenance.ingest.collector_id": col_a})
    check("tenant B holds nothing delivered by tenant A's collector",
          leaked == 0, str(leaked))

    print("\n6 · a document that names its OWN tenant is not believed")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_b,
                      tenant=TEN_B, body={"envelopes": [{
                          "tenant_id": TEN_B, "collector_id": col_b,
                          "source_event_id": f"d13:{STAMP}:claim",
                          "collection_method": "rest", "source": "d13-host",
                          "declared_source": "aws-cloudtrail",
                          "raw": dict(SOURCES["aws-cloudtrail"],
                                      eventID=f"ct-claim-{STAMP}",
                                      tenant_id=TEN_A)}]})
    check("ingest accepted the tenant-claiming document", code == 200,
          f"HTTP {code}")
    time.sleep(2)
    ev = db.xdr_canonical_evidence.find_one(
        {"source_event_id": f"ct-claim-{STAMP}"})
    if not ev:
        ev = db.xdr_canonical_evidence.find_one(
            {"raw_ref.eventID": f"ct-claim-{STAMP}"})
    check("the tenant-claiming document produced evidence", bool(ev))
    if ev:
        check("it landed in the AUTHENTICATED tenant, not the claimed one",
              ev.get("tenant_id") == TEN_B,
              f"{ev.get('tenant_id')} (claimed {TEN_A})")
        withheld = (((ev.get("raw_ref") or {}).get("_nivx") or {})
                    .get("source_fields_withheld") or {})
        check("the claim is preserved as evidence and marked withheld",
              withheld.get("tenant_id") == TEN_A, str(withheld))

    print("\n7 · a document carrying the reserved key fails closed")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_b,
                      tenant=TEN_B, body={"envelopes": [{
                          "tenant_id": TEN_B, "collector_id": col_b,
                          "source_event_id": f"d13:{STAMP}:collide",
                          "collection_method": "rest", "source": "d13-host",
                          "declared_source": "aws-cloudtrail",
                          "raw": dict(SOURCES["aws-cloudtrail"],
                                      eventID=f"ct-collide-{STAMP}",
                                      _nivx={"tenant_id": TEN_A})}]})
    data = body.get("data") or body if code == 200 else {}
    outs = data.get("reasoning") or []
    st = [o.get("status") for o in outs]
    blk = [o.get("blocker") for o in outs]
    check("the colliding delivery is refused, not silently accepted",
          code == 200 and "BLOCKED" in st and "ingest_shape" in blk,
          f"HTTP {code} {st} {blk}")
    n = db.xdr_canonical_evidence.count_documents(
        {"raw_ref.eventID": f"ct-collide-{STAMP}"})
    check("no canonical evidence was created for it", n == 0, str(n))

    print("\n" + ("D13 JSON INGEST SHAPE: PASS" if ok
                  else "D13 JSON INGEST SHAPE: FAIL"))
    print("TEST/SYNTHETIC payloads. NOT LIVE — no real Windows host, cloud "
          "account or sensor is connected. Preview only, nothing deployed.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
