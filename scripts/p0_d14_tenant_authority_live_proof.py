#!/usr/bin/env python3
"""D14 · tenant authority, over real HTTP (PREVIEW ONLY).

The adversarial matrix, end to end:

    authenticated = B, payload tenant = A   ->  canonical tenant = B
    tenant A canonical evidence             ->  ZERO
    the A claim                             ->  recorded, used=False
    authenticated tenant missing            ->  refused, no evidence

Four sources are attacked: Windows Security, CloudTrail and Sysmon as JSON
documents, auditd and CEF as verbatim lines. Every delivery is signed with
tenant B's own key, so the only thing claiming A is the payload.

TEST/SYNTHETIC payloads. NOT LIVE — no real host, cloud account or sensor is
connected. Nothing touches production.
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
TEN_A = "t-d14-victim-a"
TEN_B = "t-d14-owner-b"
AUD = f"1757452888.444:{9300 + STAMP % 600}"

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


ATTACKS = {
    "windows-security-evd": {
        "EventID": 4624, "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security", "Computer": f"WIN-DC-{STAMP % 100}",
        "TimeCreated": "2026-06-01T10:00:00+00:00",
        "EventData": {"TargetUserName": f"svc_d14_{STAMP}",
                      "LogonType": "3", "IpAddress": "10.0.0.9"},
        "tenant_id": TEN_A},
    "aws-cloudtrail": {
        "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
        "eventTime": "2026-06-01T10:00:00Z", "awsRegion": "us-east-1",
        "eventID": f"ct-d14-{STAMP}", "sourceIPAddress": "203.0.113.7",
        "userIdentity": {"type": "IAMUser", "userName": "dev1",
                         "accountId": "111122223333"},
        "tenant_id": TEN_A},
    "microsoft-sysmon": {
        "EventID": 1, "provider": "Microsoft-Windows-Sysmon",
        "Computer": f"WIN-WS-{STAMP % 100}", "User": "CORP\\dev1",
        "UtcTime": "2026-06-01T10:00:00+00:00",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": f"cmd /c whoami {STAMP}", "ProcessId": "4321",
        "tenant_id": TEN_A},
}
LINE_ATTACKS = {
    "linux-auditd": (f'node=web-prod-04 type=SYSCALL msg=audit({AUD}): '
                     f'arch=c000003e syscall=59 uid=0 euid=0 comm="bash" '
                     f'exe="/usr/bin/bash" key="exec"'),
    "cef-leef": (f"CEF:0|NivX|Firewall|1.0|{STAMP % 800}|Blocked|5|"
                 "src=10.0.0.7 dst=198.51.100.8 devTime=1780308000000"),
}


def main() -> int:
    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]
    print("login: 200\n1 · provision tenant B (the attacker's OWN tenant)")
    col_b, key_b = provision(token, TEN_B, "d14-owner-collector-b")
    check("tenant B collector + key", bool(col_b and key_b), col_b)
    if not key_b:
        return 1

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    before_a = db.xdr_canonical_evidence.count_documents(
        {"tenant_id": TEN_A})
    print(f"  tenant A canonical evidence before the attack: {before_a}")

    print("\n2 · every payload claims tenant A; every delivery is signed B")
    envs = []
    for dsm_id, doc in ATTACKS.items():
        envs.append({"tenant_id": TEN_B, "collector_id": col_b,
                     "source_event_id": f"d14:{STAMP}:{dsm_id}",
                     "collection_method": "rest", "source": "d14-host",
                     "raw": doc})
    for dsm_id, line in LINE_ATTACKS.items():
        envs.append({"tenant_id": TEN_B, "collector_id": col_b,
                     "source_event_id": f"d14:{STAMP}:{dsm_id}",
                     "collection_method": "syslog", "source": "d14-host",
                     # the line shape's own raw dict claims A too
                     "raw": {"line": line, "tenant_id": TEN_A}})
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_b,
                      tenant=TEN_B, body={"envelopes": envs})
    check("ingest accepted", code == 200, f"HTTP {code} {str(body)[:200]}")
    if code != 200:
        return 1
    data = body.get("data") or body
    print(f"  outcomes: {[o.get('status') for o in (data.get('reasoning') or [])]}")
    time.sleep(2)

    print("\n3 · where did the evidence land?")
    for dsm_id in list(ATTACKS) + list(LINE_ATTACKS):
        ev = db.xdr_canonical_evidence.find_one(
            {"tenant_id": TEN_B,
             "provenance.ingest.selected_dsm_id": dsm_id,
             "provenance.ingest.collector_id": col_b},
            sort=[("_id", -1)])
        if not ev:
            check(f"{dsm_id}: evidence created", False, "no canonical event")
            continue
        claim = (ev.get("additional_fields") or {}).get("tenant_claim") or {}
        print(f"  {dsm_id}: tenant={ev.get('tenant_id')} "
              f"claim={claim.get('claimed_tenant_id')} "
              f"used={claim.get('used')} state={claim.get('state')}")
        check(f"{dsm_id}: landed in the AUTHENTICATED tenant",
              ev.get("tenant_id") == TEN_B, str(ev.get("tenant_id")))
        check(f"{dsm_id}: did NOT land in the claimed tenant",
              ev.get("tenant_id") != TEN_A)
        check(f"{dsm_id}: the claim is recorded as untrusted, used=False",
              claim.get("state") == "UNTRUSTED_SOURCE_CLAIM"
              and claim.get("claimed_tenant_id") == TEN_A
              and claim.get("used") is False
              and claim.get("agrees_with_authenticated") is False,
              str(claim) or "no claim recorded")
        check(f"{dsm_id}: the claim names where it came from",
              bool(claim.get("claim_source")), str(claim.get("claim_source")))

    print("\n4 · what does tenant A hold?")
    after_a = db.xdr_canonical_evidence.count_documents({"tenant_id": TEN_A})
    check("tenant A gained ZERO canonical evidence",
          after_a == before_a, f"before={before_a} after={after_a}")
    leaked = db.xdr_canonical_evidence.count_documents(
        {"tenant_id": TEN_A, "provenance.ingest.collector_id": col_b})
    check("tenant A holds nothing delivered by tenant B's collector",
          leaked == 0, str(leaked))
    obs = db.xdr_observations.count_documents({"tenant_id": TEN_A}) \
        if "xdr_observations" in db.list_collection_names() else 0
    print(f"  tenant A observations: {obs}")

    print("\n5 · a delivery with no authenticated tenant is refused")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_b,
                      body={"envelopes": [{
                          "tenant_id": "", "collector_id": col_b,
                          "source_event_id": f"d14:{STAMP}:notenant",
                          "collection_method": "rest", "source": "d14-host",
                          "raw": dict(ATTACKS["aws-cloudtrail"],
                                      eventID=f"ct-nt-{STAMP}")}]})
    refused = code != 200
    if not refused:
        data = body.get("data") or body
        st = [o.get("status") for o in (data.get("reasoning") or [])]
        refused = all(s not in ("REASONED",) for s in st)
        print(f"  outcomes: {st}")
    check("the untenanted delivery produced no reasoned evidence", refused,
          f"HTTP {code}")
    n = db.xdr_canonical_evidence.count_documents(
        {"raw_ref.eventID": f"ct-nt-{STAMP}"})
    check("no canonical evidence exists for it", n == 0, str(n))

    print("\n6 · the untrusted claim did not move canonical identity")
    clean_line = LINE_ATTACKS["linux-auditd"]
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_b,
                      tenant=TEN_B, body={"envelopes": [{
                          "tenant_id": TEN_B, "collector_id": col_b,
                          "source_event_id": f"d14:{STAMP}:identity",
                          "collection_method": "syslog",
                          "source": "d14-host",
                          "raw": {"line": clean_line}}]})
    time.sleep(2)
    rows = list(db.xdr_canonical_evidence.find(
        {"tenant_id": TEN_B, "raw_ref.line": clean_line}))
    check("the same auditd event with and without the claim is ONE event",
          len({r["event_id"] for r in rows}) == 1,
          f"{len(rows)} rows, "
          f"{len({r['event_id'] for r in rows})} distinct event_ids")

    print("\n" + ("D14 TENANT AUTHORITY: PASS" if ok
                  else "D14 TENANT AUTHORITY: FAIL"))
    print("TEST/SYNTHETIC payloads. NOT LIVE. Preview only, nothing "
          "deployed. The authenticated ingest guards themselves were not "
          "modified — only what happens downstream of them.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
