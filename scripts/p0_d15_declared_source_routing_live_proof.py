#!/usr/bin/env python3
"""D15 · Snort tenant contract + declared source routing, over real HTTP
(PREVIEW ONLY).

The ingestion authority chain, end to end:

    authenticated collector identity
      -> the collector's server-side authorized source set
      -> this delivery's EXPLICIT declaration
      -> declaration / allowlist validation
      -> DSM selection
      -> content compatibility validation
      -> canonical evidence

Proved here, over the real authenticated ingest path:

    authorized collector + correct declaration + correct payload -> evidence
    authenticated collector + unauthorized declaration           -> ZERO
    missing declaration                                          -> ZERO
    unknown declaration                                          -> ZERO
    declaration/content mismatch                                 -> ZERO
    content crafted to resemble another DSM                      -> no reroute
    collector A sending a source only B is authorized for        -> ZERO
    tenant B + payload claiming tenant A                         -> stays B
    Snort EVE under the same tenant invariant                    -> stays B
    mixed legitimate sources                                     -> each by
                                                                    its own
                                                                    declaration

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
TEN_A = "t-d15-victim-a"
TEN_B = "t-d15-owner-b"
AUD = f"1757452888.777:{9700 + STAMP % 250}"

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


def provision(token, tenant, name, sources):
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=tenant, body={
                          "name": name, "protocol": "rest",
                          "authorized_sources": sources,
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
        call(f"/api/xdr/collectors/{col}", "PUT", token=token, tenant=tenant,
             body={"authorized_sources": sources})
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


SNORT_DOC = {"event_type": "alert",
             "timestamp": "2026-06-01T10:00:00+00:00",
             "src_ip": "10.0.0.5", "dest_ip": "198.51.100.9", "proto": "TCP",
             "alert": {"signature_id": 2027865, "signature": "ET SCAN"}}
WINDOWS_DOC = {"EventID": 4624,
               "provider": "Microsoft-Windows-Security-Auditing",
               "channel": "Security", "Computer": f"WIN-DC-{STAMP % 100}",
               "TimeCreated": "2026-06-01T10:00:00+00:00",
               "EventData": {"TargetUserName": f"svc_d15_{STAMP}",
                             "LogonType": "3", "IpAddress": "10.0.0.9"}}
SYSMON_DOC = {"EventID": 1, "provider": "Microsoft-Windows-Sysmon",
              "Computer": f"WIN-WS-{STAMP % 100}", "User": "CORP\\dev1",
              "UtcTime": "2026-06-01T10:00:00+00:00",
              "Image": "C:\\Windows\\System32\\cmd.exe",
              "CommandLine": f"cmd /c whoami {STAMP}", "ProcessId": "4321"}
CLOUDTRAIL_DOC = {"eventName": "ConsoleLogin",
                  "eventSource": "signin.amazonaws.com",
                  "eventTime": "2026-06-01T10:00:00Z",
                  "awsRegion": "us-east-1", "eventID": f"ct-d15-{STAMP}",
                  "sourceIPAddress": "203.0.113.7",
                  "userIdentity": {"type": "IAMUser", "userName": "dev1",
                                   "accountId": "111122223333"}}
AUDITD_LINE = (f'node=web-prod-04 type=SYSCALL msg=audit({AUD}): '
               f'arch=c000003e syscall=59 uid=0 euid=0 comm="bash" '
               f'exe="/usr/bin/bash" key="exec"')
CEF_LINE = (f"CEF:0|NivX|Firewall|1.0|{STAMP % 700}|Blocked|5|"
            "src=10.0.0.7 dst=198.51.100.8 devTime=1780308000000")

B_SOURCES = ["snort-eve", "windows-security-evd", "microsoft-sysmon",
             "linux-auditd", "cef-leef"]
#: cloudtrail is authorized for collector C only — never for B.
C_SOURCES = ["aws-cloudtrail"]


def env(collector, tenant, sei, declared, raw, method="rest"):
    return {"tenant_id": tenant, "collector_id": collector,
            "source_event_id": sei, "collection_method": method,
            "source": "d15-host", "declared_source": declared, "raw": raw}


def outcomes(body):
    data = body.get("data") or body
    return data.get("reasoning") or []


def main() -> int:
    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]
    print("login: 200\n1 · provision two collectors with DIFFERENT "
          "authorization sets")
    col_b, key_b = provision(token, TEN_B, "d15-collector-b", B_SOURCES)
    col_c, key_c = provision(token, TEN_B, "d15-collector-c", C_SOURCES)
    check("collector B (5 sources, no cloudtrail) + key",
          bool(col_b and key_b), col_b)
    check("collector C (cloudtrail only) + key", bool(col_c and key_c), col_c)
    if not (key_b and key_c):
        return 1

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ev = db.xdr_canonical_evidence
    blocks = db.xdr_ingest_routing_blocks
    before_a = ev.count_documents({"tenant_id": TEN_A})
    before_b = ev.count_documents({"tenant_id": TEN_B})
    print(f"  evidence before: A={before_a} B={before_b}")

    print("\n2 · the declared, authorized, compatible path — mixed sources")
    legit = [
        env(col_b, TEN_B, f"d15:{STAMP}:snort", "snort-eve",
            dict(SNORT_DOC, tenant_id=TEN_A)),
        env(col_b, TEN_B, f"d15:{STAMP}:win", "windows-security-evd",
            WINDOWS_DOC),
        env(col_b, TEN_B, f"d15:{STAMP}:sysmon", "microsoft-sysmon",
            SYSMON_DOC),
        env(col_b, TEN_B, f"d15:{STAMP}:auditd", "linux-auditd",
            {"line": AUDITD_LINE}, method="syslog"),
        env(col_b, TEN_B, f"d15:{STAMP}:cef", "cef-leef",
            {"line": CEF_LINE}, method="syslog"),
    ]
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_b,
                      tenant=TEN_B, body={"envelopes": legit})
    check("ingest accepted", code == 200, f"HTTP {code} {str(body)[:200]}")
    if code != 200:
        return 1
    st = [(o.get("status"), o.get("selected_dsm_id")) for o in outcomes(body)]
    print(f"  outcomes: {st}")
    check("every declared delivery was reasoned",
          all(s == "REASONED" for s, _ in st), str(st))
    check("each envelope was interpreted by the DSM it declared",
          sorted(d for _s, d in st) == sorted(
              ["snort-eve", "windows-security-evd", "microsoft-sysmon",
               "linux-auditd", "cef-leef"]), str(st))
    time.sleep(2)

    print("\n3 · the routing decision travels with the evidence")
    for dsm_id in ("snort-eve", "windows-security-evd", "microsoft-sysmon",
                   "linux-auditd", "cef-leef"):
        row = ev.find_one({"tenant_id": TEN_B,
                           "provenance.routing.selected_dsm_id": dsm_id,
                           "provenance.ingest.collector_id": col_b},
                          sort=[("_id", -1)])
        if not row:
            check(f"{dsm_id}: evidence created", False, "none found")
            continue
        r = (row.get("provenance") or {}).get("routing") or {}
        check(f"{dsm_id}: routing authority is the collector declaration",
              r.get("routing_authority")
              == "AUTHENTICATED_COLLECTOR_DECLARATION", str(r.get(
                  "routing_authority")))
        check(f"{dsm_id}: the declaration is recorded",
              r.get("declared_source") == dsm_id, str(r.get(
                  "declared_source")))
        check(f"{dsm_id}: the authorized set is recorded",
              sorted(r.get("collector_authorized_sources") or [])
              == sorted(B_SOURCES), str(r.get(
                  "collector_authorized_sources")))
        check(f"{dsm_id}: content validated the declaration",
              r.get("content_compatible") is True)
        check(f"{dsm_id}: evidence is owned by the authenticated tenant",
              row.get("tenant_id") == TEN_B, str(row.get("tenant_id")))

    print("\n4 · Snort EVE is under the SAME tenant invariant as every "
          "other DSM")
    snort = ev.find_one({"tenant_id": TEN_B,
                         "provenance.routing.selected_dsm_id": "snort-eve",
                         "provenance.ingest.collector_id": col_b},
                        sort=[("_id", -1)])
    check("snort evidence exists", bool(snort))
    if snort:
        claim = (snort.get("additional_fields") or {}).get("tenant_claim") \
            or {}
        check("snort landed in the AUTHENTICATED tenant",
              snort.get("tenant_id") == TEN_B, str(snort.get("tenant_id")))
        check("snort did NOT land in the tenant its payload claimed",
              snort.get("tenant_id") != TEN_A)
        check("the snort payload's tenant claim is recorded, used=False",
              claim.get("state") == "UNTRUSTED_SOURCE_CLAIM"
              and claim.get("claimed_tenant_id") == TEN_A
              and claim.get("used") is False
              and claim.get("agrees_with_authenticated") is False,
              str(claim))

    print("\n5 · every disagreement produces ZERO canonical evidence")
    attacks = [
        ("missing declaration", "DECLARATION_REQUIRED",
         env(col_b, TEN_B, f"d15:{STAMP}:nodecl", None,
             dict(WINDOWS_DOC, EventID=4625))),
        ("unknown declaration", "UNSUPPORTED_SOURCE",
         env(col_b, TEN_B, f"d15:{STAMP}:unknown", "crowdstrike-falcon",
             dict(WINDOWS_DOC, EventID=4768))),
        ("unauthorized declaration (cloudtrail is collector C's)",
         "SOURCE_NOT_AUTHORIZED",
         env(col_b, TEN_B, f"d15:{STAMP}:unauth", "aws-cloudtrail",
             dict(CLOUDTRAIL_DOC, eventID=f"ct-unauth-{STAMP}"))),
        ("declaration/content mismatch", "SOURCE_FORMAT_MISMATCH",
         env(col_b, TEN_B, f"d15:{STAMP}:mismatch", "windows-security-evd",
             dict(SNORT_DOC, src_ip="10.0.0.6"))),
        ("content crafted to resemble another DSM",
         "SOURCE_FORMAT_MISMATCH",
         env(col_b, TEN_B, f"d15:{STAMP}:lookalike", "windows-security-evd",
             dict(SYSMON_DOC, CommandLine=f"cmd /c lookalike {STAMP}"))),
        ("snort EVE under the auditd declaration",
         "SOURCE_FORMAT_MISMATCH",
         env(col_b, TEN_B, f"d15:{STAMP}:snortasaudit", "linux-auditd",
             dict(SNORT_DOC, src_ip="10.0.0.11"))),
        ("CEF content under the cloudtrail declaration",
         "SOURCE_NOT_AUTHORIZED",
         env(col_b, TEN_B, f"d15:{STAMP}:cefascloud", "aws-cloudtrail",
             {"line": CEF_LINE}, "syslog")),
        ("CEF content under the windows declaration",
         "SOURCE_FORMAT_MISMATCH",
         env(col_b, TEN_B, f"d15:{STAMP}:cefaswin", "windows-security-evd",
             {"line": CEF_LINE}, "syslog")),
    ]
    ev_before = ev.count_documents({"tenant_id": TEN_B})
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_b,
                      tenant=TEN_B,
                      body={"envelopes": [e for _l, _c, e in attacks]})
    check("the refused batch is answered, not crashed", code == 200,
          f"HTTP {code} {str(body)[:200]}")
    data = body.get("data") or body if code == 200 else {}
    check("no envelope in the refused batch was accepted",
          data.get("accepted") == 0 and data.get("reasoned") == 0,
          f"accepted={data.get('accepted')} reasoned={data.get('reasoned')}")
    check("all eight were counted as routing-blocked",
          data.get("routing_blocked") == len(attacks),
          str(data.get("routing_blocked")))
    by_sei = {o.get("source_event_id"): o for o in outcomes(body)}
    for label, code_expected, e in attacks:
        o = by_sei.get(e["source_event_id"]) or {}
        check(f"{label}: BLOCKED with {code_expected}",
              o.get("status") == "BLOCKED"
              and o.get("blocker") == "source_routing"
              and o.get("mismatch_reason") == code_expected,
              f"{o.get('status')}/{o.get('mismatch_reason')}")
    time.sleep(2)
    check("the refused batch created NO canonical evidence",
          ev.count_documents({"tenant_id": TEN_B}) == ev_before,
          f"before={ev_before} after={ev.count_documents({'tenant_id': TEN_B})}")
    for sei in (f"ct-unauth-{STAMP}",):
        check(f"no evidence exists for {sei}",
              ev.count_documents({"raw_ref.eventID": sei}) == 0)
    check("no raw row exists for the refused deliveries",
          db.xdr_canonical_events.count_documents(
              {"source_event_id": {"$in": [e["source_event_id"]
                                           for _l, _c, e in attacks]}}) == 0)

    print("\n6 · the refusals are kept as evidence")
    rows = list(blocks.find({"tenant_id": TEN_B, "collector_id": col_b}))
    check("a routing-block record exists per refusal",
          len(rows) >= len(attacks), str(len(rows)))
    mism = next((r for r in rows if r["routing"].get("mismatch_reason")
                 == "SOURCE_FORMAT_MISMATCH"), None)
    if mism:
        r = mism["routing"]
        print(f"  mismatch evidence: declared={r.get('declared_source')} "
              f"selected={r.get('selected_dsm_id')} "
              f"recognized_as={r.get('content_recognized_as')}")
        check("the declared DSM is still the only selected one, and the "
              "resembled DSM is reported as evidence only",
              r.get("selected_dsm_id")
              == "windows-security-evd"
              and r.get("content_recognized_as")
              and "windows-security-evd" not in (
                  r.get("content_recognized_as") or []),
              str(r))
        check("no credential material is recorded in the refusal",
              not any(k in json.dumps(mism, default=str)
                      for k in ("X-XDR-API-Key", "nvx_", "Authorization")))

    print("\n7 · collector C may send ONLY what C is authorized for")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key_c,
                      tenant=TEN_B, body={"envelopes": [
                          env(col_c, TEN_B, f"d15:{STAMP}:c-ok",
                              "aws-cloudtrail",
                              dict(CLOUDTRAIL_DOC,
                                   eventID=f"ct-c-ok-{STAMP}")),
                          env(col_c, TEN_B, f"d15:{STAMP}:c-bad",
                              "windows-security-evd",
                              dict(WINDOWS_DOC, EventID=4769))]})
    check("collector C ingest answered", code == 200, f"HTTP {code}")
    outs = {o.get("source_event_id"): o for o in outcomes(body)}
    check("C's authorized source is reasoned",
          (outs.get(f"d15:{STAMP}:c-ok") or {}).get("status") == "REASONED",
          str(outs.get(f"d15:{STAMP}:c-ok")))
    check("a source authorized only for B is refused for C",
          (outs.get(f"d15:{STAMP}:c-bad") or {}).get("mismatch_reason")
          == "SOURCE_NOT_AUTHORIZED",
          str(outs.get(f"d15:{STAMP}:c-bad")))

    print("\n8 · the victim tenant holds nothing")
    after_a = ev.count_documents({"tenant_id": TEN_A})
    check("tenant A gained ZERO canonical evidence", after_a == before_a,
          f"before={before_a} after={after_a}")
    check("tenant A holds nothing delivered by these collectors",
          ev.count_documents({"tenant_id": TEN_A,
                              "provenance.ingest.collector_id":
                                  {"$in": [col_b, col_c]}}) == 0)

    print("\n9 · the declared-source catalog is operator-visible")
    code, body = call("/api/xdr/collectors/sources/catalog", token=token,
                      tenant=TEN_B)
    data = (body.get("data") or {}) if code == 200 else {}
    check("catalog served", code == 200 and data.get("sources"),
          f"HTTP {code}")
    check("every catalog entry names exactly one DSM",
          all(s.get("dsm_id") for s in (data.get("sources") or [])))
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=TEN_B, body={
                          "name": f"d15-bad-allowlist-{STAMP}",
                          "protocol": "rest",
                          "authorized_sources": ["not-a-real-source"]})
    check("an unknown allowlist entry is refused at configuration time",
          code == 400 and "UNSUPPORTED_SOURCE" in str(body), f"HTTP {code}")

    print("\n" + ("D15 DECLARED SOURCE ROUTING: PASS" if ok
                  else "D15 DECLARED SOURCE ROUTING: FAIL"))
    print("TEST/SYNTHETIC payloads. NOT LIVE. Preview only, nothing "
          "deployed. The authenticated ingest guards themselves were not "
          "modified — routing runs downstream of them and upstream of any "
          "persistence.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
