#!/usr/bin/env python3
"""D19 · cloud & identity declarations over real HTTP (PREVIEW ONLY).

Three deliveries through the authenticated, DECLARED (D15) ingest path:

  1. CloudTrail `PutUserPolicy` granting `"Action":"*"`   -> DET-PE-003,
     cited on cloud.action + cloud.request_parameters
  2. Windows 4769 with RC4 (0x17) against a user SPN      -> DET-CR-004,
     cited on source_event_id + authentication.ticket_encryption
  3. Windows 4768 with PreAuthType 0                      -> DET-CR-005,
     cited on authentication.preauth_type

plus the benign counterparts (a least-privilege policy, an AES ticket)
which must produce evidence and NO detection.

TEST/SYNTHETIC payloads. NOT LIVE — no real AWS account or domain
controller is connected. Nothing touches production.
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
TENANT = "t-d19-cloud-identity"
SPN = f"MSSQLSvc/sql{STAMP}.corp"
USER = f"svc_legacy{STAMP}"
SOURCES = ["aws-cloudtrail", "windows-security-evd"]

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


def env(col, sei, declared, raw):
    return {"tenant_id": TENANT, "collector_id": col, "source_event_id": sei,
            "collection_method": "rest", "source": "d19-proof-host",
            "declared_source": declared, "raw": raw}


def main() -> int:
    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]
    print("login: 200\n1 · provision TEST collector + key")
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=TENANT, body={
                          "name": "d19-proof-collector", "protocol": "rest",
                          "authorized_sources": SOURCES,
                          "tenant_id": TENANT, "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True})
    if code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col = next((c["id"] for c in
                    ((lst.get("data") or {}).get("collectors") or [])
                    if c.get("name") == "d19-proof-collector"), None)
    elif code in (200, 201):
        d = body.get("data") or body
        col = d.get("id") or (d.get("collector") or {}).get("id")
    else:
        print(f"  collector create -> {code} {body}")
        return 1
    if col:
        call(f"/api/xdr/collectors/{col}", "PUT", token=token, tenant=TENANT,
             body={"authorized_sources": SOURCES})
    code, body = call("/api/xdr/api-keys", "POST", token=token,
                      tenant=TENANT, body={
                          "name": f"d19-proof-key-{STAMP}",
                          "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True,
                          "scopes": ["collectors.enroll", "collectors.read"]})
    _d = body.get("data") or {}
    key = (_d.get("api_key") or _d.get("key") or _d.get("secret")
           or _d.get("plaintext") or _d.get("token") or _d.get("value"))
    check("collector + ingest key ready", bool(col and key), col)
    if not key:
        return 1

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ev = db.xdr_canonical_evidence
    matches = db.xdr_detection_matches

    def ct(name, params, eid):
        return {"eventName": name, "eventSource": "iam.amazonaws.com",
                "eventTime": "2026-06-01T10:00:00Z",
                "awsRegion": "us-east-1", "eventID": eid,
                "sourceIPAddress": "203.0.113.7",
                "userIdentity": {"type": "IAMUser", "userName": "dev1",
                                 "accountId": "111122223333",
                                 "arn": "arn:aws:iam::111122223333:user/"
                                        "dev1"},
                "requestParameters": params}

    print("\n2 · deliver cloud + identity telemetry (malicious and benign)")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [
                          env(col, f"d19:{STAMP}:iam-bad", "aws-cloudtrail",
                              ct("PutUserPolicy",
                                 {"userName": "dev1",
                                  "policyDocument":
                                      '{"Statement":[{"Effect":"Allow",'
                                      '"Action":"*","Resource":"*"}]}'},
                                 f"ct-bad-{STAMP}")),
                          env(col, f"d19:{STAMP}:iam-ok", "aws-cloudtrail",
                              ct("PutUserPolicy",
                                 {"userName": "dev1",
                                  "policyDocument":
                                      '{"Statement":[{"Effect":"Allow",'
                                      '"Action":"s3:GetObject"}]}'},
                                 f"ct-ok-{STAMP}")),
                          env(col, f"d19:{STAMP}:krb-rc4",
                              "windows-security-evd", {
                                  "EventID": 4769,
                                  "provider": "Microsoft-Windows-Security-"
                                              "Auditing",
                                  "channel": "Security",
                                  "Computer": "WIN-DC-19",
                                  "TimeCreated": "2026-06-01T10:00:02+00:00",
                                  "EventData": {
                                      "TargetUserName": "attacker",
                                      "ServiceName": SPN,
                                      "TicketOptions": "0x40810000",
                                      "TicketEncryptionType": "0x17",
                                      "Status": "0x0",
                                      "IpAddress": "10.0.0.9"}}),
                          env(col, f"d19:{STAMP}:krb-aes",
                              "windows-security-evd", {
                                  "EventID": 4769,
                                  "provider": "Microsoft-Windows-Security-"
                                              "Auditing",
                                  "channel": "Security",
                                  "Computer": "WIN-DC-19",
                                  "TimeCreated": "2026-06-01T10:00:03+00:00",
                                  "EventData": {
                                      "TargetUserName": "user1",
                                      "ServiceName": f"AESSvc/{STAMP}.corp",
                                      "TicketOptions": "0x40810000",
                                      "TicketEncryptionType": "0x12",
                                      "Status": "0x0"}}),
                          env(col, f"d19:{STAMP}:asrep",
                              "windows-security-evd", {
                                  "EventID": 4768,
                                  "provider": "Microsoft-Windows-Security-"
                                              "Auditing",
                                  "channel": "Security",
                                  "Computer": "WIN-DC-19",
                                  "TimeCreated": "2026-06-01T10:00:04+00:00",
                                  "EventData": {
                                      "TargetUserName": USER,
                                      "TargetDomainName": "CORP",
                                      "ServiceName": "krbtgt",
                                      "PreAuthType": "0",
                                      "Status": "0x0"}})]})
    check("ingest accepted", code == 200, f"HTTP {code} {str(body)[:200]}")
    if code != 200:
        return 1
    data = body.get("data") or body
    outs = {o.get("source_event_id"): o for o in (data.get("reasoning") or [])}
    print("  outcomes: " + str([(k.rsplit(":", 1)[-1], o.get("detection"),
                                 o.get("detections_matched"))
                                for k, o in outs.items()]))
    check("all five were reasoned",
          all(o.get("status") == "REASONED" for o in outs.values()))
    time.sleep(2)

    print("\n3 · the new cloud fields are real evidence, and cited")
    bad = ev.find_one({"tenant_id": TENANT,
                       "raw_ref.eventID": f"ct-bad-{STAMP}"},
                      sort=[("_id", -1)]) or ev.find_one(
        {"tenant_id": TENANT, "source_event_id": f"ct-bad-{STAMP}"},
        sort=[("_id", -1)])
    check("CloudTrail evidence exists", bool(bad))
    if bad:
        cloud = bad.get("cloud") or {}
        print(f"  cloud: action={cloud.get('action')!r} "
              f"principal_type={cloud.get('principal_type')!r} "
              f"params_keys={sorted((cloud.get('request_parameters') or {}))}")
        check("principal_type carries the provider's own vocabulary",
              cloud.get("principal_type") == "IAMUser")
        check("request_parameters are preserved verbatim",
              "policyDocument" in (cloud.get("request_parameters") or {}))
        cit = matches.find_one({"rule_id": "DET-PE-003",
                                "canonical_event_id": bad.get("event_id")})
        check("the wildcard policy write was detected", bool(cit))
        if cit:
            fields = [c["canonical_field"]
                      for c in cit.get("matched_conditions") or []]
            print(f"  citation: {cit.get('citation_completeness')} · {fields}")
            check("it is DECLARED and complete",
                  cit.get("declaration_state") == "DECLARED"
                  and cit.get("citation_completeness") == "CITED")
            check("it cites the action and the recorded request parameters",
                  set(fields) == {"cloud.action",
                                  "cloud.request_parameters"}, str(fields))
    ok_row = ev.find_one({"tenant_id": TENANT,
                          "raw_ref.eventID": f"ct-ok-{STAMP}"},
                         sort=[("_id", -1)])
    if ok_row:
        check("a least-privilege policy write is NOT detected",
              matches.count_documents(
                  {"canonical_event_id": ok_row.get("event_id"),
                   "rule_id": "DET-PE-003"}) == 0)

    print("\n4 · kerberoasting, from canonical authentication evidence")
    krb = ev.find_one({"tenant_id": TENANT,
                       "authentication.service_name": SPN},
                      sort=[("_id", -1)])
    check("4769 evidence exists", bool(krb))
    if krb:
        auth = krb.get("authentication") or {}
        check("the RC4 encryption type is canonical evidence",
              auth.get("ticket_encryption") == "0x17", str(auth))
        check("the Windows EventID is the source_event_id",
              krb.get("source_event_id") == "4769")
        cit = matches.find_one({"rule_id": "DET-CR-004",
                                "canonical_event_id": krb.get("event_id")})
        check("kerberoasting was detected", bool(cit))
        if cit:
            fields = {c["canonical_field"]
                      for c in cit.get("matched_conditions") or []}
            print(f"  citation: {sorted(fields)}")
            check("it cites the event id, the encryption and the SPN",
                  fields == {"source_event_id",
                             "authentication.ticket_encryption",
                             "authentication.service_name"}, str(fields))
    aes = ev.find_one({"tenant_id": TENANT,
                       "authentication.service_name":
                           f"AESSvc/{STAMP}.corp"}, sort=[("_id", -1)])
    if aes:
        check("an AES ticket request is NOT kerberoasting",
              matches.count_documents(
                  {"canonical_event_id": aes.get("event_id"),
                   "rule_id": "DET-CR-004"}) == 0)

    print("\n5 · AS-REP roasting, from a field that did not exist before D19")
    asrep = ev.find_one({"tenant_id": TENANT,
                         "identity.username": USER}, sort=[("_id", -1)])
    check("4768 evidence exists", bool(asrep))
    if asrep:
        check("the pre-authentication type is canonical evidence",
              (asrep.get("authentication") or {}).get("preauth_type") == "0",
              str((asrep.get("authentication") or {}).get("preauth_type")))
        cit = matches.find_one({"rule_id": "DET-CR-005",
                                "canonical_event_id": asrep.get("event_id")})
        check("AS-REP roasting was detected", bool(cit))
        if cit:
            fields = {c["canonical_field"]
                      for c in cit.get("matched_conditions") or []}
            print(f"  citation: {sorted(fields)}")
            check("it cites the pre-auth type it actually evaluated",
                  "authentication.preauth_type" in fields, str(fields))
        check("D12 unchanged: EVTX still declares an observation time",
              (asrep.get("additional_fields") or {}).get("event_time_basis")
              == "OBSERVATION_TIME")

    print("\n6 · nothing was fabricated to make a rule fire")
    for field in ("cloud.policy", "principal_kind",
                  "network.destination_ip", "certificate.template"):
        check(f"{field} still does not exist in canonical evidence",
              ev.count_documents({"tenant_id": TENANT,
                                  field: {"$exists": True}}) == 0)

    print("\n" + ("D19 CLOUD/IDENTITY DECLARATIONS: PASS" if ok
                  else "D19 CLOUD/IDENTITY DECLARATIONS: FAIL"))
    print("TEST/SYNTHETIC payloads. NOT LIVE. Preview only, nothing "
          "deployed.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
