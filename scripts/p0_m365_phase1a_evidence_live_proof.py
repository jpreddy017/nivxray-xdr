#!/usr/bin/env python3
"""Microsoft telemetry Phase 1a · evidence plane over real HTTP (PREVIEW).

ACCEPTANCE LABEL — read this before quoting any result:

    This script is **SYNTHETIC/REPLAY PROVEN**, never REAL SOURCE PROVEN.

It delivers records in Microsoft's documented Office 365 Management Activity
schema through NivX's own authenticated, declared (D15) ingest route. The
NivX pipeline is real; the Microsoft SOURCE is not contacted. Only telemetry
actually acquired from Microsoft's service can satisfy REAL SOURCE PROVEN,
and that belongs to Phase 1b once owner-side app registration exists.

What is proven here:
  1. `m365-unified-audit` is a declarable source that routes to exactly one
     DSM, and a non-Microsoft payload declared as M365 is REFUSED.
  2. All three subscribed content types (Audit.Exchange,
     Audit.AzureActiveDirectory, Audit.General) become canonical evidence
     through ONE DSM.
  3. `CreationTime` is the activity basis; blob availability
     (`contentCreated`) is recorded as acquisition metadata and never as
     activity time.
  4. `OrganizationId` is preserved as the PROVIDER tenant while the NivX
     tenant stays the authenticated one.
  5. DET-PS-004 fires on the real recorded Exchange parameters and CITES
     them; benign Microsoft administration does not fire.
  6. The D21 routing surface shows these deliveries, tenant-scoped.
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
TENANT = "t-m365-phase1a"
ORG = "11111111-2222-3333-4444-555555555555"
SOURCES = ["m365-unified-audit"]

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
        raw = e.read().decode()[:400]
        try:
            return e.code, json.loads(raw)
        except Exception:                                      # noqa: BLE001
            return e.code, raw


def env(col, sei, raw, declared="m365-unified-audit"):
    e = {"tenant_id": TENANT, "collector_id": col, "source_event_id": sei,
         "collection_method": "rest", "source": "m365-phase1a-proof",
         "raw": raw}
    if declared:
        e["declared_source"] = declared
    return e


def exchange_rule(params, *, op="New-InboxRule", ident):
    return {"Id": ident, "RecordType": 1,
            "CreationTime": "2026-06-02T09:15:00", "Operation": op,
            "OrganizationId": ORG, "UserType": 2,
            "UserKey": "user1@corp.example", "Workload": "Exchange",
            "ResultStatus": "True", "ObjectId": "user1@corp.example",
            "UserId": "user1@corp.example", "ClientIP": "203.0.113.40",
            "ExternalAccess": False, "OrganizationName": "corp.example",
            "Parameters": params}


def main() -> int:                                          # noqa: C901
    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]
    print("admin login: 200\n1 · the Microsoft source is declarable")

    code, body = call("/api/xdr/collectors/sources/catalog", token=token,
                      tenant=TENANT)
    cat = ((body.get("data") or {}).get("sources") or []) if isinstance(
        body, dict) else []
    m365 = next((s for s in cat if s["declared_source"]
                 == "m365-unified-audit"), None)
    check("catalog lists m365-unified-audit -> one DSM", bool(m365)
          and m365["dsm_id"] == "m365-unified-audit", json.dumps(m365))
    check("its aliases resolve to the same source",
          {"m365", "o365", "office365"} <= set((m365 or {}).get("aliases")
                                               or []),
          str((m365 or {}).get("aliases")))

    name = "m365-phase1a-collector"
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=TENANT,
                      body={"name": name, "protocol": "rest",
                            "authorized_sources": SOURCES})
    if code in (200, 201):
        col = (body.get("data") or {}).get("id")
    elif code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col = next((c["id"] for c in
                    ((lst.get("data") or {}).get("collectors") or [])
                    if c.get("name") == name), None)
        if col:
            call(f"/api/xdr/collectors/{col}", "PUT", token=token,
                 tenant=TENANT, body={"authorized_sources": SOURCES})
    else:
        print(f"  collector create -> {code} {body}")
        return 1
    code, body = call("/api/xdr/api-keys", "POST", token=token, tenant=TENANT,
                      body={"name": f"m365-phase1a-key-{STAMP}",
                            "confirm_tenant_id": TENANT,
                            "allow_new_tenant": True,
                            "scopes": ["collectors.enroll",
                                       "collectors.read"]})
    d = body.get("data") or {}
    key = (d.get("api_key") or d.get("key") or d.get("secret")
           or d.get("plaintext") or d.get("token") or d.get("value"))
    check("collector authorized for m365 + ingest key", bool(col and key),
          str(col))
    if not (col and key):
        return 1

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ev = db.xdr_canonical_evidence
    matches = db.xdr_detection_matches

    print("\n2 · deliver all three subscribed content types (TEST/SYNTHETIC "
          "Microsoft-shaped records)")
    bad_id = f"ex-bad-{STAMP}"
    ok_id = f"ex-ok-{STAMP}"
    aad_id = f"aad-{STAMP}"
    gen_id = f"gen-{STAMP}"
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [
                          # Audit.Exchange — malicious external forwarding
                          env(col, f"m365:{STAMP}:ex-bad", exchange_rule(
                              [{"Name": "Name", "Value": "ext-archive"},
                               {"Name": "ForwardTo",
                                "Value": "attacker@evil.example"},
                               {"Name": "StopProcessingRules",
                                "Value": "True"}], ident=bad_id)),
                          # Audit.Exchange — benign triage rule
                          env(col, f"m365:{STAMP}:ex-ok", exchange_rule(
                              [{"Name": "Name", "Value": "triage"},
                               {"Name": "MoveToFolder", "Value": "Archive"}],
                              ident=ok_id)),
                          # Audit.AzureActiveDirectory — role assignment
                          env(col, f"m365:{STAMP}:aad", {
                              "Id": aad_id, "RecordType": 8,
                              "CreationTime": "2026-06-02T09:20:00",
                              "Operation": "Add member to role.",
                              "OrganizationId": ORG, "UserType": 0,
                              "UserKey": "admin@corp.example",
                              "Workload": "AzureActiveDirectory",
                              "ResultStatus": "Success",
                              "UserId": "admin@corp.example",
                              "ActorIpAddress": "198.51.100.22",
                              "ApplicationId":
                                  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                              "Target": [{"ID": "victim@corp.example",
                                          "Type": 5}],
                              "ModifiedProperties": [
                                  {"Name": "Role.DisplayName",
                                   "NewValue": "Global Administrator",
                                   "OldValue": ""}]}),
                          # Audit.General — with acquisition metadata, to
                          # prove blob time never becomes activity time
                          env(col, f"m365:{STAMP}:gen", {
                              "Id": gen_id, "RecordType": 18,
                              "CreationTime": "2026-06-02T09:25:00",
                              "Operation": "Set-AntiPhishPolicy",
                              "OrganizationId": ORG, "UserType": 3,
                              "UserKey": "secadmin@corp.example",
                              "Workload": "SecurityComplianceCenter",
                              "ResultStatus": "True",
                              "UserId": "secadmin@corp.example",
                              "Parameters": [
                                  {"Name": "Identity", "Value": "Default"},
                                  {"Name": "Enabled", "Value": "False"}],
                              "_nivx_m365_acquisition_probe": True})]})
    check("ingest accepted", code == 200, f"HTTP {code} {str(body)[:200]}")
    if code != 200:
        return 1
    outs = {o.get("source_event_id"): o
            for o in (body.get("reasoning") or [])}
    check("all four records were reasoned",
          all(o.get("status") == "REASONED" for o in outs.values()),
          str([(k, o.get("status")) for k, o in outs.items()]))
    check("every accepted delivery names the declared source and its DSM",
          all(o.get("declared_source") == "m365-unified-audit"
              and o.get("selected_dsm_id") == "m365-unified-audit"
              for o in outs.values() if o.get("status") == "REASONED"))
    time.sleep(2)

    print("\n3 · one DSM, three content types, Microsoft vocabulary intact")
    rows = {}
    for label, ident, workload, rtype in (
            ("exchange-malicious", bad_id, "Exchange", "ExchangeAdmin"),
            ("exchange-benign", ok_id, "Exchange", "ExchangeAdmin"),
            ("entra", aad_id, "AzureActiveDirectory", "AzureActiveDirectory"),
            ("general", gen_id, "SecurityComplianceCenter",
             "SecurityComplianceCenterEOPCmdlet")):
        row = ev.find_one({"tenant_id": TENANT, "source_event_id": ident},
                          sort=[("_id", -1)])
        rows[label] = row
        check(f"{label}: canonical evidence exists", bool(row), ident)
        if not row:
            continue
        cloud = row.get("cloud") or {}
        check(f"{label}: workload + record type are Microsoft's own",
              cloud.get("workload") == workload
              and cloud.get("record_type") == rtype,
              f"{cloud.get('workload')}/{cloud.get('record_type')}")
        check(f"{label}: the provider tenant is preserved and labelled",
              cloud.get("provider_tenant_id") == ORG
              and row.get("tenant_id") == TENANT,
              f"org={cloud.get('provider_tenant_id')} "
              f"nivx={row.get('tenant_id')}")
        check(f"{label}: the raw Microsoft record travels with the evidence",
              (row.get("raw_ref") or {}).get("Id") == ident)

    print("\n4 · D11/D12 · CreationTime is the activity instant")
    for label in ("exchange-malicious", "entra", "general"):
        row = rows.get(label)
        if not row:
            continue
        stamp = ((row.get("provenance") or {}).get("timestamps") or {}).get(
            "activity_occurred_at") or {}
        check(f"{label}: activity basis is m365:CreationTime",
              stamp.get("status") == "AVAILABLE"
              and stamp.get("source") == "m365:CreationTime",
              f"{stamp.get('status')} {stamp.get('source')}")
        obs = ((row.get("provenance") or {}).get("timestamps") or {}).get(
            "sensor_observed_at") or {}
        check(f"{label}: no sensor observation is invented for a service log",
              obs.get("status") != "AVAILABLE", str(obs.get("status")))
    mal = rows.get("exchange-malicious")
    if mal:
        check("the activity instant is the recorded one, not ingest time",
              str(mal.get("event_time", "")).startswith("2026-06-02T09:15"),
              str(mal.get("event_time")))

    print("\n5 · detection SECOND — on evidence that genuinely exists")
    if mal:
        cloud = mal.get("cloud") or {}
        check("the inbox-rule parameters are canonical evidence",
              (cloud.get("request_parameters") or {}).get("ForwardTo")
              == "attacker@evil.example",
              json.dumps(cloud.get("request_parameters")))
        cit = matches.find_one({"rule_id": "DET-PS-004",
                                "canonical_event_id": mal.get("event_id")})
        check("DET-PS-004 detected the forwarding rule", bool(cit))
        if cit:
            fields = {c["canonical_field"]
                      for c in cit.get("matched_conditions") or []}
            check("it is DECLARED and fully cited",
                  cit.get("declaration_state") == "DECLARED"
                  and cit.get("citation_completeness") == "CITED",
                  f"{cit.get('declaration_state')}/"
                  f"{cit.get('citation_completeness')}")
            check("it cites the operation and the recorded parameters",
                  fields == {"cloud.action", "cloud.request_parameters"},
                  str(sorted(fields)))
    for label in ("exchange-benign", "entra", "general"):
        row = rows.get(label)
        if not row:
            continue
        check(f"{label}: ordinary Microsoft administration is NOT detected "
              "as an inbox-rule attack",
              matches.count_documents(
                  {"canonical_event_id": row.get("event_id"),
                   "rule_id": "DET-PS-004"}) == 0)

    print("\n6 · fail-closed: a non-Microsoft payload declared as M365")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [
                          env(col, f"m365:{STAMP}:wrong", {
                              "eventName": "PutUserPolicy",
                              "eventSource": "iam.amazonaws.com",
                              "eventTime": "2026-06-02T09:30:00Z",
                              "eventID": f"ct-{STAMP}"})]})
    blocked = body.get("routing_blocked") if isinstance(body, dict) else None
    reasons = {o.get("mismatch_reason")
               for o in (body.get("reasoning") or [])}
    check("the declaration is not overridden by content",
          code == 200 and blocked == 1
          and "SOURCE_FORMAT_MISMATCH" in reasons,
          f"{code} blocked={blocked} {sorted(r for r in reasons if r)}")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [
                          env(col, f"m365:{STAMP}:nocommon", {
                              "Id": f"broken-{STAMP}",
                              "CreationTime": "2026-06-02T09:31:00"})]})
    st = [o.get("status") for o in (body.get("reasoning") or [])]
    check("a record missing the common schema is refused, not guessed",
          code == 200 and st and st[0] in ("BLOCKED", "NO_DSM"),
          f"{code} {st}")

    print("\n7 · the D21 routing surface shows the Microsoft deliveries")
    code, body = call(f"/api/xdr/ingest/routing/deliveries?collector_id={col}"
                      f"&limit=50", token=token)
    vrows = body.get("rows") or [] if isinstance(body, dict) else []
    acc = [r for r in vrows if r["delivery"] == "ACCEPTED"]
    check("accepted Microsoft deliveries are visible with their DSM",
          code == 200 and len(acc) >= 4
          and {r["selected_dsm_id"] for r in acc} == {"m365-unified-audit"},
          f"{len(acc)} accepted")
    check("the refusals are visible with their reason codes",
          {"SOURCE_FORMAT_MISMATCH"} <= {r["reason_code"] for r in vrows
                                         if r["delivery"] == "BLOCKED"},
          str(sorted({r["reason_code"] for r in vrows
                      if r["delivery"] == "BLOCKED"})))

    print("\n" + ("MICROSOFT PHASE 1a: PASS — SYNTHETIC/REPLAY PROVEN "
                  "(NOT real-source proven)" if ok
                  else "MICROSOFT PHASE 1a: FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
