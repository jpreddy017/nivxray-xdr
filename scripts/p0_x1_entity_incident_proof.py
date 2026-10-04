#!/usr/bin/env python3
"""Gate X1 · entity resolution + multi-evidence incident, on REAL evidence.

Unlike the unit suite, this composes incidents from canonical evidence that
actually travelled the authenticated ingest route: Sysmon DNS + connection
(endpoint evidence, process-attributed) and a Zeek connection to the SAME
address at the same time (network evidence, no process).

The two proofs that matter:
  * the endpoint records compose into ONE incident, on an authoritative
    entity, citing every canonical event;
  * the Zeek record — same address, same instant — does NOT join it.

EVIDENCE LABELLING — TEST/SYNTHETIC records in each source's documented
shape, delivered over the real route. No live source is claimed.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv                                  # noqa: E402

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
STAMP = int(time.time())
TEN = "default"
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
NOW = datetime.now(timezone.utc)

GUID = f"{{x1-{STAMP}-aaaa}}"
# Entities are durable by design: a re-run must not inherit the previous
# run's retracted/contradicted edges for the same host and address.
HOSTIP = f"10.60.{(STAMP // 60) % 250}.{(STAMP % 240) + 5}"
COMPUTER = f"WS-X1-{STAMP}"
PEER = f"203.0.113.{STAMP % 200 + 30}"
DOMAIN = f"x1-proof-{STAMP}.example-cdn.net"

ok = True


def ago(seconds):
    return (NOW - timedelta(seconds=seconds)).isoformat()


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
        with urllib.request.urlopen(r, timeout=90) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()[:400]
        try:
            return e.code, json.loads(raw)
        except Exception:                                       # noqa: BLE001
            return e.code, raw


def provision(token):
    _, body = call("/api/xdr/collectors", "POST", token=token, tenant=TEN,
                   body={"name": f"x1-collector-{STAMP}", "protocol": "wef",
                         "authorized_sources": ["microsoft-sysmon",
                                                "zeek-json"]})
    col = (body.get("data") or {}).get("id")
    _, body = call("/api/xdr/api-keys", "POST", token=token, tenant=TEN,
                   body={"name": f"x1-key-{STAMP}", "confirm_tenant_id": TEN,
                         "allow_new_tenant": False,
                         "scopes": ["collectors.enroll", "collectors.read"]})
    d = body.get("data") or {}
    return col, d.get("plaintext") or d.get("api_key")


def env(col, sei, declared, raw):
    return {"tenant_id": TEN, "collector_id": col, "source_event_id": sei,
            "collection_method": "wef", "source": "x1-proof",
            "declared_source": declared, "raw": raw}


async def run(evidence):
    from motor.motor_asyncio import AsyncIOMotorClient
    from services import entity_resolution as er
    from services import multi_evidence_incident as mei
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]
    await mei.ensure_indexes(db)
    dns_doc, conn_doc, zeek_doc = evidence

    print("\n== 2 · COMPOSITION ON REAL INGESTED EVIDENCE ==")
    a = await mei.compose(db, tenant_id=TEN, canonical=dns_doc,
                          detections=[{"rule_id": f"DET-X1-{STAMP}"}])
    b = await mei.compose(db, tenant_id=TEN, canonical=conn_doc,
                          correlations=[{"correlation_id": "CORR-EP-001"}])
    check("the two endpoint records composed into ONE incident",
          b["merged_into_existing"] and
          a["incident"]["incident_id"] == b["incident"]["incident_id"],
          b["incident"]["incident_id"])
    inc = b["incident"]
    check("the incident cites BOTH canonical events",
          set(inc["event_ids"]) == {dns_doc["event_id"],
                                    conn_doc["event_id"]},
          str(inc["event_ids"]))
    check("it carries the detection AND the correlation",
          bool(inc.get("detections")) and bool(inc.get("correlations")))
    check("it composed on an AUTHORITATIVE entity",
          "authoritative" in inc["composition_basis"],
          inc["composition_basis"][:60])

    print("\n== 3 · THE FALSE MERGE THAT MUST NOT HAPPEN ==")
    z = await mei.compose(db, tenant_id=TEN, canonical=zeek_doc)
    check("network-only evidence on the SAME address does NOT join",
          not z["merged_into_existing"]
          and z["incident"]["incident_id"] != inc["incident_id"],
          z["incident"]["incident_id"])
    check("…and says why it stands alone",
          "no authoritative entity" in z["reason"])

    print("\n== 4 · RELATIONSHIP TRUTH ==")
    traced = await mei.trace(db, tenant_id=TEN,
                             incident_id=inc["incident_id"])
    states = {r["relationship_type"]: r["state"]
              for r in traced["relationships"]}
    # Sysmon names the endpoint only by hostname, which is a DECLARED
    # identity — so the edge is SUPPORTED, not AUTHORITATIVE. The process
    # identity is authoritative and is what the incident composed on.
    check("endpoint→process is SUPPORTED (Sysmon's endpoint scope is a "
          "declared hostname, not an authenticated endpoint)",
          states.get("endpoint_runs_process") == er.REL_SUPPORTED,
          str(states.get("endpoint_runs_process")))
    check("process→connected peer is AUTHORITATIVE",
          states.get("process_connected_to") == er.REL_AUTHORITATIVE,
          str(states.get("process_connected_to")))
    check("domain→resolved address is SUPPORTED",
          states.get("domain_resolved_to") == er.REL_SUPPORTED,
          str(states.get("domain_resolved_to")))
    check("endpoint→address is AMBIGUOUS",
          states.get("endpoint_used_address") == er.REL_AMBIGUOUS,
          str(states.get("endpoint_used_address")))
    check("address→endpoint is recorded FORBIDDEN, not omitted",
          states.get("address_identifies_endpoint") == er.REL_FORBIDDEN,
          str(states.get("address_identifies_endpoint")))
    check("every relationship traces back to canonical evidence",
          traced["every_relationship_cites_evidence"],
          str(traced["untraceable_relationship_ids"]))

    print("\n== 5 · REPLAY / IDEMPOTENCY ==")
    again = await mei.compose(db, tenant_id=TEN, canonical=dns_doc)
    check("a replayed record creates no second incident",
          again["incident"]["incident_id"] == inc["incident_id"])
    check("…and no duplicate entities",
          len(again["incident"]["entity_ids"])
          == len(inc["entity_ids"]),
          f"{len(inc['entity_ids'])} entities")

    print("\n== 6 · TENANT ISOLATION ==")
    other = f"x1-other-{STAMP}"
    o = await mei.compose(db, tenant_id=other, canonical=dns_doc)
    check("identical evidence in another tenant resolves separately",
          o["incident"]["incident_id"] != inc["incident_id"]
          and not (set(e["entity_id"] for e in o["entities"])
                   & set(inc["entity_ids"])))
    check("an incident is invisible across tenants",
          not (await mei.trace(db, tenant_id=other,
                               incident_id=inc["incident_id"]))["found"])

    print("\n== 7 · CONTRADICTION + RETRACTION ==")
    ents = er.resolve_entities(dns_doc, TEN)
    rel = next(r for r in er.derive_relationships(dns_doc, ents)
               if r.relationship_type == "endpoint_runs_process")
    rel.state = er.REL_AUTHORITATIVE   # disagrees with the stored SUPPORTED
    rel.evidence_refs = [f"xdr_canonical_evidence/contradict-{STAMP}"]
    stored = await mei._upsert_relationship(db, rel)
    check("a disagreeing claim is recorded CONTRADICTED",
          stored["state"] == er.REL_CONTRADICTED, stored["state"])
    check("…with BOTH sides' evidence retained",
          f"xdr_canonical_evidence/contradict-{STAMP}"
          in stored["evidence_refs"] and len(stored["evidence_refs"]) >= 2,
          str(len(stored["evidence_refs"])))
    check("…and the contradiction records what disagreed",
          stored["contradictions"][0]["previous_state"] == er.REL_SUPPORTED
          and stored["contradictions"][0]["asserted_state"]
          == er.REL_AUTHORITATIVE)
    target = next(r for r in traced["relationships"]
                  if r["relationship_type"] == "endpoint_used_address")
    after = await mei.retract_relationship(
        db, tenant_id=TEN, relationship_id=target["relationship_id"],
        reason="address lease could not be corroborated")
    check("a retracted relationship becomes UNRESOLVED",
          after["state"] == er.REL_UNRESOLVED, after["state"])
    check("…and keeps the evidence that produced it",
          after["evidence_refs"] == target["evidence_refs"])
    entity_count = await db[mei.ENTITIES].count_documents(
        {"tenant_id": TEN, "entity_id": {"$in": inc["entity_ids"]}})
    check("retraction destroyed no entities or evidence",
          entity_count == len(inc["entity_ids"]),
          f"{entity_count}/{len(inc['entity_ids'])}")

    # Leave preview as found: only this run's proof tenant rows.
    await db[mei.INCIDENTS].delete_many({"tenant_id": other})
    await db[mei.ENTITIES].delete_many({"tenant_id": other})
    await db[mei.RELATIONSHIPS].delete_many({"tenant_id": other})


def main():
    print(f"== X1 ENTITY RESOLUTION + MULTI-EVIDENCE INCIDENT · {BASE} ==")
    _, body = call("/api/auth/login", "POST",
                   body={"email": ADMIN[0], "password": ADMIN[1]})
    token = body.get("access_token")
    check("admin session", bool(token))
    if not token:
        return 1
    col, key = provision(token)
    check("collector + ingest key", bool(col and key))
    if not (col and key):
        return 1

    print("\n== 1 · REAL INGEST ==")
    sysmon_dns = {"event_id": 22, "provider": "Microsoft-Windows-Sysmon",
                  "Computer": COMPUTER, "User": "CORP\\alice",
                  "Image": "C:\\Windows\\System32\\curl.exe",
                  "ProcessId": "4711", "ProcessGuid": GUID,
                  "QueryName": DOMAIN,
                  "QueryResults": f"type:  1 {PEER};", "UtcTime": ago(120)}
    sysmon_conn = {"event_id": 3, "provider": "Microsoft-Windows-Sysmon",
                   "Computer": COMPUTER, "User": "CORP\\alice",
                   "Image": "C:\\Windows\\System32\\curl.exe",
                   "ProcessId": "4711", "ProcessGuid": GUID,
                   "SourceIp": HOSTIP, "SourcePort": "44100",
                   "DestinationIp": PEER, "DestinationPort": "443",
                   "Protocol": "tcp", "UtcTime": ago(100)}
    zeek_conn = {"_path": "conn", "_system_name": "zeek-x1",
                 "ts": time.time() - 100, "uid": f"Cx1{STAMP}",
                 "id.orig_h": HOSTIP, "id.orig_p": 44101,
                 "id.resp_h": PEER, "id.resp_p": 443, "proto": "tcp",
                 "duration": 3.0, "orig_bytes": 100, "resp_bytes": 900,
                 "orig_pkts": 4, "resp_pkts": 6, "conn_state": "SF"}
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TEN, body={"envelopes": [
                          env(col, f"x1:{STAMP}:dns", "microsoft-sysmon",
                              sysmon_dns),
                          env(col, f"x1:{STAMP}:conn", "microsoft-sysmon",
                              sysmon_conn),
                          env(col, f"x1:{STAMP}:zeek", "zeek-json",
                              zeek_conn)]})
    data = body.get("data") or body
    check("three records accepted through the real route",
          code == 200 and data.get("accepted") == 3,
          f"{code} accepted={data.get('accepted')}")

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]
    dns_doc = db["xdr_canonical_evidence"].find_one(
        {"tenant_id": TEN, "network.dns_query": DOMAIN})
    conn_doc = db["xdr_canonical_evidence"].find_one(
        {"tenant_id": TEN, "process.process_guid": GUID,
         "event_type": "network_connect"})
    zeek_doc = db["xdr_canonical_evidence"].find_one(
        {"tenant_id": TEN, "network.flow_id": f"Cx1{STAMP}"})
    check("all three pieces of canonical evidence persisted",
          all([dns_doc, conn_doc, zeek_doc]))
    if not all([dns_doc, conn_doc, zeek_doc]):
        return 1
    for d in (dns_doc, conn_doc, zeek_doc):
        d.pop("_id", None)

    asyncio.run(run((dns_doc, conn_doc, zeek_doc)))
    print(f"\n== RESULT: {'PASS' if ok else 'FAIL'} ==")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
