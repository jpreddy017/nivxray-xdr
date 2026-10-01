#!/usr/bin/env python3
"""Gate N2.1 · endpoint/process → network attribution, over real HTTP.

Proves, against the running preview backend:

  1. Sysmon EID 22 and EID 3 delivered through the authenticated ingest
     boundary now carry `ProcessGuid` into canonical evidence, with
     provenance — the identity that was previously parsed and thrown away;
  2. a NivXForge sensor NETWORK event carrying the process START identity
     becomes an authoritative `process_iid`, and the SAME event without it
     is honestly downgraded to PID_ONLY_NOT_AUTHORITATIVE;
  3. `CORR-EP-001` establishes Endpoint → Process → Network peer through
     the EXISTING engine and cites both canonical event ids;
  4. the false joins do NOT occur: different process, different endpoint,
     different peer, wrong order, PID-only evidence, and — the prohibition
     itself — address+time coincidence with no process identity;
  5. endpoint address observations are recorded as time-bounded evidence
     against a REAL database and are structurally refused as identity.

EVIDENCE LABELLING — TEST/SYNTHETIC records in each source's documented
shape, delivered over the real authenticated route. Live Sysmon feed is
ABSENT; the live sensor host is EXTERNAL_ACCESS_BLOCKED. Nothing here is a
real-source claim.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
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

EP = f"ep_n2proof{STAMP}"
GUID = f"{{n2-{STAMP}-aaaa}}"
OTHER_GUID = f"{{n2-{STAMP}-bbbb}}"
HOSTIP = "10.99.0.21"
PEER = f"203.0.113.{STAMP % 200 + 20}"
DOMAIN = f"n2-proof-{STAMP}.example-cdn.net"
#: The correlation engine's window is real: the proof's activity instants
#: must be NOW, not a fixed date, or the signals fall outside it.
NOW = datetime.now(timezone.utc)


def ago(seconds: int) -> str:
    return (NOW - timedelta(seconds=seconds)).isoformat()

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
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=90) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()[:500]
        try:
            return e.code, json.loads(raw)
        except Exception:                                       # noqa: BLE001
            return e.code, raw


def login():
    code, body = call("/api/auth/login", "POST",
                      body={"email": ADMIN[0], "password": ADMIN[1]})
    return body.get("access_token") if code == 200 else None


def provision(token):
    code, body = call("/api/xdr/collectors", "POST", token=token, tenant=TEN,
                      body={"name": f"n2-proof-collector-{STAMP}",
                            "protocol": "wef",
                            "authorized_sources": ["microsoft-sysmon",
                                                   "nivxforge-linux-sensor"]})
    col = (body.get("data") or {}).get("id")
    code, body = call("/api/xdr/api-keys", "POST", token=token, tenant=TEN,
                      body={"name": f"n2-key-{STAMP}",
                            "confirm_tenant_id": TEN,
                            "allow_new_tenant": False,
                            "scopes": ["collectors.enroll",
                                       "collectors.read"]})
    d = body.get("data") or {}
    key = (d.get("api_key") or d.get("key") or d.get("secret")
           or d.get("plaintext") or d.get("token") or d.get("value"))
    return col, key


def envelope(col, sei, declared, raw):
    return {"tenant_id": TEN, "collector_id": col, "source_event_id": sei,
            "collection_method": "wef", "source": "n2-proof",
            "declared_source": declared, "raw": raw}


def deliver(key, envelopes):
    return call("/api/xdr/ingest/telemetry", "POST", key=key, tenant=TEN,
                body={"envelopes": envelopes})


def sysmon_dns(guid=GUID):
    return {"event_id": 22, "provider": "Microsoft-Windows-Sysmon",
            "Computer": "WS-N2-PROOF", "User": "CORP\\alice",
            "Image": "C:\\Windows\\System32\\curl.exe", "ProcessId": "4711",
            "ProcessGuid": guid,
            "ParentProcessGuid": f"{{n2-{STAMP}-parent}}",
            "QueryName": DOMAIN, "QueryResults": f"type:  1 {PEER};",
            "UtcTime": ago(120)}


def sysmon_conn(guid=GUID, peer=PEER):
    return {"event_id": 3, "provider": "Microsoft-Windows-Sysmon",
            "Computer": "WS-N2-PROOF", "User": "CORP\\alice",
            "Image": "C:\\Windows\\System32\\curl.exe", "ProcessId": "4711",
            "ProcessGuid": guid, "SourceIp": HOSTIP, "SourcePort": "44122",
            "DestinationIp": peer, "DestinationPort": "443",
            "Protocol": "tcp", "UtcTime": ago(100)}


def sensor_net(with_start=True):
    ev = {"activity": "NETWORK", "operation": "CONNECTION_OBSERVED",
          "observed_at": ago(90), "protocol": "TCP",
          "collection_method": "PROC_POLL",
          "local_ip": HOSTIP, "local_port": 44123, "remote_ip": PEER,
          "remote_port": 443, "direction": "OUTBOUND", "tcp_state": "01",
          "pid": 4711, "endpoint_id": EP, "hostname": "linux-n2-proof",
          "not_observed": []}
    if with_start:
        ev["process_start_ticks"] = 998877
        ev["process_start_time"] = ago(300)
    else:
        ev["not_observed"] = ["owning_process_start_identity"]
    return ev


def mongo():
    from pymongo import MongoClient
    return MongoClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]


def find_rule(token, fragment):
    _, body = call("/api/xdr/correlation/rules?limit=1000", token=token,
                   tenant=TEN)
    for r in ((body.get("data") or {}).get("rules") or []):
        if fragment.lower() in (r.get("name") or "").lower():
            return r
    return None


def post_signals(token, signals):
    _, body = call("/api/xdr/correlation/signals", "POST", token=token,
                   tenant=TEN, body={"signals": signals})
    return ((body.get("data") or {}).get("matches") or [])


async def address_evidence_proof():
    """Section 5 — against a REAL database, not a fake."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from edr_plane import endpoint_address_observation as eao
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[
        os.environ.get("DB_NAME") or "test_database"]
    await eao.ensure_indexes(db)
    canonical = {"event_id": f"cev-n2-{STAMP}",
                 "event_time": ago(90),
                 "source_product": "LinuxSensor",
                 "network": {"src_ip": HOSTIP, "dest_ip": PEER}}
    rec = await eao.record_from_canonical(
        db, tenant_id=TEN, endpoint_id=EP, canonical=canonical)
    check("the endpoint's OWN address is recorded as evidence",
          rec and rec["address"] == HOSTIP, str(rec))
    row = await db[eao.COLLECTION].find_one(
        {"tenant_id": TEN, "endpoint_id": EP, "address": HOSTIP}, {"_id": 0})
    check("the row states its lifecycle and its provenance",
          bool(row) and row["binding_policy"]
          == "TIME_BOUNDED_OBSERVATION_NOT_IDENTITY"
          and row["provenance"]["observed_field"] == "network.src_ip"
          and row["first_observed_at"] and row["last_observed_at"],
          str(row and row.get("binding_policy")))
    check("the peer's address is NOT recorded as the endpoint's",
          await db[eao.COLLECTION].count_documents(
              {"tenant_id": TEN, "address": PEER}) == 0)
    single = await eao.lookup(db, tenant_id=TEN, address=HOSTIP,
                              at=ago(90))
    check("a lookup inside the window is still NOT an attribution",
          single["state"] == "SINGLE_CANDIDATE_TIME_BOUNDED"
          and single["usable_for_attribution"] is False,
          single["state"])
    stale = await eao.lookup(db, tenant_id=TEN, address=HOSTIP,
                             at="2020-01-01T00:00:00+00:00")
    check("an address observed at another time answers nothing about now",
          stale["state"] == "OUTSIDE_OBSERVED_WINDOW"
          and stale["usable_for_attribution"] is False, stale["state"])
    await db[eao.COLLECTION].delete_many({"tenant_id": TEN,
                                          "endpoint_id": EP})


def main():
    print(f"== N2.1 ENDPOINT/PROCESS ATTRIBUTION LIVE PROOF · {BASE} ==")
    token = login()
    check("admin session", bool(token))
    if not token:
        return 1
    col, key = provision(token)
    check("collector + ingest key", bool(col and key), f"collector={col}")
    if not (col and key):
        return 1

    # ── 1 · Sysmon keeps its identity through the real ingest path ──
    print("\n== 1 · SYSMON ProcessGuid SURVIVES INGEST ==")
    dns_sei, conn_sei = f"n2:{STAMP}:dns", f"n2:{STAMP}:conn"
    code, body = deliver(key, [
        envelope(col, dns_sei, "microsoft-sysmon", sysmon_dns()),
        envelope(col, conn_sei, "microsoft-sysmon", sysmon_conn()),
    ])
    data = body.get("data") or body
    check("both Sysmon records accepted", code == 200
          and data.get("accepted") == 2, f"{code} {data.get('accepted')}")
    db = mongo()
    dns_doc = db["xdr_canonical_evidence"].find_one(
        {"tenant_id": TEN, "network.dns_query": DOMAIN})
    conn_doc = db["xdr_canonical_evidence"].find_one(
        {"tenant_id": TEN, "network.dest_ip": PEER,
         "event_type": "network_connect",
         "process.process_guid": GUID})
    check("DNS + connection evidence persisted",
          bool(dns_doc) and bool(conn_doc))
    if not (dns_doc and conn_doc):
        return 1
    check("ProcessGuid reached canonical evidence on the DNS record",
          dns_doc["process"]["process_guid"] == GUID,
          dns_doc["process"].get("process_guid"))
    check("…with field-level provenance",
          dns_doc["process"]["field_provenance"].get("process_guid")
          == "sysmon:EventData.ProcessGuid")
    check("…and an authoritative attribution state",
          dns_doc["process"]["attribution_state"] == "SOURCE_PROCESS_IDENTITY"
          and conn_doc["process"]["attribution_state"]
          == "SOURCE_PROCESS_IDENTITY")
    check("the DNS answer and the connection peer are the same address",
          dns_doc["network"]["dns_response_ips"] == [PEER]
          and conn_doc["network"]["dest_ip"] == PEER)

    # ── 2 · the sensor path: start identity decides ────────────────
    print("\n== 2 · SENSOR NETWORK EVENT · START IDENTITY DECIDES ==")
    good_sei, weak_sei = f"n2:{STAMP}:sensor-ok", f"n2:{STAMP}:sensor-pidonly"
    code, body = deliver(key, [
        envelope(col, good_sei, "nivxforge-linux-sensor", sensor_net(True)),
        envelope(col, weak_sei, "nivxforge-linux-sensor", sensor_net(False)),
    ])
    data = body.get("data") or body
    check("both sensor events accepted", data.get("accepted") == 2,
          str(data.get("accepted")))
    sensor_docs = list(db["xdr_canonical_evidence"].find(
        {"tenant_id": TEN, "source_product": "LinuxSensor",
         "network.src_ip": HOSTIP}))
    authoritative = [d for d in sensor_docs
                     if d.get("process", {}).get("attribution_state")
                     == "SOURCE_PROCESS_IDENTITY"]
    pid_only = [d for d in sensor_docs
                if d.get("process", {}).get("attribution_state")
                == "PID_ONLY_NOT_AUTHORITATIVE"]
    check("with start identity → an authoritative process_iid",
          bool(authoritative)
          and authoritative[0]["process"]["process_iid"].startswith("proc_"),
          str(authoritative[0]["process"].get("process_iid"))
          if authoritative else "none")
    check("without it → PID_ONLY_NOT_AUTHORITATIVE, and no iid",
          bool(pid_only) and not pid_only[0]["process"].get("process_iid"),
          str(len(pid_only)))
    check("the downgrade explains WHY",
          bool(pid_only) and "reused" in
          pid_only[0]["process"]["attribution_reason"])

    # ── 3 · the relationship ───────────────────────────────────────
    print("\n== 3 · ENDPOINT → PROCESS → NETWORK PEER ==")
    from detection_content.telemetry.network_signals import (
        signals_from_canonical)
    rule = find_rule(token, "Process Resolved A Domain")
    check("CORR-EP-001 exists and ships DISABLED",
          bool(rule) and not rule.get("enabled"),
          str(rule and rule.get("enabled")))
    if not rule:
        return 1
    call(f"/api/xdr/correlation/rules/{rule['id']}/enable", "POST",
         token=token, tenant=TEN)
    sigs = signals_from_canonical(dns_doc) + signals_from_canonical(conn_doc)
    check("both signals carry the endpoint and the process key",
          all(s["fields"].get("process_key") == GUID for s in sigs)
          and all(s["fields"].get("endpoint_id") for s in sigs))
    matches = post_signals(token, sigs)
    supported = [m for m in matches if m.get("correlation_id") == rule["id"]
                 and m.get("level") == "CORRELATION_SUPPORTED"]
    check("the relationship is SUPPORTED", bool(supported),
          f"matches={len(matches)}")
    if supported:
        m = supported[0]
        check("it cites BOTH canonical event ids",
              set(m.get("raw_event_ids") or [])
              == {dns_doc["event_id"], conn_doc["event_id"]},
              str(m.get("raw_event_ids")))
        check("the entity key is endpoint | process | peer",
              m.get("entity_key", "").endswith(f"|{GUID}|{PEER}"),
              m.get("entity_key"))
        check("evidence, never a verdict",
              m.get("capability_not_verdict") is True)

    # ── 4 · the false joins ────────────────────────────────────────
    print("\n== 4 · FALSE JOINS MUST NOT OCCUR ==")

    def variant(sig, **fields):
        out = json.loads(json.dumps(sig))
        out["fields"].update(fields)
        out["source_event_id"] = f"cev-variant-{fields}"
        return out

    conn_sig = sigs[1]
    cases = [
        ("a different process on the same host and address",
         variant(conn_sig, process_key=OTHER_GUID)),
        ("the same process identity on another endpoint",
         variant(conn_sig, endpoint_id="ep_someone_else")),
        ("a connection to a different peer",
         variant(conn_sig, network_peer_ip="198.51.100.200")),
        ("PID-only evidence",
         variant(conn_sig, process_attribution_state=
                 "PID_ONLY_NOT_AUTHORITATIVE", process_key=None)),
    ]
    for label, sig in cases:
        got = [m for m in post_signals(token, [sig])
               if m.get("correlation_id") == rule["id"]
               and m.get("level") == "CORRELATION_SUPPORTED"]
        check(f"{label} does not join", not got, f"matches={len(got)}")

    # The prohibition itself: address + instant, no process identity.
    coincidence = [
        variant(sigs[0], process_key=None,
                process_attribution_state="NOT_OBSERVED"),
        variant(conn_sig, process_key=None,
                process_attribution_state="NOT_OBSERVED"),
    ]
    got = [m for m in post_signals(token, coincidence)
           if m.get("correlation_id") == rule["id"]]
    check("address + time coincidence alone produces NOTHING", not got,
          f"matches={len(got)}")

    # ── 5 · endpoint address evidence (real database) ──────────────
    print("\n== 5 · ENDPOINT ADDRESS EVIDENCE (NOT IDENTITY) ==")
    asyncio.run(address_evidence_proof())

    # ── 6 · restore ───────────────────────────────────────────────
    print("\n== 6 · RESTORE ==")
    call(f"/api/xdr/correlation/rules/{rule['id']}/disable", "POST",
         token=token, tenant=TEN)
    again = find_rule(token, "Process Resolved A Domain")
    check("CORR-EP-001 is disabled again", not again.get("enabled"))

    print(f"\n== RESULT: {'PASS' if ok else 'FAIL'} ==")
    print("== LIVE SOURCES: Sysmon feed ABSENT · NivXForge live host "
          "EXTERNAL_ACCESS_BLOCKED ==")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
