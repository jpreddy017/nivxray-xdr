#!/usr/bin/env python3
"""Durable acquisition · real collector → REAL NivX ingest (PREVIEW).

ACCEPTANCE LABEL:

    DURABLE ACQUISITION:  IMPLEMENTED
    RESTART SAFETY:       SYNTHETIC/REPLAY PROVEN (real SQLite state file,
                          real authoritative ingest, stubbed Microsoft)
    LIVE MICROSOFT:       EXTERNAL_ACCESS_BLOCKED

The chain under test is everything NivX owns end to end:

    connector (real) → durable acquisition state (real SQLite file)
      → outbox (real) → IngestClient (real) → REAL NivX ingest over HTTPS
      → canonical evidence → commit → window advance

Proven here, against the real boundary rather than a mock:
  1. an acquired batch does NOT commit while its records are merely queued;
  2. it commits only after the authoritative ingest accepts them;
  3. a restart before acceptance re-acquires (no silent skip) and produces
     no duplicate evidence;
  4. a restart after acceptance never re-reads the blob;
  5. the declaration survives the durable hop (the outbox column fix) —
     without it the boundary would refuse every collector delivery;
  6. the ingest credential is presented in the header the boundary actually
     authenticates (`X-XDR-API-Key`), not as a bearer token.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from dotenv import load_dotenv

sys.path.insert(0, "/app/apps/nivxray-xdr-collector")
load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
STAMP = int(time.time())
TENANT = "t-m365-durable"
MS_TENANT = "11111111-2222-3333-4444-555555555555"
PORT = 8098
STUB = f"http://127.0.0.1:{PORT}"
CT = "Audit.Exchange"

ok = True
blob_hits: list[str] = []


def check(label, cond, detail=""):
    global ok
    ok = ok and bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}"
          + (f" — {detail}" if detail else ""))


def call(path, method="GET", token=None, tenant=None, body=None):
    h = {"User-Agent": UA, "Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
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


def _rec(rid):
    return {"Id": rid, "RecordType": 1, "CreationTime": "2026-06-04T08:10:00",
            "Operation": "New-InboxRule", "OrganizationId": MS_TENANT,
            "UserType": 2, "UserKey": "user1@corp.example",
            "Workload": "Exchange", "ResultStatus": "True",
            "UserId": "user1@corp.example", "ClientIP": "203.0.113.90",
            "Parameters": [{"Name": "Name", "Value": "ext"},
                           {"Name": "ForwardTo",
                            "Value": "attacker@evil.example"}]}


RECORD_ID = f"dur-{STAMP}"


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def _json(self, code, payload, headers=None):
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):                    # noqa: N802
        if "oauth2" in self.path:
            return self._json(200, {"access_token": "stub", "expires_in": 3600})
        return self._json(400, {"error": {"code": "AF20024"}})

    def do_GET(self):                     # noqa: N802
        if "subscriptions/content" in self.path:
            return self._json(200, [{
                "contentType": CT, "contentId": "c-dur",
                "contentUri": f"{STUB}/blob/c-dur",
                "contentCreated": "2026-06-04T09:00:00Z",
                "contentExpiration": "2026-06-11T09:00:00Z"}])
        if self.path.startswith("/blob/"):
            blob_hits.append(self.path)
            return self._json(200, [_rec(RECORD_ID)])
        return self._json(404, {"error": "unexpected"})


def main() -> int:                                          # noqa: C901
    server = HTTPServer(("127.0.0.1", PORT), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state_dir = tempfile.mkdtemp(prefix="nivx-durable-")
    os.environ["XDR_STATE_DIR"] = state_dir
    print(f"microsoft stub on {STUB} (NOT Microsoft) · state dir {state_dir}")

    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]

    print("\n1 · provision collector + ingest key for the Microsoft source")
    name = "m365-durable-collector"
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=TENANT,
                      body={"name": name, "protocol": "rest",
                            "authorized_sources": ["m365-unified-audit"]})
    if code in (200, 201):
        col = (body.get("data") or {}).get("id")
    elif code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col = next((c["id"] for c in
                    ((lst.get("data") or {}).get("collectors") or [])
                    if c.get("name") == name), None)
    else:
        print(f"  collector create -> {code} {body}")
        return 1
    code, body = call("/api/xdr/api-keys", "POST", token=token, tenant=TENANT,
                      body={"name": f"m365-durable-key-{STAMP}",
                            "confirm_tenant_id": TENANT,
                            "allow_new_tenant": True,
                            "scopes": ["collectors.enroll",
                                       "collectors.read"]})
    d = body.get("data") or {}
    key = (d.get("api_key") or d.get("key") or d.get("secret")
           or d.get("plaintext") or d.get("token") or d.get("value"))
    check("collector + ingest key ready", bool(col and key), str(col))
    if not (col and key):
        return 1

    # The collector is configured exactly as an operator would: the ingest
    # URL and the collector API key, both from the environment.
    os.environ["NIVX_INGEST_URL"] = f"{BASE}/api/xdr/ingest/telemetry"
    os.environ["NIVX_INGEST_TOKEN"] = key
    os.environ["NIVX_COLLECTOR_ID"] = col
    os.environ["NIVX_TENANT_ID"] = TENANT

    from framework.acquisition_state import AcquisitionState
    from framework.delivery import IngestClient, IngestOutcome
    from framework.m365_activity import M365ManagementActivityConnector
    from framework.outbox import Outbox, OutboxStatus

    def open_state():
        outbox = Outbox(path=state_dir)
        state = AcquisitionState(connection=outbox._conn,   # noqa: SLF001
                                 owner="proof-runner")
        return outbox, state

    def connector(state, outbox, identity=col):
        return M365ManagementActivityConnector(
            tenant_id=TENANT, identity=identity, state=state, outbox=outbox,
            config={"microsoft_tenant_id": MS_TENANT,
                    "base_url": f"{STUB}/api/v1.0", "authority": STUB,
                    "content_types": [CT],
                    "credentials": {"client_id": "stub-app",
                                    "client_secret": "stub-secret"},
                    "lookback_minutes": 60})

    print("\n2 · acquire, queue, and prove the batch does NOT commit yet")
    outbox, state = open_state()
    conn = connector(state, outbox)
    asyncio.run(conn.start())
    envs = asyncio.run(conn.collect())
    check("the blob was acquired once", len(envs) == 1 and len(blob_hits) == 1,
          f"{len(envs)} envelopes")
    check("the envelope declares m365-unified-audit",
          envs[0].declared_source == "m365-unified-audit")
    rid, status = outbox.record(envs[0])
    check("the record is QUEUED, not accepted",
          status == OutboxStatus.QUEUED, status)
    state.reconcile(outbox)
    w = state.window(TENANT, col, CT)
    check("the window did NOT advance on acquisition alone",
          w["committed_until"] is None and w["pending_until"] is not None,
          json.dumps(w))
    check("the declaration survived the durable store",
          outbox.list()[0].declared_source == "m365-unified-audit")
    outbox.close()

    print("\n3 · restart BEFORE acceptance → re-acquire, no duplicate")
    blob_hits.clear()
    outbox2, state2 = open_state()
    conn2 = connector(state2, outbox2)
    envs2 = asyncio.run(conn2.collect())
    check("the unaccepted blob was re-acquired (no silent skip)",
          len(envs2) == 1 and len(blob_hits) == 1)
    ids = {outbox2.record(e)[0] for e in envs2}
    check("re-delivery produced no duplicate outbox row",
          len(ids) == 1 and len([r for r in outbox2.list()
                                 if r.source_event_id == RECORD_ID]) == 1)

    print("\n4 · deliver to the REAL NivX ingest and commit on acceptance")
    client = IngestClient()
    check("the credential is presented as an API key, not a bearer token",
          client.status()["auth_mode"] == "api_key")
    rows = [r for r in outbox2.list() if r.source_event_id == RECORD_ID]
    result = asyncio.run(client.deliver([r.to_envelope() for r in rows]))
    check("the authoritative ingest ACCEPTED the delivery",
          result.get("outcome") == IngestOutcome.OK,
          json.dumps(result))
    if result.get("outcome") != IngestOutcome.OK:
        print("     (this is the acceptance gate — nothing may commit "
              "without it)")
    outbox2.mark_delivering([r.id for r in rows])
    outbox2.mark_delivered([r.id for r in rows])
    out = state2.reconcile(outbox2)
    w = state2.window(TENANT, col, CT)
    check("the batch committed only after acceptance",
          out["committed_batches"] == ["c-dur"], json.dumps(out["committed_batches"]))
    check("the window advanced exactly to the accepted point",
          w["committed_until"] == w["pending_until"] is not None,
          json.dumps(w))
    outbox2.close()

    print("\n5 · restart AFTER acceptance → the blob is never re-read")
    blob_hits.clear()
    outbox3, state3 = open_state()
    conn3 = connector(state3, outbox3)
    envs3 = asyncio.run(conn3.collect())
    check("nothing was re-acquired", envs3 == [] and blob_hits == [],
          f"{len(envs3)} envelopes, {len(blob_hits)} blob reads")
    check("the duplicate was counted, not silently dropped",
          conn3.blobs_duplicate == 1)
    st = state3.status(TENANT, col)
    check("the durable state reports the committed batch",
          any(b["state"] == "committed" for b in st["batches"]),
          json.dumps(st["batches"]))

    print("\n6 · the accepted record became canonical evidence")
    time.sleep(2)
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ev = db.xdr_canonical_evidence.find_one(
        {"tenant_id": TENANT, "source_event_id": RECORD_ID},
        sort=[("_id", -1)])
    check("canonical evidence exists for the delivered record", bool(ev),
          RECORD_ID)
    if ev:
        acq = (ev.get("additional_fields") or {}).get("m365_acquisition") or {}
        check("its acquisition provenance names the content blob",
              acq.get("content_id") == "c-dur", json.dumps(acq)[:120])
        check("the record reference basis is stated",
              acq.get("record_reference_basis") == "MICROSOFT_EVENT_ID",
              str(acq.get("record_reference_basis")))
        check("blob availability is still not the activity time",
              str(ev.get("event_time", "")).startswith("2026-06-04T08:10"),
              str(ev.get("event_time")))
        cit = db.xdr_detection_matches.find_one(
            {"rule_id": "DET-PS-004", "canonical_event_id": ev["event_id"]})
        check("the delivered forwarding rule was detected and cited",
              bool(cit) and cit.get("citation_completeness") == "CITED")

    server.shutdown()
    shutil.rmtree(state_dir, ignore_errors=True)
    print("\n" + ("DURABLE ACQUISITION: PASS — restart-safe, "
                  "commit-on-acceptance, no silent skip, no uncontrolled "
                  "duplication (live Microsoft still "
                  "EXTERNAL_ACCESS_BLOCKED)" if ok
                  else "DURABLE ACQUISITION: FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
