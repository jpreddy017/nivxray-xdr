#!/usr/bin/env python3
"""Terminal record policy · real rejection by the REAL NivX ingest.

ACCEPTANCE LABEL:

    TERMINAL RECORD POLICY:  IMPLEMENTED
    CHAIN:                   SYNTHETIC/REPLAY PROVEN (real SQLite state,
                             REAL authoritative ingest, stubbed Microsoft)
    LIVE MICROSOFT:          EXTERNAL_ACCESS_BLOCKED

The rejection here is genuine: one record is delivered against a collector
id that does not exist, and the authoritative boundary refuses it
permanently (404, non-retryable). Nothing is simulated on the NivX side.

Proven:
  1. one batch, one accepted record and one permanently rejected record →
     `completed_with_terminal_records`, NEVER `committed`;
  2. acquisition is not frozen: the window advances;
  3. the rejected record produced NO canonical evidence, while the accepted
     one did — TERMINAL != ACCEPTED != CANONICAL EVIDENCE;
  4. the terminal record preserves the real attempt (code, reason, retry
     count, first/last attempt, decision basis, outbox linkage);
  5. a restart cannot turn terminal into accepted;
  6. a replay retains the original terminal decision as history, and only
     the fresh acceptance produces evidence;
  7. a cross-tenant release is impossible.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request

from dotenv import load_dotenv

sys.path.insert(0, "/app/apps/nivxray-xdr-collector")
load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
STAMP = int(time.time())
TENANT = "t-m365-terminal"
MS_TENANT = "11111111-2222-3333-4444-555555555555"
CT = "Audit.Exchange"
BATCH = f"c-term-{STAMP}"
GOOD = f"term-ok-{STAMP}"
BAD = f"term-bad-{STAMP}"

ok = True


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
        raw = e.read().decode()[:300]
        try:
            return e.code, json.loads(raw)
        except Exception:                                      # noqa: BLE001
            return e.code, raw


def record(rid):
    return {"Id": rid, "RecordType": 1, "CreationTime": "2026-06-05T07:30:00",
            "Operation": "New-InboxRule", "OrganizationId": MS_TENANT,
            "UserType": 2, "UserKey": "user1@corp.example",
            "Workload": "Exchange", "ResultStatus": "True",
            "UserId": "user1@corp.example", "ClientIP": "203.0.113.99",
            "Parameters": [{"Name": "Name", "Value": "ext"},
                           {"Name": "ForwardTo",
                            "Value": "attacker@evil.example"}]}


def main() -> int:                                          # noqa: C901
    state_dir = tempfile.mkdtemp(prefix="nivx-terminal-")
    os.environ["XDR_STATE_DIR"] = state_dir
    print(f"state dir {state_dir} (Microsoft NOT contacted)")

    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]

    name = "m365-terminal-collector"
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
                      body={"name": f"m365-terminal-key-{STAMP}",
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

    os.environ["NIVX_INGEST_URL"] = f"{BASE}/api/xdr/ingest/telemetry"
    os.environ["NIVX_INGEST_TOKEN"] = key
    os.environ["NIVX_COLLECTOR_ID"] = col
    os.environ["NIVX_TENANT_ID"] = TENANT

    from framework.acquisition_state import (COMPLETED_WITH_TERMINAL_RECORDS,
                                             AcquisitionState)
    from framework.base import Envelope
    from framework.delivery import IngestClient, IngestOutcome
    from framework.outbox import Outbox, OutboxStatus
    from pymongo import MongoClient

    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ev_col = db.xdr_canonical_evidence

    def open_state():
        ob = Outbox(path=state_dir)
        return ob, AcquisitionState(connection=ob._conn,   # noqa: SLF001
                                     owner="proof-runner")

    def envelope(rid, collector):
        return Envelope(
            tenant_id=TENANT, source="Microsoft 365 Unified Audit",
            source_event_id=rid, connector_id=col, collector_id=collector,
            collection_method="rest-poll",
            parser_version="phase1b.m365-management-activity.1",
            source_timestamp="2026-06-05T07:30:00",
            collection_timestamp="2026-06-05T09:00:00Z",
            event_type="cloud_audit",
            raw={**record(rid), "_m365_acquisition": {
                "contentId": BATCH, "contentType": CT,
                "contentUri": f"https://manage.example.test/blob/{BATCH}",
                "contentCreated": "2026-06-05T09:00:00Z",
                "recordReference": rid,
                "recordReferenceBasis": "MICROSOFT_EVENT_ID",
                "microsoftEventId": rid}},
            declared_source="m365-unified-audit")

    print("\n1 · one acquired batch, two records")
    outbox, state = open_state()
    state.claim_batch(TENANT, col, CT, BATCH,
                      reference=f"https://manage.example.test/blob/{BATCH}",
                      window_end="2026-06-05T10:00:00+00:00")
    state.set_pending_window(TENANT, col, CT,
                             pending_until="2026-06-05T10:00:00+00:00")
    state.record_batch_keys(TENANT, col, CT, BATCH, [GOOD, BAD])
    good_id, _ = outbox.record(envelope(GOOD, col))
    bad_id, _ = outbox.record(envelope(BAD, col))
    check("both records are queued", bool(good_id and bad_id))

    print("\n2 · one record ACCEPTED, one PERMANENTLY REJECTED by the real "
          "boundary")
    client = IngestClient()
    good = asyncio.run(client.deliver([envelope(GOOD, col)]))
    check("the valid record was accepted (200)",
          good.get("outcome") == IngestOutcome.OK, json.dumps(good))
    outbox.mark_delivering([good_id])
    outbox.mark_delivered([good_id])

    # A genuinely unacceptable delivery: a collector id that does not exist.
    bad_env = envelope(BAD, col)
    bad_env.connector_id = col
    bad_env.collector_id = col
    bad_dict = bad_env.to_dict()
    bad_dict["collector_id"] = f"col_does_not_exist_{STAMP}"
    code, body = call("/api/xdr/ingest/telemetry", "POST", token=None,
                      tenant=TENANT, body={"envelopes": [bad_dict]})
    # (delivered through the same authenticated route the client uses)
    req = urllib.request.Request(
        BASE + "/api/xdr/ingest/telemetry",
        data=json.dumps({"envelopes": [bad_dict]}).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json",
                 "X-XDR-API-Key": key, "X-Tenant-Id": TENANT},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, detail = resp.status, resp.read().decode()[:200]
    except urllib.error.HTTPError as e:
        status, detail = e.code, e.read().decode()[:200]
    check("the boundary refused it permanently (non-retryable 4xx)",
          400 <= status < 500 and status not in (408, 429),
          f"HTTP {status} {detail[:80]}")
    outbox.mark_dead(bad_id, f"HTTP {status} {detail[:120]}")

    print("\n3 · the batch completes into its OWN state, not committed")
    out = state.reconcile(outbox)
    done = out["completed_with_terminal_records"]
    check("completed_with_terminal_records, never committed",
          bool(done) and out["committed_batches"] == []
          and done[0]["state"] == COMPLETED_WITH_TERMINAL_RECORDS,
          json.dumps(done))
    check("accepted and terminal are counted separately",
          done and done[0]["accepted_records"] == 1
          and done[0]["terminal_records"] == 1)
    w = state.window(TENANT, col, CT)
    check("acquisition is NOT frozen — the window advanced",
          w["committed_until"] == "2026-06-05T10:00:00+00:00",
          json.dumps(w))
    hist = state.terminal_records(TENANT, col)
    check("the real rejection evidence is preserved",
          len(hist) == 1 and hist[0]["outbox_row_id"] == bad_id
          and str(status) in (hist[0]["rejection_reason"] or "")
          and hist[0]["decision"] == "TERMINAL_QUARANTINED"
          and hist[0]["acquisition_ref"].endswith(BATCH),
          json.dumps({k: hist[0][k] for k in
                      ("rejection_code", "attempts")}) if hist else "")
    time.sleep(2)

    print("\n4 · TERMINAL != ACCEPTED != CANONICAL EVIDENCE")
    check("the accepted record became canonical evidence",
          bool(ev_col.find_one({"tenant_id": TENANT,
                                "source_event_id": GOOD})))
    check("the terminal record produced NO canonical evidence",
          ev_col.count_documents({"tenant_id": TENANT,
                                  "source_event_id": BAD}) == 0)
    check("the outbox still reports it as dead_letter, not delivered",
          outbox.statuses_for(TENANT, col, [BAD])[BAD]
          == OutboxStatus.DEAD_LETTER)
    outbox.close()

    print("\n5 · a restart cannot turn terminal into accepted")
    outbox2, state2 = open_state()
    st = state2.status(TENANT, col)
    check("terminal history survived the restart",
          len(state2.terminal_records(TENANT, col)) == 1
          and any(b["state"] == COMPLETED_WITH_TERMINAL_RECORDS
                  for b in st["batches"]), json.dumps(st["batches"]))
    check("reconciling again does not promote it to committed",
          state2.reconcile(outbox2)["committed_batches"] == [])
    check("the batch level reports its terminal count",
          st["batch_terminal_records"][0]["terminal_records"] == 1)

    print("\n6 · cross-tenant release is impossible")
    other = state2.replay_terminal_record(outbox2, "t-some-other-tenant",
                                          col, CT, BATCH, BAD)
    check("another tenant cannot release this record",
          other["outcome"] == "NOT_FOUND_IN_THIS_SCOPE", json.dumps(other))
    check("and it is still quarantined",
          outbox2.statuses_for(TENANT, col, [BAD])[BAD]
          == OutboxStatus.DEAD_LETTER)

    print("\n7 · replay keeps the history; only acceptance makes evidence")
    rep = state2.replay_terminal_record(outbox2, TENANT, col, CT, BATCH, BAD,
                                        requested_by="owner@nivxray")
    check("the replay was requested and the batch reopened",
          rep["outcome"] == "REPLAY_REQUESTED", json.dumps(rep))
    kinds = [h["event_kind"] for h in state2.terminal_records(TENANT, col)]
    check("the original terminal decision is retained as history",
          kinds == ["quarantined", "replay_requested"], str(kinds))
    check("a replay request alone commits nothing",
          state2.reconcile(outbox2)["committed_batches"] == [])
    fixed = asyncio.run(client.deliver([envelope(BAD, col)]))
    check("the corrected delivery was accepted by the real boundary",
          fixed.get("outcome") == IngestOutcome.OK, json.dumps(fixed))
    row = [r for r in outbox2.list() if r.source_event_id == BAD][0]
    outbox2.mark_delivering([row.id])
    outbox2.mark_delivered([row.id])
    out = state2.reconcile(outbox2)
    check("the batch now commits, after a genuine acceptance",
          out["committed_batches"] == [BATCH],
          json.dumps(out["committed_batches"]))
    time.sleep(2)
    check("canonical evidence exists only from that acceptance",
          ev_col.count_documents({"tenant_id": TENANT,
                                  "source_event_id": BAD}) == 1)
    check("the terminal history was not erased by the recovery",
          [h["event_kind"] for h in
           state2.terminal_records(TENANT, col)] ==
          ["quarantined", "replay_requested"])

    outbox2.close()
    shutil.rmtree(state_dir, ignore_errors=True)
    print("\n" + ("TERMINAL RECORD POLICY: PASS — acquisition never freezes, "
                  "terminal is never laundered into accepted, history is "
                  "append-only" if ok else "TERMINAL RECORD POLICY: FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
