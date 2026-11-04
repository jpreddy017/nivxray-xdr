#!/usr/bin/env python3
"""Microsoft telemetry Phase 1b · acquisition → authoritative DSM (PREVIEW).

ACCEPTANCE LABEL — do not quote this as anything else:

    ACQUISITION:        IMPLEMENTED
    END-TO-END CHAIN:   SYNTHETIC/REPLAY PROVEN
    LIVE MICROSOFT:     EXTERNAL_ACCESS_BLOCKED

A local stub stands in for Microsoft's token endpoint and Management
Activity API. Microsoft is NOT contacted. What is genuinely exercised is
everything NivX owns:

    the real connector (framework/m365_activity.py)
      → real OAuth2 client-credentials exchange against the stub
      → real subscription start, content list, NextPageUri pagination,
        contentUri blob fetch, checkpoint and blob-level dedup
      → real Envelope with declared_source = m365-unified-audit
      → REAL authenticated NivX ingest over HTTPS (D15 declared routing)
      → real canonical evidence, provenance and detection

Live acquisition needs an owner-side Entra app registration with the
application permission `ActivityFeed.Read` and admin consent; the script
prints exactly what is required and stops at that boundary.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
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
TENANT = "t-m365-phase1b"
MS_TENANT = "11111111-2222-3333-4444-555555555555"
PORT = 8099
STUB = f"http://127.0.0.1:{PORT}"

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


# ── the Microsoft stub · records Microsoft's own shapes ───────────
def _rec(rid, params):
    return {"Id": rid, "RecordType": 1, "CreationTime": "2026-06-03T07:45:00",
            "Operation": "New-InboxRule", "OrganizationId": MS_TENANT,
            "UserType": 2, "UserKey": "user1@corp.example",
            "Workload": "Exchange", "ResultStatus": "True",
            "ObjectId": "user1@corp.example", "UserId": "user1@corp.example",
            "ClientIP": "203.0.113.77", "ExternalAccess": False,
            "Parameters": params}


BLOBS = {
    "c1": [_rec(f"b1-{STAMP}", [{"Name": "Name", "Value": "ext-archive"},
                                {"Name": "ForwardTo",
                                 "Value": "attacker@evil.example"}])],
    "c2": [_rec(f"b2-{STAMP}", [{"Name": "Name", "Value": "triage"},
                                {"Name": "MoveToFolder",
                                 "Value": "Archive"}])],
}
HITS: dict[str, int] = {}


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *a):            # keep the proof output readable
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
        HITS[self.path.split("?")[0]] = HITS.get(
            self.path.split("?")[0], 0) + 1
        if "oauth2" in self.path:
            return self._json(200, {"access_token": f"stub-tok-{STAMP}",
                                    "expires_in": 3600})
        if "subscriptions/start" in self.path:
            # Microsoft's "already enabled" answer, to prove idempotency.
            return self._json(400, {"error": {"code": "AF20024",
                                              "message": "already enabled"}})
        return self._json(404, {"error": "unexpected"})

    def do_GET(self):                     # noqa: N802
        key = self.path.split("?")[0]
        HITS[key] = HITS.get(key, 0) + 1
        if "subscriptions/content" in self.path:
            if "page=2" in self.path:
                return self._json(200, [{
                    "contentType": "Audit.Exchange", "contentId": "c2",
                    "contentUri": f"{STUB}/blob/c2",
                    "contentCreated": "2026-06-03T09:05:00Z"}])
            return self._json(
                200,
                [{"contentType": "Audit.Exchange", "contentId": "c1",
                  "contentUri": f"{STUB}/blob/c1",
                  "contentCreated": "2026-06-03T09:00:00Z",
                  "contentExpiration": "2026-06-10T09:00:00Z"}],
                {"NextPageUri": f"{STUB}/api/v1.0/{MS_TENANT}/activity/feed/"
                                f"subscriptions/content?page=2"})
        if key.startswith("/blob/"):
            return self._json(200, BLOBS.get(key.rsplit("/", 1)[-1], []))
        return self._json(404, {"error": "unexpected"})


def main() -> int:                                          # noqa: C901
    server = HTTPServer(("127.0.0.1", PORT), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"microsoft stub listening on {STUB} (NOT Microsoft)")

    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body["access_token"]

    print("\n1 · provision the collector authorized for the Microsoft source")
    name = "m365-phase1b-collector"
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
        if col:
            call(f"/api/xdr/collectors/{col}", "PUT", token=token,
                 tenant=TENANT,
                 body={"authorized_sources": ["m365-unified-audit"]})
    else:
        print(f"  collector create -> {code} {body}")
        return 1
    code, body = call("/api/xdr/api-keys", "POST", token=token, tenant=TENANT,
                      body={"name": f"m365-phase1b-key-{STAMP}",
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

    print("\n2 · run the REAL connector against the stub Microsoft API")
    from framework.m365_activity import M365ManagementActivityConnector

    conn = M365ManagementActivityConnector(
        tenant_id=TENANT, identity=f"m365-{STAMP}", config={
            "microsoft_tenant_id": MS_TENANT,
            "base_url": f"{STUB}/api/v1.0",
            "authority": STUB,
            "content_types": ["Audit.Exchange"],
            "credentials": {"client_id": "stub-app",
                            "client_secret": "stub-secret"},
            "lookback_minutes": 60})

    asyncio.run(conn.start())
    check("subscription start is idempotent (AF20024 accepted)",
          conn.subscriptions_started == ["Audit.Exchange"],
          str(conn.subscriptions_started))
    envelopes = asyncio.run(conn.collect())
    check("the token was obtained by client credentials",
          conn.tokens.describe()["acquisitions"] == 1
          and conn.tokens.describe()["mode"] == "client_secret")
    check("pagination followed NextPageUri and both blobs were read",
          conn.blobs_read == 2 and len(envelopes) == 2,
          f"blobs={conn.blobs_read} envelopes={len(envelopes)}")
    check("every envelope DECLARES m365-unified-audit",
          {e.declared_source for e in envelopes} == {"m365-unified-audit"})
    check("acquisition metadata rides along, activity time does not move",
          all(e.raw["_m365_acquisition"]["contentCreated"].startswith(
              "2026-06-03T09") and e.raw["CreationTime"]
              == "2026-06-03T07:45:00" for e in envelopes))
    again = asyncio.run(conn.collect())
    check("a second poll re-reads nothing (blob dedup)", again == []
          and conn.blobs_duplicate >= 1,
          f"dup_blobs={conn.blobs_duplicate}")
    state = conn.checkpoint.vendor_state["Audit.Exchange"]
    check("the checkpoint advanced only after the page run completed",
          bool(state["window_start"]) and not state["next_page_uri"])

    print("\n3 · deliver the acquired envelopes to the REAL NivX ingest")
    payload = []
    for e in envelopes:
        row = e.to_dict()
        row["collector_id"] = col          # the enrolled, authorized collector
        row["tenant_id"] = TENANT
        payload.append(row)
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": payload})
    check("ingest accepted the declared Microsoft deliveries",
          code == 200 and body.get("accepted") == 2
          and body.get("routing_blocked") == 0,
          f"{code} accepted={body.get('accepted')} "
          f"blocked={body.get('routing_blocked')}")
    outs = body.get("reasoning") or []
    check("routing selected the Microsoft DSM from the declaration",
          all(o.get("selected_dsm_id") == "m365-unified-audit"
              for o in outs if o.get("status") == "REASONED"))
    time.sleep(2)

    print("\n4 · canonical evidence keeps acquisition and activity apart")
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ev = db.xdr_canonical_evidence
    matches = db.xdr_detection_matches

    mal = ev.find_one({"tenant_id": TENANT,
                       "source_event_id": f"b1-{STAMP}"},
                      sort=[("_id", -1)])
    benign = ev.find_one({"tenant_id": TENANT,
                          "source_event_id": f"b2-{STAMP}"},
                         sort=[("_id", -1)])
    check("acquired evidence exists for both records",
          bool(mal) and bool(benign))
    if mal:
        acq = (mal.get("additional_fields") or {}).get("m365_acquisition") \
            or {}
        stamp = ((mal.get("provenance") or {}).get("timestamps") or {}).get(
            "activity_occurred_at") or {}
        check("the content blob is recorded as acquisition provenance",
              acq.get("content_id") == "c1"
              and acq.get("content_type") == "Audit.Exchange"
              and str(acq.get("content_created", "")).startswith(
                  "2026-06-03T09"),
              json.dumps({k: acq.get(k) for k in
                          ("content_id", "content_created")}))
        check("blob availability is explicitly NOT activity time",
              "not when the activity happened" in str(acq.get("basis")))
        check("the activity basis is still m365:CreationTime",
              stamp.get("source") == "m365:CreationTime"
              and str(mal.get("event_time", "")).startswith(
                  "2026-06-03T07:45"),
              f"{stamp.get('source')} {mal.get('event_time')}")
        check("the Microsoft tenant is preserved as the PROVIDER tenant",
              (mal.get("cloud") or {}).get("provider_tenant_id") == MS_TENANT
              and mal.get("tenant_id") == TENANT)
        cit = matches.find_one({"rule_id": "DET-PS-004",
                                "canonical_event_id": mal.get("event_id")})
        check("the acquired forwarding rule was detected and cited",
              bool(cit) and cit.get("citation_completeness") == "CITED",
              str((cit or {}).get("citation_completeness")))
    if benign:
        check("the acquired benign rule was NOT detected",
              matches.count_documents(
                  {"canonical_event_id": benign.get("event_id"),
                   "rule_id": "DET-PS-004"}) == 0)

    server.shutdown()
    print("\n5 · EXTERNAL ACCESS BOUNDARY — owner-side setup required for "
          "REAL SOURCE PROVEN")
    print("""    Microsoft service ....... Office 365 Management Activity API
                              (https://manage.office.com/api/v1.0)
    Entra app registration .. one application in the Microsoft tenant
    API permission .......... Office 365 Management APIs ->
                              APPLICATION permission `ActivityFeed.Read`
                              (delegated permissions cannot do unattended
                              collection; ActivityFeed.ReadDlp is NOT
                              requested — DLP.All is out of Phase 1 scope)
    Admin consent ........... tenant administrator must grant consent for
                              the application permission
    Tenant identifier ....... the Microsoft directory (tenant) GUID, used
                              both in the API path and as
                              PublisherIdentifier
    Credential .............. client secret (implemented) or certificate
                              (preferred for production; recognised and
                              reported as NOT IMPLEMENTED rather than
                              faked)
    Microsoft audit config .. unified audit logging must be enabled in the
                              tenant, otherwise the feed is legitimately
                              empty
    Where to configure ...... connector config `microsoft_tenant_id`,
                              `content_types`, `publisher_identifier`; the
                              secret goes in the collector's server-side
                              credential store — never in chat, a report,
                              a fixture or source control
    NivX expects ............ a collector registered with
                              authorized_sources ["m365-unified-audit"]
                              and an ingest API key scoped
                              collectors.enroll""")

    print("\n" + ("MICROSOFT PHASE 1b: PASS — acquisition IMPLEMENTED, "
                  "chain SYNTHETIC/REPLAY PROVEN, live Microsoft "
                  "EXTERNAL_ACCESS_BLOCKED" if ok
                  else "MICROSOFT PHASE 1b: FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
