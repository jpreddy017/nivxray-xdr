#!/usr/bin/env python3
"""D17 · a declared rule cites real evidence, over real HTTP (PREVIEW ONLY).

One Sysmon process-creation document is delivered through the authenticated,
DECLARED (D15) ingest path with a command line that fires DET-IM-001 (Volume
Shadow Copy Deletion) — a rule declared in D17 batch 1. Then the persisted D8
citation is read back and checked:

    declaration_state   DECLARED
    completeness        CITED
    matched_conditions  the declared canonical fields, with observed values
    evidence_ref        resolves to the canonical event it cites
    rule_version        2  (a declaration change moved the version)

TEST/SYNTHETIC payload. NOT LIVE. Nothing touches production.
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
TENANT = "t-d17-declared"
CMD = f"vssadmin delete shadows /all /quiet {STAMP}"

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
                          "name": "d17-proof-collector", "protocol": "rest",
                          "authorized_sources": ["microsoft-sysmon"],
                          "tenant_id": TENANT, "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True})
    if code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col = next((c["id"] for c in
                    ((lst.get("data") or {}).get("collectors") or [])
                    if c.get("name") == "d17-proof-collector"), None)
    elif code in (200, 201):
        d = body.get("data") or body
        col = d.get("id") or (d.get("collector") or {}).get("id")
    else:
        print(f"  collector create -> {code} {body}")
        return 1
    if col:
        call(f"/api/xdr/collectors/{col}", "PUT", token=token, tenant=TENANT,
             body={"authorized_sources": ["microsoft-sysmon"]})
    code, body = call("/api/xdr/api-keys", "POST", token=token,
                      tenant=TENANT, body={
                          "name": f"d17-proof-key-{STAMP}",
                          "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True,
                          "scopes": ["collectors.enroll", "collectors.read"]})
    _d = body.get("data") or {}
    key = (_d.get("api_key") or _d.get("key") or _d.get("secret")
           or _d.get("plaintext") or _d.get("token") or _d.get("value"))
    check("collector + ingest key ready", bool(col and key), col)
    if not key:
        return 1

    print("\n2 · deliver a real Sysmon process-creation document")
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": [{
                          "tenant_id": TENANT, "collector_id": col,
                          "source_event_id": f"d17:{STAMP}",
                          "collection_method": "rest",
                          "source": "d17-proof-host",
                          "declared_source": "microsoft-sysmon",
                          "raw": {
                              "EventID": 1,
                              "provider": "Microsoft-Windows-Sysmon",
                              "Computer": "WIN-SRV-17",
                              "User": "CORP\\admin",
                              "UtcTime": "2026-06-01T10:00:00+00:00",
                              "Image": "C:\\Windows\\System32\\vssadmin.exe",
                              "CommandLine": CMD,
                              "ProcessId": "5150"}}]})
    check("ingest accepted", code == 200, f"HTTP {code} {str(body)[:200]}")
    if code != 200:
        return 1
    data = body.get("data") or body
    outs = data.get("reasoning") or []
    print(f"  outcome: {[(o.get('status'), o.get('detection'), o.get('detections_matched')) for o in outs]}")
    check("the event was reasoned through the declared DSM",
          outs and outs[0].get("status") == "REASONED"
          and outs[0].get("selected_dsm_id") == "microsoft-sysmon", str(outs))
    check("a rule matched", outs and outs[0].get("detections_matched", 0) >= 1,
          str(outs[0].get("detections_matched") if outs else None))
    time.sleep(2)

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    row = db.xdr_detection_matches.find_one(
        {"tenant_id": TENANT, "rule_id": "DET-IM-001"}, sort=[("_id", -1)])
    check("the citation was persisted", bool(row))
    if not row:
        return 1
    print(f"  citation: {row.get('declaration_state')} / "
          f"{row.get('citation_completeness')} · conditions="
          f"{[c['condition_id'] for c in row.get('matched_conditions') or []]}")
    check("it is DECLARED, not inferred",
          row.get("declaration_state") == "DECLARED",
          str(row.get("declaration_state")))
    check("the citation is complete",
          row.get("citation_completeness") == "CITED",
          str(row.get("citation_completeness")))
    check("the declaration version travelled with the match",
          row.get("rule_version") == "2", str(row.get("rule_version")))
    matched = row.get("matched_conditions") or []
    check("every matched condition names a canonical field and a value",
          matched and all(c.get("canonical_field")
                          and c.get("observed_value") for c in matched),
          str([c.get("canonical_field") for c in matched]))
    check("the cited value is the command line the source actually sent",
          all(CMD in str(c.get("observed_value")) for c in matched),
          str(matched[0].get("observed_value") if matched else None))
    src = db.xdr_canonical_evidence.find_one(
        {"event_id": row.get("canonical_event_id")})
    check("the evidence_ref resolves to real canonical evidence", bool(src),
          str(row.get("evidence_ref")))
    if src:
        check("and that evidence still holds the cited value",
              (src.get("process") or {}).get("command_line") == CMD)

    print("\n3 · an undeclared rule still refuses to guess")
    und = db.xdr_detection_matches.find_one(
        {"declaration_state": "NOT_DECLARED"}, sort=[("_id", -1)])
    if und:
        check("an undeclared match cites nothing and says why",
              not (und.get("matched_conditions") or [])
              and und.get("citation_completeness") == "NOT_DECLARED",
              str(und.get("rule_id")))
    else:
        print("  (no NOT_DECLARED match stored in this preview database)")

    print("\n" + ("D17 RULE DECLARATION BATCH: PASS" if ok
                  else "D17 RULE DECLARATION BATCH: FAIL"))
    print("TEST/SYNTHETIC payload. NOT LIVE. Preview only, nothing deployed.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
