#!/usr/bin/env python3
"""D12 · cross-DSM activity time, over real HTTP (PREVIEW ONLY).

Only two of the five sources can be proved through the collector path as it
stands: the ingest handler hands the DSM registry a verbatim LINE, so the
line-oriented sources resolve (linux-auditd, cef-leef) while the
JSON-document sources (sysmon, windows-security-evd, aws-cloudtrail) do
not — their `supports()` keys on document fields the line carries nowhere.
That is reported as a limitation rather than papered over: those three are
proved synthetically through the real registry, parsers and normalizers in
`tests/test_d12_cross_dsm_activity_time.py`.

TEST/SYNTHETIC payloads throughout. NOT LIVE — no real device is sending
these. Nothing touches production.
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
TENANT = "t-d12-proof"
STAMP = int(time.time())

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
                          "name": "d12-proof-collector",
                          "protocol": "syslog", "tenant_id": TENANT,
                          "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True})
    if code == 409:
        _, lst = call("/api/xdr/collectors", token=token, tenant=TENANT)
        col_id = next((c["id"] for c in
                       ((lst.get("data") or {}).get("collectors") or [])
                       if c.get("name") == "d12-proof-collector"), None)
    elif code in (200, 201):
        col = body.get("data") or body
        col_id = col.get("id") or (col.get("collector") or {}).get("id")
    else:
        print(f"  collector create -> {code} {body}")
        return 1
    check("collector ready", bool(col_id), col_id)

    code, body = call("/api/xdr/api-keys", "POST", token=token,
                      tenant=TENANT, body={
                          "name": f"d12-proof-key-{STAMP}",
                          "confirm_tenant_id": TENANT,
                          "allow_new_tenant": True,
                          "scopes": ["collectors.enroll", "collectors.read"]})
    _d = body.get("data") or {}
    key = (_d.get("api_key") or _d.get("key") or _d.get("secret")
           or _d.get("plaintext") or _d.get("token") or _d.get("value"))
    check("ingest key minted (value not printed)", bool(key))
    if not key:
        return 1

    # ── the two line-oriented sources, through the real ingest path ──
    aud = f"1757452888.123:{8000 + STAMP % 900}"
    auditd_line = (f'node=web-prod-04 type=SYSCALL msg=audit({aud}): '
                   f'arch=c000003e syscall=59 uid=0 euid=0 comm="bash" '
                   f'exe="/usr/bin/bash" key="exec"')
    cef_dev = f"CEF:0|NivX|Firewall|1.0|{STAMP % 1000}|Blocked|5|"
    cef_line = (cef_dev + "src=10.0.0.4 dst=198.51.100.2 spt=443 "
                          "devTime=1780308000000 rt=1780308060000")
    cef_rt_only = (f"CEF:0|NivX|Firewall|1.0|{STAMP % 1000}|Blocked|5|"
                   "src=10.0.0.5 dst=198.51.100.3 rt=1780308060000")

    cases = [("linux-auditd", auditd_line, "ACTIVITY_TIME",
              "auditd:msg=audit(epoch:serial)", None),
             ("cef-leef devTime", cef_line, "ACTIVITY_TIME",
              "cef-leef:devTime", "cef:rt"),
             ("cef-leef rt only", cef_rt_only, "OBSERVATION_TIME",
              None, "cef:rt")]

    print("\n2 · POST one event per line-oriented source")
    envs = [{"tenant_id": TENANT, "collector_id": col_id,
             "source_event_id": f"d12:{STAMP}:{i}",
             "collection_method": "syslog", "source": "d12-proof-host",
             "raw": {"line": line}}
            for i, (_, line, _, _, _) in enumerate(cases)]
    code, body = call("/api/xdr/ingest/telemetry", "POST", key=key,
                      tenant=TENANT, body={"envelopes": envs})
    check("ingest accepted", code == 200, f"HTTP {code} {str(body)[:200]}")
    if code != 200:
        return 1
    time.sleep(2)

    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

    print("\n3 · canonical basis per source")
    for (label, line, want_basis, want_act, want_obs) in cases:
        ev = db.xdr_canonical_evidence.find_one(
            {"tenant_id": TENANT, "raw_ref.line": line})
        if not ev:
            check(f"{label}: canonical event produced", False,
                  "no canonical event — DSM did not resolve this line")
            continue
        d = ev.get("additional_fields") or {}
        ts = ((ev.get("provenance") or {}).get("timestamps") or {})
        act, obs = ts.get("activity_occurred_at", {}), \
            ts.get("sensor_observed_at", {})
        print(f"  {label}")
        print(f"    basis       : {d.get('event_time_basis')} "
              f"substituted={d.get('event_time_substituted')}")
        print(f"    activity    : {act.get('status')} "
              f"{act.get('value') or ''} {act.get('source') or ''}")
        print(f"    observation : {obs.get('status')} "
              f"{obs.get('value') or ''} {obs.get('source') or ''}")
        check(f"{label}: basis is {want_basis}",
              d.get("event_time_basis") == want_basis,
              str(d.get("event_time_basis")))
        check(f"{label}: substituted flag matches the basis",
              d.get("event_time_substituted")
              is (want_basis != "ACTIVITY_TIME"))
        if want_act:
            check(f"{label}: activity time from {want_act}",
                  act.get("status") == "AVAILABLE"
                  and act.get("source") == want_act,
                  f"{act.get('status')} / {act.get('source')}")
            check(f"{label}: event_time equals the measured activity time",
                  ev.get("event_time") == act.get("value"))
        else:
            check(f"{label}: activity time NOT invented",
                  act.get("status") != "AVAILABLE"
                  and act.get("value") is None,
                  str(act))
        if want_obs:
            check(f"{label}: observation from {want_obs}",
                  obs.get("status") == "AVAILABLE"
                  and (obs.get("source") or "").startswith(want_obs))
            check(f"{label}: observation is not the activity time",
                  obs.get("value") != act.get("value"))
        if want_basis != "ACTIVITY_TIME":
            check(f"{label}: no source-side boundary came from our clock",
                  "clock" not in (act.get("source") or "")
                  and "clock" not in (obs.get("source") or ""))

    print("\n" + ("D12 CROSS-DSM ACTIVITY TIME (live-provable subset): PASS"
                  if ok else
                  "D12 CROSS-DSM ACTIVITY TIME (live-provable subset): FAIL"))
    print("sysmon / windows-security-evd / aws-cloudtrail are NOT provable "
          "through the collector line path and are proved synthetically "
          "through the real registry in tests/test_d12_cross_dsm_activity_"
          "time.py. TEST/SYNTHETIC payloads. NOT LIVE. Preview only.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
