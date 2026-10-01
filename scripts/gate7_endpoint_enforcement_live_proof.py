#!/usr/bin/env python3
"""GATE 7 · endpoint exclusion enforcement — LIVE proof.

Driven against the REAL NivXForge Linux Connector supervised in this
pod. Nothing is simulated: the connector fetches its policy, applies it,
acknowledges the exact config digest, evaluates exclusions locally and
drops matching events BEFORE its durable outbox.

The proof is the absence of evidence the platform never received:

  * a marker process whose command line MATCHES an approved, delivered
    exclusion must NEVER appear in `/api/edr/events`;
  * a control marker process that does NOT match must appear;
  * the exclusion must read `ENDPOINT_EXCLUSION_APPLIED` with a non-zero
    honoured count reported by the endpoint itself.

Run: python3 scripts/gate7_endpoint_enforcement_live_proof.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("NIVX_BASE") or ""
if not BASE:
    with open("/app/frontend/.env") as fh:
        for line in fh:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE = line.split("=", 1)[1].strip()
API = BASE.rstrip("/") + "/api"
TENANT = "default"
ADMIN = ("admin@nivxray.com", os.environ.get("NIVXPW",
                                             "uulVDp5cCSB3Hva99s7UUAwK"))
APPROVER = ("approver@nivxray.com",
            os.environ.get("NIVX_APPROVER_PASSWORD",
                           "AppRoVe-Excl-2026-nvx"))
#: The connector's own cadence. Nothing is asserted before it has had
#: time to act, and nothing is retried forever.
CYCLE = 15
FAILURES: list[str] = []


def call(method, path, *, token=None, tenant=True, body=None, expect=200):
    req = urllib.request.Request(
        f"{API}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0 (NivXForge-Gate7-Proof)")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if tenant:
        req.add_header("X-Tenant-Id", TENANT)
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            status, payload = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, payload = e.code, e.read().decode()
    try:
        parsed = json.loads(payload)
    except ValueError:
        parsed = {"_raw": payload[:300]}
    if status != expect:
        FAILURES.append(f"{method} {path} -> {status}: "
                        f"{json.dumps(parsed)[:250]}")
    return parsed


def check(label, ok, detail=""):
    print(("  PASS  " if ok else "  FAIL  ") + label
          + (f"   [{detail}]" if detail else ""), flush=True)
    if not ok:
        FAILURES.append(f"{label} {detail}")


def login(creds):
    d = call("POST", "/auth/login", tenant=False,
             body={"email": creds[0], "password": creds[1]})
    return d.get("access_token") or d.get("token")


def running_connector(admin):
    """The endpoint whose connector is actually alive right now."""
    d = call("GET", "/edr/events/facets?hours=1", token=admin)
    best = max(d.get("endpoints") or [], key=lambda e: e["count"], default=None)
    if not best:
        return None
    eps = call("GET", "/edr/onboarding/computers", token=admin)
    rows = eps.get("computers") or eps.get("endpoints") or []
    for r in rows:
        if r.get("endpoint_id") == best["endpoint_ref"]:
            return r
    return {"endpoint_id": best["endpoint_ref"],
            "hostname": best.get("hostname")}


def spawn(marker: str) -> subprocess.Popen:
    """A long-lived process whose OBSERVED attributes carry the marker.

    The connector reports the process name from `/proc/<pid>/comm`, which
    the kernel truncates to 15 characters, and it does not always manage
    to read `cmdline` for a short-lived process. So the marker is the
    executable's own name: a uniquely named copy of `sleep`. That makes
    the marker land in an attribute the connector genuinely observes.
    """
    exe = f"/tmp/{marker}"
    shutil.copy2("/bin/sleep", exe)
    os.chmod(exe, 0o755)
    return subprocess.Popen([exe, "600"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def seen_in_events(admin, marker: str) -> int:
    d = call("GET", f"/edr/events?q={marker}&hours=1&limit=50", token=admin)
    return int(d.get("count") or 0)


def main() -> int:
    stamp = str(int(time.time()))
    # /proc/<pid>/comm is truncated to 15 characters by the kernel, so a
    # marker longer than that would be unobservable and the proof would
    # be testing its own test harness.
    short = stamp[-8:]
    excl_marker = f"nvxg7x{short}"
    ctrl_marker = f"nvxg7c{short}"

    admin = login(ADMIN)
    approver = login(APPROVER)
    check("admin authenticated", bool(admin))
    check("second operator authenticated", bool(approver))

    print("\n── the connector that is actually running ──")
    ep = running_connector(admin)
    check("a live connector was found", bool(ep), str(ep))
    if not ep:
        return 1
    endpoint_id = ep["endpoint_id"]
    print(f"  endpoint={endpoint_id} host={ep.get('hostname')} "
          f"connector={ep.get('sensor_version') or ep.get('connector_version')}")

    print("\n── exclusion authored, approved, bound to a policy version ──")
    exset = call("POST", "/edr/exclusions/sets", token=admin,
                 body={"name": f"Gate7 endpoint {stamp}", "os": "LINUX",
                       "description": "live endpoint enforcement proof"})
    set_id = exset["set_id"]
    excl = call("POST", "/edr/exclusions", token=admin, body={
        "set_id": set_id, "type": "PROCESS",
        "value": excl_marker, "match": "EXACT",
        "reason": "live proof that the endpoint engine honours exclusions",
        "affected_engines": ["endpoint.collection",
                             "server.deterministic.rule"],
        "scope": {"type": "ENDPOINT", "ids": [endpoint_id]}})
    exclusion_id = excl["exclusion_id"]
    check("exclusion created PENDING_APPROVAL",
          excl["approval_state"] == "PENDING_APPROVAL")

    listed = call("GET", f"/edr/exclusions?set_id={set_id}", token=admin)
    mine = next((e for e in listed["exclusions"]
                 if e["exclusion_id"] == exclusion_id), {})
    ep_point = next((p for p in (mine.get("enforcement") or [])
                     if p["engine"] == "endpoint.collection"), {})
    check("before approval the endpoint state is not APPLIED",
          ep_point.get("truth_state") != "ENDPOINT_EXCLUSION_APPLIED",
          str(ep_point.get("truth_state")))

    call("POST", f"/edr/exclusions/{exclusion_id}/approval", token=approver,
         body={"decision": "APPROVED", "note": "gate 7 live proof"})

    policy = call("POST", "/edr/policies", token=admin, body={
        "name": f"Gate7 endpoint policy {stamp}", "os": "LINUX",
        "description": "carries the gate 7 exclusion set",
        "config": {"mode": "DETECT_ONLY", "report_interval_seconds": 15,
                   "heartbeat_interval_seconds": 15,
                   "collect_process_events": True,
                   "collect_network_events": True,
                   "exclusion_set_ids": [set_id]}})
    policy_id = policy["policy"]["id"]
    digest = policy["version"]["config_digest"]
    call("POST", f"/edr/policies/{policy_id}/assign", token=admin,
         body={"scope_type": "ENDPOINT", "scope_id": endpoint_id})
    print(f"  policy={policy_id} v1 digest={digest}")

    print("\n── waiting for the connector to fetch, apply and ACK ──")
    state = {}
    for attempt in range(10):
        time.sleep(CYCLE)
        rows = call("GET", f"/edr/policies/deployment?policy_id={policy_id}",
                    token=admin)
        state = next((r for r in rows["endpoints"]
                      if r["endpoint_id"] == endpoint_id), {})
        print(f"  cycle {attempt + 1}: state={state.get('state')}")
        if state.get("state") in ("APPLIED", "VERIFIED"):
            break
    check("the connector acknowledged applying the exact config digest",
          state.get("state") in ("APPLIED", "VERIFIED"),
          f"{state.get('state')} · {state.get('basis')}")
    check("the connector reports the 0.2.0 release",
          str(state.get("connector_version") or "").startswith("0.2.0"),
          str(state.get("connector_version")))

    print("\n── the actual enforcement: one excluded, one control ──")
    procs = [spawn(excl_marker), spawn(ctrl_marker)]
    print(f"  excluded marker = {excl_marker}")
    print(f"  control  marker = {ctrl_marker}")
    try:
        control_seen = excluded_seen = 0
        for attempt in range(8):
            time.sleep(CYCLE)
            control_seen = seen_in_events(admin, ctrl_marker)
            excluded_seen = seen_in_events(admin, excl_marker)
            print(f"  cycle {attempt + 1}: control_events={control_seen} "
                  f"excluded_events={excluded_seen}")
            if control_seen:
                break
        check("the CONTROL process was collected and delivered",
              control_seen > 0,
              f"{control_seen} events — without this the proof is vacuous")
        check("the EXCLUDED process never reached the platform",
              excluded_seen == 0,
              f"{excluded_seen} events leaked past the endpoint exclusion")
    finally:
        for p in procs:
            p.terminate()
        for m in (excl_marker, ctrl_marker):
            try:
                os.unlink(f"/tmp/{m}")
            except OSError:
                pass

    print("\n── the endpoint's own enforcement report ──")
    point = {}
    for attempt in range(6):
        listed = call("GET", f"/edr/exclusions?set_id={set_id}", token=admin)
        mine = next((e for e in listed["exclusions"]
                     if e["exclusion_id"] == exclusion_id), {})
        point = next((p for p in (mine.get("enforcement") or [])
                      if p["engine"] == "endpoint.collection"), {})
        print(f"  cycle {attempt + 1}: {point.get('truth_state')} "
              f"honoured={point.get('honoured_count')}")
        if point.get("truth_state") == "ENDPOINT_EXCLUSION_APPLIED":
            break
        time.sleep(CYCLE)
    check("the endpoint reports ENDPOINT_EXCLUSION_APPLIED",
          point.get("truth_state") == "ENDPOINT_EXCLUSION_APPLIED",
          f"{point.get('truth_state')} · {point.get('basis')}")
    check("the enforcement count came from the endpoint",
          int(point.get("honoured_count") or 0) > 0,
          f"honoured_count={point.get('honoured_count')}")
    check("the evaluator version was reported",
          bool(point.get("evaluator_version")),
          str(point.get("evaluator_version")))
    check("server-side enforcement is reported separately",
          any(p["truth_state"] == "SERVER_EXCLUSION_APPLIED"
              for p in (mine.get("enforcement") or [])),
          str([p["truth_state"] for p in (mine.get("enforcement") or [])]))

    print("\n── cleanup: revoke and return the endpoint to its group policy ──")
    call("POST", f"/edr/exclusions/{exclusion_id}/revoke", token=admin,
         body={"reason": "gate 7 live proof complete"})

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"FAILURES ({len(FAILURES)}):")
        for f in FAILURES:
            print("  - " + f)
        return 1
    print("ENDPOINT EXCLUSION ENFORCEMENT PROVEN ON A LIVE CONNECTOR")
    return 0


if __name__ == "__main__":
    sys.exit(main())
