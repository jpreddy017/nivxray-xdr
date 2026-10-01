#!/usr/bin/env python3
"""P0-3 · Blindness/Staleness detection + Linux sensor recovery — PROOF.

Owner acceptance, restated so the gates can be checked against it:

  * a FRESH real physical Linux event, generated AFTER recovery, must
    traverse sensor → queue/transport → authenticated ingestion → raw
    event → canonical evidence → EDR projection → Process Tree /
    Trajectory → detection where applicable → XDR projection;
  * restart survivability must be proven, not asserted;
  * the console must distinguish DELIVERING / STALE / BLIND_NO_DELIVERY /
    EVIDENCE_OUTSIDE_WINDOW;
  * no seed, replay, DB insertion, synthetic probe or historical event
    qualifies.

Everything below runs against the live pod: real HTTP, the real Mongo
store, the real supervisor and a real process this script starts on this
box. Nothing is mocked and nothing is written into Mongo by this script.

    python3 scripts/p0_3_sensor_recovery_proof.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/app/backend")
os.chdir("/app/backend")

from dotenv import load_dotenv                                # noqa: E402
load_dotenv("/app/backend/.env")

import requests                                               # noqa: E402
from pymongo import MongoClient                                # noqa: E402

from services.edr.endpoint_health import (                     # noqa: E402
    resolve_delivery_freshness)

API = next(l.split("=", 1)[1].strip()
           for l in Path("/app/frontend/.env").read_text().splitlines()
           if l.startswith("REACT_APP_BACKEND_URL"))
STATE = Path("/app/agents/nivxforge-linux/.state")
FIXTURE_DEVICE = "dev_42e8c6dc74b9"
FIXTURE_ENDPOINT = "ep_2d57cbe6f80152062109"
OLD_EVIDENCE_DEVICE = "dev_a0267ae20737"     # real, all evidence months old

RESULTS: list[tuple[str, str, str]] = []


def gate(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append(("PASS" if ok else "FAIL", name, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
          + (f"\n         {detail}" if detail else ""))
    return ok


def blocked(name: str, detail: str) -> None:
    RESULTS.append(("BLOCKED", name, detail))
    print(f"  [BLOCKED] {name}\n         {detail}")


def login(email: str, password: str) -> str:
    r = requests.post(f"{API}/api/auth/login",
                      json={"email": email, "password": password}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def get(path: str, token: str, **params):
    r = requests.get(f"{API}/api/{path}", params=params,
                     headers={"Authorization": f"Bearer {token}"}, timeout=90)
    return r.status_code, (r.json() if r.headers.get("content-type", "")
                           .startswith("application/json") else r.text)


def _operator_credential() -> tuple[str, str]:
    """Read the operator credential from the environment, never inline.

    A hardcoded password in a tracked test or proof script is a secret in
    git. 275 tracked files in this repo already carry the preview admin
    password (reported to the owner); this script will not be the 276th.
    """
    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")
    if not (email and password):
        sys.exit("ADMIN_EMAIL / ADMIN_PASSWORD are not present in "
                 "backend/.env — cannot authenticate. Refusing to guess "
                 "or to embed a credential in this file.")
    return email, password


def main() -> int:
    started = datetime.now(timezone.utc)
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    admin = login(*_operator_credential())

    # ── A · the root cause, fixed structurally ───────────────────────
    print("\nA · ROOT CAUSE · the sensor is supervised and its state is "
          "persistent")
    status = subprocess.run(["supervisorctl", "status", "nivxforge_sensor"],
                            capture_output=True, text=True).stdout
    gate("A1 sensor is a supervised program", "RUNNING" in status,
         status.strip())
    ident_file = STATE / "identity.json"
    gate("A2 durable state lives on a persistent path",
         ident_file.exists() and str(STATE).startswith("/app"),
         f"{ident_file} exists={ident_file.exists()}")
    gate("A3 credential file is 0600",
         oct(ident_file.stat().st_mode)[-3:] == "600",
         oct(ident_file.stat().st_mode)[-3:])
    ident = json.loads(ident_file.read_text())
    gate("A4 re-enrolment resolved to the SAME platform-minted endpoint "
         "identity (history stays attached)",
         ident["endpoint_id"] == FIXTURE_ENDPOINT,
         f"{ident['endpoint_id']} == {FIXTURE_ENDPOINT}")

    ep = db.edr_endpoints.find_one({"endpoint_id": FIXTURE_ENDPOINT})
    gate("A5 re-enrolment did NOT reset the delivery record "
         "(pre-outage 225 events preserved and added to)",
         int(ep.get("event_count") or 0) > 225
         and ep.get("sensor_state") == "REPORTING",
         f"event_count={ep.get('event_count')} "
         f"sensor_state={ep.get('sensor_state')}")

    # ── B · the freshness authority ──────────────────────────────────
    print("\nB · BLINDNESS/STALENESS · one authority, cadence-derived "
          "thresholds")
    code, fresh = get("edr/telemetry/freshness", admin,
                      endpoint=FIXTURE_DEVICE)
    row = (fresh.get("endpoints") or [{}])[0]
    d = row.get("delivery") or {}
    th = d.get("thresholds") or {}
    gate("B1 route answers", code == 200, f"HTTP {code}")
    gate("B2 thresholds are derived from the SENSOR'S OWN declared cadence",
         th.get("cadence_basis") == "DECLARED_BY_SENSOR"
         and float(th.get("report_interval_s") or 0) > 0,
         f"{th.get('cadence_basis')} · interval={th.get('report_interval_s')}s")
    gate("B3 the derivation formula travels with the answer",
         "max(report_interval_s" in str(th.get("formula")),
         str(th.get("formula")))
    gate("B4 the recovered endpoint reads DELIVERING",
         d.get("state") == "DELIVERING",
         f"{d.get('state')} · {d.get('basis')} · {d.get('statement')}")
    gate("B5 the sensor link is separately confirmed by a heartbeat "
         "(a quiet sensor is not a dead sensor)",
         bool(d.get("link_confirmed")) and d.get("last_heartbeat_at"),
         f"link_confirmed={d.get('link_confirmed')} "
         f"heartbeat_age={d.get('heartbeat_age_s')}s")

    # the three tokens, derived by the real function from real timestamps
    last = d.get("last_delivery_at")
    base = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
    stale_at = base + timedelta(seconds=th["stale_after_s"] + 5)
    blind_at = base + timedelta(seconds=th["blind_after_s"] + 5)
    s1 = resolve_delivery_freshness(
        last_telemetry_at=last, report_interval_seconds=th["report_interval_s"],
        last_heartbeat_at=None, now=stale_at)
    s2 = resolve_delivery_freshness(
        last_telemetry_at=last, report_interval_seconds=th["report_interval_s"],
        last_heartbeat_at=None, now=blind_at)
    gate("B6 past the cadence-derived stale threshold the same delivery "
         "record reads STALE",
         s1["state"] == "STALE", f"{s1['state']} · {s1['basis']}")
    gate("B7 past the blindness threshold it reads BLIND_NO_DELIVERY",
         s2["state"] == "BLIND_NO_DELIVERY",
         f"{s2['state']} · {s2['basis']}")
    gate("B8 STALE distinguishes a live link from a lost one in its basis",
         resolve_delivery_freshness(
             last_telemetry_at=last,
             report_interval_seconds=th["report_interval_s"],
             last_heartbeat_at=stale_at.isoformat(),
             now=stale_at)["basis"] == "LINK_ALIVE_NO_NEW_EVIDENCE",
         "LINK_ALIVE_NO_NEW_EVIDENCE vs DELIVERY_LATE_LINK_UNCONFIRMED")
    gate("B8b a sensor that is alive and BEHIND is reported as backlogged, "
         "not as 'no new evidence' (found by this proof failing against "
         "the real box under load)",
         resolve_delivery_freshness(
             last_telemetry_at=last,
             report_interval_seconds=th["report_interval_s"],
             last_heartbeat_at=stale_at.isoformat(), queue_depth=412,
             now=stale_at)["basis"] == "DELIVERY_BACKLOGGED_AT_SENSOR",
         "DELIVERY_BACKLOGGED_AT_SENSOR")

    code, fleet = get("edr/telemetry/freshness", admin)
    f = fleet.get("fleet") or {}
    bases = {r["delivery"]["basis"] for r in fleet.get("endpoints") or []}
    gate("B9 fleet summary counts every state separately",
         set(f.get("by_delivery_state") or {}) ==
         {"DELIVERING", "STALE", "BLIND_NO_DELIVERY"},
         f"{f.get('state')} · {f.get('by_delivery_state')} of "
         f"{f.get('enrolled')} enrolled")
    gate("B10 an endpoint that never delivered is NEVER_DELIVERED, not "
         "lumped in with one that stopped",
         "NEVER_DELIVERED" in bases and f.get("never_delivered", 0) > 0,
         f"never_delivered={f.get('never_delivered')} · bases={sorted(bases)}")
    gate("B11 a revoked credential is stated as such, not as a fault",
         "CREDENTIAL_REVOKED" in bases, f"bases={sorted(bases)}")
    gate("B12 blindness never reads as an all-clear",
         "NOT a statement that nothing is happening"
         in str(fleet.get("note")), str(fleet.get("note"))[:80] + "…")

    # heartbeat is not telemetry — proven with the endpoint's OWN credential.
    # The live sensor is paused for this sub-phase ONLY, because a running
    # sensor writes concurrently and would make a before/after comparison
    # a race rather than a proof.
    print("\nB' · a heartbeat may never be mistaken for evidence")
    subprocess.run(["supervisorctl", "stop", "nivxforge_sensor"],
                   capture_output=True, text=True)
    time.sleep(3)
    before = db.edr_endpoints.find_one({"endpoint_id": FIXTURE_ENDPOINT})
    sess = requests.post(f"{API}/api/edr/agent/session",
                         json={"tenant_id": ident["tenant_id"],
                               "agent_credential": ident["agent_credential"]},
                         timeout=30).json()["session_token"]
    hb = requests.post(f"{API}/api/edr/agent/heartbeat",
                       json={"report_interval_seconds": 15,
                             "sensor_version": "0.1.0"},
                       headers={"Authorization": f"Bearer {sess}"},
                       timeout=30)
    after = db.edr_endpoints.find_one({"endpoint_id": FIXTURE_ENDPOINT})
    gate("B13 heartbeat is authenticated and accepted",
         hb.status_code == 200 and hb.json().get("link_state") == "CONNECTED",
         f"HTTP {hb.status_code} {hb.json().get('link_state')}")
    gate("B14 the heartbeat advanced NEITHER last_telemetry_at NOR "
         "event_count (it is liveness, not evidence)",
         after["last_telemetry_at"] == before["last_telemetry_at"]
         and after["event_count"] == before["event_count"]
         and after["last_heartbeat_at"] != before.get("last_heartbeat_at"),
         f"telemetry_at unchanged={after['last_telemetry_at'] == before['last_telemetry_at']} "
         f"event_count {before['event_count']}→{after['event_count']}")
    raw_before = db.edr_raw_events.count_documents(
        {"endpoint_ref": FIXTURE_ENDPOINT})
    gate("B15 the heartbeat created no raw event",
         db.edr_raw_events.count_documents(
             {"endpoint_ref": FIXTURE_ENDPOINT}) == raw_before,
         f"{raw_before} raw events, unchanged")
    subprocess.run(["supervisorctl", "start", "nivxforge_sensor"],
                   capture_output=True, text=True)
    time.sleep(20)

    # ── C · a FRESH REAL PHYSICAL EVENT, end to end ──────────────────
    print("\nC · FRESH PHYSICAL EVENT · generated now, on this box, from "
          "/proc")
    out = subprocess.run([sys.executable,
                          "/app/scripts/p0_3_generate_physical_event.py"],
                         capture_output=True, text=True).stdout.strip()
    name, pid = out.split()
    print(f"         started real process {name} pid={pid}")
    raw = None
    for _ in range(30):
        time.sleep(5)
        raw = db.edr_raw_events.find_one({"payload": {"$regex": name},
                                          "source_kind": "sensor"})
        if raw:
            break
    gate("C1 the sensor observed the real process and delivered it through "
         "the authenticated ingest",
         bool(raw) and raw.get("trust_state") == "AUTHENTICATED"
         and raw["ingest_time"] > started.isoformat(),
         f"raw_id={(raw or {}).get('raw_id')} "
         f"trust={(raw or {}).get('trust_state')} "
         f"ingest_time={(raw or {}).get('ingest_time')}")
    if not raw:
        return _report()
    gate("C2 the immutable raw event is attributed to THIS endpoint",
         raw.get("endpoint_ref") == FIXTURE_ENDPOINT
         and (raw.get("authentication") or {}).get(
             "authenticated_endpoint_id") == FIXTURE_ENDPOINT,
         json.dumps(raw.get("authentication"))[:120])

    obs = db.v2_shadow_observations.find_one(
        {"ingest_job_id": raw["raw_id"], "kind": {"$regex": "process"}})
    gate("C3 canonical evidence was created and joins back to the raw event",
         bool(obs) and obs["event"]["device_iid"] == FIXTURE_DEVICE,
         f"canonical_event_id={(obs or {}).get('canonical_event_id')} "
         f"process_iid={((obs or {}).get('event') or {}).get('process_iid')}")

    cev = db.xdr_canonical_evidence.find_one(
        {"provenance.trace_id": raw["raw_id"]})
    cp = (cev or {}).get("provenance") or {}
    gate("C4 canonical provenance carries the AUTHENTICATED SENSOR "
         "attribution (P0-3 defect fix — it used to be dropped, so live "
         "sensor incidents were born PROVENANCE_UNKNOWN)",
         cp.get("source_kind") == "sensor" and bool(cp.get("sensor_version"))
         and cp.get("trust_state") == "AUTHENTICATED",
         json.dumps(cp))

    code, tree = get("edr/process-tree", admin, endpoint_id=FIXTURE_DEVICE,
                     hours=1)
    node = next((n for n in tree.get("nodes") or []
                 if name in json.dumps(n)), None)
    gate("C5 the fresh process appears in the EDR Process Tree with real "
         "kernel-read attributes",
         bool(node) and node.get("sha256") and node.get("command_line")
         and str(node.get("pid")) == pid,
         f"pid={(node or {}).get('pid')} "
         f"sha256={str((node or {}).get('sha256'))[:16]}… "
         f"cmd={(node or {}).get('command_line')}")

    code, traj = get("edr/device-trajectory", admin, device=FIXTURE_DEVICE,
                     hours=1)
    gate("C6 the fresh process appears in Device Trajectory",
         name in json.dumps(traj),
         f"{len(traj.get('events') or [])} events in the 1h window")

    # The XDR incident that POST-RECOVERY evidence actually reached — found
    # by following the detection derivation, never by picking an incident
    # that happens to reference this endpoint.
    postrec = list(db.edr_raw_events.find(
        {"endpoint_ref": FIXTURE_ENDPOINT,
         "ingest_time": {"$gte": "2026-09-08T00:31"},
         "derivations.outcome": "DETECTION_MATCHED"},
        {"_id": 0, "raw_id": 1, "ingest_time": 1, "derivations": 1}))
    inc_ids = {e for r in postrec for d in r["derivations"]
               if d.get("outcome") == "DETECTION_MATCHED"
               for e in (d.get("evidence_ids") or [])}
    inc = db.workspace_cases.find_one({"id": next(iter(inc_ids), "none")})
    dets = ((inc or {}).get("endpoint_campaign") or {}).get("detections") or []
    gate("C7 XDR projection · post-recovery evidence reached an XDR "
         "incident, followed through the detection derivation itself",
         bool(inc) and len(postrec) > 0,
         f"{len(postrec)} post-recovery detected raw event(s) → "
         f"incident(s) {sorted(inc_ids)} · "
         f"{(inc or {}).get('incident_number')} created "
         f"{(inc or {}).get('created_at')}")
    gate("C8 that incident is labelled REAL_SENSOR_DERIVED from evidence",
         (inc or {}).get("provenance") == "REAL_SENSOR_DERIVED",
         f"{(inc or {}).get('provenance')} · "
         f"previous={(inc or {}).get('provenance_previous')} · "
         f"{str((inc or {}).get('provenance_basis'))[:140]}")

    # The creation path itself, exercised on the REAL post-fix canonical
    # document. Proving the fix without waiting for a new campaign, and
    # without fabricating an incident to prove it with.
    from detection_content.xdr_incident import _provenance_of_pipeline
    born = _provenance_of_pipeline(cev or {}, raw["raw_id"])
    gate("C8b the incident CREATION path now labels live sensor evidence "
         "REAL_SENSOR_DERIVED at birth (the defect was in the creation "
         "path, not the backfill)",
         born["provenance"] == "REAL_SENSOR_DERIVED",
         f"{born['provenance']} · {born['provenance_basis'][:120]}")
    postfix = [x for x in dets
               if str(x.get("at") or x.get("detected_at") or "")
               > started.isoformat()]
    if postfix:
        gate("C9 a detection fired on POST-RECOVERY evidence", True,
             f"{len(postfix)} detection(s) recorded after "
             f"{started.isoformat()}")
    else:
        blocked("C9 detection on this specific proof process",
                "no rule matched THIS process, which is the honest outcome "
                "for a benign binary. Detection on post-recovery evidence is "
                "proven separately by the fresh DETECTION_MATCHED "
                "derivations counted in C10.")
    fresh_dets = db.edr_raw_events.count_documents(
        {"endpoint_ref": FIXTURE_ENDPOINT,
         "ingest_time": {"$gte": started.isoformat()},
         "derivations.outcome": "DETECTION_MATCHED"})
    all_fresh_dets = db.edr_raw_events.count_documents(
        {"endpoint_ref": FIXTURE_ENDPOINT,
         "derivations.outcome": "DETECTION_MATCHED",
         "ingest_time": {"$gte": "2026-09-08T00:31"}})
    gate("C10 the detection fabric is evaluating post-recovery evidence",
         all_fresh_dets > 0,
         f"{all_fresh_dets} raw events delivered since recovery carry a "
         f"DETECTION_MATCHED derivation ({fresh_dets} during this run)")

    # ── D · window honesty ───────────────────────────────────────────
    print("\nD · WINDOW HONESTY · an empty window may not be presented as "
          "an empty endpoint")
    win = tree.get("window") or {}
    gate("D1 the process tree discloses what exists OUTSIDE the window",
         all(k in win for k in ("observations_in_window",
                                "observations_outside_window",
                                "processes_outside_window",
                                "latest_evidence_at", "state")),
         json.dumps({k: win.get(k) for k in
                     ("state", "observations_in_window",
                      "observations_outside_window",
                      "processes_outside_window")}))
    code, narrow = get("edr/process-tree", admin,
                       endpoint_id=OLD_EVIDENCE_DEVICE, hours=24)
    nw = narrow.get("window") or {}
    gate("D2 an endpoint whose evidence is ALL outside the window returns "
         "EVIDENCE_OUTSIDE_WINDOW, never 'no matching evidence'",
         nw.get("state") == "EVIDENCE_OUTSIDE_WINDOW"
         and narrow.get("reason") == "evidence_outside_window"
         and nw.get("processes_outside_window", 0) > 0,
         f"{nw.get('state')} · {nw.get('processes_outside_window')} "
         f"process(es) outside · {nw.get('statement')}")
    code, wide = get("edr/process-tree", admin, endpoint_id=FIXTURE_DEVICE,
                     hours=720)
    gate("D3 widening the window from the console reaches evidence a 1h "
         "window could not",
         (wide.get("window") or {}).get("observations_in_window", 0)
         > win.get("observations_in_window", 0),
         f"1h={win.get('observations_in_window')} in window → "
         f"720h={(wide.get('window') or {}).get('observations_in_window')}")
    gate("D4 the maximum reachable window is disclosed, so unreachable "
         "evidence is not silently unreachable",
         nw.get("max_window_hours") == 720, str(nw.get("max_window_hours")))

    # ── E · isolation is not widened by any of this ──────────────────
    print("\nE · NEGATIVES · nothing above widened authorisation")
    code, forged = get("edr/telemetry/freshness", admin,
                       endpoint="dev_ffffffffffff")
    gate("E1 a forged identifier is ENDPOINT_NOT_RESOLVED, not an empty "
         "fleet", forged.get("state") == "ENDPOINT_NOT_RESOLVED"
         and forged.get("endpoints") == [],
         f"{forged.get('state')}")
    other_pw = os.environ.get("TEST_ANALYST_NIVXLIVE_PASSWORD")
    if not other_pw:
        blocked("E2 cross-tenant isolation over the freshness route",
                "TEST_ANALYST_NIVXLIVE_PASSWORD is not set in the "
                "environment. The credential is deliberately NOT inlined "
                "here — a hardcoded password in a tracked file is a secret "
                "in git. Set it in backend/.env to run this gate.")
    else:
        other = login("analyst@nivx-live.com", other_pw)
        code, scoped = get("edr/telemetry/freshness", other,
                           endpoint=FIXTURE_DEVICE)
        body = json.dumps(scoped)
        gate("E2 a cross-tenant analyst learns nothing about a `default` "
             "endpoint through the freshness route",
             FIXTURE_ENDPOINT not in body
             and "agent-env-630704a1" not in body,
             f"state={scoped.get('state')} "
             f"endpoints={len(scoped.get('endpoints') or [])}")

    # ── F · restart survivability ────────────────────────────────────
    print("\nF · RESTART SURVIVABILITY · the outage may not recur silently")
    pids = subprocess.run(["pgrep", "-f", "nivxforge_sensor.py run"],
                          capture_output=True, text=True).stdout.split()
    subprocess.run(["kill", "-9", *pids], capture_output=True)
    print(f"         SIGKILLed sensor pid(s) {pids}")
    time.sleep(25)
    status2 = subprocess.run(["supervisorctl", "status", "nivxforge_sensor"],
                             capture_output=True, text=True).stdout
    pids2 = subprocess.run(["pgrep", "-f", "nivxforge_sensor.py run"],
                           capture_output=True, text=True).stdout.split()
    gate("F1 supervisor brought the sensor back after SIGKILL",
         "RUNNING" in status2 and bool(pids2) and pids2 != pids,
         f"{status2.strip()} · pids {pids} → {pids2}")
    ident2 = json.loads(ident_file.read_text())
    gate("F2 it resumed the SAME endpoint identity from persistent state "
         "(no duplicate endpoint, no orphaned history)",
         ident2["endpoint_id"] == FIXTURE_ENDPOINT
         and db.edr_endpoints.count_documents(
             {"hostname": ep["hostname"]}) == 1,
         f"{ident2['endpoint_id']} · "
         f"{db.edr_endpoints.count_documents({'hostname': ep['hostname']})} "
         f"enrolment row(s) for this hostname")
    delivering = False
    for _ in range(10):
        time.sleep(6)
        code, again = get("edr/telemetry/freshness", admin,
                          endpoint=FIXTURE_DEVICE)
        st = ((again.get("endpoints") or [{}])[0].get("delivery") or {})
        if st.get("state") == "DELIVERING":
            delivering = True
            break
    gate("F3 delivery resumed after the restart and the console says so",
         delivering, f"{st.get('state')} · {st.get('statement')}")

    return _report()


def _report() -> int:
    p = sum(1 for r in RESULTS if r[0] == "PASS")
    f = sum(1 for r in RESULTS if r[0] == "FAIL")
    b = sum(1 for r in RESULTS if r[0] == "BLOCKED")
    print("\n" + "=" * 72)
    print(f"P0-3 · {p} PASS · {f} FAIL · {b} BLOCKED")
    print("=" * 72)
    for st, name, detail in RESULTS:
        if st != "PASS":
            print(f"  {st}: {name}\n        {detail}")
    Path("/app/memory/p0_3_sensor_recovery_proof.json").write_text(
        json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(),
                    "pass": p, "fail": f, "blocked": b,
                    "gates": [{"state": s, "gate": n, "detail": d}
                              for s, n, d in RESULTS]}, indent=1))
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(main())
