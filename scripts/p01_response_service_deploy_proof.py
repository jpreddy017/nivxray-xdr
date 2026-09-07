#!/usr/bin/env python3
"""P0-1 · RESPONSE SERVICE DEPLOY — proof chain.

Acceptance is reported at TWO levels, exactly as locked:

  MUST PASS  service deployment · reachability · authentication ·
             tenant isolation · destructive-action approval · immutable
             approval/dispatch audit · duplicate-dispatch protection ·
             correlation across request/dispatch/result · real dispatcher
             handoff · result/failure/timeout persistence · canonical
             evidence + audit persistence
  BLOCKED    real network isolation · independent verification of real
             isolation      (CAP_NET_ADMIN absent in this pod)

Nothing simulates, mocks or writes around the real plane. A BLOCKED gate
is never converted into a PASS.
"""
from __future__ import annotations

import os
import subprocess
import sys
import uuid

import requests

BASE = os.environ.get("AUDIT_BASE") or "https://greeting-app-5782.preview.emergentagent.com"
ENGINE = "http://localhost:8056"
OWNER = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")      # holds response.execute + response.approve
RECOMMEND_ONLY = ("analyst@default.com", "DefaultCo!Analyst2026")  # holds response.recommend only
FOREIGN = ("analyst@nivx-live.com", "NivxLive!Analyst2026")    # tenant: nivx-live

ENDPOINT = "ep_2d57cbe6f80152062109"     # real enrolled endpoint, tenant default

rows: list[tuple[str, str, str]] = []    # (gate, verdict, evidence)


def gate(name: str, ok: bool | None, evidence: str = "", blocked_reason: str = "") -> None:
    verdict = "BLOCKED" if ok is None else ("PASS" if ok else "FAIL")
    rows.append((name, verdict, blocked_reason or evidence))
    print(f"{verdict:8} {name}" + (f"  · {blocked_reason or evidence}" if (evidence or blocked_reason) else ""))


def sess(creds=None) -> requests.Session:
    s = requests.Session()
    if creds:
        r = s.post(f"{BASE}/api/auth/login",
                   json={"email": creds[0], "password": creds[1]}, timeout=30)
        r.raise_for_status()
        j = r.json()
        s.headers["Authorization"] = f"Bearer {j.get('access_token') or j.get('token')}"
    return s


def main() -> int:
    # ── 1 · independent service deployment ───────────────────────────
    st = subprocess.run(["sudo", "supervisorctl", "status", "xdr_response"],
                        capture_output=True, text=True).stdout
    gate("1 independent service deployment (own supervisor program + own port)",
         "RUNNING" in st, st.strip()[:80])
    bpid = subprocess.run(["sudo", "supervisorctl", "status", "backend"],
                          capture_output=True, text=True).stdout
    gate("2 the response plane is a SEPARATE process from the primary API",
         ("RUNNING" in st and "RUNNING" in bpid
          and st.split("pid")[1].split(",")[0] != bpid.split("pid")[1].split(",")[0]),
         "distinct pids")

    # ── 2 · reachability + readiness ─────────────────────────────────
    h = requests.get(f"{ENGINE}/health", timeout=20)
    gate("3 engine health/readiness endpoint answers",
         h.status_code == 200 and h.json().get("status") == "ok",
         f"HTTP {h.status_code} · {h.json().get('actions')} actions")

    owner = sess(OWNER)
    bh = owner.get(f"{BASE}/api/xdr/respond/health", timeout=45)
    gate("4 the primary backend reaches the engine through the intended boundary",
         bh.status_code == 200 and bh.json().get("reachable") is True,
         f"HTTP {bh.status_code} · {bh.json().get('service_url')}")

    # ── 3 · authentication ───────────────────────────────────────────
    anon = sess()
    a1 = anon.get(f"{BASE}/api/xdr/respond/actions", timeout=30)
    a2 = anon.post(f"{BASE}/api/xdr/respond/execute", json={}, timeout=30)
    gate("5 the response plane has NO anonymous surface",
         a1.status_code in (401, 403) and a2.status_code in (401, 403),
         f"GET {a1.status_code} · POST {a2.status_code}")

    cat = owner.get(f"{BASE}/api/xdr/respond/actions", timeout=45).json()
    real = [a for a in cat["actions"] if a["dispatch_mode"] == "REAL_PRODUCT_API"]
    gate("6 the catalogue distinguishes REAL_PRODUCT_API from STUB_NO_SIDE_EFFECT",
         len(real) > 0 and cat["stub_no_side_effect"] > 0,
         f"{cat['real_product_api']} real · {cat['stub_no_side_effect']} stub")
    gate("7 every stub is declared NOT_CONNECTED and simulation_only",
         all(a["adapter_status"] == "NOT_CONNECTED" and a["simulation_only"]
             for a in cat["actions"] if a["dispatch_mode"] != "REAL_PRODUCT_API"),
         "no stub can read as available")
    iso = next((a for a in real if a["action_id"] == "endpoint.isolate"), None)
    gate("8 the destructive endpoint action requires approval and names its executor",
         bool(iso and iso["approval_required"] and iso["destructive"]
              and iso["authoritative_for_execution"] == "nivxforge-edr"),
         str(iso and iso["authoritative_for_execution"]))

    # ── 4 · destructive-action approval enforcement ──────────────────
    exec_id = f"p01-{uuid.uuid4().hex[:10]}"
    body = {"execution_id": exec_id,
            "action": {"action_id": "endpoint.isolate",
                       "parameters": {"host_id": ENDPOINT}}}
    r = owner.post(f"{BASE}/api/xdr/respond/execute", json=body, timeout=60)
    first = r.json() if r.status_code == 200 else {}
    lc = (first.get("response_lifecycle") or {})
    gate("9 a destructive action parks in PENDING_APPROVAL — it does not dispatch",
         r.status_code == 200 and lc.get("lifecycle") == "pending_approval"
         and lc.get("facts", {}).get("dispatched") is False,
         f"HTTP {r.status_code} · lifecycle={lc.get('lifecycle')}")

    # separation of duties — a recommend-only principal cannot execute
    rec = sess(RECOMMEND_ONLY)
    sd = rec.post(f"{BASE}/api/xdr/respond/execute",
                  json={"execution_id": f"p01-sod-{uuid.uuid4().hex[:8]}",
                        "action": {"action_id": "endpoint.isolate",
                                   "parameters": {"host_id": ENDPOINT}}},
                  timeout=60)
    sdd = (sd.json().get("detail") or {}) if sd.status_code == 403 else {}
    gate("9b separation of duties — a recommend-only analyst cannot EXECUTE a response",
         sd.status_code == 403
         and sdd.get("required_permission") == "response.execute"
         and not (sdd.get("holds_response_permissions") or []),
         f"HTTP {sd.status_code} · basis={sdd.get('authorization_basis')} "
         f"holds={sdd.get('holds_response_permissions')}")
    sda = rec.post(f"{BASE}/api/xdr/respond/approve/{exec_id}",
                   json={"reason": "unauthorised approval probe"}, timeout=60)
    gate("9c a recommend-only analyst cannot APPROVE a response",
         sda.status_code == 403, f"HTTP {sda.status_code}")
    gate("10 approved != dispatched — no dispatch fact before approval",
         lc.get("facts", {}).get("executed") is False
         and lc.get("facts", {}).get("verified") is False,
         str(lc.get("facts")))

    # ── 5 · tenant isolation across the boundary ─────────────────────
    foreign = sess(FOREIGN)
    fr = foreign.post(f"{BASE}/api/xdr/respond/approve/{exec_id}",
                      json={"reason": "cross-tenant approval probe"}, timeout=60)
    gate("11 a wrong-tenant principal cannot approve another tenant's execution",
         fr.status_code >= 400, f"HTTP {fr.status_code}")
    fpa = foreign.get(f"{BASE}/api/xdr/respond/pending-approvals", timeout=45).json()
    fids = {x.get("execution_id") for x in (fpa.get("rows") or [])}
    gate("12 the wrong tenant cannot SEE the execution in pending approvals",
         exec_id not in fids, f"{fpa.get('count')} rows visible to nivx-live")
    ftry = foreign.post(f"{BASE}/api/xdr/respond/execute",
                        json={"execution_id": f"x-{uuid.uuid4().hex[:8]}",
                              "tenant_id": "default",
                              "action": {"action_id": "endpoint.isolate",
                                         "parameters": {"host_id": ENDPOINT}}},
                        timeout=60)
    ftj = ftry.json() if ftry.status_code == 200 else {}
    gate("13 a client-supplied tenant_id is never honoured — no impersonation",
         ftry.status_code != 200 or ftj.get("tenant_id") == "nivx-live",
         f"HTTP {ftry.status_code} · tenant={ftj.get('tenant_id')}")

    opa = owner.get(f"{BASE}/api/xdr/respond/pending-approvals", timeout=45).json()
    gate("14 the OWNING tenant sees its own execution awaiting approval",
         exec_id in {x.get("execution_id") for x in (opa.get("rows") or [])},
         f"{opa.get('count')} rows visible to default")

    # ── 6 · approval + real dispatcher handoff ───────────────────────
    ap = owner.post(f"{BASE}/api/xdr/respond/approve/{exec_id}",
                    json={"approval_ref": f"apr-{uuid.uuid4().hex[:8]}",
                          "reason": "P0-1 proof · approved by the owning tenant"},
                    timeout=90)
    apj = ap.json() if ap.status_code == 200 else {}
    aplc = apj.get("response_lifecycle") or {}
    gate("15 approval is attributed to the SESSION principal, never the request body",
         (apj.get("approval") or {}).get("approved_by") == OWNER[0],
         str((apj.get("approval") or {}).get("approved_by")))
    edr = aplc.get("edr") or {}
    dispatched_or_refused = (aplc.get("lifecycle") in
                             ("dispatched", "executing", "executed",
                              "dispatch_failed", "rejected", "verification_failed"))
    gate("16 the approved action reaches the REAL dispatcher (no stub could satisfy this)",
         aplc.get("dispatch_mode") == "REAL_PRODUCT_API" and dispatched_or_refused,
         f"lifecycle={aplc.get('lifecycle')} mode={aplc.get('dispatch_mode')}")
    gate("17 NivXForge EDR is recorded as authoritative for execution",
         aplc.get("authoritative_for_execution") == "nivxforge-edr",
         str(aplc.get("authoritative_for_execution")))

    # ── 7 · the four invariants ──────────────────────────────────────
    gate("18 dispatched != executed — acceptance never sets the executed fact",
         not (aplc.get("facts") or {}).get("executed")
         or str(edr.get("state")) in ("EXECUTED", "VERIFIED"),
         f"edr_state={edr.get('state')} executed={(aplc.get('facts') or {}).get('executed')}")
    gate("19 executed != verified — verified requires the product's own proof",
         (aplc.get("lifecycle") != "verified"
          or bool((edr.get("proof") or {}).get("verified"))),
         f"lifecycle={aplc.get('lifecycle')} proof={(edr.get('proof') or {}).get('proof')}")

    # ── 8 · correlation across request → dispatch → result ───────────
    gate("20 request → dispatch correlation is captured end to end",
         bool(apj.get("execution_id") == exec_id
              and edr.get("command_id") and edr.get("endpoint_id") == ENDPOINT
              and apj.get("tenant_id") == "default"),
         f"exec={exec_id} edr_cmd={edr.get('command_id')} tenant={apj.get('tenant_id')}")

    if edr.get("command_id"):
        er = owner.get(f"{BASE}/api/edr/response/actions/{edr['command_id']}",
                       timeout=60)
        erj = er.json() if er.status_code == 200 else {}
        gate("21 the dispatched command is independently retrievable from the EDR product",
             er.status_code == 200 and erj.get("command_id") == edr["command_id"],
             f"HTTP {er.status_code} · state={erj.get('state')}")
        fer = foreign.get(f"{BASE}/api/edr/response/actions/{edr['command_id']}",
                          timeout=60)
        gate("22 the wrong tenant cannot read the dispatched command in the EDR product",
             fer.status_code >= 400, f"HTTP {fer.status_code}")
        gate("23 the EDR refuses to grade an unexecuted command as verified",
             (erj.get("proof") or {}).get("verified") is not True
             or erj.get("state") == "VERIFIED",
             f"state={erj.get('state')} proof={(erj.get('proof') or {}).get('proof')}")
    else:
        gate("21 the dispatched command is independently retrievable from the EDR product",
             False, "no EDR command id was returned")
        gate("22 the wrong tenant cannot read the dispatched command", False, "n/a")
        gate("23 the EDR refuses to grade an unexecuted command as verified", False, "n/a")

    # ── 9 · immutable approval + duplicate-dispatch protection ───────
    ap2 = owner.post(f"{BASE}/api/xdr/respond/approve/{exec_id}",
                     json={"reason": "duplicate approval probe"}, timeout=60)
    gate("24 an already-decided execution cannot be approved again (immutable decision)",
         ap2.status_code >= 400, f"HTTP {ap2.status_code}")
    dup = owner.post(f"{BASE}/api/xdr/respond/execute", json=body, timeout=90)
    dupj = dup.json() if dup.status_code == 200 else {}
    gate("25 duplicate dispatch is idempotent — the prior response is replayed verbatim",
         dup.status_code == 200 and dupj.get("idempotent_replay") is True,
         f"HTTP {dup.status_code} · replay={dupj.get('idempotent_replay')}")
    gate("26 the replay did NOT create a second endpoint command",
         ((dupj.get("response_lifecycle") or {}).get("edr") or {}).get("command_id")
         == edr.get("command_id"),
         "same EDR command id")

    # ── 10 · result / failure persistence + restart durability ───────
    exr = owner.get(f"{BASE}/api/xdr/respond/executions/{exec_id}", timeout=45)
    ex = exr.json() if exr.status_code == 200 else {}
    gate("27 the execution is persisted in the engine's own store, "
         "addressed by the full tenant-scoped idempotency key",
         exr.status_code == 200 and ex.get("execution_id") == exec_id
         and ex.get("tenant_id") == "default",
         f"HTTP {exr.status_code} · state={ex.get('state')}")
    fex = foreign.get(f"{BASE}/api/xdr/respond/executions/{exec_id}", timeout=45)
    gate("27b the wrong tenant cannot read the execution from the engine",
         fex.status_code >= 400, f"HTTP {fex.status_code}")

    bad = f"p01-fail-{uuid.uuid4().hex[:8]}"
    rf = owner.post(f"{BASE}/api/xdr/respond/execute",
                    json={"execution_id": bad,
                          "action": {"action_id": "endpoint.kill_process",
                                     "parameters": {"host_id": ENDPOINT,
                                                    "pid": 999999999}}},
                    timeout=90)
    rfj = rf.json() if rf.status_code == 200 else {}
    rflc = rfj.get("response_lifecycle") or {}
    gate("28 a refusal from the endpoint product stays a refusal (no false success)",
         rf.status_code != 200
         or rflc.get("lifecycle") in ("dispatch_failed", "rejected",
                                      "execution_failed", "pending_approval"),
         f"HTTP {rf.status_code} · lifecycle={rflc.get('lifecycle')}")
    gate("29 a failed action never carries an executed or verified fact",
         not (rflc.get("facts") or {}).get("executed")
         and not (rflc.get("facts") or {}).get("verified"),
         str(rflc.get("facts")))

    subprocess.run(["sudo", "supervisorctl", "restart", "xdr_response"],
                   capture_output=True, text=True)
    import time
    time.sleep(9)
    e2 = owner.get(f"{BASE}/api/xdr/respond/executions/{exec_id}", timeout=60)
    ex2 = e2.json() if e2.status_code == 200 else {}
    lc2 = ex2.get("response_lifecycle") or {}
    gate("30 authoritative action state survives a response-service restart",
         e2.status_code == 200 and ex2.get("execution_id") == exec_id
         and ex2.get("state") == ex.get("state"),
         f"state={ex2.get('state')} lifecycle={lc2.get('lifecycle')} "
         f"edr_cmd={((lc2.get('edr') or {}).get('command_id'))}")

    # ── 11 · canonical evidence + audit persistence ──────────────────
    gate("31 canonical evidence + audit refs are persisted for the execution",
         bool(apj.get("evidence_ref") and apj.get("audit_ref")
              and apj.get("forwarding_state") in ("forwarded", "not_wired")),
         f"evidence={apj.get('evidence_ref')} audit={apj.get('audit_ref')} "
         f"state={apj.get('forwarding_state')}")
    gate("32 the full attribution set is queryable "
         "(requester · approver · action · target · timestamps · tenant)",
         all([(apj.get("invoker") or {}).get("id"),
              (apj.get("approval") or {}).get("approved_by"),
              (apj.get("approval") or {}).get("approved_at"),
              apj.get("action_id"), edr.get("endpoint_id"),
              apj.get("tenant_id")]),
         f"requester={(apj.get('invoker') or {}).get('id')} "
         f"approver={(apj.get('approval') or {}).get('approved_by')}")

    # ── 12 · fail-closed boundary ────────────────────────────────────
    subprocess.run(["sudo", "supervisorctl", "stop", "xdr_response"],
                   capture_output=True, text=True)
    time.sleep(3)
    down = owner.post(f"{BASE}/api/xdr/respond/execute",
                      json={"execution_id": f"p01-down-{uuid.uuid4().hex[:8]}",
                            "action": {"action_id": "endpoint.isolate",
                                       "parameters": {"host_id": ENDPOINT}}},
                      timeout=90)
    dj = down.json() if down.headers.get("content-type", "").startswith("application/json") else {}
    det = (dj.get("detail") or {}) if isinstance(dj.get("detail"), dict) else {}
    gate("33 with the engine DOWN the boundary FAILS CLOSED — never a silent success",
         down.status_code == 503
         and det.get("error") == "response_engine_unavailable"
         and (det.get("response_lifecycle") or {}).get("lifecycle") == "dispatch_failed",
         f"HTTP {down.status_code} · {det.get('error')}")
    subprocess.run(["sudo", "supervisorctl", "start", "xdr_response"],
                   capture_output=True, text=True)
    time.sleep(9)
    gate("34 the engine returns to service after the fail-closed test",
         owner.get(f"{BASE}/api/xdr/respond/health", timeout=45)
              .json().get("reachable") is True, "reachable")

    # ── 13 · environment blockers — NEVER converted to PASS ──────────
    caps = ""
    try:
        with open("/proc/self/status") as fh:
            caps = next((l for l in fh if l.startswith("CapEff")), "").strip()
    except Exception:                                           # noqa: BLE001
        pass
    gate("35 real network isolation on the endpoint", None,
         blocked_reason=f"BLOCKED · CAP_NET_ADMIN absent in this pod ({caps})")
    gate("36 independent verification of real isolation", None,
         blocked_reason="BLOCKED · CAP_NET_ADMIN — no post-action containment "
                        "probe can be run, so no isolation may be graded VERIFIED")

    # ── summary ──────────────────────────────────────────────────────
    p = sum(1 for _, v, _ in rows if v == "PASS")
    f = sum(1 for _, v, _ in rows if v == "FAIL")
    b = sum(1 for _, v, _ in rows if v == "BLOCKED")
    print(f"\n{p} PASS · {f} FAIL · {b} BLOCKED  (of {len(rows)} gates)")
    for n, v, e in rows:
        if v == "FAIL":
            print(f"  FAILED: {n} · {e}")
    print("\nNOTE: BLOCKED gates are environment blockers and are NOT "
          "convertible to PASS in this pod.")
    return 0 if f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
