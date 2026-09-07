#!/usr/bin/env python3
"""P0-W · WIRING PHASE PROOF · F-1 endpoint identity · F-2 console truth.

Runtime proof against the live preview.  READ-ONLY (GET) apart from the
login POST.  Asserts, on the REAL enrolled endpoint:

F-1  the device_iid and its platform-minted endpoint_id resolve to the
     SAME identity AND return the SAME evidence on every EDR surface —
     no surface may report an empty state the other contradicts.
F-1b tenant isolation is preserved: a customer-scoped analyst cannot
     widen its reach through the alias set, and a forged reference
     resolves to nothing.
F-2  the capability registry that the EDR console now reads actually
     grades the five overview surfaces, so availability is derived, not
     hardcoded.
"""
from __future__ import annotations

import os
import sys

import requests

BASE = os.environ.get("AUDIT_BASE") or "https://greeting-app-5782.preview.emergentagent.com"
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
ANALYST_NIVX = ("analyst@nivx-live.com", "NivxLive!Analyst2026")
ANALYST_DEFAULT = ("analyst@default.com", "DefaultCo!Analyst2026")

DEVICE_IID = "dev_42e8c6dc74b9"
ENDPOINT_ID = "ep_2d57cbe6f80152062109"
HOSTNAME = "agent-env-630704a1-621f-478b-9b86-a321772d01bf"

CAPS = ["experience.device_trajectory_ui", "experience.detections_ui",
        "experience.process_tree_ui", "experience.file_trajectory_ui",
        "experience.network_ui"]

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    results.append((bool(ok), label))
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  · {detail}" if detail else ""))


def session(creds) -> requests.Session:
    s = requests.Session()
    r = s.post(f"{BASE}/api/auth/login",
               json={"email": creds[0], "password": creds[1]}, timeout=30)
    r.raise_for_status()
    j = r.json()
    s.headers["Authorization"] = f"Bearer {j.get('access_token') or j.get('token')}"
    return s


def tree(s, ident):
    return s.get(f"{BASE}/api/edr/process-tree",
                 params={"endpoint_id": ident}, timeout=90).json()


def dets(s, ident):
    return s.get(f"{BASE}/api/edr/endpoint-detections",
                 params={"endpoint_id": ident}, timeout=90).json()


def traj(s, ident):
    return s.get(f"{BASE}/api/edr/endpoints/{ident}/trajectory",
                 timeout=90).json()


def main() -> int:
    a = session(ADMIN)
    print("== F-1 · one endpoint, every identifier ==")

    t_dev, t_ep, t_host = tree(a, DEVICE_IID), tree(a, ENDPOINT_ID), tree(a, HOSTNAME)
    d_dev, d_ep, d_host = dets(a, DEVICE_IID), dets(a, ENDPOINT_ID), dets(a, HOSTNAME)

    n_dev, n_ep, n_host = (len(t_dev.get("nodes") or []),
                           len(t_ep.get("nodes") or []),
                           len(t_host.get("nodes") or []))
    check(n_dev > 0, "1 process tree is NOT empty for the device_iid",
          f"nodes={n_dev} reason={t_dev.get('reason')}")
    check(n_dev == n_ep == n_host,
          "2 process tree is identical for device_iid, endpoint_id and hostname",
          f"{n_dev} / {n_ep} / {n_host}")

    c_dev, c_ep, c_host = d_dev.get("count"), d_ep.get("count"), d_host.get("count")
    check((c_dev or 0) > 0, "3 endpoint detections are NOT empty for the device_iid",
          f"count={c_dev} evaluated={d_dev.get('events_evaluated')}")
    check(c_dev == c_ep == c_host,
          "4 endpoint detections identical for all three identifiers",
          f"{c_dev} / {c_ep} / {c_host}")
    check((d_dev.get("events_evaluated") or 0) == (d_ep.get("events_evaluated") or 0)
          and (d_dev.get("events_evaluated") or 0) > 0,
          "5 events_evaluated identical and non-zero",
          f"{d_dev.get('events_evaluated')} / {d_ep.get('events_evaluated')}")

    ids_dev = sorted({r.get("raw_id") for r in d_dev.get("detections") or []})
    ids_ep = sorted({r.get("raw_id") for r in d_ep.get("detections") or []})
    check(ids_dev == ids_ep and ids_dev,
          "6 the SAME authoritative raw evidence ids are returned, not just equal counts",
          f"{len(ids_dev)} raw ids")

    for name, doc in (("process-tree", t_dev), ("endpoint-detections", d_dev)):
        idn = doc.get("identity") or {}
        check(idn.get("resolved") is True and idn.get("device_iid") == DEVICE_IID,
              f"7 {name} reports the resolved identity", str(idn.get("resolved_via")))
        check(ENDPOINT_ID in (idn.get("addressed_by") or []),
              f"8 {name} discloses the endpoint_id it addressed the store by",
              str(idn.get("addressed_by")))

    tj = traj(a, DEVICE_IID)
    check(bool((tj.get("identity") or {}).get("resolved")
               or tj.get("resolved") or tj.get("events") or tj.get("lanes")),
          "9 Device Trajectory still resolves the same device_iid (no regression)")

    print("\n== F-1b · isolation is preserved, not widened ==")
    check((tree(a, "dev_forged000000")
           .get("epistemic_state", {}).get("state") == "ENDPOINT_NOT_RESOLVED"),
          "10 a forged device reference resolves to nothing")
    fd = dets(a, "ep_forged00000000000000")
    check(fd.get("reason") == "ENDPOINT_NOT_RESOLVED" and fd.get("count") == 0,
          "11 a forged endpoint_id yields an honest unresolved state, not zero detections",
          str(fd.get("reason")))

    nx = session(ANALYST_NIVX)
    x_tree, x_dets = tree(nx, DEVICE_IID), dets(nx, DEVICE_IID)
    check((x_tree.get("epistemic_state", {}).get("state") == "ENDPOINT_NOT_RESOLVED"
           or not (x_tree.get("nodes") or [])),
          "12 a nivx-live analyst gets NO process evidence for a default-tenant endpoint",
          str(x_tree.get("epistemic_state", {}).get("state")))
    check(x_dets.get("count") == 0,
          "13 a nivx-live analyst gets NO detections for a default-tenant endpoint",
          f"reason={x_dets.get('reason')} count={x_dets.get('count')}")
    check(ENDPOINT_ID not in str(x_dets.get("identity") or {}),
          "14 the alias set does not leak the endpoint_id to an unauthorised tenant")

    df = session(ANALYST_DEFAULT)
    o_tree, o_dets = tree(df, DEVICE_IID), dets(df, DEVICE_IID)
    check(len(o_tree.get("nodes") or []) == n_dev,
          "15 the OWNING tenant's analyst sees the same tree as the admin",
          f"{len(o_tree.get('nodes') or [])} vs {n_dev}")
    check(o_dets.get("count") == c_dev,
          "16 the OWNING tenant's analyst sees the same detections as the admin",
          f"{o_dets.get('count')} vs {c_dev}")

    print("\n== F-2 · console truth comes from the capability registry ==")
    caps = a.get(f"{BASE}/api/edr/wave0/capabilities", timeout=60).json()
    by_id = {r["capability_id"]: r for r in caps.get("capabilities") or []}
    check(len(by_id) > 100, "17 capability registry is reachable and populated",
          f"{len(by_id)} rows")
    for cid in CAPS:
        row = by_id.get(cid)
        check(bool(row and row.get("declared_state")),
              f"18 {cid} is graded by the registry",
              str((row or {}).get("declared_state")))
    check((by_id.get("experience.detections_ui") or {}).get("declared_state")
          != "NOT_IMPLEMENTED",
          "19 Detections is NOT graded NOT_IMPLEMENTED (the old hardcoded claim was false)")
    check((by_id.get("experience.process_tree_ui") or {}).get("declared_state")
          != "NOT_IMPLEMENTED",
          "20 Process Tree is NOT graded NOT_IMPLEMENTED (the old hardcoded claim was false)")
    check((by_id.get("experience.network_ui") or {}).get("declared_state")
          == "NOT_IMPLEMENTED",
          "21 Network IS genuinely NOT_IMPLEMENTED — the console must keep saying so")

    passed = sum(1 for ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} PASS")
    for ok, label in results:
        if not ok:
            print(f"  FAILED: {label}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
