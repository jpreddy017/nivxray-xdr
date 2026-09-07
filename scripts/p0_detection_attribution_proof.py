#!/usr/bin/env python3
"""P0 · Detection Attribution — runtime proof.

An observation that a rule genuinely fired on must say so. The detection
is authoritative in `edr_raw_events.derivations[]` (outcome
DETECTION_MATCHED); the canonical observation carries no rule, so the
trajectory projection JOINS the two on persisted identifiers only:

    edr_raw_events.raw_id      == v2_shadow_observations.ingest_job_id
    derivations[].event_id     == v2_shadow_observations.canonical_event_id

Nothing is inferred from hostname, process name, pid or timestamp.
"""
import json
import os
import sys

import requests

BASE = (open("/app/apps/nivxray-xdr/.env").read()
        .split("REACT_APP_NIVXRAY_API_URL=")[1].split()[0])
ADMIN = ("admin@nivxray.com", os.environ.get("NVX_ADMIN_PW",
                                             "uulVDp5cCSB3Hva99s7UUAwK"))
OTHER = ("analyst@nivx-live.com", os.environ.get("NVX_OTHER_PW",
                                                 "NivxLive!Analyst2026"))
DEVICE = "dev_42e8c6dc74b9"
PLATFORM_EP = "ep_2d57cbe6f80152062109"
UNKNOWN = "UNKNOWN_NOT_ASSESSED"

R = []


def rec(item, ok, status, detail):
    R.append({"item": item, "result": "PASS" if ok else "FAIL",
              "status": status if ok else "BLOCKED", "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'}  {item}  [{status}]  {detail}")


def sess(cred):
    s = requests.Session()
    t = s.post(f"{BASE}/api/auth/login",
               json={"email": cred[0], "password": cred[1]},
               timeout=60).json()
    s.headers["Authorization"] = f"Bearer {t['access_token']}"
    return s


def main() -> int:
    a, o = sess(ADMIN), sess(OTHER)

    dets = (a.get(f"{BASE}/api/edr/endpoint-detections",
                  params={"endpoint_id": PLATFORM_EP, "hours": 720},
                  timeout=300).json().get("detections") or [])
    rec("A_authoritative_detections_exist", len(dets) >= 2,
        "REAL_RUNTIME_VERIFIED",
        f"{len(dets)} DETECTION_MATCHED derivations on {PLATFORM_EP}")

    # B/C/D · every detection, through the handoff, carries attribution
    bad = []
    checked = []
    for d in dets[:8]:
        f = a.get(f"{BASE}/api/edr/endpoints/{DEVICE}/trajectory/focus",
                  params={"raw_event_id": d["raw_id"]}, timeout=300).json()
        foc = f.get("focus") or {}
        det = foc.get("detection") or {}
        ok = (f.get("state") == "FOCUS_RESOLVED"
              and foc.get("assessment_state") == "ASSESSED_BY_DETECTION_FABRIC"
              and det.get("outcome") == "DETECTION_MATCHED"
              and det.get("rule_ids")
              and foc.get("disposition") != UNKNOWN
              and det.get("raw_event_id") == d["raw_id"]
              and det.get("canonical_event_id") == d.get("canonical_event_id"))
        (checked if ok else bad).append((d, f))
    rec("B_every_detection_reached_carries_attribution", not bad,
        "REAL_RUNTIME_VERIFIED",
        f"{len(checked)} of {len(dets[:8])} detections carry rule "
        f"attribution on the observation itself; {len(bad)} do not")
    if checked:
        d0, f0 = checked[0]
        det0 = f0["focus"]["detection"]
        rec("C_rule_attribution_matches_the_authoritative_record",
            set(det0["rule_ids"]) == set(d0.get("rule_ids") or []),
            "REAL_RUNTIME_VERIFIED",
            f"observation rules {det0['rule_ids']} == derivation rules "
            f"{d0.get('rule_ids')} · engine {det0.get('engines')} · verdict "
            f"{det0.get('verdict')}")
        rec("D_disposition_is_no_longer_unassessed",
            f0["focus"]["disposition"] != UNKNOWN,
            "REAL_RUNTIME_VERIFIED",
            f"{d0['raw_id']} -> disposition "
            f"{f0['focus']['disposition']} (was {UNKNOWN})")
        rec("E_provenance_back_to_the_raw_derivation_is_intact",
            det0["raw_event_id"] == d0["raw_id"]
            and det0["canonical_event_id"] == d0["canonical_event_id"]
            and det0["outcome"] == "DETECTION_MATCHED"
            and "derivations" in det0["basis"],
            "REAL_RUNTIME_VERIFIED",
            f"{det0['outcome']} → {det0['raw_event_id']} → "
            f"{det0['canonical_event_id']}")

    # F/G/H · the whole trajectory: attribution is exact, not blanket
    win = a.get(f"{BASE}/api/edr/endpoints/{DEVICE}/trajectory",
                params={"lane_start": 0, "lane_end": 100000, "limit": 4000},
                timeout=300).json()
    evs = win.get("events") or []
    detected = [e for e in evs if e.get("detection")]
    plain = [e for e in evs if not e.get("detection")]
    rec("F_attribution_is_exact_not_blanket",
        0 < len(detected) < len(evs), "REAL_RUNTIME_VERIFIED",
        f"{len(detected)} of {len(evs)} observations in page 1 carry a "
        f"detection; {len(plain)} do not")
    rec("G_no_detected_observation_reads_as_unassessed",
        all(e["disposition"] != UNKNOWN
            and e["assessment_state"] == "ASSESSED_BY_DETECTION_FABRIC"
            and e["is_detection"] and e["rule_ids"] for e in detected),
        "REAL_RUNTIME_VERIFIED",
        f"all {len(detected)} detected observations are assessed, e.g. "
        f"{detected[0]['rule_ids'] if detected else '-'} / "
        f"{detected[0]['disposition'] if detected else '-'}")
    rec("H_undetected_observations_are_unchanged",
        all(e["assessment_state"] == "NO_DETECTION_CLAIMED_THIS_OBSERVATION"
            and e["rule_ids"] == [] for e in plain),
        "REAL_RUNTIME_VERIFIED",
        f"{len(plain)} telemetry observations still report "
        f"NO_DETECTION_CLAIMED_THIS_OBSERVATION — absence of a detection "
        f"is not a verdict of clean")
    rec("I_attribution_is_deterministic_across_requests",
        True if not detected else
        (a.get(f"{BASE}/api/edr/endpoints/{DEVICE}/trajectory/focus",
               params={"event_iid": detected[0]["event_iid"]}, timeout=300)
         .json().get("focus", {}).get("detection", {}).get("rule_ids")
         == detected[0]["rule_ids"]),
        "REAL_RUNTIME_VERIFIED",
        "the same observation returns the same rule_ids through a second, "
        "independent request path (focus by event_iid)")
    rec("J_rule_id_is_searchable_on_the_trajectory",
        (a.get(f"{BASE}/api/edr/endpoints/{DEVICE}/trajectory",
               params={"lane_start": 0, "lane_end": 100000, "limit": 10,
                       "q": (detected[0]["rule_ids"][0] if detected
                             else "EDR-LNX-002")}, timeout=300).json()
         .get("matched_after_filters", 0) > 0),
        "REAL_RUNTIME_VERIFIED",
        "filtering the trajectory by the rule id reduces it to the "
        "observations that rule fired on")

    # K/L · nothing can be manufactured
    forged = a.get(f"{BASE}/api/edr/endpoints/{DEVICE}/trajectory/focus",
                   params={"raw_event_id": "raw_not_a_real_event"},
                   timeout=300).json()
    rec("K_a_forged_identifier_manufactures_no_attribution",
        forged.get("state") == "OBSERVATION_NOT_RESOLVED"
        and forged.get("focus") is None,
        "REAL_RUNTIME_VERIFIED", f"-> {forged.get('state')}")
    xt = o.get(f"{BASE}/api/edr/endpoints/{DEVICE}/trajectory/focus",
               params={"raw_event_id": dets[0]["raw_id"]},
               timeout=300).json() if dets else {}
    rec("L_attribution_never_crosses_a_customer_boundary",
        xt.get("state") == "ENDPOINT_NOT_RESOLVED"
        and xt.get("focus") is None,
        "REAL_RUNTIME_VERIFIED",
        f"nivx-live principal on a default endpoint -> {xt.get('state')}")

    chain = None
    if checked:
        d0, f0 = checked[0]
        det0 = f0["focus"]["detection"]
        chain = {"rule_ids": det0["rule_ids"], "engine": det0["engines"],
                 "verdict": det0["verdict"],
                 "detection_id": det0["detection_id"],
                 "outcome": det0["outcome"],
                 "raw_event_id": det0["raw_event_id"],
                 "canonical_event_id": det0["canonical_event_id"],
                 "observation": f0["focus"]["event_iid"],
                 "disposition": f0["focus"]["disposition"],
                 "assessment_state": f0["focus"]["assessment_state"]}

    failed = [r for r in R if r["result"] != "PASS"]
    out = {"phase": "P0 · DETECTION ATTRIBUTION",
           "base_url": BASE, "acceptance": R,
           "attribution_chain": chain,
           "join": ("edr_raw_events.raw_id == "
                    "v2_shadow_observations.ingest_job_id AND "
                    "derivations[].event_id == canonical_event_id — "
                    "persisted identifiers only"),
           "passed": len(R) - len(failed), "failed": len(failed)}
    with open("/app/test_reports/p0_detection_attribution_proof.json",
              "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"\n{out['passed']} passed · {out['failed']} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
