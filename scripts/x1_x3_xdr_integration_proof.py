#!/usr/bin/env python3
"""X1–X3 · XDR shell / unified search / XDR↔EDR pivot proof.

Backend-provable half of the slice. The UI half is proven in the
browser (iteration report).
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
HOST = "agent-env-630704a1-621f-478b-9b86-a321772d01bf"
INCIDENT = "inc_2305c71cd8f54dc38e55"
RAW = "raw_fac9185acde4f8ccebef7a3b"
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


def search(s, q, **kw):
    return s.get(f"{BASE}/api/xdr/search", params={"q": q, **kw},
                 timeout=300).json()


def groups(d):
    return {g["entity_type"]: g["count"] for g in d.get("groups") or []}


def main() -> int:
    a, o = sess(ADMIN), sess(OTHER)

    # ── X2 · unified search over authoritative stores ────────────
    d = search(a, "EDR-LNX-002")
    g = groups(d)
    rec("X2_rule_id_search_spans_entity_types",
        d["state"] == "RESULTS" and g.get("INCIDENT", 0) >= 1
        and g.get("DETECTION", 0) >= 1,
        "REAL_RUNTIME_VERIFIED",
        f"{d['total']} results · {g} · classified {d['term_classification']}")
    det = next(r for gr in d["groups"] if gr["entity_type"] == "DETECTION"
               for r in gr["results"])
    rec("X2_detection_result_opens_the_exact_observation",
        "raw_event_id=" in det["href"] and "device=" in det["href"],
        "REAL_RUNTIME_VERIFIED",
        f"href {det['href'][:96]} (the proven identifier-only handoff)")

    d2 = search(a, HOST)
    rec("X2_hostname_resolves_the_endpoint",
        groups(d2).get("ENDPOINT", 0) == 1,
        "REAL_RUNTIME_VERIFIED",
        f"{groups(d2)} · endpoint href "
        f"{[r['href'] for gr in d2['groups'] if gr['entity_type']=='ENDPOINT' for r in gr['results']]}")

    d3 = search(a, RAW)
    g3 = groups(d3)
    rec("X2_evidence_identifier_resolves_evidence_process_and_detection",
        g3.get("EVIDENCE", 0) >= 1 and g3.get("DETECTION", 0) >= 1
        and g3.get("PROCESS", 0) >= 1,
        "REAL_RUNTIME_VERIFIED", f"{g3}")

    d4 = search(a, "INC000000293")
    rec("X2_incident_reference_resolves_its_incident",
        groups(d4).get("INCIDENT", 0) == 1,
        "REAL_RUNTIME_VERIFIED",
        f"{d4['groups'][0]['results'][0]['href']}")

    d5 = search(a, "zzz-no-such-entity-zzz")
    rec("X2_no_match_is_stated_not_padded",
        d5["state"] == "NO_MATCH" and d5["total"] == 0
        and bool(d5.get("message")),
        "REAL_RUNTIME_VERIFIED", f"-> {d5['state']}")

    d6 = search(a, "anything", type="identity")
    rec("X2_unsupported_entity_type_is_explicit",
        d6["state"] == "NOT_SEARCHABLE_NO_INDEX"
        and d6["not_searchable"][0]["reason"],
        "REAL_RUNTIME_VERIFIED",
        f"identity -> {d6['state']} · {d6['not_searchable'][0]['reason']}")
    rec("X2_ordinary_search_is_not_cluttered_with_unsupported_types",
        all(gr["count"] > 0 for gr in d["groups"])
        and d.get("not_searchable") == [],
        "REAL_RUNTIME_VERIFIED",
        "empty/unsupported categories are absent from a normal result set; "
        "they are listed only by /api/xdr/search/capabilities or when asked")

    caps = a.get(f"{BASE}/api/xdr/search/capabilities", timeout=120).json()
    rec("X2_search_declares_what_it_cannot_answer",
        len(caps["searchable"]) >= 7 and len(caps["not_searchable"]) >= 5,
        "REAL_RUNTIME_VERIFIED",
        f"{len(caps['searchable'])} searchable · "
        f"{len(caps['not_searchable'])} NOT_SEARCHABLE_NO_INDEX")
    rec("X2_no_event_digest_is_offered_as_a_file_hash",
        all("key_type=sha256" not in r["href"]
            for gr in search(a, "bash").get("groups") or []
            for r in gr["results"]),
        "REAL_RUNTIME_VERIFIED",
        "event.raw.sha256 is an event-content digest, so FILE results "
        "pivot on the observed path only")

    xt = search(o, HOST)
    rec("X2_search_is_tenant_scoped",
        groups(xt).get("ENDPOINT", 0) == 0
        and groups(xt).get("DETECTION", 0) == 0
        and groups(xt).get("EVIDENCE", 0) == 0,
        "REAL_RUNTIME_VERIFIED",
        f"nivx-live principal searching a default endpoint -> "
        f"{xt['state']} · {groups(xt)}")

    # ── X3 · EDR → XDR linked incidents ─────────────────────────
    li = a.get(f"{BASE}/api/edr/endpoints/{DEVICE}/linked-incidents",
               timeout=300).json()
    rec("X3_linked_xdr_incidents_are_resolved",
        li["state"] == "LINKED" and li["count"] >= 1
        and all(r["href"].startswith("/xdr/incidents/")
                for r in li["incidents"]),
        "REAL_RUNTIME_VERIFIED",
        f"{li['count']} incidents · "
        f"{[r['incident_number'] for r in li['incidents']][:4]} · basis "
        f"{li['basis'][:60]}")
    lo = o.get(f"{BASE}/api/edr/endpoints/{DEVICE}/linked-incidents",
               timeout=300).json()
    rec("X3_linked_incidents_fail_closed_cross_tenant",
        lo["state"] == "ENDPOINT_NOT_RESOLVED" and lo["count"] == 0,
        "REAL_RUNTIME_VERIFIED", f"-> {lo['state']}")
    lb = a.get(f"{BASE}/api/edr/endpoints/dev_not_real/linked-incidents",
               timeout=300).json()
    rec("X3_forged_endpoint_has_no_linked_incidents",
        lb["state"] == "ENDPOINT_NOT_RESOLVED",
        "REAL_RUNTIME_VERIFIED", f"-> {lb['state']}")

    # ── X3 · explicit identifier wins over incident context ─────
    f = a.get(f"{BASE}/api/edr/endpoints/{DEVICE}/trajectory/focus",
              params={"raw_event_id": RAW, "incident_id": INCIDENT},
              timeout=300).json()
    rec("X3_explicit_identifier_wins_over_incident_derived_ids",
        f["state"] == "FOCUS_RESOLVED"
        and f["focus"]["provenance"]["raw_event_id"] == RAW
        and f["context"]["incident_id"] == INCIDENT,
        "REAL_RUNTIME_VERIFIED",
        f"named {RAW} with incident context held -> "
        f"{f['focus']['provenance']['raw_event_id']} · lane "
        f"{f['focus']['lane_index']} · incident "
        f"{f['context']['incident_id']}")
    f2 = a.get(f"{BASE}/api/edr/endpoints/{DEVICE}/trajectory/focus",
               params={"incident_id": INCIDENT,
                       "detection_id": f"{INCIDENT}::rule::EDR-LNX-002"},
               timeout=300).json()
    rec("X3_incident_only_pivot_still_resolves_from_the_campaign",
        f2["state"] == "FOCUS_RESOLVED",
        "REAL_RUNTIME_VERIFIED",
        f"case-surface detection_id -> {f2['focus']['event_iid']}")

    ctx = a.get(f"{BASE}/api/edr/context",
                params={"endpoint_id": DEVICE, "incident_id": INCIDENT},
                timeout=300).json()
    rec("X1_pivot_context_is_complete",
        ctx["entry_context"] == "XDR_PIVOT"
        and ctx["investigation"]["incident_number"]
        and ctx["active_customer"]["basis"],
        "REAL_RUNTIME_VERIFIED",
        f"tenant {ctx['active_customer']['basis']} · incident "
        f"{ctx['investigation']['incident_number']} · endpoint "
        f"{ctx['endpoint']['device_iid']}")

    failed = [r for r in R if r["result"] != "PASS"]
    out = {"phase": "X1-X3 · XDR shell · unified search · XDR↔EDR pivots",
           "base_url": BASE, "acceptance": R,
           "reuse_note": ("extends XdrShell, NivXForgeConsole, edr router "
                          "and the proven P0-F.13.5 handoff; the only new "
                          "surfaces are the genuinely missing ones "
                          "(/api/xdr/search, the context bar, linked "
                          "incidents, capability-honest IA nodes)"),
           "passed": len(R) - len(failed), "failed": len(failed)}
    with open("/app/test_reports/x1_x3_xdr_integration_proof.json", "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"\n{out['passed']} passed · {out['failed']} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
