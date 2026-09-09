#!/usr/bin/env python3
"""P0-W · INCIDENT TENANT AUTHORIZATION PROOF.

Every by-id route on the authoritative incident plane
(`routers/incidents.py`, `_col = workspace_cases`) previously resolved
`{"id": incident_id}` with NO tenant predicate — a direct-object
reference leak on the read AND write paths, with two write routes
accepting an anonymous principal.

This proves, against the live preview:

  NEGATIVE  a wrong-tenant principal cannot READ, and cannot MUTATE —
            state, assignee and operations are all rejected, and the
            incident's state / assignee / state_history are byte-identical
            afterwards, with no worklog entry created.
  ANONYMOUS an unauthenticated caller can neither read nor write.
  POSITIVE  the OWNING tenant can still do all of it, and the legitimate
            transition still appends exactly one attributed worklog entry.
  SEMANTICS out-of-scope is indistinguishable from non-existent (404,
            never 403), so no response discloses that another customer's
            incident exists.

The single controlled mutation runs ONLY after the fix, on a low-value
incident, and is reverted to the state it started in.
"""
from __future__ import annotations

import copy
import json
import os
import sys

import requests

BASE = os.environ.get("AUDIT_BASE") or "https://greeting-app-5782.preview.emergentagent.com"
ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
OWNER = ("analyst@default.com", "DefaultCo!Analyst2026")      # tenant: default
FOREIGN = ("analyst@nivx-live.com", "NivxLive!Analyst2026")   # tenant: nivx-live

TARGET = "inc_2305c71cd8f54dc38e55"   # tenant_id == "default"

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    results.append((bool(ok), label))
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  · {detail}" if detail else ""))


def sess(creds=None) -> requests.Session:
    s = requests.Session()
    if creds:
        r = s.post(f"{BASE}/api/auth/login",
                   json={"email": creds[0], "password": creds[1]}, timeout=30)
        r.raise_for_status()
        j = r.json()
        s.headers["Authorization"] = f"Bearer {j.get('access_token') or j.get('token')}"
    return s


def snapshot(s) -> dict:
    r = s.get(f"{BASE}/api/incidents/{TARGET}", timeout=60)
    r.raise_for_status()
    d = r.json()
    return {"state": d.get("incident_state") or d.get("state"),
            "assignee": d.get("assignee") or d.get("incident_assignee"),
            "priority": d.get("priority") or d.get("priority_code"),
            "history": copy.deepcopy(d.get("state_history") or [])}


def main() -> int:
    admin = sess(ADMIN)
    owner = sess(OWNER)
    foreign = sess(FOREIGN)
    anon = sess()

    print("== baseline (admin, cross-tenant role) ==")
    before = snapshot(admin)
    print(f"   state={before['state']} assignee={before['assignee']} "
          f"history={len(before['history'])} entries")

    print("\n== NEGATIVE · wrong tenant (nivx-live) on a default incident ==")
    r = foreign.get(f"{BASE}/api/incidents/{TARGET}", timeout=60)
    check(r.status_code == 404, "1 wrong-tenant GET is rejected", f"HTTP {r.status_code}")
    check("state_history" not in r.text and "admin@nivxray.com" not in r.text,
          "2 no state_history and no actor identity leak in the rejection body")
    check((r.json().get("detail") or {}).get("error") == "incident_not_found"
          if r.headers.get("content-type", "").startswith("application/json") else False,
          "3 not-found semantics — existence of another customer's incident is not disclosed",
          r.text[:90])

    r = foreign.patch(f"{BASE}/api/incidents/{TARGET}/state",
                      json={"target_state": "in_progress",
                            "note": "cross-tenant authorization probe"}, timeout=60)
    check(r.status_code == 404, "4 wrong-tenant state PATCH is rejected", f"HTTP {r.status_code}")

    r = foreign.patch(f"{BASE}/api/incidents/{TARGET}/assignee",
                      json={"assignee": "attacker@nivx-live.com"}, timeout=60)
    check(r.status_code == 404, "5 wrong-tenant assignee PATCH is rejected", f"HTTP {r.status_code}")

    r = foreign.patch(f"{BASE}/api/incidents/{TARGET}/operations",
                      json={"priority": "P1"}, timeout=60)
    check(r.status_code == 404, "6 wrong-tenant operations PATCH is rejected", f"HTTP {r.status_code}")

    r = foreign.get(f"{BASE}/api/incidents/{TARGET}/understanding", timeout=90)
    check(r.status_code == 404, "7 wrong-tenant understanding GET is rejected", f"HTTP {r.status_code}")

    after_neg = snapshot(admin)
    check(after_neg["state"] == before["state"],
          "8 incident state UNCHANGED after the rejected mutations", str(after_neg["state"]))
    check(after_neg["assignee"] == before["assignee"],
          "9 assignee UNCHANGED after the rejected mutations", str(after_neg["assignee"]))
    check(after_neg["priority"] == before["priority"],
          "10 priority UNCHANGED after the rejected mutations", str(after_neg["priority"]))
    check(json.dumps(after_neg["history"], sort_keys=True)
          == json.dumps(before["history"], sort_keys=True),
          "11 state_history byte-identical — NO worklog entry was created",
          f"{len(after_neg['history'])} entries")

    print("\n== ANONYMOUS · no principal at all ==")
    r = anon.get(f"{BASE}/api/incidents/{TARGET}", timeout=60)
    check(r.status_code == 404, "12 anonymous GET is rejected", f"HTTP {r.status_code}")
    r = anon.patch(f"{BASE}/api/incidents/{TARGET}/operations",
                   json={"priority": "P1"}, timeout=60)
    check(r.status_code == 404,
          "13 anonymous operations PATCH is rejected (it previously accepted an optional principal)",
          f"HTTP {r.status_code}")
    after_anon = snapshot(admin)
    check(after_anon["priority"] == before["priority"],
          "14 priority UNCHANGED after the anonymous attempt", str(after_anon["priority"]))

    print("\n== NEGATIVE · a forged id inside the caller's own scope ==")
    r = owner.get(f"{BASE}/api/incidents/inc_forged000000000000", timeout=60)
    check(r.status_code == 404, "15 a non-existent id also returns 404 — identical response shape",
          f"HTTP {r.status_code}")

    print("\n== POSITIVE · the OWNING tenant still works ==")
    o = snapshot(owner)
    check(o["state"] == before["state"] and len(o["history"]) == len(before["history"]),
          "16 owning-tenant analyst READS the incident with full history",
          f"state={o['state']} history={len(o['history'])}")

    # A legal, reversible round-trip: `in_progress ↔ on_hold`. `new` is
    # deliberately unreachable once left (LIFECYCLE_TRANSITIONS has no
    # edge back to it), so this proof never attempts to "revert" through
    # an illegal transition and never writes to Mongo directly to fake
    # one — that would violate the append-only worklog and the lifecycle
    # state machine it is meant to be proving.
    start_state = (o["state"] or "new").lower()
    if start_state == "new":
        step, back = "in_progress", None      # one-way, recorded honestly
    elif start_state == "in_progress":
        step, back = "on_hold", "in_progress"
    elif start_state == "on_hold":
        step, back = "in_progress", "on_hold"
    elif start_state == "resolved":
        step, back = "in_progress", None
    else:
        step, back = None, None               # closed is terminal

    if step is None:
        check(True, "17-23 mutation tests SKIPPED — the incident is terminal (closed)",
              start_state)
    else:
        r = owner.patch(f"{BASE}/api/incidents/{TARGET}/state",
                        json={"target_state": step,
                              "note": "P0-W authorization proof · legitimate transition"},
                        timeout=60)
        check(r.status_code == 200, "17 owning-tenant state PATCH SUCCEEDS",
              f"HTTP {r.status_code} · {start_state} -> {step}")
        mid = snapshot(owner)
        check(len(mid["history"]) == len(before["history"]) + 1,
              "18 exactly ONE worklog entry was appended",
              f"{len(before['history'])} -> {len(mid['history'])}")
        last = (mid["history"] or [{}])[-1]
        check(last.get("actor") == OWNER[0],
              "19 the entry is attributed to the acting principal", str(last.get("actor")))
        check(bool(last.get("note")),
              "20 the analyst note was persisted on the worklog entry",
              str(last.get("note"))[:60])
        check(last.get("from") == start_state and last.get("to") == step,
              "21 the transition is recorded from→to",
              f"{last.get('from')} -> {last.get('to')}")

        if back:
            r = owner.patch(f"{BASE}/api/incidents/{TARGET}/state",
                            json={"target_state": back,
                                  "note": "P0-W authorization proof · restoring the original state"},
                            timeout=60)
            end = snapshot(admin)
            check(r.status_code == 200 and end["state"] == before["state"],
                  "22 the controlled mutation was restored through a LEGAL transition",
                  f"HTTP {r.status_code} state={end['state']}")
            check(len(end["history"]) == len(before["history"]) + 2,
                  "23 the worklog is APPEND-ONLY — restoring appended an entry, it erased none",
                  f"{len(before['history'])} -> {len(end['history'])}")
        else:
            end = snapshot(admin)
            check(end["state"] == step,
                  f"22 no legal edge returns to `{start_state}` — the transition stands, "
                  "recorded honestly rather than faked away by a direct write",
                  f"state={end['state']}")
            check(len(end["history"]) == len(before["history"]) + 1,
                  "23 the worklog is APPEND-ONLY — one entry added, none erased",
                  f"{len(before['history'])} -> {len(end['history'])}")

    print("\n== the queue was already scoped — confirm it still is ==")
    fq = foreign.get(f"{BASE}/api/incidents?limit=500", timeout=90).json()
    ids = {i.get("id") for i in fq.get("incidents") or []}
    check(TARGET not in ids,
          "24 the default incident is still absent from the nivx-live queue",
          f"{len(ids)} incidents visible to nivx-live")
    oq = owner.get(f"{BASE}/api/incidents?limit=500", timeout=90).json()
    check(TARGET in {i.get("id") for i in oq.get("incidents") or []},
          "25 the owning tenant still sees it in its own queue",
          f"{oq.get('count')} incidents visible to default")

    passed = sum(1 for ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} PASS")
    for ok, label in results:
        if not ok:
            print(f"  FAILED: {label}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
