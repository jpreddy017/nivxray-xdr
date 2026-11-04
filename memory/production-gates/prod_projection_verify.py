#!/usr/bin/env python3
"""PRODUCTION ACCEPTANCE — Windows activity projection (Publish 100 / d85f369)

STRICTLY READ-ONLY. Every request is a GET except the one POST /api/auth/login
that mints your own session. No write, no patch, no delete, no deploy, no DB
change, no endpoint action. Nothing secret is printed: the password is read
with getpass and the bearer token is never echoed, logged or written to disk.

OWNER-SIDE USE (run it yourself; do not paste any token into chat):

    python3 memory/production-gates/prod_projection_verify.py

It asks for the admin password interactively, then prints PASS / FAIL for
every acceptance criterion and a final verdict.
"""
from __future__ import annotations

import collections
import getpass
import json
import os
import re
import sys
import urllib.error
import urllib.request

API = "https://nivxray.nivxforge.com"
EMAIL = "admin@nivxray.com"
ENDPOINT = "ep_1989031c8c1d0085812f"
TENANT = "ten_e759b7288598bd882e3dcac49d"

SUPPORTED = {("sysmon", 1): "PROCESS", ("sysmon", 3): "NETWORK",
             ("sysmon", 11): "FILE", ("sysmon", 12): "REGISTRY",
             ("sysmon", 13): "REGISTRY", ("sysmon", 22): "DNS",
             ("winsec", 4688): "PROCESS", ("winsec", 4624): "AUTH"}

results: list[tuple[str, bool | None, str]] = []


def record(name: str, ok: bool | None, detail: str = "") -> None:
    tag = {True: "PASS", False: "FAIL", None: "REVIEW"}[ok]
    results.append((name, ok, detail))
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail else ""))


def call(path: str, token: str | None = None, body: dict | None = None):
    req = urllib.request.Request(API + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
        req.add_header("X-Tenant-Id", TENANT)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw[:200]}


def event_family(row: dict) -> tuple[str, int | None]:
    p = (row.get("payload_preview") or "").replace("'", '"')
    m = re.search(r'"event_id"\s*:\s*"?(\d+)', p)
    if "Sysmon" in p:
        fam = "sysmon"
    elif "Security" in p or "Security-Auditing" in p:
        fam = "winsec"
    else:
        fam = "?"
    return fam, (int(m.group(1)) if m else None)


def main() -> int:
    print("NivXForge EDR · production acceptance · READ-ONLY")
    print(f"target {API}  endpoint {ENDPOINT}\n")

    print("0 · unauthenticated liveness")
    st, health = call("/api/health")
    record("API healthy", health.get("status") == "ok", json.dumps(health))

    # Standing policy: a SHORT-LIVED JWT is the preferred credential and a
    # password is never required. If NIVXJWT is exported, no login happens
    # at all and this script performs GET requests only.
    token = os.environ.get("NIVXJWT", "").strip()
    if token:
        print("  [PASS] using the session token from $NIVXJWT "
              "(no login, GETs only)\n")
    else:
        if not sys.stdin.isatty():
            print("  [STOP] no $NIVXJWT and no interactive terminal.\n"
                  "         Either export a short-lived console token:\n"
                  "           export NIVXJWT='<token from your signed-in "
                  "console>'\n"
                  "         or run this script in your own terminal, where "
                  "it can prompt.")
            return 2
        pw = getpass.getpass(f"password for {EMAIL} "
                             "(not echoed, not stored): ")
        st, out = call("/api/auth/login",
                       body={"email": EMAIL, "password": pw})
        token = out.get("access_token") or out.get("token")
        del pw
        if not token:
            print(f"  [FAIL] login → HTTP {st} {json.dumps(out)[:160]}")
            return 1
        print("  [PASS] authenticated (token held in memory only)\n")

    # ── 1 · is production actually running the new code? ──────────
    # Pre-patch code REFUSED activity=AUTHENTICATION with 422
    # ACTIVITY_INVALID (edr_events.py:227-231 at 86e02057^). The patched
    # code maps it through projection_class() to AUTH. This is therefore a
    # behavioural build fingerprint, unlike the OpenAPI hash, which is
    # identical before and after because no route signature changed.
    print("1 · build fingerprint — is Publish 100 code live?")
    st, out = call(f"/api/edr/events?activity=AUTHENTICATION&hours=1&limit=1",
                   token)
    applied = (out.get("filters_applied") or {}).get("activity")
    record("production serves the PATCHED read path",
           st == 200 and applied == "AUTH",
           f"HTTP {st}, filters_applied.activity={applied!r}"
           + ("" if st == 200 else f" · {json.dumps(out)[:120]}"))
    st, out = call("/api/edr/events?activity=BOGUS&hours=1&limit=1", token)
    record("input validation NOT weakened (BOGUS still 422)",
           st == 422 and (out.get("detail") or {}).get("code")
           == "ACTIVITY_INVALID", f"HTTP {st}")

    # ── 1b · the endpoint must actually resolve in this tenant ────
    # Without this, an unresolved endpoint_id silently yields 0 rows and
    # every later criterion would fail for the wrong reason.
    st, out = call("/api/edr/endpoints?limit=200", token)
    listed = out.get("endpoints") or out.get("items") or []
    ids = {e.get("endpoint_id") for e in listed}
    record("the enrolled endpoint resolves in this tenant",
           ENDPOINT in ids,
           f"{len(ids)} endpoints visible"
           + ("" if ENDPOINT in ids else
              f" — {ENDPOINT} NOT among them; check TENANT"))

    # ── 2 · facets ────────────────────────────────────────────────
    print("\n2 · activity facets")
    st, fac = call("/api/edr/events/facets?hours=24", token)
    act = fac.get("activity") or {}
    print("   facet map:", json.dumps(act))
    print("   not observed:", fac.get("activity_not_observed"))
    print("   total events (24h):", fac.get("total_events"))
    record("PROCESS facet > 0", act.get("PROCESS", 0) > 0,
           f"PROCESS={act.get('PROCESS', 0)}")
    record("AUTH facet > 0", act.get("AUTH", 0) > 0,
           f"AUTH={act.get('AUTH', 0)}")
    record("AUTHENTICATION never surfaces unprojected",
           "AUTHENTICATION" not in act)

    # ── 3 · filters return only their own class ───────────────────
    first_process_raw = None
    for cls in ("PROCESS", "AUTH"):
        print(f"\n3 · filter activity={cls}")
        st, out = call(f"/api/edr/events?endpoint_id={ENDPOINT}&hours=24"
                       f"&activity={cls}&limit=50", token)
        rows = out.get("events") or []
        wrong = [r["raw_id"] for r in rows if r.get("activity") != cls]
        nocanon = [r["raw_id"] for r in rows if not r.get("canonical_event_id")]
        print("   rows:", len(rows), "| basis:", json.dumps(dict(
            collections.Counter(r.get("activity_basis") for r in rows))))
        record(f"{cls} filter returns rows", bool(rows), f"{len(rows)} rows")
        record(f"every row is {cls}", bool(rows) and not wrong,
               f"offenders {wrong[:3]}" if wrong else "")
        record(f"every {cls} row has canonical_event_id",
               bool(rows) and not nocanon,
               f"missing {nocanon[:3]}" if nocanon else "")
        if cls == "PROCESS" and rows:
            first_process_raw = rows[0]["raw_id"]

    # ── 4 · per-record family mapping + honest gaps ───────────────
    print("\n4 · per-record mapping and coverage gaps")
    st, out = call(f"/api/edr/events?endpoint_id={ENDPOINT}&hours=24"
                   f"&limit=200", token)
    rows = out.get("events") or []
    seen: dict[tuple[str, int], collections.Counter] = \
        collections.defaultdict(collections.Counter)
    for r in rows:
        fam, eid = event_family(r)
        if eid is not None:
            seen[(fam, eid)][str(r.get("activity"))] += 1
    print("   rows sampled:", len(rows))
    for key in sorted(seen, key=str):
        got = dict(seen[key])
        want = SUPPORTED.get(key)
        if want:
            record(f"{key[0]} {key[1]} → {want}", list(got) == [want],
                   json.dumps(got))
        else:
            record(f"{key[0]} {key[1]} stays an explicit gap",
                   list(got) in (["None"], []),
                   json.dumps(got) + " (must be null — never invented)")
    gaps = [r for r in rows if r.get("activity") is None]
    print("   unclassified rows:", len(gaps))
    for r in gaps[:6]:
        fam, eid = event_family(r)
        print(f"     {fam} {eid} | canonical={bool(r.get('canonical_event_id'))}"
              f" | basis={(r.get('activity_basis') or '')[:80]}")
    record("every unclassified row states WHY",
           all(r.get("activity_basis") for r in gaps) if gaps else None,
           "no unclassified rows in window" if not gaps else "")

    # ── 5 · tenant isolation ─────────────────────────────────────
    print("\n5 · tenant isolation")
    req = urllib.request.Request(
        f"{API}/api/edr/events?endpoint_id={ENDPOINT}&hours=1&limit=1")
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("X-Tenant-Id", "ten_does_not_exist_0000")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = json.loads(r.read().decode())
            record("foreign tenant refused", False,
                   f"HTTP {r.status} returned keys {list(body)[:6]}")
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode() or "{}")
        code = (body.get("detail") or {})
        code = code.get("code") if isinstance(code, dict) else body.get("detail")
        record("foreign tenant refused, no rows",
               e.code in (403, 404) and "events" not in body,
               f"HTTP {e.code} {code}")

    # ── 6 · Device Trajectory on real canonical evidence ─────────
    print("\n6 · Device Trajectory")
    if not first_process_raw:
        record("trajectory focus on a real PROCESS record", None,
               "skipped — section 3 returned no PROCESS row")
    else:
        st, out = call(f"/api/edr/endpoints/{ENDPOINT}/trajectory/focus"
                       f"?raw_event_id={first_process_raw}", token)
        focus = out.get("focus") or {}
        prov = focus.get("provenance") or {}
        print("   state:", out.get("state"), "| search:",
              json.dumps(out.get("search") or {})[:160])
        print("   focus:", json.dumps({k: focus.get(k) for k in
              ("event_iid", "event_type", "process_iid", "lane_id",
               "timestamp")}))
        print("   provenance:", json.dumps({k: prov.get(k) for k in
              ("raw_event_id", "canonical_event_id")}))
        record("focus resolves the PROCESS record",
               out.get("state") == "FOCUS_RESOLVED",
               f"state={out.get('state')}")
        record("focus carries real provenance",
               bool(prov.get("raw_event_id") or prov.get(
                   "canonical_event_id")))
    st, out = call(f"/api/edr/endpoints/{ENDPOINT}/trajectory?limit=50", token)
    ev = out.get("events") or out.get("observations") or []
    print("   window rows:", len(ev), "| types:", json.dumps(dict(
        collections.Counter(e.get("event_type") for e in ev))))
    record("trajectory window returns real evidence", bool(ev) or None,
           f"{len(ev)} rows")

    # ── verdict ──────────────────────────────────────────────────
    fails = [n for n, ok, _ in results if ok is False]
    reviews = [n for n, ok, _ in results if ok is None]
    print("\n" + "=" * 68)
    print(f"{len(results)} criteria · "
          f"{sum(1 for _, ok, _ in results if ok)} pass · "
          f"{len(fails)} fail · {len(reviews)} review")
    if fails:
        print("FAILED:", "; ".join(fails))
    if reviews:
        print("REVIEW:", "; ".join(reviews))
    print("VERDICT:", "ACCEPTED" if not fails else "NOT ACCEPTED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
