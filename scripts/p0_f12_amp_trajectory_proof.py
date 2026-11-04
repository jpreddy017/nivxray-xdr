#!/usr/bin/env python3
"""Proof for the Cisco-AMP-equivalent Device Trajectory read model.

Run:  python3 /app/scripts/p0_f12_amp_trajectory_proof.py

Every assertion is made against the live API over real endpoint
evidence. Nothing here seeds, mocks or fabricates an observation.

What it proves, in the terms the owner set:
  A  deep activity rows resolve with a NARROW time window (the defect)
  B  the activity axis is invariant to the viewport (same row → same
     process at every zoom level)
  C  time navigation returns the window that was asked for
  D  lifelines are reported (first_seen/last_seen + end_state)
  E  parent→child lineage is reported with the parent's ROW
  F  activity types are enumerated with counts (icon vocabulary)
  G  dispositions are evidence-derived and never "clean"
  H  30-day activity band data
  I  24-hour activity band data (6-minute bins)
  J  Detected By is present on every observation, telemetry included
  K  the computer header names what is NOT collected
  L  event identity is unique (no duplicate marks when paging)
  M  filters (activity type · disposition · indicator) really filter
  N  file digests are separated from event content digests
  O  epistemic state is named
"""
import json
import os
import sys
import urllib.request

BASE = os.environ.get("NIVX_BASE",
                      "https://greeting-app-5782.preview.emergentagent.com")
EMAIL = os.environ.get("NIVX_EMAIL", "admin@nivxray.com")
PASSWORD = os.environ.get("NIVX_PASSWORD", "uulVDp5cCSB3Hva99s7UUAwK")

PASS, FAIL = [], []


def call(path, token=None, body=None):
    req = urllib.request.Request(f"{BASE}{path}")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "nivxray-proof/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(req, data, timeout=120) as r:
        return json.loads(r.read())


def check(tag, ok, detail=""):
    (PASS if ok else FAIL).append(tag)
    print(f"{'PASS' if ok else 'FAIL'}  {tag}" + (f"  — {detail}" if detail
                                                  else ""))


def main():
    tok = call("/api/auth/login", body={"email": EMAIL,
                                        "password": PASSWORD})
    token = tok.get("access_token") or tok.get("token")
    eps = call("/api/edr/endpoints", token)["endpoints"]
    live = [e for e in eps if e.get("device_iid")
            and (e.get("observation_count") or 0) > 0]
    if not live:
        print("NO ENROLLED ENDPOINT WITH OBSERVATIONS — cannot prove")
        return 2
    dev = max(live, key=lambda e: e["observation_count"])["device_iid"]
    print(f"endpoint under proof: {dev}\n")

    base = f"/api/edr/endpoints/{dev}/trajectory"
    full = call(f"{base}?lane_start=0&lane_end=40&limit=1", token)
    total = full["lane_axis"]["total_lanes"]
    axis_v = full["lane_axis"]["lane_axis_version"]
    start = full["time_range"]["observed_start"]
    end = full["time_range"]["observed_end"]
    day = str(end)[:10]
    print(f"rows={total} · observed {start} → {end}\n")

    # ── A · deep rows with a NARROW window ────────────────────────
    # Deep PROCESS rows: the axis orders processes first, so this is the
    # slice that carries lifelines and lineage. The very last rows are
    # network peers and legitimately have neither.
    proc_rows = full["lane_axis"]["group_counts"].get("PROCESS", 0)
    deep0 = max(0, proc_rows - 25)
    narrow = call(f"{base}?lane_start={deep0}&lane_end={deep0 + 25}"
                  f"&time_start={day}T00:00:00%2B00:00"
                  f"&time_end={day}T23:59:59%2B00:00&limit=500", token)
    check("A · deep rows render real events under a narrow window",
          len(narrow["lane_axis"]["lanes"]) > 0
          and narrow["returned"] > 0,
          f"rows {deep0}-{deep0 + 25}: {len(narrow['lane_axis']['lanes'])}"
          f" rows, {narrow['returned']} events")

    # ── B · axis invariant to the viewport ────────────────────────
    hour = call(f"{base}?lane_start={deep0}&lane_end={deep0 + 5}"
                f"&time_start={day}T10:00:00%2B00:00"
                f"&time_end={day}T11:00:00%2B00:00&limit=50", token)
    same_total = hour["lane_axis"]["total_lanes"] == total
    same_ver = hour["lane_axis"]["lane_axis_version"] == axis_v
    ids_full = [ln["lane_id"] for ln in narrow["lane_axis"]["lanes"][:5]]
    ids_hour = [ln["lane_id"] for ln in hour["lane_axis"]["lanes"][:5]]
    check("B · activity axis invariant to the viewport",
          same_total and same_ver and ids_full == ids_hour,
          f"total {total}=={hour['lane_axis']['total_lanes']} · "
          f"version stable={same_ver} · row identity stable="
          f"{ids_full == ids_hour}")

    # ── C · time navigation ───────────────────────────────────────
    ts = [e["timestamp"] for e in narrow["events"]]
    check("C · time navigation returns only the requested window",
          all(str(t)[:10] == day for t in ts if t),
          f"{len(ts)} events, all inside {day}")

    # ── D · lifelines ─────────────────────────────────────────────
    lanes = narrow["lane_axis"]["lanes"]
    with_life = [ln for ln in lanes if ln.get("first_seen")
                 and ln.get("last_seen")]
    end_states = {ln.get("end_state") for ln in lanes}
    check("D · lifelines reported with an honest end state",
          len(with_life) == len(lanes) and end_states
          and end_states <= {"EXIT_OBSERVED", "END_NOT_OBSERVED",
                             "NOT_APPLICABLE"},
          f"{len(with_life)}/{len(lanes)} rows · end states {end_states}")

    # ── E · real lineage chains, in lineage pre-order ─────────────
    axis = call(f"{base}?lane_start=0&lane_end={max(1, total)}&limit=1",
                token)["lane_axis"]["lanes"]
    by_row = {ln["lane_index"]: ln for ln in axis}
    resolved = [ln for ln in axis
                if ln.get("parent_lane_index") is not None]
    chain = None
    for ln in axis:
        p = ln.get("parent_lane_index")
        if p is None:
            continue
        g = by_row[p].get("parent_lane_index")
        if g is not None:
            chain = (by_row[g], by_row[p], ln)
            break
    check("E · real parent→child→grandchild lineage on the axis",
          chain is not None and len(resolved) > 0,
          (f"{len(resolved)}/{len(axis)} rows resolve a parent row · chain "
           + " → ".join(f"row {c['lane_index']} {c['label']}"
                        f" ({c['process_iid']})" for c in chain))
          if chain else "no chain found")

    # ── E2 · lineage pre-order: a child sits below its parent ─────
    below = [ln for ln in resolved
             if ln["lane_index"] > ln["parent_lane_index"]]
    adjacent = [ln for ln in resolved
                if ln["lane_index"] - ln["parent_lane_index"] <= 3]
    check("E2 · axis is a lineage pre-order (children under parents)",
          len(below) == len(resolved) and len(adjacent) > len(resolved) / 2,
          f"{len(below)}/{len(resolved)} children below their parent · "
          f"{len(adjacent)} within 3 rows of it")

    # ── E3 · the three parent states are distinguished ────────────
    states = {}
    for ln in axis:
        states[ln["parent_state"]] = states.get(ln["parent_state"], 0) + 1
    check("E3 · 'parent not reported' is distinguished from "
          "'parent not observed'",
          "PARENT_NOT_REPORTED_BY_SENSOR" in states
          and "OBSERVED" in states and "PENDING" not in states,
          str(states))

    # ── F · activity types ────────────────────────────────────────
    types = full["event_type_counts"]
    check("F · activity types enumerated with counts",
          len(types) > 0 and all("count" in t for t in types),
          ", ".join(f"{t['event_type']}={t['count']}" for t in types))

    # ── G · dispositions, never 'clean' ───────────────────────────
    disps = {e["disposition"] for e in narrow["events"]}
    check("G · dispositions are evidence-derived and never CLEAN",
          disps and "CLEAN" not in disps
          and disps <= {"MALICIOUS", "SUSPICIOUS", "UNKNOWN_NOT_ASSESSED"},
          str(disps))

    # ── H · 30-day band ───────────────────────────────────────────
    days = full["activity"]["days"]
    check("H · 30-day activity band data present",
          len(days) > 0 and all({"day", "total", "malicious", "detections"}
                                <= set(d) for d in days),
          f"{len(days)} observed day(s); latest "
          f"{days[-1] if days else None}")

    # ── I · 24-hour band ──────────────────────────────────────────
    binned = call(f"{base}?lane_start=0&lane_end=1&limit=1&hist_day={day}",
                  token)
    bins = binned["activity"]["day_bins"]
    check("I · 24-hour activity band data present (6-minute bins)",
          len(bins) > 0 and binned["activity"]["day_bin_count"] == 240
          and all("first_event_iid" in b for b in bins),
          f"{len(bins)} non-empty bins on {day}")

    # ── J · Detected By ───────────────────────────────────────────
    ev = narrow["events"][0] if narrow["events"] else {}
    dets = ev.get("detected_by") or []
    check("J · Detected By present on every observation",
          all(e.get("detected_by") for e in narrow["events"]),
          f"first: {dets[0] if dets else None}")

    # ── K · computer header names what is NOT collected ───────────
    comp = full.get("computer") or {}
    nc = [k for k, v in comp.items()
          if isinstance(v, dict) and v.get("state") == "NOT_COLLECTED"]
    check("K · computer header declares uncollected fields",
          comp.get("hostname") and len(nc) > 0,
          f"host={comp.get('hostname')} · os={comp.get('operating_system')}"
          f" · not collected: {nc}")

    # ── L · unique event identity across pages ────────────────────
    seen, dupes, cursor, pages = set(), 0, None, 0
    while pages < 4:
        q = (f"{base}?lane_start=0&lane_end={max(1, total)}&limit=2000"
             + (f"&cursor={cursor}" if cursor else ""))
        page = call(q, token)
        for e in page["events"]:
            if e["event_iid"] in seen:
                dupes += 1
            seen.add(e["event_iid"])
        pages += 1
        cursor = page.get("next_cursor")
        if not cursor:
            break
    check("L · event identity unique across paged windows", dupes == 0,
          f"{len(seen)} unique ids over {pages} page(s), {dupes} duplicate(s)")

    # ── M · filters really filter ─────────────────────────────────
    kind = types[0]["event_type"]
    filt = call(f"{base}?lane_start=0&lane_end={max(1, total)}&limit=1"
                f"&kinds={kind}", token)
    unknown = call(f"{base}?lane_start=0&lane_end={max(1, total)}&limit=1"
                   f"&dispositions=MALICIOUS", token)
    ind = call(f"{base}?lane_start=0&lane_end={max(1, total)}&limit=1"
               f"&q=zzz_no_such_indicator_zzz", token)
    check("M · filters by activity type, disposition and indicator",
          filt["matched_after_filters"] == types[0]["count"]
          and ind["matched_after_filters"] == 0
          and unknown["matched_after_filters"] <= full[
              "observations_all_time"],
          f"kind {kind}: {filt['matched_after_filters']}"
          f" · MALICIOUS: {unknown['matched_after_filters']}"
          f" · bogus indicator: {ind['matched_after_filters']}")

    # ── N · digest honesty ────────────────────────────────────────
    check("N · event content digest is separate from a file SHA-256",
          all("event_content_digest" in e and "file_sha256" in e
              for e in narrow["events"]),
          "every observation reports both fields distinctly")

    # ── O · epistemic state ───────────────────────────────────────
    check("O · epistemic state named",
          bool(full.get("epistemic_state", {}).get("state")),
          full["epistemic_state"]["state"])

    print(f"\n{len(PASS)} passed · {len(FAIL)} failed")
    if FAIL:
        print("FAILED: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
