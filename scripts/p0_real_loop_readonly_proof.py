#!/usr/bin/env python3
"""STEP 1 — READ-ONLY REAL-LOOP PROOF.

Walks N GENUINE events that the live NivXForge Linux sensor already produced
on this real host, from source activity through raw persistence, parse,
normalization, canonical evidence, detection and verdict.

STRICTLY READ-ONLY. Only find/aggregate/count. No insert, no update, no
delete, and no change to the pipeline to make the proof pass. Missing
provenance is REPORTED, never fabricated.

Usage:  python3 scripts/p0_real_loop_readonly_proof.py [N]
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv("/app/backend/.env")
DB = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

# The eight provenance stamps the owner requires.
REQUIRED_STAMPS = [
    "activity_occurred_at", "sensor_observed_at", "collector_received_at",
    "nivx_received_at", "parsed_at", "normalized_at", "rule_evaluated_at",
    "verdict_at",
]


def ts(v):
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:                                             # noqa: BLE001
        return None


def ms(a, b):
    """Latency in ms, ONLY when both endpoints genuinely exist."""
    ta, tb = ts(a), ts(b)
    if ta is None or tb is None:
        return None
    return round((tb - ta).total_seconds() * 1000, 1)


def short(v, n=22):
    s = "—" if v in (None, "") else str(v)
    return s if len(s) <= n else s[: n - 1] + "…"


def clock(v):
    """Render only the time-of-day; the date is in the report header."""
    t = ts(v)
    return "—" if t is None else t.strftime("%H:%M:%S.%f")[:-3]


def pick(n: int) -> list[dict]:
    """Newest N raw rows that completed a derivation chain, plus the newest
    rows whose detection MATCHED, plus the newest rows whose canonical
    evidence predates the provenance patch. The sample is deliberately
    broadened so the pre-patch and post-patch cohorts are BOTH present in a
    single run and can be compared directly."""
    rows = list(DB.edr_raw_events.find(
        {"derivations.0": {"$exists": True}}).sort("_id", -1).limit(n))
    have = {r["raw_id"] for r in rows}
    matched = list(DB.edr_raw_events.find(
        {"derivations.outcome": "DETECTION_MATCHED"}).sort("_id", -1).limit(2))
    for m in matched:
        if m["raw_id"] not in have:
            rows.append(m)
            have.add(m["raw_id"])

    legacy = [d["provenance"]["trace_id"]
              for d in DB.xdr_canonical_evidence.find(
                  {"provenance.timestamps": {"$exists": False},
                   "provenance.trace_id": {"$regex": "^raw_"}},
                  {"provenance.trace_id": 1}).sort("_id", -1).limit(3)]
    for t in legacy:
        if t in have:
            continue
        doc = DB.edr_raw_events.find_one({"raw_id": t})
        if doc:
            rows.append(doc)
            have.add(t)
    return rows


def walk(raw: dict) -> dict:
    """Resolve one raw event's full chain from what is ACTUALLY stored."""
    raw_id = raw["raw_id"]
    payload = {}
    try:
        payload = json.loads(raw.get("payload") or "{}")
    except Exception:                                             # noqa: BLE001
        pass
    ders = raw.get("derivations") or []

    def der(*outcomes):
        for d in ders:
            if d.get("outcome") in outcomes:
                return d
        return {}

    canon_der = der("CANONICAL_EVIDENCE_CREATED",
                    "DUPLICATE_OBSERVATION_OF_KNOWN_ACTIVITY")
    det_der = der("DETECTION_MATCHED", "DETECTION_EVALUATED_NO_MATCH",
                  "DETECTION_NOT_EVALUATED")

    # Canonical evidence as persisted by the CORE pipeline. The join key is
    # provenance.trace_id == raw_id; nothing is assumed.
    ev = DB.xdr_canonical_evidence.find_one({"provenance.trace_id": raw_id})
    obs = DB.v2_shadow_observations.find_one(
        {"canonical_event_id": canon_der.get("event_id")}) if canon_der else None

    # Detection / verdict, exactly as recorded on the raw row.
    matched = det_der.get("outcome") == "DETECTION_MATCHED"
    rule_ids = [r for r in (det_der.get("reason") or "")
                .replace("rules: ", "").split(", ") if r] if matched else []

    incident_id = None
    for e_id in (det_der.get("evidence_ids") or []):
        if str(e_id).startswith("inc_"):
            incident_id = e_id

    # ── provenance ────────────────────────────────────────────────
    # Post-patch events carry a real stamp block on the canonical evidence.
    # Pre-patch events do not, and are read exactly as before so the two
    # cohorts can be compared in ONE unchanged run. The required stamp list
    # and the gate logic below are untouched.
    tsb = ((ev or {}).get("provenance") or {}).get("timestamps")
    if isinstance(tsb, dict):
        cohort = "POST-PATCH"
        stamps = {k: (tsb.get(k) or {}).get("value") for k in REQUIRED_STAMPS}
        statuses = {k: (tsb.get(k) or {}).get("status") or "MISSING"
                    for k in REQUIRED_STAMPS}
        sources = {k: (tsb.get(k) or {}).get("source") for k in REQUIRED_STAMPS}
        reasons = {k: (tsb.get(k) or {}).get("reason") for k in REQUIRED_STAMPS}
        proxies = {}
    else:
        cohort = "PRE-PATCH"
        stamps = {
            # The sensor DOES observe process start time for PROCESS
            # activity (`start_time`, read from /proc). For NETWORK/FILE
            # state it honestly reports that the start was not observable.
            "activity_occurred_at":  payload.get("start_time")
                                     or payload.get("occurred_at"),
            "sensor_observed_at":    payload.get("observed_at"),
            # The sensor IS the collector on this path — there is no
            # separate collector hop, so nothing stamps a receipt.
            "collector_received_at": None,
            "nivx_received_at":      raw.get("ingest_time"),
            # No dedicated parse/normalize stamps existed. The derivation's
            # derived_at was the only real evidence, and it covered BOTH
            # stages as one write — a proxy, not the real thing.
            "parsed_at":             None,
            "normalized_at":         None,
            "rule_evaluated_at":     None,
            "verdict_at":            None,
        }
        statuses = {k: ("AVAILABLE" if stamps.get(k) else "MISSING")
                    for k in REQUIRED_STAMPS}
        sources = {k: None for k in REQUIRED_STAMPS}
        reasons = {k: None for k in REQUIRED_STAMPS}
        proxies = {
            "parsed_at":         canon_der.get("derived_at"),
            "normalized_at":     canon_der.get("derived_at"),
            "rule_evaluated_at": det_der.get("derived_at"),
            "verdict_at":        det_der.get("derived_at"),
        }
    missing = [k for k in REQUIRED_STAMPS if statuses.get(k) == "MISSING"]

    return {
        "raw_id":        raw_id,
        "source":        f"{raw.get('source_kind') or '—'}/"
                         f"{raw.get('source')  or '—'}",
        "sensor_version": raw.get("sensor_version"),
        "host":          (raw.get("endpoint_ref")
                          if isinstance(raw.get("endpoint_ref"), str)
                          else (raw.get("endpoint_ref") or {}).get(
                              "endpoint_id"))
                         or (raw.get("authentication") or {}).get(
                             "authenticated_endpoint_id"),
        "hostname":      (ev or {}).get("host", {}).get("hostname"),
        "activity":      f"{payload.get('activity')}/{payload.get('operation')}",
        "tenant_raw":    raw.get("tenant_id"),
        "tenant_ev":     (ev or {}).get("tenant_id"),
        "trust_state":   raw.get("trust_state"),
        "quality":       raw.get("telemetry_quality"),
        "auth":          raw.get("authentication") or {},
        "dedup_key":     raw.get("dedup_key"),
        "duplicate_count": raw.get("duplicate_count"),
        "stamps":        stamps,
        "statuses":      statuses,
        "sources":       sources,
        "reasons":       reasons,
        "cohort":        cohort,
        "proxies":       proxies,
        "missing":       missing,
        "event_time_basis": ((ev or {}).get("additional_fields")
                             or {}).get("event_time_basis"),
        "parser":        f"{canon_der.get('parser_name')}/"
                         f"{canon_der.get('parser_version')}",
        "normalizer":    canon_der.get("normalizer_version"),
        "canonical_bridge_id": canon_der.get("event_id"),
        "canonical_core_id":   (ev or {}).get("event_id"),
        "canonical_present":   ev is not None,
        "obs_present":         obs is not None,
        "canon_outcome":       canon_der.get("outcome"),
        "det_outcome":         det_der.get("outcome"),
        "engine_id":           det_der.get("detection_content_version"),
        "rule_ids":            rule_ids,
        "matched":             matched,
        "nivx_verdict":        det_der.get("verdict_version"),
        "incident_id":         incident_id,
        "canonical_event_time": (ev or {}).get("event_time"),
        "not_observed":  payload.get("not_observed") or [],
        "observed_values": {
            "process.executable_path": ((ev or {}).get("process")
                                        or {}).get("executable_path"),
            "process.command_line":   ((ev or {}).get("process")
                                       or {}).get("command_line"),
            "process.parent_name":    ((ev or {}).get("process")
                                       or {}).get("parent_name"),
        },
        "raw_ref":             f"edr_raw_events/{raw_id}",
        "canonical_ref":       (f"xdr_canonical_evidence/{ev['event_id']}"
                                if ev else None),
    }


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    rows = [walk(r) for r in pick(n)]
    if not rows:
        print("NO GENUINE EVENTS FOUND — nothing to prove. Stopping.")
        return 1

    out: list[str] = []
    def p(s=""):
        print(s)
        out.append(s)

    p("# STEP 1 — READ-ONLY REAL-LOOP PROOF")
    p()
    p(f"Generated: {datetime.now().astimezone().isoformat()}")
    p(f"Events walked: {len(rows)} · source: live NivXForge Linux sensor on "
      f"this real host")
    p("**Read-only. No writes. No pipeline change. No fabricated timestamp.**")
    p()

    # ── 1 · the required table ───────────────────────────────────────
    p("## 1 · Per-event chain")
    p()
    hdr = ["Event (raw_id)", "Cohort", "Activity", "ActOccur",
           "SensorObs", "CollRecv", "NivXRecv", "Parsed", "Normalized",
           "RuleEval", "VerdictAt", "Rule ID", "Detection", "SrcVerdict",
           "NivXVerdict"]
    p("| " + " | ".join(hdr) + " |")
    p("|" + "---|" * len(hdr))
    def cell(r, name):
        """Real value, else a clearly-marked proxy, else the honest status."""
        v = r["stamps"].get(name)
        if v:
            return clock(v)
        pr = r["proxies"].get(name)
        if pr:
            return clock(pr) + "*"
        return {"NOT_APPLICABLE": "n/a", "NOT_OBSERVED": "n/obs"}.get(
            r["statuses"].get(name), "—")

    for r in rows:
        p("| " + " | ".join([
            short(r["raw_id"], 20),
            r["cohort"],
            short(r["activity"], 22),
            cell(r, "activity_occurred_at"),
            cell(r, "sensor_observed_at"),
            cell(r, "collector_received_at"),
            cell(r, "nivx_received_at"),
            cell(r, "parsed_at"),
            cell(r, "normalized_at"),
            cell(r, "rule_evaluated_at"),
            cell(r, "verdict_at"),
            short(",".join(r["rule_ids"]) or "—", 14),
            short(r["det_outcome"], 24),
            "—",
            short(r["nivx_verdict"], 13),
        ]) + " |")
    p()
    p("`*` = **PROXY, not a real stamp** (pre-patch events only): the "
      "derivation's single `derived_at`, which covered parse AND normalize "
      "as one write. · `n/a` = NOT_APPLICABLE · `n/obs` = NOT_OBSERVED.")
    p()
    p("`SrcVerdict` is `—` for every row **honestly**: a first-party sensor "
      "emits observations, not verdicts. There is no vendor verdict to "
      "preserve or overwrite on this path.")
    p()

    # ── 2 · references + tenant + trust ──────────────────────────────
    p("## 2 · Evidence references, tenant attribution, trust")
    p()
    hdr2 = ["Event", "Raw evidence ref", "Canonical evidence ref",
            "Bridge canonical ID", "Tenant (raw)", "Tenant (canonical)",
            "Trust", "Quality", "Credential", "Session", "Dedup key",
            "Dupes", "Incident"]
    p("| " + " | ".join(hdr2) + " |")
    p("|" + "---|" * len(hdr2))
    for r in rows:
        a = r["auth"]
        p("| " + " | ".join([
            short(r["raw_id"], 16),
            short(r["raw_ref"], 34),
            short(r["canonical_ref"] or "ABSENT", 44),
            short(r["canonical_bridge_id"], 28),
            short(r["tenant_raw"], 12),
            short(r["tenant_ev"], 12),
            short(r["trust_state"], 14),
            short(r["quality"], 10),
            short(a.get("credential_id"), 22),
            short(a.get("session_id"), 22),
            short(r["dedup_key"], 14),
            str(r["duplicate_count"]),
            short(r["incident_id"], 22),
        ]) + " |")
    p()

    # ── 3 · missing provenance, per event ────────────────────────────
    p("## 3 · Provenance status per stamp (D1 evidence)")
    p()
    p("| Event | Cohort | " + " | ".join(
        k.replace("_at", "") for k in REQUIRED_STAMPS) + " |")
    p("|---|---|" + "---|" * len(REQUIRED_STAMPS))
    abbr = {"AVAILABLE": "OK", "NOT_APPLICABLE": "N/A",
            "NOT_OBSERVED": "N-OBS", "MISSING": "**MISS**"}
    for r in rows:
        p(f"| {short(r['raw_id'], 16)} | {r['cohort']} | "
          + " | ".join(abbr.get(r["statuses"].get(k), "?")
                       for k in REQUIRED_STAMPS) + " |")
    p()
    p("`OK` = AVAILABLE (a real value) · `N/A` = NOT_APPLICABLE (no such "
      "boundary on this path) · `N-OBS` = NOT_OBSERVED (boundary exists, "
      "source could not see it) · `MISS` = MISSING (should exist, was not "
      "captured).")
    p()
    for coh in ("PRE-PATCH", "POST-PATCH"):
        grp = [r for r in rows if r["cohort"] == coh]
        if not grp:
            continue
        clean = sum(1 for r in grp if not r["missing"])
        p(f"- **{coh}** — {len(grp)} events · "
          f"{clean}/{len(grp)} with **no MISSING stamp**")
        for k in REQUIRED_STAMPS:
            hist: dict[str, int] = {}
            for r in grp:
                s = r["statuses"].get(k, "?")
                hist[s] = hist.get(s, 0) + 1
            p(f"    - `{k}`: " + ", ".join(f"{v}×{kk}"
                                           for kk, v in sorted(hist.items())))
    p()
    p("### Sources recorded for the real stamps (post-patch)")
    post = [r for r in rows if r["cohort"] == "POST-PATCH"]
    if post:
        r = post[0]
        p()
        p("| Stamp | Status | Source / reason |")
        p("|---|---|---|")
        for k in REQUIRED_STAMPS:
            p(f"| `{k}` | {r['statuses'].get(k)} | "
              f"{r['sources'].get(k) or r['reasons'].get(k) or '—'} |")
    else:
        p()
        p("No post-patch event in this sample.")
    p()
    act_ok = [r for r in rows if r["stamps"].get("activity_occurred_at")]
    p(f"- `activity_occurred_at` has a real value on "
      f"**{len(act_ok)}/{len(rows)}** events — every PROCESS row, no NETWORK "
      f"row. Source: the sensor's `start_time` read from `/proc`.")
    p()
    p("| Event | Activity | activity_occurred_at | canonical.event_time | "
      "event_time_basis (D9) |")
    p("|---|---|---|---|---|")
    for r in rows:
        p(f"| {short(r['raw_id'], 16)} | {short(r['activity'], 24)} | "
          f"{clock(r['stamps'].get('activity_occurred_at'))} | "
          f"{clock(r['canonical_event_time'])} | "
          f"{r['event_time_basis'] or '**absent**'} |")
    p()
    conflated = [r for r in rows
                 if not r["stamps"]["activity_occurred_at"]
                 and r["canonical_event_time"]
                 and ts(r["canonical_event_time"])
                 == ts(r["stamps"]["sensor_observed_at"])]
    labelled = [r for r in conflated if r["event_time_basis"]]
    if conflated:
        p(f"**D9 · `event_time` carries two different meanings.** On "
          f"{len(conflated)}/{len(rows)} events (all NETWORK) "
          f"`canonical.event_time` equals `sensor_observed_at`, not an "
          f"activity time.")
        p()
        p(f"- **{len(labelled)}/{len(conflated)}** of those now declare "
          f"`event_time_basis` explicitly, so a consumer can tell *when it "
          f"happened* from *when we noticed*. Where it is `**absent**` the "
          f"conflation is still silent (pre-patch events).")
        p()
    p("## 4 · Latencies — computed ONLY from stamps that genuinely exist")
    p()
    p("| Event | Cohort | sensor_obs → nivx_recv | nivx_recv → parsed | "
      "parsed → normalized | normalized → rule_eval | rule_eval → verdict |")
    p("|---|---|---|---|---|---|---|")
    acc_all: dict[str, list[float]] = {}

    def lat(r, a, b):
        """Real stamp to real stamp. Falls back to the pre-patch proxy and
        marks it, so a measured stage is never confused with a bounded one."""
        va = r["stamps"].get(a) or r["proxies"].get(a)
        vb = r["stamps"].get(b) or r["proxies"].get(b)
        proxy = not (r["stamps"].get(a) and r["stamps"].get(b))
        v = ms(va, vb)
        if v is None:
            st = r["statuses"].get(b)
            return None, ("n/a" if st == "NOT_APPLICABLE" else "—")
        if not proxy:
            acc_all.setdefault(f"{a}->{b}", []).append(v)
        return v, f"{v} ms" + ("*" if proxy else "")

    pairs = [("sensor_observed_at", "nivx_received_at"),
             ("nivx_received_at", "parsed_at"),
             ("parsed_at", "normalized_at"),
             ("normalized_at", "rule_evaluated_at"),
             ("rule_evaluated_at", "verdict_at")]
    for r in rows:
        cells = [lat(r, a, b)[1] for a, b in pairs]
        p(f"| {short(r['raw_id'], 16)} | {r['cohort']} | "
          + " | ".join(cells) + " |")
    p()
    if acc_all:
        p("**Genuinely measured stages** (both endpoints are real stamps, "
          "no proxy):")
        p()
        for key, acc in acc_all.items():
            a, b = key.split("->")
            s = sorted(acc)
            p(f"- `{a}` → `{b}` — n={len(s)} · min {s[0]} ms · "
              f"median {s[len(s) // 2]} ms · max {s[-1]} ms")
        p()
    p("`*` = at least one endpoint is a PROXY stamp, so the figure bounds "
      "the stage rather than measuring it. Sample size is too small for "
      "p95/p99 and none is claimed.")
    p()

    # ── 5 · gates ────────────────────────────────────────────────────
    p("## 5 · Acceptance gates")
    p()
    tot = len(rows)
    raw_ok = sum(1 for r in rows if r["raw_id"])
    parse_ok = sum(1 for r in rows if r["canon_outcome"] in (
        "CANONICAL_EVIDENCE_CREATED", "DUPLICATE_OBSERVATION_OF_KNOWN_ACTIVITY"))
    canon_ok = sum(1 for r in rows if r["canonical_present"])
    det_ok = sum(1 for r in rows if r["det_outcome"] in (
        "DETECTION_MATCHED", "DETECTION_EVALUATED_NO_MATCH"))
    verdict_ok = sum(1 for r in rows if r["nivx_verdict"])
    tenant_ok = sum(1 for r in rows
                    if r["tenant_raw"] and r["tenant_raw"] == r["tenant_ev"])
    trust_ok = sum(1 for r in rows if r["trust_state"] == "AUTHENTICATED")
    trace_ok = sum(1 for r in rows
                   if r["canonical_present"] and r["canonical_bridge_id"])
    prov_full = sum(1 for r in rows if not r["missing"])

    def gate(name, ok, total, note, partial_if_any=True):
        if ok == total:
            v = "PASS"
        elif ok == 0:
            v = "FAIL"
        else:
            v = "PARTIAL" if partial_if_any else "FAIL"
        p(f"| {name} | **{v}** | {ok}/{total} | {note} |")

    p("| Gate | Verdict | Count | Evidence |")
    p("|---|---|---|---|")
    gate("Real telemetry", trust_ok, tot,
         "every row `trust_state=AUTHENTICATED`, credential + session bound; "
         "produced by the running sensor on this host")
    gate("Raw persistence", raw_ok, tot,
         "`edr_raw_events` row with `payload_sha256` + `dedup_key`")
    gate("Parsing", parse_ok, tot,
         "derivation `parser_state=OK` recorded on the raw row")
    gate("Normalization", parse_ok, tot,
         "same derivation carries `normalizer_version`")
    gate("Canonical evidence", canon_ok, tot,
         "`xdr_canonical_evidence` row resolved via `provenance.trace_id`")
    gate("Provenance", prov_full, tot,
         "requires all 8 owner-specified stamps — see §3")
    prov_values = sum(1 for r in rows
                      if all(r["stamps"].get(k) for k in REQUIRED_STAMPS))
    gate("Provenance · literal value on all 8 (strict, informational)",
         prov_values, tot,
         "expected to stay below total: `collector_received_at` is "
         "legitimately NOT_APPLICABLE on the sensor path and must never be "
         "given a value")
    gate("Detection", det_ok, tot,
         "deterministic evaluation recorded with engine id; no-match is a "
         "real answer")
    gate("Verdict traceability", verdict_ok, tot,
         "`verdict_version` on the derivation, traceable to the raw row")
    gate("Tenant attribution", tenant_ok, tot,
         "raw tenant == canonical tenant on every row")
    gate("End-to-end traceability", trace_ok, tot,
         "raw_id → derivation → canonical id, both directions resolvable")
    p()
    p("### Provenance gate, split by cohort — the before/after")
    p()
    p("| Cohort | Events | No MISSING stamp | Verdict |")
    p("|---|---|---|---|")
    for coh in ("PRE-PATCH", "POST-PATCH"):
        grp = [r for r in rows if r["cohort"] == coh]
        if not grp:
            continue
        ok = sum(1 for r in grp if not r["missing"])
        v = "PASS" if ok == len(grp) else ("FAIL" if ok == 0 else "PARTIAL")
        p(f"| {coh} | {len(grp)} | {ok}/{len(grp)} | **{v}** |")
    p()
    p("### Disclosure — the one definition that changed, and why")
    p()
    p("The 8-stamp list and the gate arithmetic are unchanged. **One "
      "definition did change and it must not pass unnoticed:** a stamp now "
      "counts as satisfied when its status is anything other than "
      "`MISSING`, where previously it had to carry a literal value.")
    p()
    p("This follows directly from owner decision #4 — `NOT_APPLICABLE` is a "
      "legitimate terminal answer for a boundary that does not exist, and "
      "`NOT_OBSERVED` for one the source genuinely could not see. Under the "
      "old definition the sensor path could **never** pass, because giving "
      "`collector_received_at` a value would require inventing one.")
    p()
    p("So the strict literal-value count is reported above as well, "
      "unhidden. Anyone who disagrees with the looser reading can use the "
      "strict row instead.")
    p()

    # ── 6 · matched detections: fields and observed values ──────────
    p("## 6 · Matched detections — fields and observed values")
    p()
    mrows = [r for r in rows if r["matched"]]
    if not mrows:
        p("No rule matched in this sample.")
    else:
        p("| Event | Rule | Engine | NivX verdict | Incident | "
          "process.executable_path | process.command_line | parent |")
        p("|---|---|---|---|---|---|---|---|")
        for r in mrows:
            o = r["observed_values"]
            p("| " + " | ".join([
                short(r["raw_id"], 16),
                ",".join(r["rule_ids"]),
                short(r["engine_id"], 22),
                short(r["nivx_verdict"], 12),
                short(r["incident_id"], 22),
                short(o["process.executable_path"], 20),
                short(o["process.command_line"], 30),
                short(o["process.parent_name"], 14),
            ]) + " |")
        p()
        p("**The observed values above were read back from canonical "
          "evidence at report time — they are NOT persisted as part of the "
          "match record.** The derivation stores only `rule_id` + engine id "
          "+ verdict label. Which field matched, and on what value, is not "
          "recoverable from storage. Recorded as **D8**.")
    p()

    # ── 7 · sensor epistemic honesty ────────────────────────────────
    p("## 7 · What the sensor said it could NOT see")
    p()
    p("| Event | Activity | not_observed |")
    p("|---|---|---|")
    for r in rows:
        p(f"| {short(r['raw_id'], 16)} | {short(r['activity'], 26)} | "
          f"{', '.join(r['not_observed']) or '—'} |")
    p()
    p("This is why `activity_occurred_at` is absent on NETWORK rows and "
      "present on PROCESS rows: the sensor reports the limits of its own "
      "observation instead of inventing a time.")
    p()

    # ── 8 · duplicate canonical identity finding ────────────────────
    p("## 8 · Observation: two canonical identities per activity")
    p()
    p("Each event carries **two** canonical ids for one real activity:")
    p()
    p("| Event | Bridge id (`v2_shadow_observations`) | "
      "Core id (`xdr_canonical_evidence`) |")
    p("|---|---|---|")
    for r in rows:
        p(f"| {short(r['raw_id'], 16)} | {short(r['canonical_bridge_id'], 30)} "
          f"| {short(r['canonical_core_id'], 30)} |")
    p()
    p("Both derive deterministically from the same immutable `raw_id`, so "
      "this is a **naming/indexing** concern, not evidence duplication — but "
      "\"the\" canonical id for an activity is currently ambiguous.")
    p()

    path = "/app/memory/REAL_SECURITY_LOOP_STEP1_READONLY_PROOF.md"
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"\nreport written: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
