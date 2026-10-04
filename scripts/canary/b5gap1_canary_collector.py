#!/usr/bin/env python3
"""B5-GAP-1 · DISPOSABLE WINDOWS CANARY — READ-ONLY MEASUREMENT COLLECTOR.

MEASURE ONLY. This process never writes to the sensor's state, never
touches the evidence journal except through a READ-ONLY connection (or an
untouched copy of it), never calls a mutating API, and never changes
product semantics to make a measurement easier. If a number cannot be
obtained honestly it is reported as unknown, never estimated.

Evidence chain it measures, stage by stage:

    SOURCE -> ACQUISITION -> LOCAL EVIDENCE JOURNAL -> NORMALIZATION
      -> BATCH TRANSPORT -> BACKEND INGEST -> RAW ACCEPTANCE
      -> CANONICAL EVIDENCE -> ACK -> JOURNAL RELEASE

Output:
    <out-dir>/canary_<scenario>_<stamp>.csv      time series, one row per
                                                 (sample, channel)
    <out-dir>/canary_<scenario>_<stamp>.json     final machine-readable
                                                 verdict

Run ON THE DISPOSABLE CANARY HOST ONLY:

    python b5gap1_canary_collector.py \
        --scenario NORMAL --duration 900 --interval 15 \
        --backend https://nivxray.nivxforge.com \
        --tenant <canary_tenant> --endpoint <canary_endpoint_id> \
        --out-dir C:\\NivXForgeCanary

The read token comes from the environment (NIVX_CANARY_READ_TOKEN) and is
never printed, never written to the CSV and never written to the verdict.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CONTRACT = "nivxforge.b5gap1.canary_measurement"
CONTRACT_VERSION = 1

JOURNAL_FILENAME = "evidence_journal.db"
INTEGRITY_FILENAME = "acquisition_integrity.json"
FAULT_FILENAME = "journal_fault.json"

DEFAULT_CHANNELS = ("Security", "System",
                    "Microsoft-Windows-Sysmon/Operational")
DELIVERABLE_STATES = ("ACQUIRED", "QUEUED")

#: What each scenario is allowed to look like. Nothing here relaxes an
#: acceptance invariant; it only records which OBSERVATIONS are expected,
#: so an expected backlog is not read as loss and an injected source
#: discontinuity is not read as a sensor defect.
SCENARIOS: dict[str, dict] = {
    "NORMAL": {},
    "BURST": {"expect_backlog": True},
    "BACKEND_SLOW": {"impaired": True, "expect_backlog": True,
                     "allow_duplicates": True},
    "BACKEND_DOWN": {"impaired": True, "expect_backlog": True,
                     "allow_duplicates": True},
    "RECOVERY": {"expect_backlog": True, "allow_duplicates": True,
                 "require_drain_to_zero": True},
    "SENSOR_RESTART": {"allow_duplicates": True},
    "NETWORK_INTERRUPTION": {"impaired": True, "expect_backlog": True,
                             "allow_duplicates": True,
                             "require_drain_to_zero": True},
    "MULTI_CHANNEL": {"require_all_channels_progress": True},
    "JOURNAL_PRESSURE": {"expect_backlog": True, "expect_pressure": True},
    "SOURCE_DISCONTINUITY": {"expect_gaps": True},
}

COLUMNS = [
    "sample_at", "scenario", "elapsed_seconds", "channel",
    # SOURCE
    "source_oldest_record_id", "source_newest_record_id",
    "source_records_per_sec",
    # ACQUISITION + JOURNAL (per channel)
    "cursor_committed", "continuity_established", "last_record_id_journaled",
    "acquisition_lag_records", "journal_rows", "journal_rows_deliverable",
    "journal_rows_backend_accepted", "journaled_records_per_sec",
    "query_ms_last",
    # JOURNAL (endpoint-wide, repeated per channel row)
    "journal_depth", "journal_bytes", "journal_live_bytes", "journal_pct",
    "journal_pressure_state", "oldest_pending_age_seconds",
    "records_read_total", "records_journaled_total",
    "backend_accepted_total", "delivery_failures_total",
    "query_total", "query_failures_total", "acquisition_halted_reason",
    "acquisition_gap_count", "unreported_gap_count", "last_gap",
    "health_states", "journal_fault",
    # TRANSPORT + BACKEND (endpoint-wide, repeated per channel row)
    "delivery_backlog", "backend_http_status", "backend_rtt_ms",
    "backend_received", "backend_parsed", "backend_accepted",
    "backend_canonicalized", "backend_deduplicated", "backend_refused",
    "backend_accepted_per_sec", "backend_gap_count",
    "backend_tenants_observed", "journal_read_mode",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _age_seconds(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return round((datetime.now(timezone.utc) - parsed).total_seconds(), 3)


def _rate(current, previous, seconds: float):
    if current is None or previous is None or not seconds:
        return None
    delta = current - previous
    return round(delta / seconds, 3) if delta >= 0 else None


# ── SOURCE ────────────────────────────────────────────────────────
def source_tail(channel: str) -> dict:
    """Oldest/newest RecordID still held by the source channel.

    READ-ONLY: `wevtutil qe` only queries. Returns unknowns rather than
    guesses when the platform or the tool cannot answer.
    """
    if os.name != "nt" or not shutil.which("wevtutil"):
        return {"oldest": None, "newest": None,
                "unknown_reason": "SOURCE_TAIL_UNAVAILABLE_OFF_WINDOWS"}
    out: dict = {"oldest": None, "newest": None, "unknown_reason": None}
    for key, reverse in (("newest", "true"), ("oldest", "false")):
        try:
            proc = subprocess.run(
                ["wevtutil", "qe", channel, "/c:1", f"/rd:{reverse}",
                 "/f:RenderedXml"], capture_output=True, text=True,
                timeout=60)
        except (OSError, subprocess.SubprocessError) as ex:
            out["unknown_reason"] = f"{type(ex).__name__}"
            continue
        text = proc.stdout or ""
        start = text.find("<EventRecordID>")
        end = text.find("</EventRecordID>")
        if start >= 0 and end > start:
            try:
                out[key] = int(text[start + 15:end])
            except ValueError:
                pass
        elif not out["unknown_reason"]:
            out["unknown_reason"] = (proc.stderr or "NO_RECORD_RETURNED"
                                     ).strip()[:160]
    return out


# ── JOURNAL (read-only) ───────────────────────────────────────────
def open_journal_readonly(path: Path) -> tuple[sqlite3.Connection, str, Path]:
    """Open the live journal WITHOUT being able to write to it.

    A WAL database cannot always be opened read-only by another user (the
    shared-memory file may not be readable), so the fallback copies the
    db + -wal + -shm to a scratch directory and reads the COPY. The
    originals are never opened for writing, never checkpointed and never
    renamed.
    """
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True,
                               timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("SELECT COUNT(*) FROM evidence").fetchone()
        return conn, "LIVE_READONLY", path
    except sqlite3.Error:
        scratch = Path(tempfile.mkdtemp(prefix="nvx-canary-snapshot-"))
        copy = scratch / path.name
        for suffix in ("", "-wal", "-shm"):
            source = Path(str(path) + suffix)
            if source.exists():
                shutil.copy2(source, str(copy) + suffix)
        conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn, "SNAPSHOT_COPY_READONLY", copy


def read_journal(state_dir: Path, channels: tuple[str, ...]) -> dict:
    path = state_dir / JOURNAL_FILENAME
    if not path.exists():
        return {"available": False,
                "unknown_reason": f"NO_JOURNAL_AT:{path}", "channels": {}}
    conn, mode, _ = open_journal_readonly(path)
    try:
        counters = {row["key"]: row["value"] for row in
                    conn.execute("SELECT key, value FROM integrity")}
        by_state = {row["state"]: row["n"] for row in conn.execute(
            "SELECT state, COUNT(*) AS n FROM evidence GROUP BY state")}
        per_channel: dict[str, dict] = {}
        rows = conn.execute(
            "SELECT channel, state, COUNT(*) AS n FROM evidence "
            "GROUP BY channel, state")
        for row in rows:
            entry = per_channel.setdefault(
                row["channel"], {"rows": 0, "deliverable": 0,
                                 "backend_accepted": 0})
            entry["rows"] += row["n"]
            if row["state"] in DELIVERABLE_STATES:
                entry["deliverable"] += row["n"]
            if row["state"] == "BACKEND_ACCEPTED":
                entry["backend_accepted"] += row["n"]
        for row in conn.execute(
                "SELECT channel, committed_record_id, continuity_established "
                "FROM cursors"):
            entry = per_channel.setdefault(
                row["channel"], {"rows": 0, "deliverable": 0,
                                 "backend_accepted": 0})
            entry["cursor_committed"] = int(row["committed_record_id"])
            entry["continuity_established"] = int(
                row["continuity_established"])
        oldest_pending = conn.execute(
            "SELECT MIN(collected_at) AS oldest FROM evidence "
            f"WHERE state IN ({','.join('?' * len(DELIVERABLE_STATES))})",
            DELIVERABLE_STATES).fetchone()["oldest"]
        gap_total = conn.execute(
            "SELECT COUNT(*) AS n FROM acquisition_gaps").fetchone()["n"]
        unreported = conn.execute(
            "SELECT COUNT(*) AS n FROM acquisition_gaps "
            "WHERE reported=0").fetchone()["n"]
        last_gap = conn.execute(
            "SELECT channel, missing_start_record_id, missing_end_record_id, "
            "missing_record_id_count, cause, detected_at "
            "FROM acquisition_gaps ORDER BY gap_id DESC LIMIT 1").fetchone()
        gap_causes = {row["cause"] for row in conn.execute(
            "SELECT DISTINCT cause FROM acquisition_gaps")}
        deliverable_total = sum(by_state.get(s, 0)
                                for s in DELIVERABLE_STATES)
        for channel in channels:
            per_channel.setdefault(channel, {"rows": 0, "deliverable": 0,
                                             "backend_accepted": 0})
        return {
            "available": True, "read_mode": mode, "counters": counters,
            "evidence_by_state": by_state, "channels": per_channel,
            "journal_depth": deliverable_total,
            "oldest_pending_age_seconds": _age_seconds(oldest_pending),
            "acquisition_gap_count": gap_total,
            "unreported_gap_count": unreported,
            "gap_causes": sorted(gap_causes),
            "last_gap": (dict(last_gap) if last_gap else None),
            "journal_bytes": path.stat().st_size,
        }
    finally:
        conn.close()


def read_integrity_snapshot(state_dir: Path) -> dict:
    for name, key in ((INTEGRITY_FILENAME, "snapshot"),
                      (FAULT_FILENAME, "fault")):
        path = state_dir / name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError) as ex:
            return {key: None, "unknown_reason": type(ex).__name__}
        if key == "snapshot":
            fault = state_dir / FAULT_FILENAME
            return {"snapshot": data,
                    "fault": (fault.read_text()[:400]
                              if fault.exists() else None)}
        return {"snapshot": None, "fault": json.dumps(data)[:400]}
    return {"snapshot": None, "fault": None}


# ── BACKEND (read-only HTTP) ──────────────────────────────────────
class BackendReader:
    """Authenticated READ-ONLY reads of the platform's own surfaces.

    No ingest middleware, no temporary instrumentation: these are the
    existing operator endpoints. Per-event backend cost is measured
    separately by `scripts/b5gap1_ingest_cost_profile.py`.
    """

    def __init__(self, api: str, token: str | None, tenant: str,
                 endpoint: str) -> None:
        self.api = api.rstrip("/")
        self.token = token
        self.tenant = tenant
        self.endpoint = endpoint

    def _get(self, path: str) -> tuple[int, dict | None, float]:
        request = urllib.request.Request(self.api + path, method="GET")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("X-Tenant-Id", self.tenant)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.loads(response.read().decode() or "{}")
                return response.status, body, (
                    time.perf_counter() - started) * 1000
        except urllib.error.HTTPError as ex:
            return ex.code, None, (time.perf_counter() - started) * 1000
        except (urllib.error.URLError, OSError, ValueError):
            return 0, None, (time.perf_counter() - started) * 1000

    def read(self) -> dict:
        status, stats, rtt = self._get("/api/edr/wave0/raw-events/stats")
        boundaries: dict = {}
        if isinstance(stats, dict):
            raw_boundaries = stats.get("delivery_boundaries")
            rows = (raw_boundaries.get("counters")
                    if isinstance(raw_boundaries, dict) else raw_boundaries)
            for row in (rows or []):
                if not isinstance(row, dict):
                    continue
                if row.get("endpoint_id") not in (None, self.endpoint):
                    continue
                for key, value in row.items():
                    if isinstance(value, (int, float)):
                        boundaries[key] = boundaries.get(key, 0) + value
        integrity_status, integrity, _ = self._get(
            "/api/edr/enrollment/acquisition-integrity"
            f"?endpoint_id={self.endpoint}")
        gaps = (integrity or {}).get("acquisition_gaps") or []
        channels = (integrity or {}).get("channels") or []
        tenants = sorted({str(row.get("tenant_id")) for row in
                          (list(gaps) + list(channels))
                          if isinstance(row, dict) and row.get("tenant_id")})
        return {
            "http_status": status, "rtt_ms": round(rtt, 3),
            "integrity_http_status": integrity_status,
            "received": boundaries.get("received"),
            "parsed": boundaries.get("parsed"),
            "accepted": boundaries.get("accepted"),
            "canonicalized": boundaries.get("canonicalized"),
            "deduplicated": boundaries.get("deduplicated"),
            "refused": boundaries.get("refused"),
            "gap_count": len(gaps),
            "gap_rows": gaps,
            "channel_rows": channels,
            "tenants_observed": tenants,
        }


# ── COLLECTOR ─────────────────────────────────────────────────────
class CanaryCollector:
    def __init__(self, *, state_dir, scenario, out_dir, channels=None,
                 backend_reader=None, source_reader=source_tail,
                 tenant="", endpoint="", artifact_sha256=""):
        self.state_dir = Path(state_dir)
        self.scenario = scenario
        self.out_dir = Path(out_dir)
        self.channels = tuple(channels or DEFAULT_CHANNELS)
        self.backend_reader = backend_reader
        self.source_reader = source_reader
        self.tenant = tenant
        self.endpoint = endpoint
        self.artifact_sha256 = artifact_sha256
        self.started = time.time()
        self._previous: dict | None = None
        self.rows: list[dict] = []
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.csv_path = self.out_dir / f"canary_{scenario}_{stamp}.csv"
        self.verdict_path = self.out_dir / f"canary_{scenario}_{stamp}.json"

    # one measurement of every stage
    def sample(self) -> list[dict]:
        at = _now()
        elapsed = round(time.time() - self.started, 3)
        journal = read_journal(self.state_dir, self.channels)
        snapshot = read_integrity_snapshot(self.state_dir)
        health = (snapshot.get("snapshot") or {})
        backend = self.backend_reader.read() if self.backend_reader else {}
        tails = {channel: self.source_reader(channel)
                 for channel in self.channels}
        counters = journal.get("counters") or {}
        previous = self._previous
        seconds = (elapsed - previous["elapsed"]) if previous else 0.0

        def total(key):
            try:
                return int(counters[key])
            except (KeyError, TypeError, ValueError):
                return None

        rows = []
        for channel in self.channels:
            entry = (journal.get("channels") or {}).get(channel) or {}
            tail = tails.get(channel) or {}
            cursor = entry.get("cursor_committed")
            newest = tail.get("newest")
            previous_channel = ((previous or {}).get("channels")
                                or {}).get(channel) or {}
            rows.append({
                "sample_at": at, "scenario": self.scenario,
                "elapsed_seconds": elapsed, "channel": channel,
                "source_oldest_record_id": tail.get("oldest"),
                "source_newest_record_id": newest,
                "source_records_per_sec": _rate(
                    newest, previous_channel.get("source_newest_record_id"),
                    seconds),
                "cursor_committed": cursor,
                "continuity_established": entry.get("continuity_established"),
                "last_record_id_journaled": counters.get(
                    f"last_record_id_journaled:{channel}"),
                "acquisition_lag_records": (
                    max(0, newest - cursor)
                    if isinstance(newest, int) and isinstance(cursor, int)
                    else None),
                "journal_rows": entry.get("rows"),
                "journal_rows_deliverable": entry.get("deliverable"),
                "journal_rows_backend_accepted": entry.get(
                    "backend_accepted"),
                "journaled_records_per_sec": _rate(
                    entry.get("rows"), previous_channel.get("journal_rows"),
                    seconds),
                "query_ms_last": counters.get(f"query_ms_last:{channel}"),
                "journal_depth": journal.get("journal_depth"),
                "journal_bytes": journal.get("journal_bytes"),
                "journal_live_bytes": health.get("journal_live_bytes"),
                "journal_pct": health.get("journal_pct"),
                "journal_pressure_state": ",".join(
                    s for s in (health.get("states") or [])
                    if "JOURNAL" in s) or None,
                "oldest_pending_age_seconds": journal.get(
                    "oldest_pending_age_seconds"),
                "records_read_total": total("records_read"),
                "records_journaled_total": total("records_journaled"),
                "backend_accepted_total": total("backend_accepted"),
                "delivery_failures_total": total("delivery_failures"),
                "query_total": total("query_total"),
                "query_failures_total": total("query_failures"),
                "acquisition_halted_reason": counters.get(
                    "acquisition_halted_reason"),
                "acquisition_gap_count": journal.get("acquisition_gap_count"),
                "unreported_gap_count": journal.get("unreported_gap_count"),
                "last_gap": (json.dumps(journal.get("last_gap"))
                             if journal.get("last_gap") else None),
                "health_states": ",".join(health.get("states") or []) or None,
                "journal_fault": snapshot.get("fault"),
                "delivery_backlog": journal.get("journal_depth"),
                "backend_http_status": backend.get("http_status"),
                "backend_rtt_ms": backend.get("rtt_ms"),
                "backend_received": backend.get("received"),
                "backend_parsed": backend.get("parsed"),
                "backend_accepted": backend.get("accepted"),
                "backend_canonicalized": backend.get("canonicalized"),
                "backend_deduplicated": backend.get("deduplicated"),
                "backend_refused": backend.get("refused"),
                "backend_accepted_per_sec": _rate(
                    backend.get("accepted"),
                    (previous or {}).get("backend_accepted"), seconds),
                "backend_gap_count": backend.get("gap_count"),
                "backend_tenants_observed": ",".join(
                    backend.get("tenants_observed") or []) or None,
                "journal_read_mode": journal.get("read_mode")
                or journal.get("unknown_reason"),
            })
        self._previous = {
            "elapsed": elapsed,
            "backend_accepted": backend.get("accepted"),
            "channels": {row["channel"]: row for row in rows},
        }
        self.rows += rows
        self._backend_last = backend
        return rows

    def write_csv(self) -> Path:
        with self.csv_path.open("w", newline="", encoding="ascii") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS,
                                    extrasaction="ignore")
            writer.writeheader()
            for row in self.rows:
                writer.writerow(row)
        return self.csv_path

    def run(self, duration: float, interval: float) -> Path:
        deadline = time.time() + duration
        while True:
            self.sample()
            self.write_csv()
            if time.time() >= deadline:
                break
            time.sleep(max(1.0, interval))
        return self.csv_path

    # ── invariants ────────────────────────────────────────────────
    def verdict(self) -> dict:
        rules = SCENARIOS.get(self.scenario, {})
        rows = self.rows
        checks: dict[str, dict] = {}
        limitations: list[str] = []

        def record(name, result, observed, note=""):
            checks[name] = {"result": result, "observed": observed,
                            "note": note}

        if not rows:
            record("SAMPLES_COLLECTED", "FAIL", 0, "no samples")
            return self._verdict_envelope(checks, {}, limitations)
        record("SAMPLES_COLLECTED", "PASS", len(rows))

        by_channel: dict[str, list[dict]] = {}
        for row in rows:
            by_channel.setdefault(row["channel"], []).append(row)

        # cursor may only move forward, and never past what was journaled
        regressions, past_journal, past_source = [], [], []
        for channel, series in by_channel.items():
            cursors = [r["cursor_committed"] for r in series
                       if isinstance(r["cursor_committed"], int)]
            for before, after in zip(cursors, cursors[1:]):
                if after < before:
                    regressions.append({"channel": channel,
                                        "from": before, "to": after})
            for row in series:
                cursor = row["cursor_committed"]
                journaled = row["last_record_id_journaled"]
                newest = row["source_newest_record_id"]
                if isinstance(cursor, int) and isinstance(journaled, str):
                    try:
                        journaled = int(journaled)
                    except ValueError:
                        journaled = None
                if isinstance(cursor, int) and isinstance(journaled, int) \
                        and cursor > journaled:
                    past_journal.append({"channel": channel,
                                         "cursor": cursor,
                                         "journaled": journaled})
                if isinstance(cursor, int) and isinstance(newest, int) \
                        and cursor > newest:
                    past_source.append({"channel": channel,
                                        "cursor": cursor, "source": newest})
        record("CURSOR_MONOTONIC", "PASS" if not regressions else "FAIL",
               regressions)
        record("SOURCE_CURSOR_LE_DURABLY_OWNED",
               "PASS" if not (past_journal or past_source) else "FAIL",
               {"past_journal": past_journal, "past_source": past_source})

        # unacknowledged deletion: deliverable rows may only fall when the
        # platform accepted at least that many
        deletions = []
        for channel, series in by_channel.items():
            for before, after in zip(series, series[1:]):
                dropped = ((before["journal_rows_deliverable"] or 0)
                           - (after["journal_rows_deliverable"] or 0))
                accepted_gain = ((after["journal_rows_backend_accepted"] or 0)
                                 - (before["journal_rows_backend_accepted"]
                                    or 0))
                released = ((before["journal_rows"] or 0)
                            - (after["journal_rows"] or 0))
                if dropped > 0 and accepted_gain + released < dropped:
                    deletions.append({"channel": channel,
                                      "deliverable_dropped": dropped,
                                      "accepted_gain": accepted_gain,
                                      "rows_released": released})
        record("UNACKNOWLEDGED_DELETION", "PASS" if not deletions else "FAIL",
               deletions)

        # duplicates
        dedup = [r["backend_deduplicated"] for r in rows
                 if isinstance(r["backend_deduplicated"], (int, float))]
        dedup_delta = (max(dedup) - min(dedup)) if dedup else None
        if dedup_delta is None:
            record("DUPLICATES", "NOT_PROVABLE", None,
                   "backend dedup counter unavailable to this reader")
            limitations.append("duplicate count not readable")
        elif dedup_delta == 0:
            record("DUPLICATES", "PASS", 0)
        elif rules.get("allow_duplicates"):
            record("DUPLICATES", "PASS", dedup_delta,
                   "retry-window duplicates are refused at the platform "
                   "boundary, not accepted twice")
        else:
            record("DUPLICATES", "FAIL", dedup_delta)

        # wrong tenant
        tenants = sorted({t for r in rows
                          for t in (r["backend_tenants_observed"] or ""
                                    ).split(",") if t})
        foreign = [t for t in tenants if self.tenant and t != self.tenant]
        record("WRONG_TENANT_EVIDENCE", "PASS" if not foreign else "FAIL",
               {"tenants_observed": tenants, "foreign": foreign},
               "scope: the canary tenant's own authority only")
        limitations.append(
            "cross-tenant leakage can only be excluded within the reader's "
            "authority; a platform-wide scan is a separate owner action")

        # gaps
        gap_counts = [r["acquisition_gap_count"] for r in rows
                      if isinstance(r["acquisition_gap_count"], int)]
        gaps_seen = max(gap_counts) if gap_counts else None
        if rules.get("expect_gaps"):
            record("DECLARED_GAP_FOR_INJECTED_DISCONTINUITY",
                   "PASS" if (gaps_seen or 0) > 0 else "FAIL", gaps_seen,
                   "an injected discontinuity MUST surface as a declared "
                   "gap, never be absorbed silently")
        else:
            record("UNEXPLAINED_ACQUISITION_GAPS",
                   "PASS" if not gaps_seen else "FAIL", gaps_seen)

        # silent loss
        loss: dict[str, object] = {}
        provable = False
        for channel, series in by_channel.items():
            first, last = series[0], series[-1]
            start_cursor = first["cursor_committed"]
            end_newest = last["source_newest_record_id"]
            end_cursor = last["cursor_committed"]
            if not all(isinstance(v, int) for v in
                       (start_cursor, end_newest, end_cursor)):
                loss[channel] = "NOT_PROVABLE_SOURCE_TAIL_UNKNOWN"
                continue
            provable = True
            journaled = ((last["journal_rows"] or 0)
                         - (first["journal_rows"] or 0))
            declared_missing = 0
            if last["last_gap"]:
                try:
                    declared_missing = int(json.loads(
                        last["last_gap"]).get("missing_record_id_count") or 0)
                except (ValueError, TypeError):
                    declared_missing = 0
            expected = max(0, end_newest - start_cursor)
            outstanding = max(0, end_newest - end_cursor)
            loss[channel] = {
                "source_records_available": expected,
                "journaled": journaled,
                "declared_missing_in_gaps": declared_missing,
                "still_outstanding_at_end": outstanding,
                "unexplained": max(0, expected - journaled - declared_missing
                                   - outstanding),
            }
        unexplained = sum(v["unexplained"] for v in loss.values()
                          if isinstance(v, dict))
        record("SILENT_LOSS",
               ("PASS" if unexplained == 0 else "FAIL") if provable
               else "NOT_PROVABLE", loss,
               "" if provable else "source RecordID tails unavailable")
        if not provable:
            limitations.append(
                "silent loss is only provable where the source channel tail "
                "can be read (Windows canary host)")

        # acquisition must continue while delivery is impaired
        if rules.get("impaired"):
            progressed = any(
                (r["journaled_records_per_sec"] or 0) > 0 for r in rows)
            record("ACQUISITION_CONTINUES_WHILE_DELIVERY_IMPAIRED",
                   "PASS" if progressed else "FAIL", progressed,
                   "subject to available journal capacity")
        if rules.get("expect_backlog"):
            peak = max((r["delivery_backlog"] or 0) for r in rows)
            record("BACKLOG_OBSERVED", "PASS" if peak > 0 else "FAIL", peak)
        if rules.get("require_drain_to_zero"):
            peak = max((r["delivery_backlog"] or 0) for r in rows)
            final = rows[-1]["delivery_backlog"]
            record("BACKLOG_DRAINED_TO_ZERO",
                   "PASS" if (peak > 0 and final == 0) else "FAIL",
                   {"peak": peak, "final": final})
        if rules.get("require_all_channels_progress"):
            stalled = [c for c, s in by_channel.items()
                       if ((s[-1]["journal_rows"] or 0)
                           - (s[0]["journal_rows"] or 0)) <= 0]
            record("ALL_CHANNELS_PROGRESSED",
                   "PASS" if not stalled else "FAIL", {"stalled": stalled})
        if rules.get("expect_pressure"):
            states = {s for r in rows
                      for s in (r["health_states"] or "").split(",") if s}
            pressured = {"JOURNAL_PRESSURE", "JOURNAL_CRITICAL",
                         "ACQUISITION_HALTED_JOURNAL_FULL"} & states
            record("JOURNAL_PRESSURE_SURFACED_EXPLICITLY",
                   "PASS" if pressured else "FAIL", sorted(states),
                   "pressure must be an explicit state, never a silent drop")

        faults = [r["journal_fault"] for r in rows if r["journal_fault"]]
        record("JOURNAL_NOT_CORRUPT", "PASS" if not faults else "FAIL",
               faults[:1])

        return self._verdict_envelope(checks, self._throughput(by_channel),
                                      limitations)

    def _throughput(self, by_channel: dict) -> dict:
        def series(key):
            return [r[key] for r in self.rows
                    if isinstance(r.get(key), (int, float))]

        source = series("source_records_per_sec")
        acquired = series("journaled_records_per_sec")
        delivered = series("backend_accepted_per_sec")
        sustained_source = round(statistics.median(source), 3) if source \
            else None
        sustained_delivery = round(statistics.median(delivered), 3) \
            if delivered else None
        headroom = None
        if sustained_source and sustained_delivery is not None \
                and sustained_source > 0:
            headroom = round(sustained_delivery / sustained_source, 3)
        return {
            "sustained_source_rate_eps": sustained_source,
            "sustained_acquisition_rate_eps": round(
                statistics.median(acquired), 3) if acquired else None,
            "sustained_delivery_rate_eps": sustained_delivery,
            "peak_delivery_rate_eps": max(delivered) if delivered else None,
            "recovery_drain_rate_eps": max(delivered) if delivered else None,
            "delivery_headroom": headroom,
            "peak_delivery_backlog": max(
                (r["delivery_backlog"] or 0) for r in self.rows),
            "final_delivery_backlog": self.rows[-1]["delivery_backlog"],
            "http_rtt_ms_median": round(statistics.median(
                series("backend_rtt_ms")), 3) if series("backend_rtt_ms")
                else None,
            "note": ("no required headroom is asserted here: the production "
                     "threshold is an owner decision taken from these "
                     "measurements"),
        }

    def _verdict_envelope(self, checks, throughput, limitations) -> dict:
        results = [c["result"] for c in checks.values()]
        verdict = ("FAIL" if "FAIL" in results
                   else ("NOT_PROVABLE" if "NOT_PROVABLE" in results
                         else "PASS"))
        return {
            "contract": CONTRACT, "contract_version": CONTRACT_VERSION,
            "scenario": self.scenario,
            "scenario_expectations": SCENARIOS.get(self.scenario, {}),
            "generated_at": _now(),
            "canary": {"tenant_id": self.tenant,
                       "endpoint_id": self.endpoint,
                       "state_dir": str(self.state_dir),
                       "artifact_sha256": self.artifact_sha256,
                       "designation": "DISPOSABLE_CANARY"},
            "samples": len(self.rows),
            "csv": str(self.csv_path),
            "verdict": verdict,
            "invariants": checks,
            "throughput": throughput,
            "limitations": sorted(set(limitations)),
            "evidence_labelling": "CANARY/VALIDATION — not production truth",
            "boundary": {"CANARY_HOST_ONLY": True,
                         "DESKTOP_A9HGFJJ_TOUCHED": "NO",
                         "PRODUCTION_DEPLOYED": "NO",
                         "PRODUCT_CODE_MODIFIED_FOR_MEASUREMENT": "NO"},
        }

    def write_verdict(self) -> Path:
        self.verdict_path.write_text(
            json.dumps(self.verdict(), indent=2, default=str))
        return self.verdict_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="b5gap1_canary_collector",
        description="read-only B5-GAP-1 canary measurement collector")
    ap.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    ap.add_argument("--state-dir", default=os.environ.get(
        "NIVXFORGE_SENSOR_STATE",
        r"C:\ProgramData\NivXForge\sensor"))
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--duration", type=float, default=900.0)
    ap.add_argument("--interval", type=float, default=15.0)
    ap.add_argument("--backend", default="")
    ap.add_argument("--tenant", default="")
    ap.add_argument("--endpoint", default="")
    ap.add_argument("--artifact-sha256", default="")
    ap.add_argument("--channels", default=",".join(DEFAULT_CHANNELS))
    args = ap.parse_args(argv)

    token = os.environ.get("NIVX_CANARY_READ_TOKEN") or None
    reader = (BackendReader(args.backend, token, args.tenant, args.endpoint)
              if args.backend else None)
    if args.backend and not token:
        print("NIVX_CANARY_READ_TOKEN is not set: backend-side numbers will "
              "be unavailable and reported as unknown, not estimated.",
              file=sys.stderr)
    collector = CanaryCollector(
        state_dir=args.state_dir, scenario=args.scenario,
        out_dir=args.out_dir, channels=tuple(
            c for c in args.channels.split(",") if c),
        backend_reader=reader, tenant=args.tenant, endpoint=args.endpoint,
        artifact_sha256=args.artifact_sha256)
    collector.run(args.duration, args.interval)
    collector.write_csv()
    path = collector.write_verdict()
    print(json.dumps(json.loads(path.read_text()), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
