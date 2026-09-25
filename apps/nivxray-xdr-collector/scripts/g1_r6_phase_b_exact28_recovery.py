#!/usr/bin/env python3
"""G1-R6 Phase B · bounded recovery of the EXACT 28 retryable identities.

Phase A repaired the 22 rows the server already held as canonical. These 28
are the remainder of the interrupted population: the authoritative
reconciliation said RETRYABLE_STILL_QUEUED, so they were never durably
accounted for and must actually be delivered.

Why this is a dedicated path and not the delivery worker
--------------------------------------------------------
`framework.outbox.Outbox.__init__` calls `_reset_stuck_delivering()`, which
runs `UPDATE envelopes SET status='queued' WHERE status='delivering'`. Merely
CONSTRUCTING the outbox would flip all 28 rows to `queued` and expose them to
the general backlog drain, destroying the isolation Phase A established. So
this tool never constructs `Outbox`; it owns its own sqlite3 connection
(`mode=ro` in readiness) and imports only the pure `Envelope` dataclass.

Everything else is the existing hardened machinery: `IngestClient` for the
wire call and its G1-R1 classification, the R3.1 `DeliveryHealthGate` restored
from its persisted row, and the same deterministic delivery identity the
exact-50 reconciliation proved against.

The canary boundary
-------------------
HTTP accepted != canonicalized != durably evidenced. One identity is
delivered, then RECONCILED, and only an authoritative canonical/retained-raw
disposition authorises the remaining 27. A 2xx alone authorises nothing.

Local accounting
----------------
`delivering -> delivered` is permitted ONLY for dispositions whose
authoritative semantics support terminal local accounting: DELIVERED_CANONICAL
and DELIVERED_RETAINED_RAW (recorded distinctly - B4 is preserved, retained
raw is never relabelled canonical). Rows that remain legitimately retryable
stay `delivering` with their status, attempts, next_attempt_at and last_error
untouched, and are explicitly accounted for in the identity equation:

    canonical + retained_raw + retryable + terminal + unexplained = 28
    required: unexplained = 0
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

import importlib.util  # noqa: E402

_EXACT50 = os.path.join(_HERE, "g1_r5_inflight50_reconcile.py")
_spec = importlib.util.spec_from_file_location("g1_r5_exact50_lib", _EXACT50)
exact50 = importlib.util.module_from_spec(_spec)
sys.modules["g1_r5_exact50_lib"] = exact50
_spec.loader.exec_module(exact50)

from framework.base import Envelope  # noqa: E402
from framework.delivery import (DeliveryClassification,  # noqa: E402
                                IngestClient, IngestOutcome)
from framework.health_gate import DeliveryHealthGate  # noqa: E402

PHASE = "G1-R6-B"
PHASE_A_MARKER = "G1-R6-A"
DELIVERING = "delivering"
DELIVERED = "delivered"

CANONICAL = exact50.CANONICAL
RETAINED = exact50.RETAINED
RETRYABLE = exact50.RETRYABLE
TERMINAL = exact50.TERMINAL
UNEXPLAINED = exact50.UNEXPLAINED
#: the only dispositions whose semantics support local terminal accounting
ACCOUNTABLE = (CANONICAL, RETAINED)

TARGET_COUNT = 28
EXCLUDED_COUNT = 22
MAX_TARGET = 28
DEFAULT_REMAINDER_BATCH = 7
DESTINATION_KEY = "nivx-ingest"

#: The server's own issuance format (`nvx_` + 48 lowercase hex) and the exact
#: syntax gate `authenticate_api_key()` applies before any credential lookup.
INGEST_KEY_PATTERN = r"^nvx_[0-9a-f]{48}$"
_INGEST_KEY_RE = re.compile(INGEST_KEY_PATTERN)


class PhaseBRefusal(Exception):
    """Hard stop. Nothing was delivered or changed beyond what is reported."""


class PhaseBStop(Exception):
    """A legitimate, evidence-backed stop: the remaining 27 are NOT sent."""

    def __init__(self, reason: str, report: Dict[str, Any]):
        super().__init__(reason)
        self.reason = reason
        self.report = report


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── local state, read without ever constructing the Outbox ────────────
def _histogram(conn: sqlite3.Connection) -> Dict[str, int]:
    return {r[0]: int(r[1]) for r in conn.execute(
        "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}


def _bookmark_fingerprint(conn: sqlite3.Connection) -> Optional[str]:
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if "windows_channel_state" not in tables:
        return None
    digest = hashlib.sha256()
    for row in conn.execute("SELECT * FROM windows_channel_state "
                            "ORDER BY rowid"):
        digest.update(("|".join("" if v is None else str(v)
                                for v in tuple(row))).encode("utf-8"))
    return digest.hexdigest()


def _population_fingerprint(conn: sqlite3.Connection,
                            status: str) -> Tuple[int, str]:
    """Row-level fingerprint of a population we must prove we never moved."""
    digest = hashlib.sha256()
    count = 0
    for row in conn.execute(
            "SELECT id, status, attempts, next_attempt_at, last_error "
            "FROM envelopes WHERE status=? ORDER BY id", (status,)):
        count += 1
        digest.update(("|".join("" if v is None else str(v)
                                for v in tuple(row))).encode("utf-8"))
    return count, digest.hexdigest()


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(conn: sqlite3.Connection, db_path: str) -> Dict[str, Any]:
    queued_n, queued_fp = _population_fingerprint(conn, "queued")
    retry_n, retry_fp = _population_fingerprint(conn, "retrying")
    return {
        "at": _now(),
        "status_histogram": _histogram(conn),
        "total": int(conn.execute(
            "SELECT COUNT(*) FROM envelopes").fetchone()[0]),
        "bookmarks_sha256": _bookmark_fingerprint(conn),
        "database_sha256": _file_sha256(db_path),
        "delivering_row_ids": sorted(
            str(r[0]) for r in conn.execute(
                "SELECT id FROM envelopes WHERE status=?", (DELIVERING,))),
        "queued_count": queued_n,
        "queued_fingerprint": queued_fp,
        "retrying_count": retry_n,
        "retrying_fingerprint": retry_fp,
    }


# ── authority ─────────────────────────────────────────────────────────
def load_authority(path: str) -> Dict[str, Any]:
    """The exact-50 PASS record. The untrusted sibling is not authority."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise PhaseBRefusal(f"{path} is not a reconciliation report.")
    if "VERDICT" in doc:
        raise PhaseBRefusal(
            f"{path} is the FAILED/UNTRUSTED forensic sibling, not authority "
            f"for R6: {doc['VERDICT']}. Nothing was attempted.")
    if doc.get("pass") is not True:
        raise PhaseBRefusal(
            f"{path} does not carry pass=true, so it is not authority. "
            "Nothing was attempted.")
    rows = doc.get("rows")
    if not isinstance(rows, list) or not rows:
        raise PhaseBRefusal(
            f"{path} carries no reconciliation rows. Nothing was attempted.")

    by_ref: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        ref = str(row.get("ref") or "")
        if not ref:
            raise PhaseBRefusal("an authority row carries no ref.")
        if ref in by_ref:
            raise PhaseBRefusal(f"authority row {ref} is duplicated.")
        by_ref[ref] = row
    target = sorted(r for r, row in by_ref.items()
                    if row.get("bucket") == RETRYABLE)
    excluded = sorted(r for r, row in by_ref.items()
                      if row.get("bucket") == CANONICAL)
    other = sorted(r for r, row in by_ref.items()
                   if row.get("bucket") not in (RETRYABLE, CANONICAL))
    if other:
        raise PhaseBRefusal(
            f"{len(other)} authority rows are neither canonical nor "
            "retryable; this is not the exact-50 population.")
    if len(target) != TARGET_COUNT or len(excluded) != EXCLUDED_COUNT:
        raise PhaseBRefusal(
            f"authority holds {len(excluded)} canonical + {len(target)} "
            f"retryable, expected exactly {EXCLUDED_COUNT} + {TARGET_COUNT}. "
            "Nothing was attempted.")
    if set(target) & set(excluded):
        raise PhaseBRefusal("a ref is both canonical and retryable.")
    if len(target) > MAX_TARGET:
        raise PhaseBRefusal(
            f"refusing a population of {len(target)}; this operation is hard "
            f"bounded to {MAX_TARGET} identities.")
    return {"target": target, "excluded": excluded, "by_ref": by_ref,
            "authority_sha256": _file_sha256(path)}


# ── preconditions ─────────────────────────────────────────────────────
def _identity_for(row: sqlite3.Row, collector: str) -> Tuple[str, str]:
    raw = json.loads(row["raw_json"] or "{}")
    return (exact50.delivery_key(
        tenant_id=row["tenant_id"], collector_id=collector,
        source=row["source"], source_event_id=row["source_event_id"],
        raw=raw), exact50.payload_digest(raw))


def verify_preconditions(conn: sqlite3.Connection, authority: Dict[str, Any],
                         collector: str, pre: Dict[str, Any],
                         expect_total: int, expect_queued: int,
                         expect_retrying: int) -> List[Dict[str, Any]]:
    """Every check that must hold before a single byte goes on the wire."""
    target, excluded = authority["target"], authority["excluded"]

    if sorted(pre["delivering_row_ids"]) != target:
        raise PhaseBRefusal(
            "the local `delivering` set is not exactly the 28 authoritative "
            f"retryable refs ({len(pre['delivering_row_ids'])} local vs "
            f"{len(target)} expected). Phase A's post-state is not intact. "
            "Nothing was attempted.")
    if expect_total and pre["total"] != expect_total:
        raise PhaseBRefusal(
            f"outbox holds {pre['total']} rows, expected {expect_total}.")
    if expect_queued and pre["queued_count"] != expect_queued:
        raise PhaseBRefusal(
            f"queued is {pre['queued_count']}, expected {expect_queued}.")
    if expect_retrying and pre["retrying_count"] != expect_retrying:
        raise PhaseBRefusal(
            f"retrying is {pre['retrying_count']}, expected "
            f"{expect_retrying}.")
    if pre["status_histogram"].get("dead_letter", 0) != 0:
        raise PhaseBRefusal("dead_letter is not 0.")

    # positive proof Phase A is intact and its 22 rows are excluded
    for ref in excluded:
        row = conn.execute("SELECT * FROM envelopes WHERE id=?",
                           (ref,)).fetchone()
        if row is None:
            raise PhaseBRefusal(f"Phase A row {ref} is missing locally.")
        if row["status"] != DELIVERED:
            raise PhaseBRefusal(
                f"Phase A row {ref} is {row['status']!r}, expected "
                f"{DELIVERED!r}. Phase A is not intact; nothing was "
                "attempted.")
        marker = row["recovery_json"] or ""
        if PHASE_A_MARKER not in marker:
            raise PhaseBRefusal(
                f"Phase A row {ref} carries no {PHASE_A_MARKER} marker. "
                "Refusing to proceed on an unproven post-state.")

    plan: List[Dict[str, Any]] = []
    for ref in target:
        row = conn.execute("SELECT * FROM envelopes WHERE id=?",
                           (ref,)).fetchone()
        if row is None:
            raise PhaseBRefusal(f"target row {ref} is missing locally.")
        if row["status"] != DELIVERING:
            raise PhaseBRefusal(
                f"target row {ref} is {row['status']!r}, expected "
                f"{DELIVERING!r}.")
        if PHASE_A_MARKER in (row["recovery_json"] or ""):
            raise PhaseBRefusal(
                f"target row {ref} carries the {PHASE_A_MARKER} marker: it is "
                "one of the 22 already repaired. Refusing.")
        key, digest = _identity_for(row, collector)
        expected = authority["by_ref"][ref].get("delivery_key")
        if expected and key != expected:
            raise PhaseBRefusal(
                f"target row {ref} would be delivered under identity {key} "
                f"but the authority proved {expected}. A different identity "
                "would not be the same event. Refusing.")
        plan.append({
            "ref": ref, "delivery_key": key, "payload_digest": digest,
            "source_event_id": row["source_event_id"],
            "connector_id": row["connector_id"],
            "attempts_before": int(row["attempts"] or 0),
            "local_status": row["status"],
        })
    return plan


# ── credential format gate (second, independent fail-closed layer) ────
def assert_ingest_credential(client: Any) -> Dict[str, Any]:
    """Refuse a malformed ingest credential BEFORE any delivery path.

    The first APPLY spent the canary on a value the server rejected as
    `malformed-api-key`, i.e. it never even reached credential lookup. The
    PowerShell wrapper now catches that locally, but this engine enforces the
    identical requirement independently so a direct invocation - or a future
    wrapper edit - still cannot hand a malformed credential to
    `IngestClient.deliver()`. Nothing is stripped, normalised, case-folded or
    repaired: a malformed credential is rejected, never silently fixed.
    """
    mode = getattr(client, "auth_mode", None)
    if mode != "api_key":
        raise PhaseBRefusal(
            f"the ingest client is in auth_mode {mode!r}; this bounded "
            "recovery delivers only with an `api_key` collector credential. "
            "Nothing was attempted.")
    token = getattr(client, "token", None)
    if not isinstance(token, str) or not _INGEST_KEY_RE.fullmatch(token):
        length = len(token) if isinstance(token, str) else None
        raise PhaseBRefusal(
            "the collector ingest credential does not satisfy the required "
            f"format {INGEST_KEY_PATTERN} (length {length}, expected 52). "
            "It would be refused as `malformed-api-key` before credential "
            "lookup, so the canary was NOT spent on it. The value was not "
            "trimmed, case-folded or repaired. Nothing was attempted.")
    return {"format": INGEST_KEY_PATTERN, "format_valid": True,
            "auth_mode": mode, "public_prefix": token[:12], "length": 52}


# ── delivery ──────────────────────────────────────────────────────────
def build_envelope(row: sqlite3.Row, collector: str) -> Envelope:
    """The SAME payload identity as the interrupted attempt, not a new one."""
    return Envelope(
        tenant_id=row["tenant_id"],
        source=row["source"],
        source_event_id=row["source_event_id"],
        connector_id=row["connector_id"],
        collector_id=collector,
        collection_method=row["collection_method"],
        parser_version=row["parser_version"],
        source_timestamp=row["source_timestamp"],
        collection_timestamp=row["collection_timestamp"],
        event_type=row["event_type"],
        raw=json.loads(row["raw_json"] or "{}"),
        canonical=json.loads(row["canonical_json"] or "{}"),
        declared_source=row["declared_source"],
    )


def deliver_batch(client: IngestClient, conn: sqlite3.Connection,
                  refs: List[str], collector: str,
                  gate: DeliveryHealthGate) -> Dict[str, Any]:
    envelopes = []
    for ref in refs:
        row = conn.execute("SELECT * FROM envelopes WHERE id=?",
                           (ref,)).fetchone()
        envelopes.append(build_envelope(row, collector))
    result = asyncio.run(client.deliver(envelopes))
    classification = result.get("classification")
    if result.get("outcome") == IngestOutcome.OK:
        gate.record_success()
    else:
        gate.record_destination_failure(
            str(result.get("reason") or classification or "unknown"))
    return {
        "refs": list(refs),
        "attempted": len(refs),
        "outcome": result.get("outcome"),
        "classification": classification,
        "status_code": result.get("status_code"),
        "app_attributed": result.get("app_attributed"),
        "reason": result.get("reason"),
        "failure_detail": result.get("failure_detail"),
        "gate_state_after": gate.state,
        "note": ("HTTP acceptance is NOT proof of canonicalisation; only the "
                 "reconciliation below is authoritative"),
    }


# ── reconciliation ────────────────────────────────────────────────────
def reconcile(plan: List[Dict[str, Any]], base_url: str, token: str,
              collector: str, timeout: int,
              reconcile_fn=None) -> Dict[str, Any]:
    identities = [{
        "ref": entry["ref"],
        "delivery_key": entry["delivery_key"],
        "source_event_id": entry["source_event_id"],
        "collector_id": collector,
        "connector_id": entry["connector_id"],
        "payload_digest": entry["payload_digest"],
        "endpoint_outcome": DELIVERING,
    } for entry in plan]
    send = reconcile_fn or (lambda ids: exact50.post_reconcile(
        base_url, token, ids, timeout))
    return send(identities)


def _disposition_map(response: Dict[str, Any],
                     expected_refs: List[str]) -> Dict[str, Dict[str, Any]]:
    rows = response.get("rows")
    rows = rows if isinstance(rows, list) else []
    returned = [str(r.get("ref")) for r in rows]
    if sorted(returned) != sorted(expected_refs):
        raise PhaseBRefusal(
            "the reconciliation response does not correspond 1:1 with the "
            f"identities sent ({len(returned)} returned vs "
            f"{len(expected_refs)} sent; "
            f"missing={sorted(set(expected_refs) - set(returned))}, "
            f"foreign={sorted(set(returned) - set(expected_refs))}). "
            "Nothing was accounted.")
    return {str(r.get("ref")): r for r in rows}


def _equation(dispositions: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    counts = {CANONICAL: 0, RETAINED: 0, RETRYABLE: 0, TERMINAL: 0,
              UNEXPLAINED: 0}
    for row in dispositions.values():
        bucket = str(row.get("bucket") or UNEXPLAINED)
        if bucket not in counts:
            raise PhaseBRefusal(
                f"unrecognised reconciliation bucket {bucket!r}; refusing to "
                "account an outcome this tool does not understand.")
        counts[bucket] += 1
    return counts


def _accountable(row: Dict[str, Any]) -> bool:
    """Only server-proven evidence authorises a local `delivered`."""
    bucket = row.get("bucket")
    if bucket == CANONICAL:
        return bool(row.get("evidence_ref")
                    and (row.get("claim") or {}).get("canonical_event_id"))
    if bucket == RETAINED:
        return bool(row.get("retained_raw_id") or row.get("evidence_ref"))
    return False


# ── local accounting ──────────────────────────────────────────────────
def apply_accounting(conn: sqlite3.Connection,
                     dispositions: Dict[str, Dict[str, Any]],
                     authority_sha: str) -> Dict[str, Any]:
    updated: List[str] = []
    left: List[str] = []
    conn.execute("BEGIN IMMEDIATE")
    try:
        for ref, row in sorted(dispositions.items()):
            bucket = row.get("bucket")
            if bucket not in ACCOUNTABLE:
                left.append(ref)
                continue
            if not _accountable(row):
                raise PhaseBRefusal(
                    f"{ref} is bucketed {bucket} but carries no resolvable "
                    "evidence; refusing to mark it delivered.")
            marker = json.dumps({
                "phase": PHASE,
                "action": "delivery_recovery_then_accounting",
                "from_status": DELIVERING,
                "to_status": DELIVERED,
                "disposition": bucket,
                "retained_raw": bucket == RETAINED,
                "canonical_event_id": (row.get("claim") or {}).get(
                    "canonical_event_id"),
                "retained_raw_id": row.get("retained_raw_id"),
                "evidence_ref": row.get("evidence_ref"),
                "network_delivery_performed": True,
                "basis": ("delivered by this bounded recovery and then proven "
                          "by authoritative server reconciliation"),
                "authority_sha256": authority_sha,
                "at": _now(),
            }, sort_keys=True)
            cur = conn.execute(
                "UPDATE envelopes SET status=?, updated_at=?, recovery_json=? "
                " WHERE id=? AND status=?",
                (DELIVERED, _now(), marker, ref, DELIVERING))
            if cur.rowcount != 1:
                raise PhaseBRefusal(
                    f"{ref} did not transition exactly once "
                    f"(rowcount={cur.rowcount}); the whole repair is rolled "
                    "back.")
            updated.append(ref)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"updated": updated, "left_delivering": left}


# ── gate stores, without the Outbox ───────────────────────────────────
class _GateStore:
    def __init__(self, conn: sqlite3.Connection, read_only: bool):
        self._conn = conn
        self._read_only = read_only

    def load_health_gate(self, destination_key: str) -> Optional[Dict[str, Any]]:
        tables = {r[0] for r in self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "delivery_health_gate" not in tables:
            return None
        row = self._conn.execute(
            "SELECT * FROM delivery_health_gate WHERE destination_key=?",
            (destination_key,)).fetchone()
        return None if row is None else {k: row[k] for k in row.keys()}

    def save_health_gate(self, destination_key: str,
                         snapshot: Dict[str, Any]) -> None:
        if self._read_only:
            raise PhaseBRefusal(
                "readiness mode attempted to persist delivery-gate state. A "
                "dry run must not mutate the gate's memory of the "
                "destination.")
        self._conn.execute("""
            INSERT INTO delivery_health_gate
            (destination_key, state_version, state, consecutive_failures,
             cooldown_seconds, cooldown_until_epoch, opened_count, probes,
             last_reason, last_transition_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(destination_key) DO UPDATE SET
              state_version=excluded.state_version, state=excluded.state,
              consecutive_failures=excluded.consecutive_failures,
              cooldown_seconds=excluded.cooldown_seconds,
              cooldown_until_epoch=excluded.cooldown_until_epoch,
              opened_count=excluded.opened_count, probes=excluded.probes,
              last_reason=excluded.last_reason,
              last_transition_at=excluded.last_transition_at,
              updated_at=excluded.updated_at
        """, (destination_key, snapshot.get("state_version"),
              snapshot.get("state"), snapshot.get("consecutive_failures"),
              snapshot.get("cooldown_seconds"),
              snapshot.get("cooldown_until_epoch"),
              snapshot.get("opened_count"), snapshot.get("probes"),
              snapshot.get("last_reason"),
              snapshot.get("last_transition_at"), _now()))
        self._conn.commit()


_FORBIDDEN = ("Outbox" "(", "DeliveryWorker" "(", "EvtSubscribe",
              "next_batch" "(", "release_delivering" "(")


def _own_forbidden_usage() -> List[str]:
    """This tool must never construct the Outbox or a DeliveryWorker."""
    with open(os.path.abspath(__file__), encoding="utf-8") as fh:
        source = fh.read()
    # the guard's own declaration of what it forbids is not usage of it
    start = source.find("_FORBIDDEN = (")
    end = source.find("\ndef _non_mutation_checks")
    scanned = source[:start] + source[end:] if -1 not in (start, end) \
        else source
    body = "\n".join(line for line in scanned.split('"""', 2)[-1].splitlines()
                     if not line.strip().startswith("#"))
    return [token for token in _FORBIDDEN if token in body]


def _non_mutation_checks(pre: Dict[str, Any],
                         post: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "bookmarks_unchanged": {
            "holds": pre["bookmarks_sha256"] == post["bookmarks_sha256"],
            "sha256": post["bookmarks_sha256"]},
        "queued_population_untouched": {
            "holds": (pre["queued_fingerprint"] == post["queued_fingerprint"]
                      and pre["queued_count"] == post["queued_count"]),
            "count": post["queued_count"]},
        "retrying_population_untouched": {
            "holds": (pre["retrying_fingerprint"]
                      == post["retrying_fingerprint"]
                      and pre["retrying_count"] == post["retrying_count"]),
            "count": post["retrying_count"]},
        "total_rows_unchanged": {
            "holds": pre["total"] == post["total"], "total": post["total"]},
        "no_outbox_or_worker_constructed": {
            "holds": not _own_forbidden_usage(),
            "forbidden_usage_found": _own_forbidden_usage(),
            "note": ("Outbox.__init__ would reset delivering -> queued; this "
                     "tool never constructs it")},
    }


def run(*, state_dir: str, authority_path: str, base_url: str, token: str,
        collector_id: str, apply_changes: bool = False,
        expect_total: int = 125452, expect_queued: int = 121993,
        expect_retrying: int = 125,
        remainder_batch: int = DEFAULT_REMAINDER_BATCH, timeout: int = 120,
        client: Optional[IngestClient] = None,
        gate: Optional[DeliveryHealthGate] = None,
        reconcile_fn=None) -> Dict[str, Any]:
    db_path = os.path.join(state_dir, "outbox.db")
    if not os.path.exists(db_path):
        raise PhaseBRefusal(f"outbox database not found: {db_path}")
    if not collector_id:
        raise PhaseBRefusal("NIVX_COLLECTOR_ID is required.")
    if apply_changes and not token:
        raise PhaseBRefusal(
            "no reconciliation bearer token was supplied; without it the "
            "delivery could never be proven. Nothing was attempted.")

    uri = f"file:{db_path}?mode=ro" if not apply_changes else f"file:{db_path}"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        authority = load_authority(authority_path)
        pre = _snapshot(conn, db_path)
        plan = verify_preconditions(conn, authority, collector_id, pre,
                                    expect_total, expect_queued,
                                    expect_retrying)

        gate = gate or DeliveryHealthGate(
            store=_GateStore(conn, read_only=not apply_changes),
            destination_key=DESTINATION_KEY)
        gate_pre = gate.snapshot()
        allowed = gate.allow_delivery()
        if not allowed:
            raise PhaseBRefusal(
                f"the R3.1 delivery-health gate is {gate.state} and its "
                "cooldown has not elapsed. This recovery does not override an "
                "open gate. Nothing was attempted.")

        canary_ref = plan[0]["ref"]
        remainder = [entry["ref"] for entry in plan[1:]]
        batches = [remainder[i:i + remainder_batch]
                   for i in range(0, len(remainder), remainder_batch)]

        report: Dict[str, Any] = {
            "phase": f"{PHASE} · bounded recovery of the exact 28",
            "at": _now(),
            "mode": "APPLY" if apply_changes else "READINESS",
            "collector_id": collector_id,
            "authority_sha256": authority["authority_sha256"],
            "target_count": len(plan),
            "excluded_phase_a_count": len(authority["excluded"]),
            "canary_ref": canary_ref,
            "remainder_count": len(remainder),
            "remainder_batches": [len(b) for b in batches],
            "gate_pre": gate_pre,
            "gate_allowed_delivery": allowed,
            "plan": plan,
            "pre_snapshot": pre,
        }

        if not apply_changes:
            post = _snapshot(conn, db_path)
            checks = _non_mutation_checks(pre, post)
            checks["database_file_unchanged"] = {
                "holds": pre["database_sha256"] == post["database_sha256"],
                "sha256": post["database_sha256"]}
            checks["delivering_set_unchanged"] = {
                "holds": (pre["delivering_row_ids"]
                          == post["delivering_row_ids"]),
                "count": len(post["delivering_row_ids"])}
            checks["no_delivery_attempted"] = {
                "holds": True,
                "note": "readiness mode opens SQLite mode=ro and never calls "
                        "IngestClient.deliver"}
            checks["gate_state_not_mutated_in_readiness"] = {
                "holds": True,
                "store": "write-refusing",
                "persist_refusal": gate.state_load_error,
                "note": ("the readiness gate store raises on save, and the "
                         "connection is mode=ro, so the gate's memory of the "
                         "destination cannot be rewritten by a dry run")}
            report.update({
                "post_snapshot": post,
                "checks": checks,
                "delivered_nothing": True,
                "failed_checks": sorted(k for k, v in checks.items()
                                        if not v["holds"]),
            })
            report["pass"] = not report["failed_checks"]
            return report

        client = client or IngestClient()
        if not client.configured():
            raise PhaseBRefusal(
                "the ingest client is not configured on this endpoint, so a "
                "delivery attempt could only ever be recorded as a failure. "
                "Nothing was attempted.")
        # fail closed on the credential's syntax before the canary is spent
        report["ingest_credential"] = assert_ingest_credential(client)
        report["ingest_target"] = {"url": client.url,
                                   "auth_mode": client.auth_mode,
                                   "timeout": client.timeout}

        # ── canary: one identity, then PROVE it ──────────────────────
        report["canary_delivery"] = deliver_batch(
            client, conn, [canary_ref], collector_id, gate)
        canary_plan = [entry for entry in plan if entry["ref"] == canary_ref]
        canary_response = reconcile(canary_plan, base_url, token,
                                    collector_id, timeout, reconcile_fn)
        canary_rows = _disposition_map(canary_response, [canary_ref])
        canary_bucket = str(canary_rows[canary_ref].get("bucket"))
        report["canary_reconciliation"] = {
            "bucket": canary_bucket,
            "row": canary_rows[canary_ref],
            "proved_by": "authoritative reconciliation, not the HTTP status",
        }

        if canary_bucket not in ACCOUNTABLE:
            report["stopped_before_remainder"] = True
            report["remainder_delivered"] = 0
            report["post_snapshot"] = _snapshot(conn, db_path)
            report["checks"] = _non_mutation_checks(
                report["pre_snapshot"], report["post_snapshot"])
            report["pass"] = False
            if canary_bucket == RETRYABLE:
                raise PhaseBStop(
                    "the canary is still RETRYABLE_STILL_QUEUED after a "
                    "delivery attempt. That is a legitimate transient "
                    "outcome, so the remaining 27 were NOT sent and nothing "
                    "was accounted.", report)
            raise PhaseBStop(
                f"the canary reconciled as {canary_bucket}, which does not "
                "authorise continuation. The remaining 27 were NOT sent and "
                "nothing was accounted.", report)
        if not _accountable(canary_rows[canary_ref]):
            report["stopped_before_remainder"] = True
            report["pass"] = False
            raise PhaseBStop(
                f"the canary is bucketed {canary_bucket} but carries no "
                "resolvable evidence. The remaining 27 were NOT sent.",
                report)
        if not gate.allow_delivery():
            report["stopped_before_remainder"] = True
            report["pass"] = False
            raise PhaseBStop(
                f"the delivery-health gate closed ({gate.state}) after the "
                "canary. The remaining 27 were NOT sent.", report)

        # ── remainder, bounded ───────────────────────────────────────
        report["remainder_deliveries"] = [
            deliver_batch(client, conn, batch, collector_id, gate)
            for batch in batches]
        report["stopped_before_remainder"] = False

        # ── one authoritative reconciliation of all 28 ───────────────
        response = reconcile(plan, base_url, token, collector_id, timeout,
                             reconcile_fn)
        dispositions = _disposition_map(response,
                                        [e["ref"] for e in plan])
        equation = _equation(dispositions)
        report["reconciliation"] = {
            "tenant_scope": response.get("tenant_scope"),
            "buckets_server_reported": response.get("buckets"),
            "equation": equation,
            "sum": sum(equation.values()),
            "rows": [dispositions[e["ref"]] for e in plan],
        }
        if equation[UNEXPLAINED] != 0:
            raise PhaseBRefusal(
                f"{equation[UNEXPLAINED]} identities came back UNEXPLAINED. "
                "Nothing may disappear from accounting, so nothing was "
                "accounted and the run fails.")
        if sum(equation.values()) != len(plan):
            raise PhaseBRefusal(
                f"the identity equation sums to {sum(equation.values())}, "
                f"expected {len(plan)}.")

        repair = apply_accounting(conn, dispositions,
                                  authority["authority_sha256"])
        post = _snapshot(conn, db_path)
        checks = _non_mutation_checks(pre, post)
        expected_delivered_delta = equation[CANONICAL] + equation[RETAINED]
        checks["delivered_delta_exact"] = {
            "expected": expected_delivered_delta,
            "actual": (post["status_histogram"].get(DELIVERED, 0)
                       - pre["status_histogram"].get(DELIVERED, 0)),
            "holds": (post["status_histogram"].get(DELIVERED, 0)
                      - pre["status_histogram"].get(DELIVERED, 0)
                      == expected_delivered_delta)}
        checks["delivering_delta_exact"] = {
            "expected": -expected_delivered_delta,
            "actual": (post["status_histogram"].get(DELIVERING, 0)
                       - pre["status_histogram"].get(DELIVERING, 0)),
            "holds": (post["status_histogram"].get(DELIVERING, 0)
                      - pre["status_histogram"].get(DELIVERING, 0)
                      == -expected_delivered_delta)}
        checks["only_accountable_rows_changed"] = {
            "expected": expected_delivered_delta,
            "actual": len(repair["updated"]),
            "holds": len(repair["updated"]) == expected_delivered_delta}
        checks["retryable_rows_left_delivering"] = {
            "expected": equation[RETRYABLE] + equation[TERMINAL],
            "actual": len(repair["left_delivering"]),
            "holds": (len(repair["left_delivering"])
                      == equation[RETRYABLE] + equation[TERMINAL])}
        checks["unexplained_zero"] = {"actual": equation[UNEXPLAINED],
                                      "holds": equation[UNEXPLAINED] == 0}
        checks["identity_equation_sums_to_target"] = {
            "expected": len(plan), "actual": sum(equation.values()),
            "holds": sum(equation.values()) == len(plan)}

        report.update({
            "repair": repair,
            "gate_post": gate.snapshot(),
            "post_snapshot": post,
            "checks": checks,
            "failed_checks": sorted(k for k, v in checks.items()
                                    if not v["holds"]),
        })
        report["pass"] = not report["failed_checks"]
        report["honesty_note"] = (
            f"{len(repair['updated'])} of {len(plan)} identities are now "
            "durably evidenced and locally accounted. "
            f"{len(repair['left_delivering'])} remain legitimately "
            "unaccounted-for and are STILL `delivering` with their retry "
            "metadata untouched; they were not converted to delivered.")
        return report
    finally:
        conn.close()


def _write(evidence_dir: str, name: str, payload: Any) -> str:
    os.makedirs(evidence_dir, exist_ok=True)
    path = os.path.join(evidence_dir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="G1-R6 Phase B · bounded recovery of the exact 28")
    ap.add_argument("--state-dir", default=os.environ.get("XDR_STATE_DIR"))
    ap.add_argument("--authority", required=True,
                    help="r5-inflight-50-server-reconciliation.json")
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--expect-total", type=int, default=125452)
    ap.add_argument("--expect-queued", type=int, default=121993)
    ap.add_argument("--expect-retrying", type=int, default=125)
    ap.add_argument("--remainder-batch", type=int,
                    default=DEFAULT_REMAINDER_BATCH)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--apply", action="store_true",
                    help="deliver and account; omit for a read-only readiness "
                         "pass")
    args = ap.parse_args(argv)

    if not args.state_dir:
        print("ERROR: --state-dir or XDR_STATE_DIR is required")
        return 2

    try:
        report = run(state_dir=args.state_dir,
                     authority_path=args.authority,
                     base_url=args.base_url,
                     token=os.environ.get("NIVX_RECONCILE_TOKEN") or "",
                     collector_id=os.environ.get("NIVX_COLLECTOR_ID") or "",
                     apply_changes=args.apply,
                     expect_total=args.expect_total,
                     expect_queued=args.expect_queued,
                     expect_retrying=args.expect_retrying,
                     remainder_batch=args.remainder_batch,
                     timeout=args.timeout)
    except PhaseBStop as stop:
        _write(args.evidence_dir, "r6-phaseB-stopped.json",
               {"STOPPED": stop.reason, "report": stop.report})
        print(json.dumps({"pass": False, "stopped": stop.reason,
                          "remainder_sent": 0,
                          "evidence": os.path.join(args.evidence_dir,
                                                   "r6-phaseB-stopped.json")},
                         indent=2, default=str))
        return 3
    except PhaseBRefusal as refusal:
        print(f"HARD STOP: {refusal}")
        return 2

    name = ("r6-phaseB-final.json" if args.apply
            else "r6-phaseB-readiness.json")
    path = _write(args.evidence_dir, name, report)
    if args.apply:
        _write(args.evidence_dir, "r6-phaseB-delivery.json",
               {"canary": report.get("canary_delivery"),
                "canary_reconciliation": report.get("canary_reconciliation"),
                "remainder": report.get("remainder_deliveries"),
                "gate_pre": report.get("gate_pre"),
                "gate_post": report.get("gate_post")})
        _write(args.evidence_dir, "r6-phaseB-reconciliation.json",
               report.get("reconciliation"))

    summary = {
        "pass": report["pass"],
        "mode": report["mode"],
        "target_count": report["target_count"],
        "canary_ref": report["canary_ref"],
        "remainder_batches": report["remainder_batches"],
        "gate_state": (report.get("gate_post") or report["gate_pre"]).get(
            "state"),
        "failed_checks": report["failed_checks"],
        "evidence": path,
    }
    if args.apply:
        summary.update({
            "equation": report["reconciliation"]["equation"],
            "accounted_delivered": len(report["repair"]["updated"]),
            "left_delivering": len(report["repair"]["left_delivering"]),
            "post_histogram": report["post_snapshot"]["status_histogram"],
        })
    else:
        summary["pre_histogram"] = report["pre_snapshot"]["status_histogram"]
    print(json.dumps(summary, indent=2, default=str))
    return 0 if report["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
