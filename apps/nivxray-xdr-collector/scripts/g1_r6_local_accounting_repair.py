#!/usr/bin/env python3
"""G1-R6 Phase A · local accounting repair for rows the SERVER already holds.

R5 proved, at identity level, that of the 50 rows the interrupted worker left
in `delivering`:

    22  are DELIVERED_CANONICAL server-side   → the endpoint's accounting is
                                                 stale, the delivery is not
    28  are RETRYABLE_STILL_QUEUED server-side → genuinely not delivered

This script repairs ONLY the first group, and only as local bookkeeping:
`delivering → delivered`. It performs NO network I/O at all — there is no
ingest client, no HTTP, no destination. Redelivering an event the
authoritative plane already accounted for is exactly the duplicate work the
idempotency claim exists to prevent, and it would put real traffic on a
production endpoint to fix a local counter.

It deliberately does NOT construct the `Outbox`, because doing so would run
R3.1 restart recovery and reset the 28 genuinely-undelivered rows to `queued`
as a side effect. Those 28 are a separate, owner-authorised decision; this
script must not pre-empt it. It therefore opens SQLite directly and touches
only the rows it was authorised to touch.

Authority: every repaired row must be justified by the R5 server
reconciliation record — `bucket=DELIVERED_CANONICAL` with a resolvable
`evidence_ref` and `canonical_event_id`. A row is also refused unless its
locally recomputed delivery identity equals the identity the server answered
about, so a stale or mismatched proof file can never mark the wrong row
delivered.

Dry run by default. `--apply` is the only mutating path, it is transactional,
and it verifies the population before and after.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DELIVERING = "delivering"
DELIVERED = "delivered"
CANONICAL = "DELIVERED_CANONICAL"
RETRYABLE = "RETRYABLE_STILL_QUEUED"

_IDENTITY_SEPARATOR = "\x1f"
_NO_SOURCE_EVENT_ID = "__no_source_event_id__"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def payload_digest(raw: Any) -> str:
    return hashlib.sha256(
        json.dumps(raw if raw is not None else {}, sort_keys=True,
                   default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def delivery_key(*, tenant_id: str, collector_id: str, source: Optional[str],
                 source_event_id: Optional[str], raw: Any) -> str:
    material = _IDENTITY_SEPARATOR.join([
        str(tenant_id or ""), str(collector_id or ""), str(source or ""),
        str(source_event_id if source_event_id else _NO_SOURCE_EVENT_ID),
        payload_digest(raw),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _histogram(conn: sqlite3.Connection) -> Dict[str, int]:
    return {r[0]: int(r[1]) for r in conn.execute(
        "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}


def _bookmark_fingerprint(conn: sqlite3.Connection) -> Optional[str]:
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if "windows_channel_state" not in tables:
        return None
    h = hashlib.sha256()
    for row in conn.execute("SELECT * FROM windows_channel_state "
                            "ORDER BY rowid"):
        h.update(("|".join("" if v is None else str(v)
                           for v in tuple(row))).encode("utf-8"))
    return h.hexdigest()


def _own_delivery_imports() -> List[str]:
    """Any delivery/acquisition surface THIS script imports. Must be empty."""
    import re
    try:
        with open(os.path.abspath(__file__), encoding="utf-8") as fh:
            source = fh.read()
    except OSError:                                          # pragma: no cover
        return []
    found = []
    for line in source.splitlines():
        stripped = line.strip()
        if not re.match(r"^(import|from)\s", stripped):
            continue
        if re.search(r"\b(httpx|requests|framework\.(outbox|delivery|"
                     r"delivery_worker|windows_eventlog|runtime))\b",
                     stripped):
            found.append(stripped)
    return found


def _fingerprint(conn: sqlite3.Connection, refs: List[str]) -> Optional[str]:
    """Bookkeeping fingerprint of specific rows: status + retry budget."""
    if not refs:
        return None
    h = hashlib.sha256()
    for ref in sorted(refs):
        row = conn.execute(
            "SELECT id, status, attempts, next_attempt_at, last_error "
            "  FROM envelopes WHERE id=?", (ref,)).fetchone()
        h.update(("|".join("" if v is None else str(v)
                           for v in (tuple(row) if row else ("MISSING",))
                           )).encode("utf-8"))
    return h.hexdigest()


def _snapshot(conn: sqlite3.Connection, db_path: str,
              canonical_refs: Optional[List[str]] = None,
              retryable_refs: Optional[List[str]] = None) -> Dict[str, Any]:
    hist = _histogram(conn)
    digest = hashlib.sha256()
    with open(db_path, "rb") as fh:
        # The endpoint database holds 125,452 rows: hash it in chunks rather
        # than reading it into memory.
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    db_sha = digest.hexdigest()
    return {
        "at": _now(),
        "status_histogram": hist,
        "total": int(conn.execute(
            "SELECT COUNT(*) FROM envelopes").fetchone()[0]),
        "bookmarks_sha256": _bookmark_fingerprint(conn),
        "database_sha256": db_sha,
        "delivering_row_ids": sorted(
            r[0] for r in conn.execute(
                "SELECT id FROM envelopes WHERE status=?", (DELIVERING,))),
        "canonical_rows_fingerprint": _fingerprint(conn, canonical_refs or []),
        "retryable_rows_fingerprint": _fingerprint(conn, retryable_refs or []),
    }


def load_proof(path: str) -> Dict[str, List[Dict[str, Any]]]:
    """Split the R5 reconciliation record into the two authoritative groups."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    rows = doc.get("rows") if isinstance(doc, dict) else doc
    if not isinstance(rows, list) or not rows:
        raise SystemExit(f"no reconciliation rows found in {path}")
    inflight = [r for r in rows
                if str(r.get("endpoint_outcome") or "") == DELIVERING]
    return {
        "all": rows,
        "inflight": inflight,
        "canonical": [r for r in inflight if r.get("bucket") == CANONICAL],
        "retryable": [r for r in inflight if r.get("bucket") == RETRYABLE],
        "other": [r for r in inflight
                  if r.get("bucket") not in (CANONICAL, RETRYABLE)],
    }


def _row_checks(row: sqlite3.Row, proof: Dict[str, Any],
                collector_id: str) -> List[str]:
    """Every reason this row may NOT be repaired. Empty list = eligible."""
    refusals: List[str] = []
    if row["status"] != DELIVERING:
        refusals.append(
            f"local status is {row['status']!r}, expected {DELIVERING!r}")
    claim = proof.get("claim") or {}
    if not proof.get("evidence_ref"):
        refusals.append("server proof has no resolvable evidence_ref")
    if not claim.get("canonical_event_id"):
        refusals.append("server proof has no canonical_event_id")
    local_key = delivery_key(
        tenant_id=row["tenant_id"], collector_id=collector_id,
        source=row["source"], source_event_id=row["source_event_id"],
        raw=json.loads(row["raw_json"] or "{}"))
    proof_key = proof.get("delivery_key")
    if proof_key and local_key != proof_key:
        refusals.append("delivery identity mismatch: the server answered "
                        "about a different delivery than this local row")
    if not proof_key:
        refusals.append("server proof carries no delivery_key to bind to")
    return refusals


def plan(conn: sqlite3.Connection, proof: Dict[str, List[Dict[str, Any]]],
         collector_id: str) -> Dict[str, Any]:
    eligible, refused = [], []
    for row_proof in proof["canonical"]:
        ref = row_proof.get("ref")
        row = conn.execute("SELECT * FROM envelopes WHERE id=?",
                           (ref,)).fetchone()
        if row is None:
            refused.append({"ref": ref, "reasons": ["no such local row"]})
            continue
        reasons = _row_checks(row, row_proof, collector_id)
        entry = {
            "ref": ref,
            "source_event_id": row["source_event_id"],
            "local_status": row["status"],
            "attempts": row["attempts"],
            "canonical_event_id": (row_proof.get("claim") or {}).get(
                "canonical_event_id"),
            "evidence_ref": row_proof.get("evidence_ref"),
            "matched_by": row_proof.get("matched_by"),
        }
        if reasons:
            refused.append({**entry, "reasons": reasons})
        else:
            eligible.append(entry)
    return {"eligible": eligible, "refused": refused,
            "retryable_untouched": [
                {"ref": r.get("ref"),
                 "source_event_id": r.get("source_event_id"),
                 "bucket": r.get("bucket")} for r in proof["retryable"]]}


def apply_repair(conn: sqlite3.Connection, eligible: List[Dict[str, Any]],
                 repair_id: str, evidence_path: str,
                 allow_schema_add: bool) -> Dict[str, Any]:
    cols = {c[1] for c in conn.execute("PRAGMA table_info(envelopes)")}
    marker_column = "recovery_json" in cols
    if not marker_column:
        if not allow_schema_add:
            raise SystemExit(
                "the envelopes table has no recovery_json column, so the "
                "repair could not be recorded on the row itself. Re-run with "
                "--allow-schema-add to add the column (additive, as R4 did), "
                "or repair with an auditable marker elsewhere. Nothing was "
                "changed.")
        conn.execute("ALTER TABLE envelopes ADD COLUMN recovery_json TEXT")
        marker_column = True

    marker = json.dumps({
        "repair_id": repair_id,
        "phase": "G1-R6-A",
        "action": "local_accounting_repair",
        "from_status": DELIVERING,
        "to_status": DELIVERED,
        "basis": ("R5 identity-level server reconciliation returned "
                  "DELIVERED_CANONICAL for this exact delivery identity"),
        "network_delivery_performed": False,
        "evidence": os.path.basename(evidence_path),
        "at": _now(),
    }, separators=(",", ":"))

    updated, now = [], _now()
    try:
        conn.execute("BEGIN IMMEDIATE")
        for entry in eligible:
            cur = conn.execute(
                "UPDATE envelopes "
                "   SET status=?, last_error=NULL, updated_at=?, "
                "       recovery_json=? "
                " WHERE id=? AND status=?",
                (DELIVERED, now, marker, entry["ref"], DELIVERING))
            if cur.rowcount != 1:
                raise sqlite3.IntegrityError(
                    f"row {entry['ref']} was not in {DELIVERING!r} at update "
                    "time; the whole repair is rolled back")
            updated.append(entry["ref"])
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"repair_id": repair_id, "updated": updated,
            "marker_column": "recovery_json"}


def run(*, state_dir: str, proof_path: str, expect_canonical: int,
        expect_retryable: int, collector_id: str, apply_changes: bool,
        allow_schema_add: bool = False,
        expect_total: int = 0) -> Dict[str, Any]:
    db_path = os.path.join(state_dir, "outbox.db")
    if not os.path.exists(db_path):
        raise SystemExit(f"outbox database not found: {db_path}")
    if not collector_id:
        raise SystemExit(
            "NIVX_COLLECTOR_ID is required: the delivery identity that binds "
            "the server proof to a local row is derived from it.")

    proof = load_proof(proof_path)
    counts = {"inflight": len(proof["inflight"]),
              "canonical": len(proof["canonical"]),
              "retryable": len(proof["retryable"]),
              "other": len(proof["other"])}
    if counts["canonical"] != expect_canonical:
        raise SystemExit(
            f"the proof holds {counts['canonical']} canonical in-flight rows, "
            f"expected exactly {expect_canonical}. Nothing was changed.")
    if counts["retryable"] != expect_retryable:
        raise SystemExit(
            f"the proof holds {counts['retryable']} retryable in-flight rows, "
            f"expected exactly {expect_retryable}. Nothing was changed.")
    if counts["other"]:
        raise SystemExit(
            f"{counts['other']} in-flight rows are in neither authoritative "
            "group. Nothing was changed.")

    mode = "" if apply_changes else "?mode=ro"
    conn = sqlite3.connect(f"file:{db_path}{mode}", uri=True)
    conn.row_factory = sqlite3.Row
    canonical_refs = [r.get("ref") for r in proof["canonical"]]
    retryable_refs = [r.get("ref") for r in proof["retryable"]]
    try:
        pre = _snapshot(conn, db_path, canonical_refs, retryable_refs)
        the_plan = plan(conn, proof, collector_id)
        if the_plan["refused"]:
            raise SystemExit(
                f"{len(the_plan['refused'])} of the {expect_canonical} rows "
                "failed their eligibility checks: "
                f"{json.dumps(the_plan['refused'][:5], default=str)} . "
                "Nothing was changed.")
        if len(the_plan["eligible"]) != expect_canonical:
            raise SystemExit(
                f"{len(the_plan['eligible'])} eligible rows, expected "
                f"{expect_canonical}. Nothing was changed.")

        repair = None
        if apply_changes:
            repair = apply_repair(conn, the_plan["eligible"],
                                  f"r6a_{uuid.uuid4().hex[:16]}", proof_path,
                                  allow_schema_add)
        post = _snapshot(conn, db_path, canonical_refs, retryable_refs)
    finally:
        conn.close()

    delivered_delta = (post["status_histogram"].get(DELIVERED, 0)
                       - pre["status_histogram"].get(DELIVERED, 0))
    delivering_delta = (post["status_histogram"].get(DELIVERING, 0)
                        - pre["status_histogram"].get(DELIVERING, 0))
    expected_delivered_delta = expect_canonical if apply_changes else 0

    invariants = {
        "total_rows_unchanged": {
            "pre": pre["total"], "post": post["total"],
            "holds": pre["total"] == post["total"]},
        "bookmarks_unchanged": {
            "sha256": post["bookmarks_sha256"],
            "holds": pre["bookmarks_sha256"] == post["bookmarks_sha256"]},
        "delivered_delta_exact": {
            "expected": expected_delivered_delta, "actual": delivered_delta,
            "holds": delivered_delta == expected_delivered_delta},
        "delivering_delta_exact": {
            "expected": -expected_delivered_delta,
            "actual": delivering_delta,
            "holds": delivering_delta == -expected_delivered_delta},
        "retryable_left_untouched": {
            "count": expect_retryable,
            "delivering_remaining": post["status_histogram"].get(
                DELIVERING, 0),
            "holds": (post["status_histogram"].get(DELIVERING, 0)
                      == expect_retryable if apply_changes
                      else post["status_histogram"].get(DELIVERING, 0)
                      == expect_canonical + expect_retryable)},
        "no_other_status_changed": {
            "holds": all(
                post["status_histogram"].get(s, 0)
                == pre["status_histogram"].get(s, 0)
                for s in set(pre["status_histogram"]) |
                set(post["status_histogram"])
                if s not in (DELIVERED, DELIVERING))},
        "no_network_delivery": {
            "holds": True,
            "note": ("this script imports no ingest client and opens no "
                     "socket; the repair is local bookkeeping only")},
        "no_delivery_surface_loaded": {
            "imports_declared_by_this_script": _own_delivery_imports(),
            "modules_loaded_in_this_process": sorted(
                m for m in sys.modules
                if m in ("httpx", "requests")
                or m.startswith(("framework.outbox", "framework.delivery",
                                 "framework.windows_eventlog"))),
            "holds": not _own_delivery_imports(),
            "note": ("the attestation is the SCRIPT's own imports: it never "
                     "imports an ingest client, a delivery worker or the "
                     "Outbox, so R3.1 restart recovery cannot run and cannot "
                     "requeue the retryable rows as a side effect. Modules "
                     "loaded by an embedding process (a test session) are "
                     "reported but are not this script's surface.")},
        "database_file_unchanged": {
            "pre": pre["database_sha256"], "post": post["database_sha256"],
            "holds": (pre["database_sha256"] == post["database_sha256"]
                      if not apply_changes else True),
            "note": ("a dry run opens the database read-only, so its bytes "
                     "must be identical; an apply legitimately changes them")},
        "retryable_rows_untouched_exactly": {
            "fingerprint": post["retryable_rows_fingerprint"],
            "holds": (pre["retryable_rows_fingerprint"]
                      == post["retryable_rows_fingerprint"]),
            "note": ("status + attempts + next_attempt_at + last_error of the "
                     "retryable rows, unchanged in BOTH modes")},
        "canonical_rows_untouched_in_dry_run": {
            "holds": (pre["canonical_rows_fingerprint"]
                      == post["canonical_rows_fingerprint"]
                      if not apply_changes else True)},
        "delivering_set_matches_the_proof": {
            "delivering_rows": len(post["delivering_row_ids"]),
            "holds": (set(pre["delivering_row_ids"])
                      == set(canonical_refs) | set(retryable_refs))},
        "expected_total_rows": {
            "expected": expect_total or None, "actual": post["total"],
            "holds": (post["total"] == expect_total if expect_total
                      else True)},
    }

    return {
        "phase": "G1-R6 Phase A · local accounting repair",
        "mode": "APPLY" if apply_changes else "DRY_RUN",
        "at": _now(),
        "proof_file": proof_path,
        "proof_counts": counts,
        "collector_id": collector_id,
        "planned": the_plan["eligible"],
        "refused": the_plan["refused"],
        "retryable_untouched": the_plan["retryable_untouched"],
        "repair": repair,
        "pre_snapshot": pre,
        "post_snapshot": post,
        "invariants": invariants,
        "pass": all(v["holds"] for v in invariants.values()),
        "honesty_note": (
            "The 28 retryable rows were NOT repaired and NOT redelivered. "
            "They are still in `delivering` and remain a separate, bounded "
            "owner decision."),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="G1-R6 Phase A local accounting repair (dry run default)")
    ap.add_argument("--state-dir", default=os.environ.get("XDR_STATE_DIR"))
    ap.add_argument("--proof", required=True,
                    help="r5-server-reconciliation.json from the R5 proof")
    ap.add_argument("--evidence-dir", default=None)
    ap.add_argument("--expect-canonical", type=int, default=22)
    ap.add_argument("--expect-retryable", type=int, default=28)
    ap.add_argument("--apply", action="store_true",
                    help="perform the local status repair (transactional)")
    ap.add_argument("--allow-schema-add", action="store_true")
    ap.add_argument("--expect-total", type=int, default=0,
                    help="refuse unless the outbox holds exactly this many "
                         "rows (e.g. 125452)")
    args = ap.parse_args(argv)

    if not args.state_dir:
        print("ERROR: --state-dir or XDR_STATE_DIR is required")
        return 2
    report = run(state_dir=args.state_dir, proof_path=args.proof,
                 expect_canonical=args.expect_canonical,
                 expect_retryable=args.expect_retryable,
                 collector_id=os.environ.get("NIVX_COLLECTOR_ID") or "",
                 apply_changes=args.apply,
                 allow_schema_add=args.allow_schema_add,
                 expect_total=args.expect_total)

    evidence_dir = args.evidence_dir or os.path.join(args.state_dir,
                                                     "g1_r6_evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    name = ("r6-phaseA-apply.json" if args.apply else "r6-phaseA-dryrun.json")
    path = os.path.join(evidence_dir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    print(json.dumps({
        "mode": report["mode"],
        "proof_counts": report["proof_counts"],
        "planned": len(report["planned"]),
        "refused": len(report["refused"]),
        "repaired": len((report["repair"] or {}).get("updated", [])),
        "retryable_untouched": len(report["retryable_untouched"]),
        "pre_histogram": report["pre_snapshot"]["status_histogram"],
        "post_histogram": report["post_snapshot"]["status_histogram"],
        "total_rows_unchanged": report["invariants"][
            "total_rows_unchanged"]["holds"],
        "bookmarks_unchanged": report["invariants"][
            "bookmarks_unchanged"]["holds"],
        "database_file_unchanged": report["invariants"][
            "database_file_unchanged"]["holds"],
        "retryable_rows_untouched": report["invariants"][
            "retryable_rows_untouched_exactly"]["holds"],
        "delivering_set_matches_proof": report["invariants"][
            "delivering_set_matches_the_proof"]["holds"],
        "no_delivery_surface_loaded": report["invariants"][
            "no_delivery_surface_loaded"]["holds"],
        "pass": report["pass"],
        "evidence": path,
    }, indent=2, default=str))
    return 0 if report["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
