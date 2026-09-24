#!/usr/bin/env python3
"""G1-R5 evidence recovery · reconcile the EXACT 50 in-flight identities.

The successful 450-row reconciliation proved, in aggregate, that 422 of the
450 already-touched rows are DELIVERED_CANONICAL and 28 are
RETRYABLE_STILL_QUEUED — but `r5-server-reconciliation.json` was never
persisted, so the PER-ROW split of the 50 locally-`delivering` rows
(22 canonical / 28 retryable) does not exist on disk. R6 Phase A cannot repair
individual rows from aggregate counts: it needs to know WHICH 22.

This tool recovers exactly that missing evidence and nothing else.

    · SQLite is opened strictly read-only (`mode=ro`).
    · It never imports the Outbox, the DeliveryWorker or an ingest client, so
      R3.1 restart recovery cannot run and cannot requeue the 28 as a side
      effect. No acquisition, no delivery, no redelivery, no requeue.
    · It issues exactly ONE reconciliation request, containing exactly the 50
      supplied identities. There is no negative control: an auxiliary request
      already destroyed this evidence once.
    · The authoritative output file is written ONLY if every assertion passes.
      If a server response was received but an assertion failed, the complete
      raw response is persisted beside it, clearly marked FAILED / UNTRUSTED —
      NOT AUTHORITY FOR R6. Pre-request failures write nothing at all.

The bearer token is read from the environment and is never echoed or persisted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DELIVERING = "delivering"
CANONICAL = "DELIVERED_CANONICAL"
RETRYABLE = "RETRYABLE_STILL_QUEUED"
RETAINED = "DELIVERED_RETAINED_RAW"
TERMINAL = "TERMINAL_ACCOUNTED"
UNEXPLAINED = "UNEXPLAINED"

_IDENTITY_SEPARATOR = "\x1f"
_NO_SOURCE_EVENT_ID = "__no_source_event_id__"

RECONCILE_PATH = "/api/xdr/ingest/routing/reconcile"
FAILED_SUFFIX = ".FAILED-UNTRUSTED.json"
UNTRUSTED_BANNER = ("FAILED / UNTRUSTED FORENSIC EVIDENCE — NOT AUTHORITY "
                    "FOR R6. One or more required assertions did not hold.")


class PreRequestRefusal(Exception):
    """Refused before any reconciliation request was issued."""


class PostResponseFailure(Exception):
    """A response WAS received but an assertion failed; persist it untrusted."""

    def __init__(self, reasons: List[str], response: Any,
                 report: Dict[str, Any]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons
        self.response = response
        self.report = report


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


def _own_delivery_imports() -> List[str]:
    """Any delivery/acquisition surface THIS script imports. Must be empty."""
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


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(conn: sqlite3.Connection, db_path: str) -> Dict[str, Any]:
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
    }


def load_refs(path: str) -> List[str]:
    """The exact in-flight population, however the evidence file shaped it."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    entries = doc
    if isinstance(doc, dict):
        for key in ("identities", "rows", "refs", "ids"):
            if isinstance(doc.get(key), list):
                entries = doc[key]
                break
    if not isinstance(entries, list) or not entries:
        raise PreRequestRefusal(
            f"no in-flight identities found in {path}. Nothing was requested.")
    refs: List[str] = []
    for entry in entries:
        if isinstance(entry, str):
            refs.append(entry)
            continue
        if not isinstance(entry, dict):
            raise PreRequestRefusal(
                f"unrecognised identity entry of type {type(entry).__name__} "
                f"in {path}. Nothing was requested.")
        ref = entry.get("ref") or entry.get("id") or entry.get("envelope_id")
        if not ref:
            raise PreRequestRefusal(
                f"an identity entry in {path} carries no ref. Nothing was "
                "requested.")
        refs.append(str(ref))
    if len(set(refs)) != len(refs):
        raise PreRequestRefusal(
            f"{len(refs) - len(set(refs))} duplicate refs in {path}. "
            "Nothing was requested.")
    return refs


def build_identities(conn: sqlite3.Connection, refs: List[str],
                     collector_id: str) -> List[Dict[str, Any]]:
    """Recompute each delivery identity read-only from the local row itself."""
    identities = []
    for ref in refs:
        row = conn.execute("SELECT * FROM envelopes WHERE id=?",
                           (ref,)).fetchone()
        if row is None:
            raise PreRequestRefusal(
                f"ref {ref} is not in the local outbox. The supplied "
                "population does not describe this endpoint. Nothing was "
                "requested.")
        if row["status"] != DELIVERING:
            raise PreRequestRefusal(
                f"ref {ref} is locally {row['status']!r}, expected "
                f"{DELIVERING!r}. The supplied population is stale. Nothing "
                "was requested.")
        raw = json.loads(row["raw_json"] or "{}")
        identities.append({
            "ref": str(row["id"]),
            "delivery_key": delivery_key(
                tenant_id=row["tenant_id"], collector_id=collector_id,
                source=row["source"], source_event_id=row["source_event_id"],
                raw=raw),
            "source_event_id": row["source_event_id"],
            "collector_id": collector_id,
            "connector_id": row["connector_id"],
            "payload_digest": payload_digest(raw),
            "endpoint_outcome": DELIVERING,
        })
    return identities


def post_reconcile(base_url: str, token: str, identities: List[Dict[str, Any]],
                   timeout: int) -> Dict[str, Any]:
    body = json.dumps({"identities": identities}).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + RECONCILE_PATH, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as ex:
        detail = ex.read().decode("utf-8", "replace")[:600]
        raise PreRequestRefusal(
            f"the reconciliation surface answered HTTP {ex.code}: {detail} . "
            "No evidence was written.") from ex
    except urllib.error.URLError as ex:
        raise PreRequestRefusal(
            f"the reconciliation surface was unreachable: {ex.reason} . "
            "No evidence was written.") from ex


def _assert_population(pre: Dict[str, Any], refs: List[str],
                       expect_count: int,
                       expect_histogram: Dict[str, int],
                       expect_total: int) -> None:
    if len(refs) != expect_count:
        raise PreRequestRefusal(
            f"the supplied population holds {len(refs)} identities, expected "
            f"exactly {expect_count}. This recovery neither widens nor "
            "narrows it. Nothing was requested.")
    local = set(pre["delivering_row_ids"])
    if local != set(refs):
        raise PreRequestRefusal(
            f"the local {DELIVERING!r} set does not equal the supplied "
            f"population: {len(local - set(refs))} local rows are not in the "
            f"file, {len(set(refs) - local)} file rows are not locally "
            f"{DELIVERING!r}. Nothing was requested.")
    if expect_total and pre["total"] != expect_total:
        raise PreRequestRefusal(
            f"the outbox holds {pre['total']} rows, expected {expect_total}. "
            "The endpoint is not in the frozen state this recovery was "
            "written for. Nothing was requested.")
    drift = {status: {"expected": count,
                      "actual": pre["status_histogram"].get(status, 0)}
             for status, count in expect_histogram.items()
             if pre["status_histogram"].get(status, 0) != count}
    if drift:
        raise PreRequestRefusal(
            f"pre-state histogram drift: {json.dumps(drift)}. Nothing was "
            "requested.")


def _verify_response(response: Dict[str, Any], refs: List[str],
                     expect_canonical: int,
                     expect_retryable: int) -> Dict[str, Any]:
    rows = response.get("rows")
    rows = rows if isinstance(rows, list) else []
    returned = [str(r.get("ref")) for r in rows]
    requested, seen = set(refs), set(returned)
    buckets: Dict[str, int] = {}
    for row in rows:
        bucket = str(row.get("bucket") or "UNRECOGNISED_BUCKET")
        buckets[bucket] = buckets.get(bucket, 0) + 1
    per_ref = {str(r.get("ref")): str(r.get("bucket") or "") for r in rows}
    checks = {
        "rows_returned_exactly": {
            "expected": len(refs), "actual": len(rows),
            "holds": len(rows) == len(refs)},
        "refs_one_to_one": {
            "missing": sorted(requested - seen),
            "foreign": sorted(seen - requested),
            "duplicates": sorted({r for r in returned
                                  if returned.count(r) > 1}),
            "holds": (requested == seen
                      and len(returned) == len(seen) == len(refs))},
        "canonical_exactly": {
            "expected": expect_canonical,
            "actual": buckets.get(CANONICAL, 0),
            "holds": buckets.get(CANONICAL, 0) == expect_canonical},
        "retryable_exactly": {
            "expected": expect_retryable,
            "actual": buckets.get(RETRYABLE, 0),
            "holds": buckets.get(RETRYABLE, 0) == expect_retryable},
        "retained_raw_zero": {
            "actual": buckets.get(RETAINED, 0),
            "holds": buckets.get(RETAINED, 0) == 0},
        "terminal_zero": {
            "actual": buckets.get(TERMINAL, 0),
            "holds": buckets.get(TERMINAL, 0) == 0},
        "unexplained_zero": {
            "actual": buckets.get(UNEXPLAINED, 0),
            "holds": buckets.get(UNEXPLAINED, 0) == 0},
        "no_unrecognised_bucket": {
            "actual": sorted(b for b in buckets
                             if b not in (CANONICAL, RETRYABLE, RETAINED,
                                          TERMINAL, UNEXPLAINED)),
            "holds": all(b in (CANONICAL, RETRYABLE, RETAINED, TERMINAL,
                               UNEXPLAINED) for b in buckets)},
        "server_totals_agree_with_local_recount": {
            "server": response.get("buckets"), "local": buckets,
            "holds": all(
                int((response.get("buckets") or {}).get(bucket, 0))
                == buckets.get(bucket, 0)
                for bucket in (CANONICAL, RETRYABLE, RETAINED, TERMINAL,
                               UNEXPLAINED))},
    }
    return {"checks": checks, "buckets_local_recount": buckets,
            "per_ref_bucket": per_ref,
            "canonical_refs": sorted(r for r, b in per_ref.items()
                                     if b == CANONICAL),
            "retryable_refs": sorted(r for r, b in per_ref.items()
                                     if b == RETRYABLE)}


def _non_mutation_checks(pre: Dict[str, Any],
                         post: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "database_file_unchanged": {
            "pre": pre["database_sha256"], "post": post["database_sha256"],
            "holds": pre["database_sha256"] == post["database_sha256"]},
        "status_histogram_unchanged": {
            "pre": pre["status_histogram"], "post": post["status_histogram"],
            "holds": pre["status_histogram"] == post["status_histogram"]},
        "total_rows_unchanged": {
            "pre": pre["total"], "post": post["total"],
            "holds": pre["total"] == post["total"]},
        "bookmarks_unchanged": {
            "sha256": post["bookmarks_sha256"],
            "holds": pre["bookmarks_sha256"] == post["bookmarks_sha256"]},
        "delivering_set_unchanged": {
            "count": len(post["delivering_row_ids"]),
            "holds": (pre["delivering_row_ids"]
                      == post["delivering_row_ids"])},
        "no_delivery_surface_loaded": {
            "imports_declared_by_this_script": _own_delivery_imports(),
            "modules_loaded_in_this_process": sorted(
                m for m in sys.modules
                if m in ("httpx", "requests")
                or m.startswith(("framework.outbox", "framework.delivery",
                                 "framework.windows_eventlog"))),
            "holds": not _own_delivery_imports(),
            "note": ("no Outbox, DeliveryWorker or ingest client is imported, "
                     "so R3.1 restart recovery cannot run and the retryable "
                     "rows cannot be requeued as a side effect")},
    }


def run(*, state_dir: str, refs: List[str], base_url: str, token: str,
        collector_id: str, expect_count: int = 50,
        expect_canonical: int = 22, expect_retryable: int = 28,
        expect_histogram: Optional[Dict[str, int]] = None,
        expect_total: int = 0, timeout: int = 120,
        transport=None) -> Dict[str, Any]:
    db_path = os.path.join(state_dir, "outbox.db")
    if not os.path.exists(db_path):
        raise PreRequestRefusal(f"outbox database not found: {db_path}")
    if not collector_id:
        raise PreRequestRefusal(
            "NIVX_COLLECTOR_ID is required: the delivery identity the server "
            "answers about is derived from it. Nothing was requested.")
    if not token:
        raise PreRequestRefusal(
            "no bearer token was supplied. Nothing was requested.")

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        pre = _snapshot(conn, db_path)
        _assert_population(pre, refs, expect_count,
                           expect_histogram or {}, expect_total)
        identities = build_identities(conn, refs, collector_id)
        send = transport or (lambda payload: post_reconcile(
            base_url, token, payload, timeout))
        response = send(identities)
        post = _snapshot(conn, db_path)
    finally:
        conn.close()

    verification = _verify_response(response, refs, expect_canonical,
                                   expect_retryable)
    checks = {**verification["checks"], **_non_mutation_checks(pre, post)}
    failed = sorted(name for name, check in checks.items()
                    if not check["holds"])
    report = {
        "phase": "G1-R5 evidence recovery · exact-50 in-flight reconciliation",
        "at": _now(),
        "mode": "READ_ONLY_RECONCILE",
        "collector_id": collector_id,
        "identities_requested": len(identities),
        "reconciliation_requests_issued": 1,
        "negative_control_issued": False,
        "delivered_nothing": True,
        "recovery_performed": False,
        "tenant_scope": response.get("tenant_scope"),
        "buckets_server_reported": response.get("buckets"),
        "buckets_local_recount": verification["buckets_local_recount"],
        "canonical_refs": verification["canonical_refs"],
        "retryable_refs": verification["retryable_refs"],
        "per_ref_bucket": verification["per_ref_bucket"],
        "pre_snapshot": pre,
        "post_snapshot": post,
        "checks": checks,
        "failed_checks": failed,
        "pass": not failed,
        "honesty_note": (
            "Read-only. Nothing was delivered, redelivered, requeued or "
            "recovered; the 50 rows are still in `delivering`. This file is "
            "the per-row authority R6 Phase A consumes."),
    }
    if failed:
        raise PostResponseFailure(failed, response, report)
    report["rows"] = response.get("rows")
    return report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="G1-R5 exact-50 in-flight reconciliation (read-only)")
    ap.add_argument("--state-dir", default=os.environ.get("XDR_STATE_DIR"))
    ap.add_argument("--identities", required=True,
                    help="r5-inflight-identities-*.json (exactly 50 refs)")
    ap.add_argument("--out", required=True,
                    help="authoritative output, written ONLY on full PASS")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--expect-count", type=int, default=50)
    ap.add_argument("--expect-canonical", type=int, default=22)
    ap.add_argument("--expect-retryable", type=int, default=28)
    ap.add_argument("--expect-total", type=int, default=0)
    ap.add_argument("--expect-histogram", default="",
                    help="status=count,... e.g. delivered=3284,delivering=50")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args(argv)

    if not args.state_dir:
        print("ERROR: --state-dir or XDR_STATE_DIR is required")
        return 2
    if os.path.exists(args.out):
        print(f"HARD STOP: {args.out} already exists. This recovery refuses "
              "to overwrite existing authoritative evidence. Nothing was "
              "requested.")
        return 2

    histogram = {}
    for part in [p for p in args.expect_histogram.split(",") if p.strip()]:
        status, _, count = part.partition("=")
        histogram[status.strip()] = int(count)

    failed_path = args.out + FAILED_SUFFIX
    try:
        refs = load_refs(args.identities)
        report = run(state_dir=args.state_dir, refs=refs,
                     base_url=args.base_url,
                     token=os.environ.get("NIVX_RECONCILE_TOKEN") or "",
                     collector_id=os.environ.get("NIVX_COLLECTOR_ID") or "",
                     expect_count=args.expect_count,
                     expect_canonical=args.expect_canonical,
                     expect_retryable=args.expect_retryable,
                     expect_histogram=histogram,
                     expect_total=args.expect_total,
                     timeout=args.timeout)
    except PreRequestRefusal as ex:
        print(f"HARD STOP (pre-request): {ex}")
        return 2
    except PostResponseFailure as ex:
        os.makedirs(os.path.dirname(os.path.abspath(failed_path)) or ".",
                    exist_ok=True)
        with open(failed_path, "w", encoding="utf-8") as fh:
            json.dump({"VERDICT": UNTRUSTED_BANNER,
                       "failed_checks": ex.reasons,
                       "report": ex.report,
                       "raw_server_response": ex.response},
                      fh, indent=2, default=str)
        print(json.dumps({
            "pass": False,
            "verdict": UNTRUSTED_BANNER,
            "failed_checks": ex.reasons,
            "authoritative_evidence_written": False,
            "untrusted_evidence": failed_path,
        }, indent=2, default=str))
        return 2

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".",
                exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    print(json.dumps({
        "pass": True,
        "identities_requested": report["identities_requested"],
        "buckets": report["buckets_local_recount"],
        "canonical_refs": len(report["canonical_refs"]),
        "retryable_refs": len(report["retryable_refs"]),
        "pre_histogram": report["pre_snapshot"]["status_histogram"],
        "post_histogram": report["post_snapshot"]["status_histogram"],
        "database_file_unchanged": report["checks"][
            "database_file_unchanged"]["holds"],
        "bookmarks_unchanged": report["checks"]["bookmarks_unchanged"]["holds"],
        "delivering_set_unchanged": report["checks"][
            "delivering_set_unchanged"]["holds"],
        "no_delivery_surface_loaded": report["checks"][
            "no_delivery_surface_loaded"]["holds"],
        "authoritative_evidence": args.out,
    }, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
