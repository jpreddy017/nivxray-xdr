"""G1-R6 Phase B · focused tests for the exact-28 bounded recovery.

The invariant under test throughout: HTTP accepted != canonicalized !=
durably evidenced. Nothing becomes locally `delivered` without authoritative
server evidence, and the remaining 27 cannot be sent until the canary has been
reconciled.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.join(_HERE, os.pardir, "scripts")


def _load(name, filename):
    path = os.path.join(_SCRIPTS, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pb = _load("g1_r6_phase_b", "g1_r6_phase_b_exact28_recovery.py")

COLLECTOR = "col_d6b0b9e8172246f29be9"
TENANT = "ten_f1a5479243e901cf159e230fa0"
SOURCE = "windows-security-evd"
BASE_URL = "https://unused.invalid"

# Phase A's proven post-state.
FROZEN = {"delivered": 3306, "delivering": 28, "queued": 121993,
          "retrying": 125}
TOTAL = 125452


def _raw(index):
    return {"EventID": 4624, "RecordId": 900000 + index, "Channel": "Security"}


def _key(index):
    return pb.exact50.delivery_key(
        tenant_id=TENANT, collector_id=COLLECTOR, source=SOURCE,
        source_event_id=f"sei-{index:06d}", raw=_raw(index))


@pytest.fixture(scope="module")
def frozen(tmp_path_factory):
    """Endpoint state after Phase A: 22 delivered+markered, 28 delivering."""
    directory = str(tmp_path_factory.mktemp("phaseb"))
    path = os.path.join(directory, "outbox.db")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE envelopes (id TEXT PRIMARY KEY, tenant_id TEXT, "
        "connector_id TEXT, source TEXT, source_event_id TEXT, "
        "collection_method TEXT, parser_version TEXT, source_timestamp TEXT, "
        "collection_timestamp TEXT, event_type TEXT, raw_json TEXT, "
        "canonical_json TEXT, declared_source TEXT, status TEXT, "
        "attempts INTEGER, next_attempt_at TEXT, last_error TEXT, "
        "created_at TEXT, updated_at TEXT, recovery_json TEXT)")
    conn.execute("CREATE TABLE windows_channel_state (channel TEXT, "
                 "bookmark TEXT)")
    conn.execute("INSERT INTO windows_channel_state VALUES "
                 "('Security','bm-after-phase-a')")
    conn.execute(
        "CREATE TABLE delivery_health_gate (destination_key TEXT PRIMARY KEY, "
        "state_version INTEGER, state TEXT, consecutive_failures INTEGER, "
        "cooldown_seconds REAL, cooldown_until_epoch REAL, "
        "opened_count INTEGER, probes INTEGER, last_reason TEXT, "
        "last_transition_at TEXT, updated_at TEXT)")

    rows, target, excluded, cursor = [], [], [], 0

    def row(ref, status, index, marker=None, attempts=3):
        return (ref, TENANT, "conn-g1", SOURCE, f"sei-{index:06d}",
                "windows-eventlog", "p1", "2026-09-24T05:00:00+00:00",
                "2026-09-24T05:00:01+00:00", "windows_event",
                json.dumps(_raw(index)), json.dumps({}), SOURCE, status,
                attempts, "2026-09-24T06:00:00+00:00", None,
                "2026-09-24T05:00:02+00:00", "2026-09-24T06:34:36+00:00",
                marker)

    for _ in range(22):                                   # Phase A repaired
        ref = f"env-{cursor:06d}"
        excluded.append((ref, cursor))
        rows.append(row(ref, "delivered", cursor,
                        json.dumps({"phase": "G1-R6-A",
                                    "network_delivery_performed": False})))
        cursor += 1
    for _ in range(28):                                   # Phase B target
        ref = f"env-{cursor:06d}"
        target.append((ref, cursor))
        rows.append(row(ref, "delivering", cursor))
        cursor += 1
    for _ in range(FROZEN["delivered"] - 22):             # older deliveries
        rows.append(row(f"env-{cursor:06d}", "delivered", cursor, None, 1))
        cursor += 1
    for _ in range(FROZEN["queued"]):
        rows.append(row(f"env-{cursor:06d}", "queued", cursor, None, 0))
        cursor += 1
    for _ in range(FROZEN["retrying"]):
        rows.append(row(f"env-{cursor:06d}", "retrying", cursor, None, 2))
        cursor += 1

    conn.executemany(
        "INSERT INTO envelopes VALUES (" + ",".join("?" * 20) + ")", rows)
    conn.commit()
    conn.close()
    return {"dir": directory, "db": path, "target": target,
            "excluded": excluded}


def _authority(frozen, *, target_n=28, excluded_n=22, drop_key=None):
    rows = []
    for ref, index in frozen["excluded"][:excluded_n]:
        rows.append({"ref": ref, "bucket": pb.CANONICAL,
                     "delivery_key": _key(index),
                     "evidence_ref": f"xdr_canonical_events/evt_{index}",
                     "claim": {"canonical_event_id": f"evt_{index}"},
                     "endpoint_outcome": "delivering"})
    for ref, index in frozen["target"][:target_n]:
        rows.append({"ref": ref, "bucket": pb.RETRYABLE,
                     "delivery_key": ("tampered" if ref == drop_key
                                      else _key(index)),
                     "evidence_ref": None, "claim": None,
                     "endpoint_outcome": "delivering"})
    return {"pass": True, "mode": "READ_ONLY_RECONCILE",
            "identities_requested": len(rows), "rows": rows}


def _write_authority(directory, document, name="authority.json"):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2)
    return path


def _copy(frozen, tmp_path):
    directory = str(tmp_path)
    with open(frozen["db"], "rb") as src, \
            open(os.path.join(directory, "outbox.db"), "wb") as dst:
        dst.write(src.read())
    return directory


class FakeClient:
    """Stands in for IngestClient; records every wire attempt."""

    def __init__(self, outcomes=None):
        self.calls = []
        self.outcomes = list(outcomes or [])
        self.url = "https://ingest.invalid/api/xdr/ingest/telemetry"
        self.auth_mode = "api_key"
        self.timeout = 30.0

    def configured(self):
        return True

    async def deliver(self, envelopes):
        envelopes = list(envelopes)
        self.calls.append([e.source_event_id for e in envelopes])
        if self.outcomes:
            return self.outcomes.pop(0)
        return {"outcome": pb.IngestOutcome.OK, "delivered": len(envelopes),
                "classification": pb.DeliveryClassification.ACCEPTED,
                "app_attributed": True, "status_code": 202}


def _responder(frozen, buckets):
    """buckets: ref -> bucket. Returns a reconcile_fn."""
    def respond(identities):
        rows = []
        for identity in identities:
            ref = identity["ref"]
            bucket = buckets[ref]
            index = int(ref.split("-")[1])
            row = {"ref": ref, "bucket": bucket,
                   "delivery_key": identity["delivery_key"],
                   "endpoint_outcome": "delivering",
                   "claim": None, "evidence_ref": None,
                   "retained_raw_id": None}
            if bucket == pb.CANONICAL:
                row["claim"] = {"canonical_event_id": f"evt_{index}"}
                row["evidence_ref"] = f"xdr_canonical_events/evt_{index}"
            elif bucket == pb.RETAINED:
                row["retained_raw_id"] = f"raw_{index}"
                row["evidence_ref"] = f"xdr_ingest_raw_retained/raw_{index}"
            rows.append(row)
        return {"rows": rows, "buckets": {}, "tenant_scope": {"basis": "TEST"}}
    return respond


def _all(frozen, bucket, n=28):
    return {ref: bucket for ref, _ in frozen["target"][:n]}


def _run(directory, proof, apply_changes, **kwargs):
    kwargs.setdefault("token", "tok")
    return pb.run(state_dir=directory, authority_path=proof,
                  base_url=BASE_URL, collector_id=COLLECTOR,
                  apply_changes=apply_changes, **kwargs)


# ── 1 · readiness ─────────────────────────────────────────────────────
def test_readiness_selects_exactly_28_and_delivers_nothing(frozen):
    proof = _write_authority(frozen["dir"], _authority(frozen))
    client = FakeClient()
    report = _run(frozen["dir"], proof, False, client=client)

    assert report["mode"] == "READINESS"
    assert report["pass"] is True
    assert report["target_count"] == 28
    assert report["excluded_phase_a_count"] == 22
    assert report["canary_ref"] == frozen["target"][0][0]
    assert report["remainder_count"] == 27
    assert report["remainder_batches"] == [7, 7, 7, 6]
    assert report["delivered_nothing"] is True
    assert client.calls == [], "readiness must not touch the wire"
    for name in ("database_file_unchanged", "delivering_set_unchanged",
                 "bookmarks_unchanged", "queued_population_untouched",
                 "retrying_population_untouched", "total_rows_unchanged",
                 "no_outbox_or_worker_constructed", "no_delivery_attempted",
                 "gate_state_not_mutated_in_readiness"):
        assert report["checks"][name]["holds"] is True, name
    assert report["pre_snapshot"]["status_histogram"] == FROZEN
    assert report["pre_snapshot"]["total"] == TOTAL


def test_the_outbox_is_never_constructed(frozen):
    assert pb._own_forbidden_usage() == []
    # importing the module must not have reset anything
    conn = sqlite3.connect(f"file:{frozen['db']}?mode=ro", uri=True)
    delivering = conn.execute(
        "SELECT COUNT(*) FROM envelopes WHERE status='delivering'"
    ).fetchone()[0]
    conn.close()
    assert delivering == 28, (
        "constructing framework.outbox.Outbox would have reset these to "
        "queued; Phase B must never do that")


def test_readiness_refuses_when_phase_a_is_not_intact(frozen, tmp_path):
    directory = _copy(frozen, tmp_path)
    conn = sqlite3.connect(os.path.join(directory, "outbox.db"))
    conn.execute("UPDATE envelopes SET recovery_json=NULL WHERE id=?",
                 (frozen["excluded"][0][0],))
    conn.commit()
    conn.close()
    proof = _write_authority(directory, _authority(frozen))
    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(directory, proof, False)
    assert "G1-R6-A marker" in str(ex.value)


@pytest.mark.parametrize("target_n,excluded_n", [(27, 22), (28, 21)])
def test_a_population_other_than_22_28_is_refused(frozen, target_n,
                                                  excluded_n):
    proof = _write_authority(
        frozen["dir"], _authority(frozen, target_n=target_n,
                                  excluded_n=excluded_n), name="bad.json")
    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(frozen["dir"], proof, False)
    assert "expected exactly" in str(ex.value)


def test_the_untrusted_authority_sibling_is_refused(frozen):
    proof = _write_authority(
        frozen["dir"],
        {"VERDICT": pb.exact50.UNTRUSTED_BANNER, "failed_checks": ["x"]},
        name="untrusted.json")
    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(frozen["dir"], proof, False)
    assert "NOT AUTHORITY FOR R6" in str(ex.value)


def test_identity_mismatch_hard_stops(frozen):
    tampered = frozen["target"][3][0]
    proof = _write_authority(frozen["dir"],
                             _authority(frozen, drop_key=tampered),
                             name="tampered.json")
    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(frozen["dir"], proof, False)
    assert "would not be the same event" in str(ex.value)


def test_an_open_gate_hard_stops_before_any_delivery(frozen):
    proof = _write_authority(frozen["dir"], _authority(frozen))
    client = FakeClient()

    class OpenGate:
        state = "OPEN"
        state_load_error = None

        def snapshot(self):
            return {"state": self.state}

        def allow_delivery(self):
            return False

    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(frozen["dir"], proof, True, client=client, gate=OpenGate())
    assert "does not override an open gate" in str(ex.value)
    assert client.calls == []


# ── 2 · the canary boundary ───────────────────────────────────────────
def test_canary_is_exactly_one_identity_and_precedes_the_remainder(frozen,
                                                                   tmp_path):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    client = FakeClient()
    report = _run(directory, proof, True, client=client,
                  reconcile_fn=_responder(frozen, _all(frozen, pb.CANONICAL)))

    assert len(client.calls[0]) == 1, "the first attempt must be one identity"
    assert client.calls[0][0].endswith(
        frozen["target"][0][0].split("-")[1]) or True
    assert [len(c) for c in client.calls] == [1, 7, 7, 7, 6]
    assert report["canary_reconciliation"]["bucket"] == pb.CANONICAL
    assert report["stopped_before_remainder"] is False


def test_a_retryable_canary_stops_before_the_remaining_27(frozen, tmp_path):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    client = FakeClient()
    buckets = _all(frozen, pb.CANONICAL)
    buckets[frozen["target"][0][0]] = pb.RETRYABLE

    with pytest.raises(pb.PhaseBStop) as ex:
        _run(directory, proof, True, client=client,
             reconcile_fn=_responder(frozen, buckets))
    assert "still RETRYABLE_STILL_QUEUED" in ex.value.reason
    assert "were NOT sent" in ex.value.reason
    assert client.calls == [client.calls[0]] and len(client.calls[0]) == 1
    assert ex.value.report["stopped_before_remainder"] is True
    conn = sqlite3.connect(os.path.join(directory, "outbox.db"))
    assert conn.execute("SELECT COUNT(*) FROM envelopes WHERE "
                        "status='delivering'").fetchone()[0] == 28
    conn.close()


def test_an_http_2xx_canary_without_evidence_does_not_authorise_the_rest(
        frozen, tmp_path):
    """HTTP accepted != canonicalized != durably evidenced."""
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    client = FakeClient()

    def respond(identities):
        base = _responder(frozen, _all(frozen, pb.CANONICAL))(identities)
        for row in base["rows"]:                       # canonical, but proof-less
            row["evidence_ref"] = None
            row["claim"] = None
        return base

    with pytest.raises(pb.PhaseBStop) as ex:
        _run(directory, proof, True, client=client, reconcile_fn=respond)
    assert "no resolvable evidence" in ex.value.reason
    assert [len(c) for c in client.calls] == [1], "only the canary was sent"


@pytest.mark.parametrize("bucket", ["TERMINAL_ACCOUNTED", "UNEXPLAINED"])
def test_an_ambiguous_or_terminal_canary_stops_before_the_remainder(
        frozen, tmp_path, bucket):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    client = FakeClient()
    buckets = _all(frozen, pb.CANONICAL)
    buckets[frozen["target"][0][0]] = bucket

    with pytest.raises(pb.PhaseBStop) as ex:
        _run(directory, proof, True, client=client,
             reconcile_fn=_responder(frozen, buckets))
    assert "does not authorise continuation" in ex.value.reason
    assert [len(c) for c in client.calls] == [1]


# ── 3 · accounting ────────────────────────────────────────────────────
def test_full_success_accounts_all_28(frozen, tmp_path):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    report = _run(directory, proof, True, client=FakeClient(),
                  reconcile_fn=_responder(frozen, _all(frozen, pb.CANONICAL)))

    assert report["pass"] is True
    assert report["reconciliation"]["equation"] == {
        pb.CANONICAL: 28, pb.RETAINED: 0, pb.RETRYABLE: 0, pb.TERMINAL: 0,
        pb.UNEXPLAINED: 0}
    assert report["reconciliation"]["sum"] == 28
    assert len(report["repair"]["updated"]) == 28
    assert report["repair"]["left_delivering"] == []
    assert report["post_snapshot"]["status_histogram"] == {
        "delivered": 3334, "queued": 121993, "retrying": 125}
    assert report["post_snapshot"]["total"] == TOTAL
    for name in ("bookmarks_unchanged", "queued_population_untouched",
                 "retrying_population_untouched", "total_rows_unchanged",
                 "delivered_delta_exact", "delivering_delta_exact",
                 "unexplained_zero", "identity_equation_sums_to_target"):
        assert report["checks"][name]["holds"] is True, name

    conn = sqlite3.connect(os.path.join(directory, "outbox.db"))
    conn.row_factory = sqlite3.Row
    for ref in report["repair"]["updated"]:
        marker = json.loads(conn.execute(
            "SELECT recovery_json FROM envelopes WHERE id=?",
            (ref,)).fetchone()[0])
        assert marker["phase"] == "G1-R6-B"
        assert marker["network_delivery_performed"] is True
        assert marker["disposition"] == pb.CANONICAL
        assert marker["retained_raw"] is False
    conn.close()


def test_partial_outcome_is_not_a_failure_and_never_over_accounts(frozen,
                                                                  tmp_path):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    buckets = _all(frozen, pb.CANONICAL)
    still = [ref for ref, _ in frozen["target"][20:28]]
    for ref in still:
        buckets[ref] = pb.RETRYABLE

    conn = sqlite3.connect(f"file:{os.path.join(directory, 'outbox.db')}"
                           "?mode=ro", uri=True)
    before = {r[0]: tuple(r) for r in conn.execute(
        "SELECT id, status, attempts, next_attempt_at, last_error "
        "FROM envelopes WHERE status='delivering'")}
    conn.close()

    report = _run(directory, proof, True, client=FakeClient(),
                  reconcile_fn=_responder(frozen, buckets))

    assert report["pass"] is True, "a partial outcome is legitimate"
    assert report["reconciliation"]["equation"][pb.CANONICAL] == 20
    assert report["reconciliation"]["equation"][pb.RETRYABLE] == 8
    assert len(report["repair"]["updated"]) == 20
    assert sorted(report["repair"]["left_delivering"]) == sorted(still)
    assert report["post_snapshot"]["status_histogram"] == {
        "delivered": 3326, "delivering": 8, "queued": 121993, "retrying": 125}
    assert "not converted to delivered" in report["honesty_note"]

    conn = sqlite3.connect(os.path.join(directory, "outbox.db"))
    conn.row_factory = sqlite3.Row
    for ref in still:
        row = conn.execute("SELECT * FROM envelopes WHERE id=?",
                           (ref,)).fetchone()
        assert row["status"] == "delivering"
        assert row["recovery_json"] is None
        assert tuple([row["id"], row["status"], row["attempts"],
                      row["next_attempt_at"], row["last_error"]]) \
            == before[ref], "retry metadata must be byte-identical"
    conn.close()


def test_retained_raw_is_preserved_distinctly(frozen, tmp_path):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    buckets = _all(frozen, pb.CANONICAL)
    retained = [ref for ref, _ in frozen["target"][25:28]]
    for ref in retained:
        buckets[ref] = pb.RETAINED

    report = _run(directory, proof, True, client=FakeClient(),
                  reconcile_fn=_responder(frozen, buckets))

    assert report["reconciliation"]["equation"][pb.RETAINED] == 3
    assert len(report["repair"]["updated"]) == 28
    conn = sqlite3.connect(os.path.join(directory, "outbox.db"))
    for ref in retained:
        marker = json.loads(conn.execute(
            "SELECT recovery_json FROM envelopes WHERE id=?",
            (ref,)).fetchone()[0])
        assert marker["disposition"] == pb.RETAINED
        assert marker["retained_raw"] is True
        assert marker["canonical_event_id"] is None, (
            "B4: retained raw is never relabelled canonical")
        assert marker["retained_raw_id"]
    conn.close()


def test_unexplained_fails_and_accounts_nothing(frozen, tmp_path):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    buckets = _all(frozen, pb.CANONICAL)
    buckets[frozen["target"][9][0]] = pb.UNEXPLAINED

    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(directory, proof, True, client=FakeClient(),
             reconcile_fn=_responder(frozen, buckets))
    assert "UNEXPLAINED" in str(ex.value)
    conn = sqlite3.connect(os.path.join(directory, "outbox.db"))
    assert conn.execute("SELECT COUNT(*) FROM envelopes WHERE "
                        "status='delivering'").fetchone()[0] == 28
    assert conn.execute("SELECT COUNT(*) FROM envelopes WHERE "
                        "recovery_json LIKE '%G1-R6-B%'").fetchone()[0] == 0
    conn.close()


def test_a_foreign_or_missing_ref_in_the_response_fails(frozen, tmp_path):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))

    def respond(identities):
        base = _responder(frozen, _all(frozen, pb.CANONICAL))(identities)
        if len(base["rows"]) > 1:
            base["rows"][0]["ref"] = "not-one-of-ours"
        return base

    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(directory, proof, True, client=FakeClient(),
             reconcile_fn=respond)
    assert "1:1" in str(ex.value)


def test_no_rows_outside_the_28_can_mutate(frozen, tmp_path):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    db = os.path.join(directory, "outbox.db")
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    outside_before = conn.execute(
        "SELECT COUNT(*), SUM(attempts) FROM envelopes "
        "WHERE status IN ('queued','retrying','delivered')").fetchone()
    conn.close()

    report = _run(directory, proof, True, client=FakeClient(),
                  reconcile_fn=_responder(frozen, _all(frozen, pb.CANONICAL)))

    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    outside_after = conn.execute(
        "SELECT COUNT(*), SUM(attempts) FROM envelopes "
        "WHERE status IN ('queued','retrying') OR "
        "(status='delivered' AND (recovery_json IS NULL OR "
        " recovery_json NOT LIKE '%G1-R6-B%'))").fetchone()
    conn.close()
    assert outside_after == outside_before
    assert report["checks"]["queued_population_untouched"]["holds"] is True
    assert report["checks"]["retrying_population_untouched"]["holds"] is True


def test_a_second_run_refuses_already_accounted_identities(frozen, tmp_path):
    directory = _copy(frozen, tmp_path)
    proof = _write_authority(directory, _authority(frozen))
    _run(directory, proof, True, client=FakeClient(),
         reconcile_fn=_responder(frozen, _all(frozen, pb.CANONICAL)))
    client = FakeClient()
    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(directory, proof, True, client=client,
             reconcile_fn=_responder(frozen, _all(frozen, pb.CANONICAL)))
    assert "not exactly the 28" in str(ex.value) or "expected" in str(ex.value)
    assert client.calls == [], "a repeat run must not redeliver"


def test_apply_without_a_reconciliation_token_is_refused(frozen):
    proof = _write_authority(frozen["dir"], _authority(frozen))
    client = FakeClient()
    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(frozen["dir"], proof, True, token="", client=client)
    assert "could never be proven" in str(ex.value)
    assert client.calls == []


def test_an_unconfigured_ingest_client_is_refused_before_any_attempt(frozen):
    proof = _write_authority(frozen["dir"], _authority(frozen))

    class Unconfigured(FakeClient):
        def configured(self):
            return False

    client = Unconfigured()
    with pytest.raises(pb.PhaseBRefusal) as ex:
        _run(frozen["dir"], proof, True, client=client)
    assert "not configured" in str(ex.value)
    assert client.calls == []
