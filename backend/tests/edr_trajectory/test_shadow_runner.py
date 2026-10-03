"""The Behavior shadow runner, end to end on SYNTHETIC evidence only.

This is the first suite in which `SequenceEngine` actually executes. Every byte
of evidence is hermetic: an in-memory §d collection, in-memory checkpoint, run
and detection stores. No production Mongo, no real endpoint, no KUSHU, no
DESKTOP, no sensor, no Fabric Finding, no evaluation ledger, no index or
collection creation, no deploy.

The invariant under test: the checkpoint is the LAST durable operation for an
item, and it never acknowledges work that is not already durable.
"""
from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from edr_behavior import engine as eng_mod
from edr_behavior.contracts import MODE_SHADOW
from edr_behavior.replay import InMemoryCheckpointStore
from edr_behavior.rules import RuleRegistry, parse_rule
from edr_behavior.suppression import SuppressionEntry, SuppressionPolicy
from edr_plane import behavior_shadow_frontier as fr
from edr_plane import behavior_shadow_run as rr
from edr_plane import behavior_shadow_runner as run
from edr_plane.behavior_sd_provider import SdEvidenceProvider
from edr_plane.behavior_shadow_detection_store import (
    WRITE_CREATED, WRITE_DUPLICATE, InMemoryShadowDetectionBackend)
from edr_plane.behavior_shadow_runner import (ShadowBudgets,
                                              ShadowRunnerRefused, run_shadow,
                                              ruleset_digest)

from test_sd_behavior_provider import DEV, EP, T, T_B, doc, ts
from test_sd_production_adapter import FakeCollection

BY = "operator@nivxray.com"
T0 = datetime(2026, 10, 3, 4, 0, 0, tzinfo=timezone.utc)
INIT_END = T0 + timedelta(minutes=5)
RUN_END = T0 + timedelta(hours=2)

STAGE_EVIL = {"id": "s1", "type": "DETECTION",
              "predicate": {"field": "detection.rule_id", "op": "eq",
                            "value": "sig_evil"}}
STAGE_SECOND = {"id": "s2", "type": "DETECTION",
                "predicate": {"field": "detection.rule_id", "op": "eq",
                              "value": "sig_second"}}
STAGE_UNKNOWABLE = {"id": "s2", "type": "DETECTION",
                    "predicate": {"field": "detection.absent_field",
                                  "op": "eq", "value": "z"}}
#: A complete match whose declared evidence requirement is not collected ->
#: INSUFFICIENT_EVIDENCE (matcher `_requirements`), never NO_MATCH.
REQUIRES_ABSENT = ["process.sha256"]

#: Canonical predicates of the shape the shipped rules actually use. None of
#: these could resolve before the Step-31 namespace reconciliation.
STAGE_PROC_NAME = {"id": "s1", "type": "PROCESS",
                   "predicate": {"field": "process.name", "op": "eq",
                                 "value": "p30.exe"}}
STAGE_CMDLINE = {"id": "s1", "type": "COMMAND",
                 "predicate": {"field": "process.command_line",
                               "op": "contains", "value": "p30 run"}}
STAGE_REGISTRY = {"id": "s1", "type": "REGISTRY",
                  "predicate": {"field": "registry.key", "op": "contains",
                                "value": "CurrentVersion\\Run"}}


def rule_doc(stages, *, rule_id="shadow_demo", version=1):
    if stages and stages[0] is STAGE_PROC_NAME and rule_id == "shadow_demo":
        rule_id = "shadow_proc"
    return {"rule_id": rule_id, "version": version, "name": "shadow demo",
            "description": "hermetic shadow rule", "lifecycle": "ACTIVE",
            "severity": "HIGH", "confidence": 60, "time_window_seconds": 300,
            "entity_scope": "device", "ordered": True, "stages": stages}


def registry_of(*docs):
    reg = RuleRegistry()
    for d in docs:
        reg.register(parse_rule(d))
    return reg


def detection_row(minute, pid, *, rule_id="sig_evil", tenant=T,
                  activity="DETECTION", with_user=True):
    """A §d DETECTION observation, carrying an acting user by default.

    Before Step 31 a row with a user crashed `detection.build` (GAP-10): the
    adapter emitted a FLAT `user` string where the canonical contract requires
    `user: {"name": ...}`. It is kept here deliberately so the regression stays
    covered.
    """
    d = doc(ts(minute), pid, tenant=tenant, activity=activity)
    if not with_user:
        d["event"]["process"].pop("user", None)
    d["event"]["detection"] = {"rule_id": rule_id, "source": "RULE",
                               "name": "Evil", "severity": "HIGH"}
    return d


def process_row(minute, pid, *, tenant=T):
    """A plain §d PROCESS_START observation — the evidence shape a real endpoint
    produces constantly, and the one no predicate could address before Step 31.
    """
    return doc(ts(minute), pid, tenant=tenant, activity="PROCESS")


def db_of(*docs):
    return {"v2_shadow_observations": FakeCollection(list(docs)),
            "xdr_canonical_evidence": FakeCollection([])}


async def frontier(db, cps, h, *, tenant=T, endpoint=EP, end=INIT_END):
    return await fr.initialize(
        SdEvidenceProvider(db, tenant_id=tenant, endpoint_id=endpoint,
                           refs=[DEV, EP]), cps, tenant_id=tenant,
        endpoint_id=endpoint, ruleset_id="rs_core", ruleset_version=3,
        ruleset_content_hash=h, window_start=T0, window_end=end,
        initialized_by=BY)


class Bench:
    """One hermetic shadow environment."""

    def __init__(self, *rules_docs):
        self.registry = registry_of(*(rules_docs or (rule_doc([STAGE_EVIL]),)))
        self.hash = ruleset_digest(self.registry.live_rules())
        self.cps = InMemoryCheckpointStore()
        self.runs = rr.InMemoryShadowRunStore()
        self.backend = InMemoryShadowDetectionBackend()

    async def go(self, db, *, tenant=T, endpoint=EP, run_id="shadow_run_1",
                 h=None, budgets=None, suppression=None, refs=(DEV, EP),
                 window_end=RUN_END, single_writer=True, init=True,
                 init_end=INIT_END, reason="SYNTHETIC_VALIDATION"):
        if init:
            await frontier(db, self.cps, h or self.hash, tenant=tenant,
                           endpoint=endpoint, end=init_end)
        return await run_shadow(
            db=db, tenant_id=tenant, endpoint_id=endpoint, refs=list(refs),
            registry=self.registry, ruleset_id="rs_core", ruleset_version=3,
            ruleset_content_hash=h or self.hash, checkpoint_store=self.cps,
            run_store=self.runs, detection_backend=self.backend,
            shadow_run_id=run_id, invoked_by=BY, reason=reason,
            window_start=T0, window_end=window_end,
            single_writer=single_writer, budgets=budgets,
            suppression=suppression)

    def checkpoint(self, *, tenant=T, endpoint=EP, h=None):
        return self.cps._d.get((tenant, fr.stream_id(h or self.hash),
                                endpoint))


# ── entry guards ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_single_writer_must_be_declared_explicitly():
    b = Bench()
    with pytest.raises(ShadowRunnerRefused) as e:
        await b.go(db_of(detection_row(1, 1)), single_writer=False)
    assert e.value.reason == run.REFUSED_NOT_SINGLE_WRITER


@pytest.mark.asyncio
async def test_uninitialized_frontier_is_refused_and_never_created():
    b = Bench()
    with pytest.raises(fr.ShadowFrontierRefused) as e:
        await b.go(db_of(detection_row(1, 1)), init=False)
    assert e.value.reason == fr.REFUSED_NOT_INITIALIZED
    assert b.checkpoint() is None
    assert b.runs.all() == []


@pytest.mark.asyncio
async def test_no_evidence_frontier_is_refused():
    b = Bench()
    with pytest.raises(ShadowRunnerRefused) as e:
        await b.go(db_of())                      # nothing to initialize from
    assert e.value.reason == run.REFUSED_NO_EVIDENCE_FRONTIER
    assert b.runs.all() == []


@pytest.mark.asyncio
async def test_declared_ruleset_hash_must_match_the_evaluated_rules():
    b = Bench()
    with pytest.raises(ShadowRunnerRefused) as e:
        await b.go(db_of(detection_row(1, 1)), h="rs_" + "0" * 32)
    assert e.value.reason == run.REFUSED_RULESET_DIGEST


@pytest.mark.asyncio
async def test_a_frontier_from_another_ruleset_stream_is_not_usable():
    b = Bench()
    db = db_of(detection_row(1, 1))
    await frontier(db, b.cps, "rs_" + "9" * 32)   # a different stream
    with pytest.raises(fr.ShadowFrontierRefused):
        await b.go(db, init=False)


@pytest.mark.asyncio
async def test_a_frontier_for_another_endpoint_is_not_usable():
    b = Bench()
    db = db_of(detection_row(1, 1))
    await frontier(db, b.cps, b.hash, endpoint=EP)
    with pytest.raises(fr.ShadowFrontierRefused):
        await b.go(db, endpoint="ep_other", init=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("end", [T0, T0 + timedelta(seconds=300),
                                 T0 + timedelta(days=2)])
async def test_window_bounds_are_enforced(end):
    b = Bench()
    with pytest.raises(ShadowRunnerRefused):
        await b.go(db_of(detection_row(1, 1)), window_end=end)


@pytest.mark.asyncio
async def test_an_already_started_run_blocks_a_second_invocation():
    b = Bench()
    db = db_of(detection_row(1, 1))
    await frontier(db, b.cps, b.hash)
    await rr.create(b.runs, tenant_id=T, shadow_run_id="stuck",
                    endpoint_id=EP, ruleset_id="rs_core", ruleset_version=3,
                    ruleset_content_hash=b.hash,
                    replay_id=fr.stream_id(b.hash), invoked_by=BY,
                    reason="MANUAL")
    with pytest.raises(ShadowRunnerRefused) as e:
        await b.go(db, init=False)
    assert e.value.reason == run.REFUSED_OVERLAPPING_RUN


@pytest.mark.asyncio
async def test_no_live_rules_is_refused():
    reg = RuleRegistry()
    reg.register(parse_rule({**rule_doc([STAGE_EVIL]), "lifecycle": "DRAFT"}))
    b = Bench()
    b.registry = reg
    with pytest.raises(ShadowRunnerRefused) as e:
        await b.go(db_of(detection_row(1, 1)), h=ruleset_digest([]))
    assert e.value.reason == run.REFUSED_NO_RULES


# ── the engine actually runs: MATCH ──────────────────────────────────────

@pytest.mark.asyncio
async def test_match_persists_a_verified_shadow_detection_then_advances():
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(30, 30))
    out = await b.go(db)
    assert out["state"] == rr.STATE_COMPLETED
    assert out["items_processed"] == 1
    assert out["engine_metrics"]["counters"]["events_evaluated"] == 1
    assert out["engine_metrics"]["counters"]["matches"] == 1
    docs = b.backend.all()
    assert len(docs) == 1
    d = docs[0]
    assert d["shadow"] is True and d["analyst_visible"] is False
    assert d["detection_source_claim"] == "NONE"
    assert d["status"] == "SHADOW_ONLY"
    assert d["provenance"]["mode"] == MODE_SHADOW
    assert out["detection_writes"][0]["outcome"] == WRITE_CREATED
    assert out["detection_writes"][0]["verified"] is True
    cp = b.checkpoint()
    assert cp["after_key"] == d["evidence_keys"][0]
    rec = out["record"]
    assert rec["state"] == rr.STATE_COMPLETED
    assert rec["counters"]["matches"] == 1
    assert rec["outcome_counts"]["MATCH"] == 1
    assert rr.zero_targets_held(rec) is True


@pytest.mark.asyncio
async def test_completed_carries_no_clean_or_benign_meaning():
    b = Bench()
    out = await b.go(db_of(detection_row(1, 1)))
    assert out["state"] == rr.STATE_COMPLETED
    assert out["record"]["completed_meaning"] == rr.COMPLETED_MEANING
    assert out["record"]["detection_source_claim"] == "NONE"


@pytest.mark.asyncio
async def test_gap10_canonical_namespace_restored_a_row_with_a_user_evaluates():
    """GAP-10 regression (Step 31).

    A §d row carrying `process.user` used to crash `detection.build` because the
    adapter emitted a flat `user` string. It now resolves through the canonical
    `user.name` path and the item completes normally.
    """
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(30, 30, with_user=True))
    out = await b.go(db)
    assert out["state"] == rr.STATE_COMPLETED
    assert out["record"]["counters"]["engine_failures"] == 0
    assert out["record"]["outcome_counts"]["MATCH"] == 1
    d = b.backend.all()[0]
    assert d["involved_entities"]["user"] == ["KUSHU\\jp"]
    assert b.checkpoint()["after_key"] == d["evidence_keys"][0]


@pytest.mark.asyncio
async def test_a_process_rule_now_matches_a_plain_process_observation():
    """The evaluation that was structurally impossible before Step 31: a shipped
    rule shape (`process.name` + `process.command_line`) against an ordinary §d
    PROCESS_START row."""
    b = Bench(rule_doc([STAGE_PROC_NAME]))
    db = db_of(process_row(1, 1), process_row(30, 30))
    out = await b.go(db)
    assert out["state"] == rr.STATE_COMPLETED
    assert out["record"]["outcome_counts"]["MATCH"] == 1
    assert out["record"]["counters"]["engine_failures"] == 0
    d = b.backend.all()[0]
    assert d["rule_id"] == "shadow_proc"
    assert "p30.exe" in d["explanation"]
    assert b.checkpoint()["after_key"] == d["evidence_keys"][0]


@pytest.mark.asyncio
async def test_a_command_line_predicate_resolves_canonically():
    b = Bench(rule_doc([STAGE_CMDLINE], rule_id="shadow_cmd"))
    out = await b.go(db_of(process_row(1, 1), process_row(30, 30)))
    assert out["state"] == rr.STATE_COMPLETED
    assert out["record"]["outcome_counts"]["MATCH"] == 1


@pytest.mark.asyncio
async def test_a_predicate_on_a_domain_sd_does_not_carry_is_unknown_not_false():
    """§d carries no registry data, so a registry predicate must yield
    INSUFFICIENT_EVIDENCE — never a NO_MATCH that would read as 'we checked'."""
    b = Bench(rule_doc([STAGE_REGISTRY], rule_id="shadow_reg"))
    out = await b.go(db_of(process_row(1, 1),
                           doc(ts(30), 30, activity="REGISTRY")))
    assert out["state"] == rr.STATE_INTERRUPTED
    assert out["failure_reason"] == run.STOP_INSUFFICIENT
    assert out["record"]["outcome_counts"]["NO_MATCH"] == 0
    assert out["record"]["outcome_counts"]["INSUFFICIENT_EVIDENCE"] == 1
    assert b.backend.all() == []


# ── NO_MATCH ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_match_advances_without_writing_a_detection():
    b = Bench(rule_doc([STAGE_EVIL, STAGE_SECOND]))
    db = db_of(detection_row(1, 1), detection_row(30, 30),
               detection_row(31, 31, rule_id="sig_other"))
    out = await b.go(db)
    assert out["state"] == rr.STATE_COMPLETED
    assert out["record"]["outcome_counts"]["NO_MATCH"] >= 1
    assert out["record"]["outcome_counts"]["MATCH"] == 0
    assert b.backend.all() == []
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:31")


# ── SUPPRESSED ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_suppressed_persists_and_advances_but_is_not_a_match():
    policy = SuppressionPolicy((SuppressionEntry(
        entry_id="sup_1", tenant_id=T, reason="hermetic test",
        predicate={"field": "detection.rule_id", "op": "eq",
                   "value": "sig_evil"}, created_by=BY),))
    b = Bench()
    out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)),
                     suppression=policy)
    assert out["state"] == rr.STATE_COMPLETED
    assert out["record"]["outcome_counts"]["SUPPRESSED"] == 1
    assert out["record"]["outcome_counts"]["MATCH"] == 0
    assert out["record"]["counters"]["matches"] == 0
    docs = b.backend.all()
    assert len(docs) == 1
    assert docs[0]["suppression"]["kind"] == "TENANT_SUPPRESSION"
    assert docs[0]["status"] == "SHADOW_ONLY"
    assert docs[0]["analyst_visible"] is False
    assert b.checkpoint()["after_key"] == docs[0]["evidence_keys"][0]


# ── INSUFFICIENT_EVIDENCE ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_insufficient_evidence_never_becomes_no_match_and_holds_the_frontier():
    b = Bench({**rule_doc([STAGE_EVIL]),
               "evidence_requirements": REQUIRES_ABSENT})
    db = db_of(detection_row(1, 1), detection_row(30, 30))
    await frontier(db, b.cps, b.hash)
    before = b.checkpoint()["after_key"]
    out = await b.go(db, init=False)
    assert out["state"] == rr.STATE_INTERRUPTED
    assert out["failure_reason"] == run.STOP_INSUFFICIENT
    assert out["record"]["outcome_counts"]["INSUFFICIENT_EVIDENCE"] == 1
    assert out["record"]["outcome_counts"]["NO_MATCH"] == 0
    assert b.checkpoint()["after_key"] == before        # frontier held
    assert out["record"]["resume_after_key"] == before
    assert b.backend.all() == []


# ── BUDGET_EXCEEDED / truncation ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_window_truncation_never_becomes_no_match_and_holds_the_frontier():
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(30, 30),
               detection_row(31, 31, rule_id="sig_other"))
    out = await b.go(db, budgets=ShadowBudgets(max_window_events=1))
    assert out["state"] == rr.STATE_TRUNCATED
    assert out["failure_reason"] in (run.STOP_BUDGET,
                                     run.STOP_WINDOW_TRUNCATED)
    assert out["record"]["window_truncated"] is True
    assert out["record"]["outcome_counts"]["NO_MATCH"] == 0
    assert out["record"]["resume_after_key"]
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:01")
    assert b.backend.all() == []


@pytest.mark.asyncio
async def test_trigger_row_budget_truncates_with_a_resume_cursor():
    b = Bench()
    rows = [detection_row(1, 1)] + [detection_row(10 + i, 100 + i)
                                    for i in range(4)]
    out = await b.go(db_of(*rows), budgets=ShadowBudgets(max_trigger_rows=2))
    assert out["state"] == rr.STATE_TRUNCATED
    assert out["failure_reason"] == run.STOP_ROWS
    assert out["items_processed"] == 2
    assert out["record"]["resume_after_key"] == b.checkpoint()["after_key"]


@pytest.mark.asyncio
async def test_sd_page_budget_stops_the_run_rather_than_broadening():
    b = Bench()
    rows = [detection_row(1, 1)] + [detection_row(10 + i, 100 + i)
                                    for i in range(3)]
    out = await b.go(db_of(*rows), budgets=ShadowBudgets(max_sd_pages=2))
    assert out["state"] == rr.STATE_TRUNCATED
    assert out["failure_reason"] == run.STOP_SD_PAGES
    assert out["provider"]["counters"]["sd_pages_read"] <= 3


# ── adapter refusal (E8) ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_any_adapter_refusal_refuses_the_page_before_the_engine_runs():
    b = Bench()
    db = db_of(detection_row(1, 1),
               doc(ts(30), 30, activity="SOMETHING_UNMAPPED"))
    out = await b.go(db)
    assert out["state"] == rr.STATE_INTERRUPTED
    assert out["failure_reason"] == run.STOP_ADAPTER_REFUSAL
    assert out["engine_metrics"]["counters"]["events_evaluated"] == 0
    assert out["items_processed"] == 0
    assert out["detection_writes"] == []
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:01")
    assert any(v > 0 for v in
               out["record"]["adapter_refusals"].values())
    assert "process" not in out["trace"]


# ── engine failure ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_rule_error_is_not_a_no_match_and_holds_the_frontier(
        monkeypatch):
    def boom(*a, **k):
        raise ValueError("synthetic rule failure")

    monkeypatch.setattr(eng_mod, "evaluate_rule", boom)
    b = Bench()
    out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    assert out["state"] == rr.STATE_FAILED
    assert out["failure_reason"] == run.STOP_ENGINE
    assert out["record"]["counters"]["engine_failures"] >= 1
    assert out["record"]["outcome_counts"]["NO_MATCH"] == 0
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:01")
    assert b.backend.all() == []


@pytest.mark.asyncio
async def test_an_unexpected_engine_exception_holds_the_frontier(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("synthetic engine crash")

    monkeypatch.setattr(eng_mod, "evaluate_rule", boom)
    b = Bench()
    out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    assert out["state"] == rr.STATE_FAILED
    assert out["failure_reason"] == run.STOP_ENGINE
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:01")
    assert b.backend.all() == []


# ── persistence failures ─────────────────────────────────────────────────

class Amnesiac(InMemoryShadowDetectionBackend):
    """Acknowledges a write and stores nothing."""

    async def insert(self, doc):
        return True


class RefusingBackend(InMemoryShadowDetectionBackend):
    async def insert(self, doc):
        return False                     # looks like a duplicate-key conflict


@pytest.mark.asyncio
async def test_an_unverifiable_detection_write_holds_the_frontier():
    b = Bench()
    b.backend = Amnesiac()
    out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    assert out["state"] == rr.STATE_FAILED
    assert out["failure_reason"] == \
        "SHADOW_DETECTION_READBACK_VERIFICATION_FAILED"
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:01")
    assert b.backend.all() == []


@pytest.mark.asyncio
async def test_a_detection_write_conflict_holds_the_frontier():
    b = Bench()
    b.backend = RefusingBackend()
    out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    assert out["state"] == rr.STATE_FAILED
    assert out["failure_reason"] in (run.STOP_ENGINE,
                                     run.STOP_DETECTION_UNVERIFIED)
    assert out["record"]["counters"]["concurrency_retries"] >= 1
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:01")


class FailingRunStore(rr.InMemoryShadowRunStore):
    def __init__(self, fail_after: int) -> None:
        super().__init__()
        self.left = fail_after

    async def put(self, doc, expected_revision):
        if self.left <= 0:
            raise OSError("synthetic run-record store failure")
        self.left -= 1
        return await super().put(doc, expected_revision)


@pytest.mark.asyncio
async def test_a_run_record_failure_never_advances_the_checkpoint():
    b = Bench()
    b.runs = FailingRunStore(1)           # create succeeds, measurement fails
    out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    assert out["state"] == rr.STATE_FAILED
    assert out["failure_reason"] == run.STOP_RUN_RECORD
    assert out["finalize_failed"] is True
    assert b.runs.all()[0]["state"] == rr.STATE_STARTED      # unaccounted
    assert b.runs.all()[0]["completed_at"] is None
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:01")
    assert len(b.backend.all()) == 1       # the detection IS durable


class FailingCheckpointStore(InMemoryCheckpointStore):
    def __init__(self, fail_after: int) -> None:
        super().__init__()
        self.left = fail_after

    async def save(self, tenant_id, replay_id, endpoint_id, cp):
        if self.left <= 0:
            raise OSError("synthetic checkpoint store failure")
        self.left -= 1
        return await super().save(tenant_id, replay_id, endpoint_id, cp)


@pytest.mark.asyncio
async def test_a_checkpoint_failure_leaves_the_frontier_behind():
    b = Bench()
    b.cps = FailingCheckpointStore(1)     # initialize succeeds, advance fails
    out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    assert out["state"] == rr.STATE_FAILED
    assert out["failure_reason"] == run.STOP_CHECKPOINT
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:01")
    assert len(b.backend.all()) == 1       # detection durable
    assert out["record"]["counters"]["matches"] == 1   # measurement durable
    assert out["record"]["resume_after_key"] == b.checkpoint()["after_key"]


# ── crash boundaries and retry ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_crash_before_detection_persistence_leaves_nothing(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("crash before persist")

    monkeypatch.setattr(eng_mod, "evaluate_rule", boom)
    b = Bench()
    out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    assert b.backend.all() == []
    assert out["record"]["counters"]["matches"] == 0
    assert b.checkpoint()["after_time"].startswith("2026-10-03T04:01")


@pytest.mark.asyncio
async def test_crash_after_detection_before_run_record_then_retry():
    """B1: detection durable, measurement lost, checkpoint behind."""
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(30, 30))
    b.runs = FailingRunStore(1)
    first = await b.go(db)
    assert first["state"] == rr.STATE_FAILED
    assert len(b.backend.all()) == 1
    held = b.checkpoint()["after_key"]

    b.runs = rr.InMemoryShadowRunStore()          # operator fixed the store
    second = await b.go(db, run_id="shadow_run_2", init=False)
    assert second["state"] == rr.STATE_COMPLETED
    assert len(b.backend.all()) == 1              # NO second detection
    assert second["detection_writes"][0]["outcome"] == WRITE_DUPLICATE
    assert second["record"]["counters"]["duplicates_prevented"] == 1
    assert b.checkpoint()["after_key"] != held


@pytest.mark.asyncio
async def test_crash_after_run_record_before_checkpoint_then_retry():
    """B2: both durable, checkpoint behind. The item is counted in TWO
    records, which is truthful — it really was processed twice."""
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(30, 30))
    b.cps = FailingCheckpointStore(1)
    first = await b.go(db)
    assert first["state"] == rr.STATE_FAILED
    assert first["record"]["counters"]["events_evaluated"] == 1

    b.cps = InMemoryCheckpointStore()
    second = await b.go(db, run_id="shadow_run_2")
    assert second["state"] == rr.STATE_COMPLETED
    assert len(b.backend.all()) == 1
    assert second["record"]["counters"]["events_evaluated"] == 1
    assert second["record"]["counters"]["duplicates_prevented"] == 1
    assert first["record"]["shadow_run_id"] != \
        second["record"]["shadow_run_id"]


@pytest.mark.asyncio
async def test_repeated_match_is_deterministic_and_idempotent():
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(30, 30))
    b.cps = FailingCheckpointStore(1)
    first = await b.go(db)
    ids = [w["detection_id"] for w in first["detection_writes"]]
    b.cps = InMemoryCheckpointStore()
    for i in range(2, 5):
        b.cps = FailingCheckpointStore(1)
        out = await b.go(db, run_id=f"shadow_run_{i}")
        assert [w["detection_id"] for w in out["detection_writes"]] == ids
    assert len(b.backend.all()) == 1


# ── G-8: duplicate authority is the store ────────────────────────────────

@pytest.mark.asyncio
async def test_duplicates_prevented_comes_from_the_store_not_the_engine():
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(30, 30))
    b.cps = FailingCheckpointStore(1)
    await b.go(db)
    b.cps = InMemoryCheckpointStore()
    out = await b.go(db, run_id="shadow_run_2")
    assert out["record"]["counters"]["duplicates_prevented"] == 1
    # the engine's own duplicate counter cannot see it (status is rewritten)
    assert out["engine_metrics"]["counters"]["duplicates_prevented"] == 0
    assert out["detection_writes"][0]["outcome"] == WRITE_DUPLICATE
    src = inspect.getsource(run)
    assert 'd.get("duplicates_prevented"' not in src


# ── G-9: the trigger is always declared ──────────────────────────────────

class OrderedStoreProbe:
    """Wraps the shadow detection backend and records call order."""

    collection = InMemoryShadowDetectionBackend.collection

    def __init__(self) -> None:
        self.inner = InMemoryShadowDetectionBackend()
        self.calls: list = []

    async def load(self, *a, **k):
        return await self.inner.load(*a, **k)

    async def overlapping(self, *a, **k):
        return await self.inner.overlapping(*a, **k)

    async def insert(self, doc):
        self.calls.append("insert")
        return await self.inner.insert(doc)

    async def replace(self, doc, rev):
        self.calls.append("replace")
        return await self.inner.replace(doc, rev)

    def all(self, tenant_id=None):
        return self.inner.all(tenant_id)


@pytest.mark.asyncio
async def test_expect_trigger_is_set_before_every_engine_execution():
    b = Bench()
    rows = [detection_row(1, 1)] + [detection_row(10 + i, 100 + i)
                                    for i in range(3)]
    out = await b.go(db_of(*rows))
    trace = out["trace"]
    assert trace.count("process") == out["items_processed"]
    for i, step in enumerate(trace):
        if step == "process":
            assert trace[i - 1].startswith("expect_trigger:")


@pytest.mark.asyncio
async def test_a_detection_is_never_written_without_a_declared_trigger():
    b = Bench()
    probe = OrderedStoreProbe()
    b.backend = probe
    seen = {}
    real = ShadowStoreSpy.patch(seen)
    try:
        out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    finally:
        real()
    assert probe.calls == ["insert"]
    assert seen["trigger_at_put"], "trigger key must be set before any put"
    assert out["state"] == rr.STATE_COMPLETED


class ShadowStoreSpy:
    """Records whether a trigger was declared at the moment of each put."""

    @staticmethod
    def patch(seen):
        from edr_plane import behavior_shadow_detection_store as sds
        original = sds.ShadowDetectionStore.put

        async def spy(self, doc, expected_revision):
            seen["trigger_at_put"] = bool(self._trigger_key)
            return await original(self, doc, expected_revision)

        sds.ShadowDetectionStore.put = spy

        def restore():
            sds.ShadowDetectionStore.put = original
        return restore


def test_the_runner_source_declares_the_trigger_before_processing():
    src = inspect.getsource(run._item)
    assert src.index("expect_trigger(") < src.index("engine.process(")


# ── checkpoint is always last ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_checkpoint_is_the_final_durable_operation_for_a_match():
    journal: list = []
    b = Bench()

    class JBackend(InMemoryShadowDetectionBackend):
        async def insert(self, doc):
            journal.append("detection")
            return await super().insert(doc)

    class JRuns(rr.InMemoryShadowRunStore):
        async def put(self, doc, expected_revision):
            journal.append("run_record")
            return await super().put(doc, expected_revision)

    class JCps(InMemoryCheckpointStore):
        async def save(self, *a, **k):
            journal.append("checkpoint")
            return await super().save(*a, **k)

    b.backend, b.runs, b.cps = JBackend(), JRuns(), JCps()
    out = await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    assert out["state"] == rr.STATE_COMPLETED
    # drop the initialization save and the create/finalize record writes
    i = journal.index("detection")
    assert journal[i:i + 3] == ["detection", "run_record", "checkpoint"]
    assert journal.index("checkpoint", i) > journal.index("run_record", i)


@pytest.mark.asyncio
async def test_checkpoint_never_advances_for_any_unresolved_outcome():
    cases = []
    # insufficient
    b1 = Bench({**rule_doc([STAGE_EVIL]),
                "evidence_requirements": REQUIRES_ABSENT})
    cases.append((b1, await b1.go(db_of(detection_row(1, 1),
                                        detection_row(30, 30)))))
    # truncated window
    b2 = Bench()
    cases.append((b2, await b2.go(db_of(detection_row(1, 1),
                                        detection_row(30, 30),
                                        detection_row(31, 31)),
                                  budgets=ShadowBudgets(max_window_events=1))))
    # adapter refusal
    b3 = Bench()
    cases.append((b3, await b3.go(db_of(detection_row(1, 1),
                                        doc(ts(30), 30, activity="NOPE")))))
    for bench, out in cases:
        assert out["state"] != rr.STATE_COMPLETED
        assert bench.checkpoint()["after_time"].startswith(
            "2026-10-03T04:01"), out["failure_reason"]


# ── isolation ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_another_tenants_evidence_is_never_read_or_counted():
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(30, 30, tenant=T_B))
    out = await b.go(db)
    assert out["items_processed"] == 0
    assert out["state"] == rr.STATE_COMPLETED
    assert out["record"]["counters"]["cross_tenant_reference_count"] == 0
    assert b.backend.all() == []


@pytest.mark.asyncio
async def test_a_foreign_tenant_record_would_stop_the_run():
    """The provider cannot produce one, so the guard is exercised directly."""
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(30, 30))
    await b.go(db)
    doc_ = b.backend.all()[0]
    assert doc_["tenant_id"] == T
    assert all(r["tenant_id"] == T for r in doc_["evidence_refs"])
    assert run.STOP_SCOPE == "SHADOW_CROSS_TENANT_OR_ENDPOINT_RECORD"
    src = inspect.getsource(run._item)
    assert "rec.tenant_id != ctx.tenant" in src
    assert "rec.ref.tenant_id != ctx.tenant" in src
    assert "rec.endpoint_id != ctx.endpoint" in src


@pytest.mark.asyncio
async def test_detections_are_bound_to_the_running_shadow_stream():
    b = Bench()
    await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    d = b.backend.all()[0]
    assert d["shadow_run_id"] == "shadow_run_1"
    assert d["replay_id"] == fr.stream_id(b.hash)
    assert d["ruleset_content_hash"] == b.hash


# ── measurement authority ────────────────────────────────────────────────

def test_the_runner_accepts_no_caller_supplied_measurements():
    params = set(inspect.signature(run_shadow).parameters)
    for forbidden in ("matches", "outcomes", "counters", "duplicates",
                      "duplicates_prevented", "engine_failures",
                      "events_evaluated", "rules_evaluated",
                      "cross_tenant_reference_count",
                      "matches_without_valid_evidence_refs", "metrics",
                      "measurements"):
        assert forbidden not in params, forbidden


@pytest.mark.asyncio
async def test_measurements_match_what_actually_happened():
    b = Bench()
    rows = [detection_row(1, 1)] + [detection_row(10 + i * 20, 100 + i)
                                    for i in range(3)]
    out = await b.go(db_of(*rows))
    rec, em = out["record"], out["engine_metrics"]["counters"]
    assert rec["counters"]["events_evaluated"] == em["events_evaluated"] == 3
    assert rec["counters"]["matches"] == em["matches"] == 3
    assert rec["counters"]["rules_evaluated"] == em["candidate_rules"]
    assert rec["counters"]["rows_read"] >= 3
    assert rec["counters"]["engine_failures"] == 0
    assert rec["counters"]["matches_without_valid_evidence_refs"] == 0
    assert rec["counters"]["cross_tenant_reference_count"] == 0
    assert rec["execution_duration_ms"] >= 0
    assert rec["evidence_lag_ms"] is not None and rec["evidence_lag_ms"] >= 0
    assert len(b.backend.all()) == 3


@pytest.mark.asyncio
async def test_evidence_at_or_before_the_frontier_is_counted_as_skipped():
    b = Bench()
    db = db_of(detection_row(1, 1), detection_row(2, 2), detection_row(30, 30))
    out = await b.go(db, init_end=T0 + timedelta(minutes=5))
    assert out["items_processed"] == 1
    assert out["record"]["counters"]["skipped_observed_before_frontier"] >= 1


# ── nothing analyst-visible, nothing fabric ──────────────────────────────

@pytest.mark.asyncio
async def test_no_analyst_visible_or_fabric_output_is_produced():
    b = Bench()
    await b.go(db_of(detection_row(1, 1), detection_row(30, 30)))
    for d in b.backend.all():
        assert d["analyst_visible"] is False
        assert d["detection_source_claim"] == "NONE"
        assert d["status"] == "SHADOW_ONLY"
        for forbidden in ("finding_id", "incident_id", "verdict",
                          "response_action", "evaluation_state"):
            assert forbidden not in d


def test_runner_touches_no_fabric_response_or_production_authority():
    src = inspect.getsource(run)
    for forbidden in ("findings_intake", "EvaluationState", "response",
                      "isolate", "quarantine", "e3_behavior_detections",
                      "MongoClient", "motor", "create_index",
                      "ensure_indexes", "VITE_E3_DT_V3", "KUSHU",
                      "AsyncIOMotorClient"):
        assert forbidden not in src, forbidden


def test_runner_uses_only_the_established_boundaries():
    src = inspect.getsource(run)
    assert "SdEvidenceProvider" in src
    assert "ShadowDetectionStore" in src
    assert "behavior_shadow_frontier" in src
    assert "behavior_shadow_run" in src
    assert "MODE_SHADOW" in src
    assert "MongoStoreProvider" not in src
    assert "MODE_LIVE" not in src and "MODE_RETRO" not in src


def test_budgets_are_runner_local_and_not_configuration():
    src = inspect.getsource(run)
    assert "os.environ" not in src and "getenv" not in src
    b = ShadowBudgets()
    assert (b.max_trigger_rows, b.provider_page_size, b.max_sd_pages) == \
        (25, 100, 24)
    assert (b.max_window_events, b.matcher_budget) == (500, 2000)
    assert b.max_observation_span_seconds == 6 * 3600
