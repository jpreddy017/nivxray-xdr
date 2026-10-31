"""The shadow run record: identity, isolation, lifecycle, measurements.

Hermetic. No SequenceEngine, no rule evaluation, no evidence read, no provider,
no checkpoint, no detection document, no ledger, no Fabric Finding, no index
creation, no production, no real endpoint.
"""
from __future__ import annotations

import inspect
from datetime import datetime, timezone

import pytest

from edr_plane import behavior_shadow_run as sr
from edr_plane.behavior_shadow_run import (COUNTERS, OUTCOMES, REFUSED_BINDING,
                                           REFUSED_DUPLICATE,
                                           REFUSED_FAILURE_REASON,
                                           REFUSED_FORBIDDEN_METRIC,
                                           REFUSED_IDENTITY,
                                           REFUSED_NEGATIVE_METRIC,
                                           REFUSED_NOT_FOUND, REFUSED_REASON,
                                           REFUSED_RESUME_NOT_ALLOWED,
                                           REFUSED_RESUME_REQUIRED,
                                           REFUSED_STATE, REFUSED_TENANT,
                                           REFUSED_TERMINAL,
                                           REFUSED_UNKNOWN_METRIC,
                                           STATE_COMPLETED, STATE_FAILED,
                                           STATE_INTERRUPTED, STATE_STARTED,
                                           STATE_TRUNCATED, TERMINAL_STATES,
                                           InMemoryShadowRunStore,
                                           ShadowRunRefused, StaleShadowRun,
                                           create, finalize, read, update,
                                           zero_targets_held)

T = "ten_a"
T_B = "ten_b"
EP = "ep_1"
RUN = "shadow_run_0001"
HASH = "a1" * 16
BY = "operator@nivxray.com"
T0 = datetime(2026, 10, 3, 4, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 10, 3, 4, 5, 0, tzinfo=timezone.utc)


async def started(store=None, *, tenant=T, run=RUN, endpoint=EP,
                  reason="SYNTHETIC_VALIDATION"):
    store = store or InMemoryShadowRunStore()
    doc = await create(store, tenant_id=tenant, shadow_run_id=run,
                       endpoint_id=endpoint, ruleset_id="rs_core",
                       ruleset_version=3, ruleset_content_hash=HASH,
                       replay_id=f"shadow:{HASH}", invoked_by=BY,
                       reason=reason, started_at=T0)
    return store, doc


# ── identity and binding ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_record_identity_and_required_bindings():
    _, doc = await started()
    assert (doc["tenant_id"], doc["shadow_run_id"]) == (T, RUN)
    for field in ("endpoint_id", "ruleset_id", "ruleset_version",
                  "ruleset_content_hash", "replay_id", "invoked_by", "reason",
                  "started_at", "state"):
        assert doc[field] not in (None, "")
    assert doc["state"] == STATE_STARTED
    assert doc["completed_at"] is None
    assert doc["revision"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["endpoint_id", "ruleset_id",
                                     "ruleset_content_hash", "replay_id",
                                     "invoked_by"])
async def test_missing_binding_is_refused(missing):
    kwargs = dict(tenant_id=T, shadow_run_id=RUN, endpoint_id=EP,
                  ruleset_id="rs", ruleset_version=1,
                  ruleset_content_hash=HASH, replay_id="shadow:x",
                  invoked_by=BY, reason="MANUAL")
    kwargs[missing] = "  "
    with pytest.raises(ShadowRunRefused) as e:
        await create(InMemoryShadowRunStore(), **kwargs)
    assert e.value.reason == REFUSED_BINDING


@pytest.mark.asyncio
async def test_missing_ruleset_version_is_refused():
    with pytest.raises(ShadowRunRefused) as e:
        await create(InMemoryShadowRunStore(), tenant_id=T, shadow_run_id=RUN,
                     endpoint_id=EP, ruleset_id="rs", ruleset_version=None,
                     ruleset_content_hash=HASH, replay_id="shadow:x",
                     invoked_by=BY, reason="MANUAL")
    assert e.value.reason == REFUSED_BINDING


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [None, "", "   "])
async def test_blank_identity_is_refused(bad):
    with pytest.raises(ShadowRunRefused) as e:
        await started(run=bad)
    assert e.value.reason == REFUSED_IDENTITY


@pytest.mark.asyncio
async def test_reason_vocabulary_is_closed():
    with pytest.raises(ShadowRunRefused) as e:
        await started(reason="BECAUSE_I_SAID_SO")
    assert e.value.reason == REFUSED_REASON


@pytest.mark.asyncio
async def test_duplicate_identity_in_same_tenant_is_refused():
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await started(store)
    assert e.value.reason == REFUSED_DUPLICATE


# ── tenant isolation ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_same_run_id_in_two_tenants_never_collides():
    store, a = await started()
    _, b = await started(store, tenant=T_B)
    assert a["shadow_run_id"] == b["shadow_run_id"]
    assert len(store.all()) == 2
    assert len(store.all(T)) == 1 and len(store.all(T_B)) == 1


@pytest.mark.asyncio
async def test_record_is_not_readable_cross_tenant():
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await read(store, tenant_id=T_B, shadow_run_id=RUN)
    assert e.value.reason == REFUSED_NOT_FOUND


@pytest.mark.asyncio
async def test_misfiled_tenant_document_is_rejected_on_read():
    store, _ = await started()
    doc = (await read(store, tenant_id=T, shadow_run_id=RUN))
    doc["tenant_id"] = T   # body says tenant A, filed under tenant B's key
    store._d[(T_B, RUN)] = doc
    with pytest.raises(ShadowRunRefused) as e:
        await read(store, tenant_id=T_B, shadow_run_id=RUN)
    assert e.value.reason == REFUSED_TENANT


@pytest.mark.asyncio
async def test_updates_do_not_leak_across_tenants():
    store, _ = await started()
    await started(store, tenant=T_B)
    await update(store, tenant_id=T, shadow_run_id=RUN,
                 counters={"rows_read": 7})
    other = await read(store, tenant_id=T_B, shadow_run_id=RUN)
    assert other["counters"]["rows_read"] == 0


@pytest.mark.asyncio
async def test_finalize_cross_tenant_is_refused():
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await finalize(store, tenant_id=T_B, shadow_run_id=RUN,
                       state=STATE_COMPLETED)
    assert e.value.reason == REFUSED_NOT_FOUND


# ── lifecycle ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("state", list(TERMINAL_STATES))
async def test_started_reaches_every_terminal_state(state):
    store, doc = await started()
    extra = {}
    if state == STATE_FAILED:
        extra["failure_reason"] = "ENGINE_FAILURE"
    if state == STATE_TRUNCATED:
        extra.update(resume_after_time=T1, resume_after_key="ev_last")
    out = await finalize(store, tenant_id=T, shadow_run_id=RUN, state=state,
                         completed_at=T1, expected_revision=doc["revision"],
                         **extra)
    assert out["state"] == state
    assert out["completed_at"].startswith("2026-10-03T04:05")


@pytest.mark.asyncio
async def test_unknown_state_is_refused():
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await finalize(store, tenant_id=T, shadow_run_id=RUN, state="CLEAN")
    assert e.value.reason == REFUSED_STATE


@pytest.mark.asyncio
async def test_finalizing_back_to_started_is_refused():
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await finalize(store, tenant_id=T, shadow_run_id=RUN,
                       state=STATE_STARTED)
    assert e.value.reason != REFUSED_STATE


@pytest.mark.asyncio
async def test_terminal_record_cannot_be_refinalized():
    store, _ = await started()
    await finalize(store, tenant_id=T, shadow_run_id=RUN,
                   state=STATE_INTERRUPTED, completed_at=T1)
    with pytest.raises(ShadowRunRefused) as e:
        await finalize(store, tenant_id=T, shadow_run_id=RUN,
                       state=STATE_COMPLETED, completed_at=T1)
    assert e.value.reason == REFUSED_TERMINAL


@pytest.mark.asyncio
async def test_terminal_record_cannot_be_updated():
    store, _ = await started()
    await finalize(store, tenant_id=T, shadow_run_id=RUN,
                   state=STATE_COMPLETED, completed_at=T1)
    with pytest.raises(ShadowRunRefused) as e:
        await update(store, tenant_id=T, shadow_run_id=RUN,
                     counters={"rows_read": 1})
    assert e.value.reason == REFUSED_TERMINAL


@pytest.mark.asyncio
async def test_failed_requires_a_failure_reason():
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await finalize(store, tenant_id=T, shadow_run_id=RUN,
                       state=STATE_FAILED, completed_at=T1)
    assert e.value.reason == REFUSED_FAILURE_REASON


@pytest.mark.asyncio
async def test_interrupted_keeps_partial_measurements_and_position():
    store, _ = await started()
    await update(store, tenant_id=T, shadow_run_id=RUN,
                 counters={"rows_read": 40, "events_evaluated": 12},
                 outcomes={"NO_MATCH": 12})
    out = await finalize(store, tenant_id=T, shadow_run_id=RUN,
                         state=STATE_INTERRUPTED, completed_at=T1,
                         resume_after_time=T1, resume_after_key="ev_12",
                         failure_reason="OPERATOR_ABORT")
    assert out["counters"]["rows_read"] == 40
    assert out["outcome_counts"]["NO_MATCH"] == 12
    assert out["resume_after_key"] == "ev_12"
    assert out["failure_reason"] == "OPERATOR_ABORT"


@pytest.mark.asyncio
async def test_read_after_finalize_is_durable():
    store, _ = await started()
    await update(store, tenant_id=T, shadow_run_id=RUN,
                 counters={"matches": 2}, outcomes={"MATCH": 2})
    await finalize(store, tenant_id=T, shadow_run_id=RUN,
                   state=STATE_COMPLETED, completed_at=T1,
                   execution_duration_ms=900, evidence_lag_ms=1500)
    got = await read(store, tenant_id=T, shadow_run_id=RUN)
    assert got["state"] == STATE_COMPLETED
    assert got["counters"]["matches"] == 2
    assert got["execution_duration_ms"] == 900
    assert got["evidence_lag_ms"] == 1500


@pytest.mark.asyncio
async def test_reading_an_unknown_run_fails_closed():
    with pytest.raises(ShadowRunRefused) as e:
        await read(InMemoryShadowRunStore(), tenant_id=T,
                   shadow_run_id="nope")
    assert e.value.reason == REFUSED_NOT_FOUND


# ── truncation and resume ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_truncated_requires_a_resume_position():
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await finalize(store, tenant_id=T, shadow_run_id=RUN,
                       state=STATE_TRUNCATED, completed_at=T1)
    assert e.value.reason == REFUSED_RESUME_REQUIRED


@pytest.mark.asyncio
async def test_truncated_records_position_and_sets_window_truncated():
    store, _ = await started()
    out = await finalize(store, tenant_id=T, shadow_run_id=RUN,
                         state=STATE_TRUNCATED, completed_at=T1,
                         resume_after_time=T1, resume_after_key="ev_last")
    assert out["window_truncated"] is True
    assert out["resume_after_time"].startswith("2026-10-03T04:05")
    assert out["resume_after_key"] == "ev_last"


@pytest.mark.asyncio
async def test_completed_may_not_carry_a_resume_position():
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await finalize(store, tenant_id=T, shadow_run_id=RUN,
                       state=STATE_COMPLETED, completed_at=T1,
                       resume_after_time=T1, resume_after_key="ev_last")
    assert e.value.reason == REFUSED_RESUME_NOT_ALLOWED


# ── measurements ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_every_counter_and_outcome_starts_at_zero():
    _, doc = await started()
    assert doc["counters"] == {name: 0 for name in COUNTERS}
    assert doc["outcome_counts"] == {name: 0 for name in OUTCOMES}
    assert doc["adapter_refusals"] == {}
    assert doc["window_truncated"] is False
    assert doc["execution_duration_ms"] == 0
    assert "evidence_lag_ms" in doc and doc["evidence_lag_ms"] is None
    assert doc["resume_after_time"] is None and doc["resume_after_key"] is None


@pytest.mark.asyncio
async def test_zero_target_counters_are_always_present_and_measurable():
    store, doc = await started()
    for name in sr.ZERO_TARGET_COUNTERS:
        assert doc["counters"][name] == 0
    assert zero_targets_held(doc) is True
    bad = await update(store, tenant_id=T, shadow_run_id=RUN,
                       counters={"cross_tenant_reference_count": 1})
    assert zero_targets_held(bad) is False


@pytest.mark.asyncio
async def test_measurements_accumulate_across_updates():
    store, _ = await started()
    await update(store, tenant_id=T, shadow_run_id=RUN,
                 counters={"rows_read": 10, "rules_evaluated": 4},
                 outcomes={"NO_MATCH": 10},
                 adapter_refusals={"MISSING_RAW_REF": 2})
    out = await update(store, tenant_id=T, shadow_run_id=RUN,
                       counters={"rows_read": 5},
                       outcomes={"NO_MATCH": 5, "INSUFFICIENT_EVIDENCE": 1},
                       adapter_refusals={"MISSING_RAW_REF": 1,
                                         "UNKNOWN_KIND": 3})
    assert out["counters"]["rows_read"] == 15
    assert out["counters"]["rules_evaluated"] == 4
    assert out["outcome_counts"] == {"MATCH": 0, "NO_MATCH": 15,
                                     "INSUFFICIENT_EVIDENCE": 1,
                                     "BUDGET_EXCEEDED": 0, "SUPPRESSED": 0}
    assert out["adapter_refusals"] == {"MISSING_RAW_REF": 3, "UNKNOWN_KIND": 3}


@pytest.mark.asyncio
async def test_all_step24_measurement_fields_are_persistable():
    store, _ = await started()
    out = await update(store, tenant_id=T, shadow_run_id=RUN,
                       counters={name: 1 for name in COUNTERS},
                       outcomes={name: 1 for name in OUTCOMES},
                       execution_duration_ms=1234, evidence_lag_ms=5678,
                       window_truncated=True)
    for name in COUNTERS:
        assert out["counters"][name] == 1
    for name in OUTCOMES:
        assert out["outcome_counts"][name] == 1
    assert out["execution_duration_ms"] == 1234
    assert out["evidence_lag_ms"] == 5678
    assert out["window_truncated"] is True


@pytest.mark.asyncio
async def test_unknown_counter_or_outcome_is_refused():
    store, _ = await started()
    for payload in ({"counters": {"made_up": 1}},
                    {"outcomes": {"PROBABLY_BAD": 1}}):
        with pytest.raises(ShadowRunRefused) as e:
            await update(store, tenant_id=T, shadow_run_id=RUN, **payload)
        assert e.value.reason == REFUSED_UNKNOWN_METRIC


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"counters": {"rows_read": -1}},
    {"outcomes": {"MATCH": -2}},
    {"adapter_refusals": {"X": -1}},
    {"counters": {"rows_read": True}},
    {"execution_duration_ms": -5},
    {"evidence_lag_ms": -1},
])
async def test_negative_or_non_integer_measurements_are_refused(payload):
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await update(store, tenant_id=T, shadow_run_id=RUN, **payload)
    assert e.value.reason == REFUSED_NEGATIVE_METRIC


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["true_positives", "false_positives",
                                  "precision", "accuracy", "malicious",
                                  "benign", "verdict", "confidence"])
async def test_quality_or_verdict_claims_are_refused(name):
    store, _ = await started()
    with pytest.raises(ShadowRunRefused) as e:
        await update(store, tenant_id=T, shadow_run_id=RUN,
                     adapter_refusals={name: 1})
    assert e.value.reason == REFUSED_FORBIDDEN_METRIC


def test_no_quality_metric_exists_in_the_record_vocabulary():
    for name in sr.FORBIDDEN_FIELDS:
        assert name not in COUNTERS and name not in OUTCOMES


# ── revision handling ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_revision_advances_on_every_write():
    store, doc = await started()
    one = await update(store, tenant_id=T, shadow_run_id=RUN,
                       counters={"rows_read": 1},
                       expected_revision=doc["revision"])
    assert one["revision"] == doc["revision"] + 1
    two = await finalize(store, tenant_id=T, shadow_run_id=RUN,
                         state=STATE_COMPLETED, completed_at=T1,
                         expected_revision=one["revision"])
    assert two["revision"] == one["revision"] + 1


@pytest.mark.asyncio
async def test_stale_revision_update_is_refused():
    store, doc = await started()
    await update(store, tenant_id=T, shadow_run_id=RUN,
                 counters={"rows_read": 1}, expected_revision=doc["revision"])
    with pytest.raises(StaleShadowRun):
        await update(store, tenant_id=T, shadow_run_id=RUN,
                     counters={"rows_read": 1},
                     expected_revision=doc["revision"])


@pytest.mark.asyncio
async def test_stale_revision_finalize_is_refused():
    store, doc = await started()
    await update(store, tenant_id=T, shadow_run_id=RUN,
                 counters={"rows_read": 1}, expected_revision=doc["revision"])
    with pytest.raises(StaleShadowRun):
        await finalize(store, tenant_id=T, shadow_run_id=RUN,
                       state=STATE_COMPLETED, completed_at=T1,
                       expected_revision=doc["revision"])


def test_g3_is_stated_not_solved():
    """Application-level revision checking is not advertised as Mongo CAS."""
    assert InMemoryShadowRunStore.supports_atomic_cas is False
    assert sr.MongoShadowRunStore.supports_atomic_cas is True
    doc = inspect.getdoc(sr) or ""
    assert "G-3" in doc and "compare-and-set" in doc
    assert "G-4" in doc


# ── shadow-only guarantees ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_shadow_markers_are_set_and_not_caller_controlled():
    store, doc = await started()
    assert doc["shadow"] is True
    assert doc["analyst_visible"] is False
    assert doc["detection_source_claim"] == "NONE"
    out = await finalize(store, tenant_id=T, shadow_run_id=RUN,
                         state=STATE_COMPLETED, completed_at=T1)
    assert (out["shadow"], out["analyst_visible"],
            out["detection_source_claim"]) == (True, False, "NONE")


@pytest.mark.asyncio
async def test_tampered_shadow_markers_are_refused_on_read():
    store, _ = await started()
    store._d[(T, RUN)]["analyst_visible"] = True
    with pytest.raises(ShadowRunRefused) as e:
        await read(store, tenant_id=T, shadow_run_id=RUN)
    assert e.value.reason == sr.REFUSED_MARKERS


@pytest.mark.asyncio
async def test_completed_has_no_clean_or_benign_semantics():
    store, _ = await started()
    out = await finalize(store, tenant_id=T, shadow_run_id=RUN,
                         state=STATE_COMPLETED, completed_at=T1,
                         outcomes={"NO_MATCH": 25})
    assert out["completed_meaning"] == sr.COMPLETED_MEANING
    assert out["detection_source_claim"] == "NONE"
    # a zero-match completed run states nothing about the endpoint
    assert out["counters"]["matches"] == 0
    for word in ("clean", "benign", "no_threat", "safe", "verdict"):
        assert word not in str(out).lower().replace("completed_meaning", "")


@pytest.mark.asyncio
async def test_record_has_no_verdict_or_response_field():
    _, doc = await started()
    for forbidden in ("verdict", "isolate", "quarantine", "response_action",
                      "finding_id", "incident_id", "analyst_note",
                      "severity", "risk_score", "confidence"):
        assert forbidden not in doc, forbidden
    src = inspect.getsource(sr)
    for forbidden in ("isolate", "quarantine", "response_action",
                      "finding_id", "incident_id"):
        assert forbidden not in src, forbidden


# ── index design only ────────────────────────────────────────────────────

def test_unique_index_is_designed_but_never_created():
    keys, opts = sr.INDEXES[0]
    assert keys == [("tenant_id", 1), ("shadow_run_id", 1)]
    assert opts["unique"] is True
    src = inspect.getsource(sr)
    assert "create_index" not in src and "ensure_indexes" not in src


def test_collection_is_additive_and_not_a_detection_store():
    assert sr.COLLECTION == "e3_behavior_shadow_runs"
    src = inspect.getsource(sr)
    for forbidden in ("e3_behavior_detections",
                      "e3_behavior_replay_checkpoints",
                      "record_endpoint_detection", "findings_intake",
                      "EvaluationState", "DetectionStore"):
        assert forbidden not in src.replace(
            "`edr_behavior.store.DetectionStore`", ""), forbidden


# ── isolation from everything else ───────────────────────────────────────

def test_module_does_not_import_or_execute_the_behavior_engine():
    import subprocess
    import sys
    from pathlib import Path
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; import edr_plane.behavior_shadow_run;"
         "print(sorted(m for m in sys.modules if m.startswith('edr_behavior')))"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parents[2]))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


def test_module_reads_no_evidence_and_touches_no_checkpoint():
    src = inspect.getsource(sr)
    for forbidden in ("SequenceEngine", "provider", "window(", "process(",
                      "behavior_shadow_frontier", "SdEvidenceProvider",
                      "advance(", "initialize(", "MongoClient", "motor"):
        assert forbidden not in src, forbidden
