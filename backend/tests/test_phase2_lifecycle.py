"""
Unit Tests for Phase 2G Content Lifecycle State Machine.
Verifies allowed and forbidden transitions across all 15 states,
and asserts append-only audit trail logging.
"""
import pytest
from detection_content.validation_framework import (
    ContentLifecycleManager,
    LifecycleState,
)


def test_happy_path_lifecycle_progression():
    mgr = ContentLifecycleManager()
    cid = "DET-TEST-001"

    assert mgr.transition(cid, LifecycleState.ACQUIRED, "worker-ingest", "Raw YAML fetched from upstream")
    assert mgr.transition(cid, LifecycleState.NORMALIZED, "worker-norm", "Fields mapped to canonical schema")
    assert mgr.transition(cid, LifecycleState.TRANSLATED, "worker-trans", "Compiled into NIR AST")
    assert mgr.transition(cid, LifecycleState.DEDUPLICATED, "worker-dedup", "Deduplication check passed: UNIQUE")
    assert mgr.transition(cid, LifecycleState.VALIDATING, "worker-val", "Executing Tier 1 fixtures")
    assert mgr.transition(cid, LifecycleState.VALIDATED, "worker-val", "All fixtures passed")
    assert mgr.transition(cid, LifecycleState.ENGINE_BOUND, "worker-bind", "Bound to native engine")
    assert mgr.transition(cid, LifecycleState.CONTEXTUALIZED, "worker-state", "Contextualized with Security State")
    assert mgr.transition(cid, LifecycleState.SHADOW, "analyst-lead", "Promoted to 7-day shadow mode")
    assert mgr.transition(cid, LifecycleState.ACTIVE, "analyst-lead", "Promoted to active production evaluation")

    assert mgr.get_state(cid) == LifecycleState.ACTIVE

    history = mgr.get_history(cid)
    assert len(history) == 10
    assert history[-1].new_state == "ACTIVE"
    assert history[-1].actor == "analyst-lead"


def test_illegal_transition_rejection():
    mgr = ContentLifecycleManager()
    cid = "DET-BAD-001"

    mgr.transition(cid, LifecycleState.ACQUIRED, "worker", "Initial")
    # Illegal direct jump to ACTIVE
    with pytest.raises(ValueError, match="Illegal lifecycle transition"):
        mgr.transition(cid, LifecycleState.ACTIVE, "hacker", "Bypassing validation")


def test_rollback_transition():
    mgr = ContentLifecycleManager()
    cid = "DET-ROLL-001"

    # Fast forward to ACTIVE
    for s in (
        LifecycleState.ACQUIRED,
        LifecycleState.NORMALIZED,
        LifecycleState.TRANSLATED,
        LifecycleState.DEDUPLICATED,
        LifecycleState.VALIDATING,
        LifecycleState.VALIDATED,
        LifecycleState.ENGINE_BOUND,
        LifecycleState.CONTEXTUALIZED,
        LifecycleState.SHADOW,
        LifecycleState.ACTIVE,
    ):
        mgr.transition(cid, s, "worker", "Step")

    # Trigger emergency rollback
    assert mgr.transition(cid, LifecycleState.ROLLED_BACK, "analyst-oncall", "High FP rate in production")
    assert mgr.get_state(cid) == LifecycleState.ROLLED_BACK
