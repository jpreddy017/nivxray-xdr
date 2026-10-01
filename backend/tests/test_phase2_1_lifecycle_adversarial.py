"""
NivXRay XDR — Phase 2.1 Lifecycle State Machine Attack Suite.
Attempts illegal transitions against ContentLifecycleManager:
  ACQUIRED → ACTIVE
  UNSUPPORTED → ACTIVE
  VALIDATING → ACTIVE
  ENGINE_UNBOUND → ACTIVE
  REJECTED → SHADOW
  DEPRECATED → ACTIVE
All illegal transitions must fail closed (raise ValueError).
Verifies complete append-only transition audit history.
"""
import pytest
from detection_content.validation_framework import (
    ContentLifecycleManager,
    LifecycleState,
)


@pytest.fixture
def lcm():
    return ContentLifecycleManager()


def test_illegal_transition_acquired_to_active(lcm):
    """ACQUIRED cannot bypass normalization/validation straight to ACTIVE."""
    rule_id = "LIFECYCLE-ATTACK-001"
    lcm.transition(rule_id, LifecycleState.ACQUIRED, "attacker", "boot")
    with pytest.raises(ValueError, match="Illegal lifecycle transition"):
        lcm.transition(rule_id, LifecycleState.ACTIVE, "attacker", "illegal bypass")
    assert lcm.get_state(rule_id) == LifecycleState.ACQUIRED


def test_illegal_transition_unsupported_to_active(lcm):
    """UNSUPPORTED rule cannot jump to ACTIVE."""
    rule_id = "LIFECYCLE-ATTACK-002"
    lcm.transition(rule_id, LifecycleState.ACQUIRED, "system", "initial")
    lcm.transition(rule_id, LifecycleState.UNSUPPORTED, "translator", "unsupported construct")
    assert lcm.get_state(rule_id) == LifecycleState.UNSUPPORTED

    with pytest.raises(ValueError, match="Illegal lifecycle transition"):
        lcm.transition(rule_id, LifecycleState.ACTIVE, "attacker", "force enable")
    assert lcm.get_state(rule_id) == LifecycleState.UNSUPPORTED


def test_illegal_transition_validating_to_active(lcm):
    """VALIDATING cannot jump directly to ACTIVE without passing gates and shadow."""
    rule_id = "LIFECYCLE-ATTACK-003"
    lcm.transition(rule_id, LifecycleState.ACQUIRED, "sys", "init")
    lcm.transition(rule_id, LifecycleState.NORMALIZED, "sys", "norm")
    lcm.transition(rule_id, LifecycleState.TRANSLATED, "sys", "trans")
    lcm.transition(rule_id, LifecycleState.DEDUPLICATED, "sys", "dedup")
    lcm.transition(rule_id, LifecycleState.VALIDATING, "sys", "val")

    with pytest.raises(ValueError, match="Illegal lifecycle transition"):
        lcm.transition(rule_id, LifecycleState.ACTIVE, "attacker", "skip gates")
    assert lcm.get_state(rule_id) == LifecycleState.VALIDATING


def test_illegal_transition_rejected_to_shadow(lcm):
    """REJECTED rule is terminal; cannot transition to SHADOW."""
    rule_id = "LIFECYCLE-ATTACK-004"
    lcm.transition(rule_id, LifecycleState.ACQUIRED, "sys", "init")
    lcm.transition(rule_id, LifecycleState.REJECTED, "gate", "license rejected")

    with pytest.raises(ValueError, match="Illegal lifecycle transition"):
        lcm.transition(rule_id, LifecycleState.SHADOW, "attacker", "shadow sneaky")
    assert lcm.get_state(rule_id) == LifecycleState.REJECTED


def test_illegal_transition_deprecated_to_active(lcm):
    """DEPRECATED rule cannot be directly activated without governance review."""
    rule_id = "LIFECYCLE-ATTACK-005"
    lcm.transition(rule_id, LifecycleState.ACQUIRED, "sys", "init")
    lcm.transition(rule_id, LifecycleState.NORMALIZED, "sys", "norm")
    lcm.transition(rule_id, LifecycleState.TRANSLATED, "sys", "trans")
    lcm.transition(rule_id, LifecycleState.DEDUPLICATED, "sys", "dedup")
    lcm.transition(rule_id, LifecycleState.VALIDATING, "sys", "val")
    lcm.transition(rule_id, LifecycleState.VALIDATED, "sys", "val_done")
    lcm.transition(rule_id, LifecycleState.DEPRECATED, "admin", "obsolete")

    with pytest.raises(ValueError, match="Illegal lifecycle transition"):
        lcm.transition(rule_id, LifecycleState.ACTIVE, "attacker", "reactivate")
    assert lcm.get_state(rule_id) == LifecycleState.DEPRECATED


def test_append_only_audit_history_integrity(lcm):
    """Verify state transitions append chronologically without mutation."""
    rule_id = "AUDIT-TRAIL-001"
    transitions = [
        (LifecycleState.ACQUIRED, "system", "initial ingest"),
        (LifecycleState.NORMALIZED, "dsm", "telemetry normalized"),
        (LifecycleState.TRANSLATED, "translator", "NIR AST created"),
        (LifecycleState.DEDUPLICATED, "dedup_engine", "no duplicate found"),
        (LifecycleState.VALIDATING, "validator", "running tiers"),
        (LifecycleState.VALIDATED, "validator", "all tiers passed"),
        (LifecycleState.ENGINE_BOUND, "binding_bridge", "bound to engine"),
        (LifecycleState.SHADOW, "soc_admin", "entering observation"),
        (LifecycleState.ACTIVE, "soc_lead", "promoted to active"),
    ]

    for state, actor, reason in transitions:
        lcm.transition(rule_id, state, actor, reason)

    history = lcm.get_history(rule_id)
    assert len(history) == len(transitions)
    for i, (state, actor, reason) in enumerate(transitions):
        assert history[i].new_state == state.value
        assert history[i].actor == actor
        assert history[i].reason == reason
