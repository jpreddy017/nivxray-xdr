"""Orchestrator × Registry-Planner integration test  (R28.7.1).

Proves that a plugin registered ONLY via the Capability Registry
(no legacy ``capability.register`` call) actually executes when the
orchestrator processes an artifact whose type its contract admits.

This is the acceptance test for the architectural boundary:
    · No orchestrator change is needed to add a new capability.
    · A contract + impl is sufficient.
"""
from __future__ import annotations

from services.uaie import capability as cap_mod
from services.uaie import contract  as ct_mod
from services.uaie.capability import CapabilityResult
from services.uaie.contract   import (CAT_EXECUTOR, CapabilityContract,
                                         IMPROVES_DECODE, register)
from services.uaie.orchestrator import Orchestrator
from services.uaie.recognizer  import CERTAIN, Reason, Recognition
from services.uaie.artifact    import make_artifact


class _R:
    name = "r28.7.1.recognizer"
    def recognize(self, artifact):
        # Only claim the ROOT — don't re-claim children (else the
        # executor would run twice: once on root, once on the emitted
        # widget_decoded child).
        if artifact.artifact_type in ("widget", "widget_decoded"):
            return []
        return [Recognition(artifact_type="widget", confidence=CERTAIN,
                             reasons=[Reason("t", 1.0)], recognizer=self.name)]


class _ContractOnlyExecutor:
    """Registered ONLY via the Capability Registry — never touches
    ``capability._REGISTRY``.  The orchestrator must still execute it."""
    name = "r28.7.1.contract_only_executor"
    requires_artifact_type = ["widget"]     # matches Capability protocol
    requires_evidence      = []

    def __init__(self):
        self.execution_count = 0

    def execute(self, artifact):
        self.execution_count += 1
        # Emit ONE child so the orchestrator lifecycle records progress.
        child = make_artifact(b"decoded-widget", "widget_decoded",
                                parent_uri=artifact.uri,
                                depth=artifact.depth + 1,
                                discovered_by=self.name)
        return CapabilityResult(child_artifacts=[child])


def _snap():
    return (dict(ct_mod._CONTRACT_REGISTRY), dict(ct_mod._IMPL_REGISTRY),
             dict(cap_mod._REGISTRY))


def _restore(s):
    ct_mod._CONTRACT_REGISTRY.clear(); ct_mod._CONTRACT_REGISTRY.update(s[0])
    ct_mod._IMPL_REGISTRY.clear();     ct_mod._IMPL_REGISTRY.update(s[1])
    ct_mod._rebuild_indexes()
    cap_mod._REGISTRY.clear();         cap_mod._REGISTRY.update(s[2])


def test_registry_only_plugin_is_executed_by_orchestrator():
    snap = _snap()
    try:
        cap_mod._REGISTRY.clear()
        ct_mod._CONTRACT_REGISTRY.clear()
        ct_mod._IMPL_REGISTRY.clear()

        impl = _ContractOnlyExecutor()
        register(
            CapabilityContract(
                id="executor.widget.decode", version="1.0",
                category=CAT_EXECUTOR,
                requires=("widget",),
                produces=("widget_decoded",),
                improves=(IMPROVES_DECODE,),
                confidence_gain=0.5,
                description="unit-test executor registered ONLY via registry",
            ),
            impl=impl,
        )

        orch = Orchestrator(recognizers=[_R()], max_artifacts=8, max_depth=3)
        r = orch.run(b"anything", root_type="unknown")

        # Prove: the contract-only executor actually ran.
        assert impl.execution_count == 1, (
            "orchestrator did NOT execute a contract-only capability — "
            "R28.7.1 wiring is broken"
        )
        # Prove: the child artifact it produced entered the graph.
        assert any(a.artifact_type == "widget_decoded"
                     for a in r.artifacts.values()), (
            "child artifact from contract-only executor missing from graph"
        )
    finally:
        _restore(snap)


def test_registry_planning_does_not_break_legacy_capabilities():
    """Prove legacy plugins keep working when a contract-registered
    capability is ALSO present."""
    snap = _snap()
    try:
        cap_mod._REGISTRY.clear()
        ct_mod._CONTRACT_REGISTRY.clear()
        ct_mod._IMPL_REGISTRY.clear()

        # A legacy-registered capability
        class _LegacyExec:
            name = "r28.7.1.legacy_exec"
            requires_artifact_type = ["widget"]
            requires_evidence      = []
            def __init__(self): self.n = 0
            def execute(self, artifact):
                self.n += 1
                return CapabilityResult()

        legacy = _LegacyExec()
        cap_mod.register(legacy)

        # A contract-only capability
        contract_impl = _ContractOnlyExecutor()
        register(
            CapabilityContract(
                id="executor.widget.decode", version="1.0",
                category=CAT_EXECUTOR, requires=("widget",),
                produces=("widget_decoded",),
                improves=(IMPROVES_DECODE,),
                confidence_gain=0.5,
            ),
            impl=contract_impl,
        )

        orch = Orchestrator(recognizers=[_R()], max_artifacts=8, max_depth=3)
        orch.run(b"anything", root_type="unknown")

        # BOTH plugins ran exactly once (no double-fire, no missed fire).
        assert legacy.n == 1,          "legacy capability did NOT run"
        assert contract_impl.execution_count == 1, "contract capability did NOT run"
    finally:
        _restore(snap)


def test_no_contracts_means_pure_legacy_path():
    """Prove the orchestrator falls back cleanly to the legacy plan
    when no contracts are registered for the artifact's type."""
    snap = _snap()
    try:
        cap_mod._REGISTRY.clear()
        ct_mod._CONTRACT_REGISTRY.clear()
        ct_mod._IMPL_REGISTRY.clear()

        # Nothing in the contract registry at all.
        orch = Orchestrator(recognizers=[_R()], max_artifacts=4, max_depth=2)
        r = orch.run(b"hello", root_type="unknown")

        # Orchestrator ran to fixed point without crashing.
        cert = r.termination_certificate
        assert cert is not None
        assert cert.fixed_point is True
    finally:
        _restore(snap)
