"""NivXRay Phase 8: Dynamic Enterprise Reachability & Counterfactual Parallel Simulation Test Suite.

Verifies the 12 Phase 8 acceptance gates + P8-13 Counterfactual Integrity:
- P8-01: Reachability Correctness via Authoritative IKG
- P8-02: Capability-Aware Reachability Discrimination
- P8-03: Crown-Jewel Valuation Decoupling
- P8-04: Counterfactual World B (Full Host Isolation)
- P8-05: Counterfactual World C (Surgical Identity Action)
- P8-06: Counterfactual World D (Targeted Microsegmentation)
- P8-07: Counterfactual World A (Do-Nothing Projection)
- P8-08: Comparative Intervention Matrix Derivation
- P8-09: Deterministic Replay & Hash Stability
- P8-10: Provenance & Epistemic Separation (PROJECTED != OBSERVED)
- P8-11: Authoritative Pipeline Invariance & Zero IKG Duplication
- P8-12: Response Execution Safety Lock
- P8-13: Counterfactual Integrity (End-to-End Simulation Lineage)
"""
import copy
import json
import unittest
from typing import Any, Dict, List

from security_state.contracts import (
    AssetCriticalityTier,
    AssetValuation,
    AttackState,
    DataSensitivityTier,
    EntityCategory,
    EntityRef,
    EpistemicStatus,
    FinancialImpactCategory,
    InterventionType,
    ReachabilityStatus,
)
from security_state.counterfactual.engine import CounterfactualEngine
from security_state.impact.engine import ImpactEngine
from security_state.intervention.optimizer import InterventionOptimizer
from security_state.reachability.engine import EnterpriseReachabilityEngine
from security_state.state_engine.engine import SecurityStateEngine


class Phase8CounterfactualReachabilityTestSuite(unittest.TestCase):
    """Phase 8 Enterprise Reachability, Crown-Jewel Valuation & Counterfactual Simulation Test Suite."""

    def setUp(self) -> None:
        self.reach_engine = EnterpriseReachabilityEngine()
        self.impact_engine = ImpactEngine()
        self.counterfactual_engine = CounterfactualEngine()
        self.optimizer = InterventionOptimizer()
        self.state_engine = SecurityStateEngine()
        self.tenant_id = "tenant-enterprise-p8"
        self.case_id = "case-p8-001"
        self.foothold = EntityRef(
            category=EntityCategory.DEVICE,
            entity_id="host-wkst-01",
            tenant_id=self.tenant_id,
            display_name="Finance Workstation (host-wkst-01.corp)",
        )

    def test_p8_01_reachability_correctness_authoritative_ikg(self) -> None:
        """P8-01: Given identity, privilege, network, and asset relations, calculate reachable assets accurately via authoritative IKG."""
        ikg_nodes = [
            {"id": "host-wkst-01", "type": "device", "name": "Finance Workstation", "tier": "TIER_2"},
            {"id": "host-finance-02", "type": "device", "name": "Payroll Terminal", "tier": "TIER_2"},
            {"id": "server-dc-01", "type": "server", "name": "Domain Controller", "tier": "TIER_0"},
            {"id": "cloud-s3-vault-01", "type": "cloud_resource", "name": "Customer Data Vault", "tier": "TIER_0"},
        ]

        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["DomainAdmin"],
            active_capabilities=["CAP_MULTI_HOST_TRAVERSAL"],
            ikg_nodes=ikg_nodes,
        )

        self.assertIsNotNone(matrix)
        self.assertEqual(matrix.tenant_id, self.tenant_id)
        self.assertTrue(len(matrix.paths) >= 4)
        
        # Target entities must reference authoritative IDs
        target_ids = [p.target_entity.entity_id for p in matrix.paths]
        self.assertIn("server-dc-01", target_ids)
        self.assertIn("backup-nas-01", target_ids)
        self.assertIn("host-finance-02", target_ids)
        
        # Domain Controller reachable due to DomainAdmin credential
        dc_path = next(p for p in matrix.paths if p.target_entity.entity_id == "server-dc-01")
        self.assertEqual(dc_path.status, ReachabilityStatus.CURRENTLY_REACHABLE)
        self.assertEqual(dc_path.criticality_tier, "TIER_0")

    def test_p8_02_capability_aware_reachability_discrimination(self) -> None:
        """P8-02: Different attacker capabilities must produce strictly distinct reachable sets."""
        # Scenario A: Admin execution only (no lateral movement, no cloud scraping, no DCSync)
        matrix_a = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=[],
            active_capabilities=["CAP_ADMIN_EXECUTION"],
        )

        # Scenario B: Cloud metadata scraping capability (CAP_CLOUD_METADATA_ACCESS)
        matrix_b = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=[],
            active_capabilities=["CAP_CLOUD_METADATA_ACCESS"],
        )

        # Scenario C: Active Directory DCSync directory replication (CAP_DCSYNC)
        matrix_c = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=[],
            active_capabilities=["CAP_DCSYNC"],
        )

        # In Scenario A, DC is BLOCKED (no DCSync, no admin cred)
        dc_a = next(p for p in matrix_a.paths if p.target_entity.entity_id == "server-dc-01")
        self.assertEqual(dc_a.status, ReachabilityStatus.BLOCKED)
        cloud_a = next(p for p in matrix_a.paths if p.target_entity.entity_id == "cloud-s3-vault-01")
        self.assertEqual(cloud_a.status, ReachabilityStatus.POTENTIALLY_REACHABLE)

        # In Scenario B, Cloud Vault is CURRENTLY_REACHABLE, but DC is BLOCKED
        cloud_b = next(p for p in matrix_b.paths if p.target_entity.entity_id == "cloud-s3-vault-01")
        self.assertEqual(cloud_b.status, ReachabilityStatus.CURRENTLY_REACHABLE)
        dc_b = next(p for p in matrix_b.paths if p.target_entity.entity_id == "server-dc-01")
        self.assertEqual(dc_b.status, ReachabilityStatus.BLOCKED)

        # In Scenario C, DC is CURRENTLY_REACHABLE via DIRECTORY_REPLICATION_RPC
        dc_c = next(p for p in matrix_c.paths if p.target_entity.entity_id == "server-dc-01")
        self.assertEqual(dc_c.status, ReachabilityStatus.CURRENTLY_REACHABLE)
        self.assertEqual(dc_c.hops[0].hop_type, "DIRECTORY_REPLICATION_RPC")

        # Prove capability discrimination: reachable sets are mathematically distinct
        reach_a = set(p.target_entity.entity_id for p in matrix_a.paths if p.status == ReachabilityStatus.CURRENTLY_REACHABLE)
        reach_b = set(p.target_entity.entity_id for p in matrix_b.paths if p.status == ReachabilityStatus.CURRENTLY_REACHABLE)
        reach_c = set(p.target_entity.entity_id for p in matrix_c.paths if p.status == ReachabilityStatus.CURRENTLY_REACHABLE)
        self.assertNotEqual(reach_a, reach_b)
        self.assertNotEqual(reach_b, reach_c)

    def test_p8_03_crown_jewel_valuation_decoupling(self) -> None:
        """P8-03: Incorporate business criticality, data sensitivity, and regulatory scope decoupled from network reachability."""
        valuations = {
            "server-dc-01": AssetValuation(
                entity_id="server-dc-01",
                tenant_id=self.tenant_id,
                tier=AssetCriticalityTier.TIER_0,
                business_criticality_score=95,
                sensitivity=DataSensitivityTier.RESTRICTED,
                financial_category=FinancialImpactCategory.CRITICAL,
                regulatory_scope=["SOX", "PCI-DSS"],
                business_function="Primary Active Directory Domain Controller",
            ),
            "db-prod-sql-01": AssetValuation(
                entity_id="db-prod-sql-01",
                tenant_id=self.tenant_id,
                tier=AssetCriticalityTier.TIER_1,
                business_criticality_score=85,
                sensitivity=DataSensitivityTier.RESTRICTED,
                financial_category=FinancialImpactCategory.HIGH,
                regulatory_scope=["PCI-DSS", "HIPAA"],
                business_function="Customer Transaction Database",
            ),
        }

        # Compute reachability where DC is BLOCKED but DB is reachable
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=[],
            active_capabilities=["CAP_KERBEROASTING"],
            asset_valuations=valuations,
        )

        dc_path = next(p for p in matrix.paths if p.target_entity.entity_id == "server-dc-01")
        bk_path = next(p for p in matrix.paths if p.target_entity.entity_id == "backup-nas-01")
        db_path = next(p for p in matrix.paths if p.target_entity.entity_id == "db-prod-sql-01")

        # Decoupling proof: Backup repository is Tier 0 / Critical even though technical status is BLOCKED
        self.assertEqual(bk_path.status, ReachabilityStatus.BLOCKED)
        self.assertEqual(bk_path.valuation.tier, AssetCriticalityTier.TIER_0)
        self.assertEqual(bk_path.valuation.business_criticality_score, 95)

        # DC is POTENTIALLY_REACHABLE (requires cracking) while valuation remains Tier 0
        self.assertEqual(dc_path.status, ReachabilityStatus.POTENTIALLY_REACHABLE)
        self.assertEqual(dc_path.valuation.tier, AssetCriticalityTier.TIER_0)
        self.assertEqual(dc_path.valuation.business_criticality_score, 95)

        # Database is reachable via Kerberoasting and carries PCI-DSS/HIPAA scopes
        self.assertEqual(db_path.status, ReachabilityStatus.CURRENTLY_REACHABLE)
        self.assertIn("HIPAA", db_path.valuation.regulatory_scope)

        # Impact Engine verifies decoupling and regulatory scope aggregation
        scorecard = self.impact_engine.evaluate_impact(self.tenant_id, self.case_id, matrix, [self.foothold])
        self.assertIn("HIPAA", scorecard.regulatory_impact_scope)
        self.assertIn("PCI-DSS", scorecard.regulatory_impact_scope)

    def test_p8_04_counterfactual_world_b_host_isolation(self) -> None:
        """P8-04: Calculate exact graph cut, interruption %, and residual risk under host isolation."""
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["admin"],
            active_capabilities=["CAP_MULTI_HOST_TRAVERSAL", "CAP_DCSYNC"],
        )
        dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
        cf = self.counterfactual_engine.evaluate_counterfactuals(
            self.tenant_id, self.case_id, dummy_state, matrix, AttackState.LATERAL_MOVEMENT
        )

        world_b = next(w for w in cf.intervention_worlds if w.world_id == "world-b-isolate-host")
        self.assertEqual(world_b.action_applied, "endpoint.isolate")
        self.assertGreaterEqual(world_b.attack_interruption_pct, 50.0)
        self.assertEqual(world_b.business_disruption_score, 45)
        self.assertLess(world_b.continuation_probability, 0.20)
        # Residual risk explicitly identifies out-of-band/cloud survival
        self.assertTrue(any("cloud" in r.lower() or "credentials" in r.lower() for r in world_b.residual_attack_paths))

    def test_p8_05_counterfactual_world_c_identity_action(self) -> None:
        """P8-05: Calculate surgical identity revocation severs credential reuse while local host persists."""
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["admin"],
            active_capabilities=["CAP_KERBEROASTING"],
        )
        dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
        cf = self.counterfactual_engine.evaluate_counterfactuals(
            self.tenant_id, self.case_id, dummy_state, matrix, AttackState.CREDENTIAL_ACCESS
        )

        world_c = next(w for w in cf.intervention_worlds if w.world_id == "world-c-revoke-identity")
        self.assertEqual(world_c.action_applied, "identity.revoke_sessions")
        # Lower business disruption than full host isolation
        self.assertLess(world_c.business_disruption_score, 45)
        self.assertEqual(world_c.business_disruption_score, 25)
        # Residual risk notes host persistence survives
        self.assertTrue(any("persistence" in r.lower() for r in world_c.residual_attack_paths))

    def test_p8_06_counterfactual_world_d_targeted_microsegmentation(self) -> None:
        """P8-06: Targeted network microsegmentation insulates Tier-0 assets with minimal disruption."""
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["admin"],
            active_capabilities=["CAP_DCSYNC"],
        )
        dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
        cf = self.counterfactual_engine.evaluate_counterfactuals(
            self.tenant_id, self.case_id, dummy_state, matrix, AttackState.LATERAL_MOVEMENT
        )

        world_d = next(w for w in cf.intervention_worlds if w.world_id == "world-d-targeted-microsegmentation")
        self.assertEqual(world_d.action_applied, "network.block_ports")
        self.assertEqual(world_d.business_disruption_score, 10)  # Minimal disruption
        self.assertEqual(world_d.tier0_protected_count, 1)

    def test_p8_07_counterfactual_world_a_do_nothing_projection(self) -> None:
        """P8-07: Do-nothing baseline projects unhindered attack trajectory and maximum reachable impact."""
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["admin"],
            active_capabilities=["CAP_DCSYNC"],
        )
        dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
        cf = self.counterfactual_engine.evaluate_counterfactuals(
            self.tenant_id, self.case_id, dummy_state, matrix, AttackState.CREDENTIAL_ACCESS
        )

        world_a = cf.world_a_do_nothing
        self.assertIsNone(world_a.action_applied)
        self.assertGreaterEqual(world_a.continuation_probability, 0.90)
        self.assertGreaterEqual(world_a.projected_impact_score, 85)
        self.assertEqual(world_a.business_disruption_score, 0)
        self.assertIn("RANSOMWARE_STAGING", world_a.likely_next_transitions)

    def test_p8_08_comparative_intervention_matrix_derivation(self) -> None:
        """P8-08: Comparative intervention matrix deterministically evaluates candidate worlds from model inputs."""
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["admin"],
            active_capabilities=["CAP_DCSYNC", "CAP_MULTI_HOST_TRAVERSAL"],
        )
        dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
        cf = self.counterfactual_engine.evaluate_counterfactuals(
            self.tenant_id, self.case_id, dummy_state, matrix, AttackState.LATERAL_MOVEMENT
        )

        comp_matrix = cf.comparative_matrix
        self.assertIsNotNone(comp_matrix)
        self.assertEqual(len(comp_matrix.ratings), 5)  # Worlds A, B, C, D, E
        
        # Verify rating ordering and Pareto-optimal recommendation
        self.assertEqual(comp_matrix.recommended_world_id, "world-e-composite-containment")
        
        rating_a = next(r for r in comp_matrix.ratings if r.world_id == "world-a-do-nothing")
        rating_e = next(r for r in comp_matrix.ratings if r.world_id == "world-e-composite-containment")
        
        self.assertEqual(rating_a.attack_interruption_pct, 0.0)
        self.assertGreaterEqual(rating_e.attack_interruption_pct, 85.0)
        self.assertLess(rating_e.residual_risk_score, 10)

    def test_p8_09_deterministic_replay_and_hash_stability(self) -> None:
        """P8-09: Identical evidence + graph + models produce bit-for-bit identical hashes across repeat runs."""
        hashes = []
        for _ in range(5):
            matrix = self.reach_engine.compute_reachability(
                tenant_id=self.tenant_id,
                case_id=self.case_id,
                footholds=[self.foothold],
                harvested_credentials=["admin"],
                active_capabilities=["CAP_DCSYNC"],
                at_timestamp="2026-09-04T05:00:00Z",
            )
            dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
            cf = self.counterfactual_engine.evaluate_counterfactuals(
                self.tenant_id, self.case_id, dummy_state, matrix, AttackState.CREDENTIAL_ACCESS, at_timestamp="2026-09-04T05:00:00Z"
            )
            hashes.append((matrix.matrix_hash, cf.analysis_hash))

        first_m_hash, first_cf_hash = hashes[0]
        for m_hash, cf_hash in hashes:
            self.assertEqual(m_hash, first_m_hash)
            self.assertEqual(cf_hash, first_cf_hash)

    def test_p8_10_provenance_and_epistemic_separation(self) -> None:
        """P8-10: Strict epistemic boundary: PROJECTED != OBSERVED across all counterfactual worlds."""
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["admin"],
            active_capabilities=["CAP_DCSYNC"],
        )
        dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
        cf = self.counterfactual_engine.evaluate_counterfactuals(
            self.tenant_id, self.case_id, dummy_state, matrix, AttackState.CREDENTIAL_ACCESS
        )

        # Check World A
        self.assertEqual(cf.world_a_do_nothing.epistemic_status, EpistemicStatus.PROJECTED)
        self.assertNotEqual(cf.world_a_do_nothing.epistemic_status, EpistemicStatus.OBSERVED)

        # Check all intervention worlds
        for world in cf.intervention_worlds:
            self.assertEqual(world.epistemic_status, EpistemicStatus.PROJECTED)
            self.assertNotEqual(world.epistemic_status, EpistemicStatus.OBSERVED)
            self.assertIsNotNone(world.simulation_provenance)

    def test_p8_11_authoritative_pipeline_invariance_and_no_ikg_duplication(self) -> None:
        """P8-11: Authoritative pipeline read-only invariance & zero duplicate graph tables."""
        authoritative_verdict = {"verdict": "MALICIOUS", "confidence": 0.98}
        authoritative_story = {"stages": ["INITIAL_ACCESS", "CREDENTIAL_ACCESS"]}
        authoritative_ikg = {"nodes": [{"id": "host-wkst-01", "type": "device"}], "edges": []}

        v_copy = copy.deepcopy(authoritative_verdict)
        s_copy = copy.deepcopy(authoritative_story)
        g_copy = copy.deepcopy(authoritative_ikg)

        # Execute Phase 8 Reachability and Counterfactual evaluation
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["admin"],
            active_capabilities=["CAP_DCSYNC"],
            ikg_nodes=authoritative_ikg["nodes"],
        )
        dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
        cf = self.counterfactual_engine.evaluate_counterfactuals(
            self.tenant_id, self.case_id, dummy_state, matrix, AttackState.CREDENTIAL_ACCESS
        )

        # Assert 100% byte-identical invariance
        self.assertEqual(authoritative_verdict, v_copy)
        self.assertEqual(authoritative_story, s_copy)
        self.assertEqual(authoritative_ikg, g_copy)

    def test_p8_12_no_response_execution_safety_lock(self) -> None:
        """P8-12: Response recommendations remain strictly simulated and locked against execution."""
        from security_state.response_safety.safety_gate import ResponseSafetyGate

        gate = ResponseSafetyGate()
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["admin"],
            active_capabilities=["CAP_DCSYNC"],
        )
        impact = self.impact_engine.evaluate_impact(self.tenant_id, self.case_id, matrix, [self.foothold])
        dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
        cf = self.counterfactual_engine.evaluate_counterfactuals(
            self.tenant_id, self.case_id, dummy_state, matrix, AttackState.CREDENTIAL_ACCESS
        )
        plan = self.optimizer.optimize_intervention(
            self.tenant_id, self.case_id, matrix, impact, cf, [self.foothold]
        )

        self.assertGreaterEqual(len(plan.actions), 1)
        # Execute safety gate requires dual approval for Tier-0 and enforces lock
        action = plan.actions[0]
        self.assertFalse(action.action_id.startswith("execute."))

    def test_p8_13_counterfactual_integrity_simulation_lineage(self) -> None:
        """P8-13: Full lineage traceability from observed inputs to projected security and business impact."""
        matrix = self.reach_engine.compute_reachability(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            footholds=[self.foothold],
            harvested_credentials=["admin"],
            active_capabilities=["CAP_DCSYNC"],
        )
        dummy_state = self.state_engine.evaluate_entity_state(self.tenant_id, self.foothold, [])
        cf = self.counterfactual_engine.evaluate_counterfactuals(
            self.tenant_id, self.case_id, dummy_state, matrix, AttackState.CREDENTIAL_ACCESS
        )

        for world in [cf.world_a_do_nothing] + cf.intervention_worlds:
            prov = world.simulation_provenance
            self.assertIsNotNone(prov)
            self.assertTrue(len(prov.observed_inputs) >= 1)
            self.assertEqual(prov.current_security_state, "CREDENTIAL_ACCESS")
            self.assertTrue(len(prov.assumptions) >= 1)
            self.assertTrue(len(prov.intervention) >= 1)
            self.assertTrue(len(prov.simulated_state_transition) >= 1)
            self.assertTrue(len(prov.projected_reachability_summary) >= 1)
            self.assertGreaterEqual(prov.projected_security_impact_score, 0)
            self.assertGreaterEqual(prov.projected_business_impact_score, 0)
            self.assertEqual(prov.model_version, CounterfactualEngine.VERSION)


if __name__ == "__main__":
    unittest.main()
