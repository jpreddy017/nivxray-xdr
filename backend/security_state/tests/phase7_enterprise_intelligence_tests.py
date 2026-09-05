"""NivXRay Phase 7: Enterprise Security Intelligence Expansion & Temporal Progression Test Suite.

Verifies the 10 Phase 7 acceptance gates:
- P7-01: Pre-Attack Trajectory & Grounded Likelihood (Likelihood != probability)
- P7-02: RMM Contextual Discrimination (Authorized IT vs Silent Staging)
- P7-03: Active Directory NTDS.dit Extraction via Volume Shadow Copy
- P7-04: AS-REP Roasting & Kerberos Ticket Forgery
- P7-05: AD CS Certificate Template Abuse (ESC1)
- P7-06: Cloud IMDS Token Theft & Pivot (169.254.169.254)
- P7-07: Ransomware Precursor VSS & Backup Destruction
- P7-08: Hypervisor / ESXi VM Termination
- P7-09: Post-Attack Residual Risk Evaluation (attack_is_active vs environment_is_vulnerable)
- P7-10: Authoritative Pipeline Invariance & Deterministic Replay
"""
import copy
import json
import unittest
from typing import Any, Dict, List

from security_state.contracts import (
    AttackState,
    CapabilityStatus,
    EntityCategory,
    EntityRef,
    EpistemicStatus,
    ReachabilityStatus,
    TemporalAttackPhase,
)
from security_state.capability.engine import (
    CapabilityCategory,
    CapabilityContext,
    TrustedCapabilityAbuseEngine,
)
from security_state.causal.engine import CausalSecurityEngine
from security_state.progression.engine import TemporalProgressionEngine
from security_state.reachability.engine import EnterpriseReachabilityEngine
from security_state.state_engine.engine import SecurityStateEngine


class Phase7EnterpriseIntelligenceTestSuite(unittest.TestCase):
    """Phase 7 Enterprise Security Intelligence and Temporal Attack Progression Test Suite."""

    def setUp(self) -> None:
        self.progression_engine = TemporalProgressionEngine()
        self.capability_engine = TrustedCapabilityAbuseEngine()
        self.causal_engine = CausalSecurityEngine()
        self.state_engine = SecurityStateEngine()
        self.reachability_engine = EnterpriseReachabilityEngine()
        self.tenant_id = "tenant-enterprise-p7"
        self.case_id = "case-p7-001"

    def test_p7_01_pre_attack_trajectory_and_grounded_likelihood(self) -> None:
        """P7-01: Pre-attack trajectory predicts Kerberoasting with explicit missing evidence and next actions."""
        # Telemetry: Precursor events (SPN enumeration + service account LDAP filter query)
        events = [
            {
                "id": "ev-p7-01a",
                "timestamp": "2026-09-04T02:00:00Z",
                "process_name": "powershell.exe",
                "command_line": "Get-NetUser -SPN | Select-Object samaccountname, serviceprincipalname",
                "action": "directory_enumeration",
                "user": "corp\\jdoe",
                "is_authorized_admin": False,
            },
            {
                "id": "ev-p7-01b",
                "timestamp": "2026-09-04T02:01:30Z",
                "process_name": "powershell.exe",
                "command_line": "Get-ADUser -Filter {admincount -eq 1 -and serviceprincipalname -like '*'} -Properties *",
                "action": "ad_query",
                "user": "corp\\jdoe",
                "is_authorized_admin": False,
            }
        ]

        assessment, residual = self.progression_engine.evaluate_progression(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            events=events,
            causal_facts=[],
            capabilities=[],
        )

        # 1. Verify Phase is PRE_ATTACK and Status is LIKELY
        self.assertEqual(assessment.phase, TemporalAttackPhase.PRE_ATTACK)
        self.assertEqual(assessment.epistemic_status, EpistemicStatus.LIKELY)
        self.assertEqual(assessment.chain_name, "Kerberoasting Credential Harvesting")

        # 2. Verify Likelihood != probability (deterministic score grounded in evidence)
        self.assertGreaterEqual(assessment.risk_score, 30.0)
        self.assertLessEqual(assessment.risk_score, 75.0)

        # 3. Verify Completed Stages (2 of 5)
        self.assertEqual(assessment.total_expected_stages, 5)
        self.assertIn("SPN_ENUMERATION", assessment.completed_stages)
        self.assertIn("ANOMALOUS_ACCOUNT_DISCOVERY", assessment.completed_stages)
        self.assertEqual(assessment.progression_ratio, 0.4)

        # 4. Verify Grounded Evidence, Contradictions, Missing Telemetry, and Next Expected Behaviors
        self.assertGreaterEqual(len(assessment.supporting_evidence_ids), 1)
        self.assertEqual(len(assessment.contradictory_evidence_ids), 0)
        self.assertTrue(any("4769" in m for m in assessment.missing_telemetry_indicators))
        self.assertTrue(any("TGS" in n for n in assessment.next_expected_behaviors))
        self.assertTrue(any("ASSUMED" in a for a in assessment.explicit_assumptions))
        self.assertTrue(assessment.potential_impact_projection.startswith("PROJECTED:"))

    def test_p7_02_rmm_contextual_discrimination(self) -> None:
        """P7-02: Differentiate authorized IT ScreenConnect from silent weaponized RustDesk staging."""
        # Scenario A: Authorized IT Support ScreenConnect
        ctx_admin = CapabilityContext(
            capability_name="screenconnect",
            identity_ref=EntityRef(EntityCategory.USER, "user-it-admin", self.tenant_id),
            is_authorized_admin=True,
            source_ip_or_subnet="10.0.10.5",
            destination_ip_or_domain="screenconnect.corp.local",
            timestamp="2026-09-04T10:00:00Z",
            is_within_business_hours=True,
            command_line="screenconnect.client.exe /connect /ticket:INC-94810",
            parent_process="explorer.exe",
            process_privilege_level="ADMIN",
        )
        eval_admin = self.capability_engine.evaluate_capability(self.tenant_id, ctx_admin, ["ev-rmm-legit"])
        self.assertEqual(eval_admin.status, CapabilityStatus.AUTHORIZED_USE)
        self.assertIsNone(eval_admin.reversal_action_recommendation)

        # Scenario B: Silent RustDesk installation with reverse proxy
        ctx_evil = CapabilityContext(
            capability_name="rustdesk",
            identity_ref=EntityRef(EntityCategory.USER, "user-compromised", self.tenant_id),
            is_authorized_admin=False,
            source_ip_or_subnet="192.168.1.50",
            destination_ip_or_domain="relay.rustdesk.com",
            timestamp="2026-09-04T03:30:00Z",
            is_within_business_hours=False,
            command_line="rustdesk.exe --silent-install --service --import-config payload.toml",
            parent_process="word.exe",
            process_privilege_level="SYSTEM",
            has_inbound_tunnel_or_proxy=True,
        )
        eval_evil = self.capability_engine.evaluate_capability(self.tenant_id, ctx_evil, ["ev-rmm-evil"])
        self.assertEqual(eval_evil.status, CapabilityStatus.CONFIRMED_ATTACK)
        self.assertIsNotNone(eval_evil.reversal_action_recommendation)
        self.assertIn("Silent background installation", " ".join(eval_evil.reasons))

    def test_p7_03_active_directory_ntds_extraction_chain(self) -> None:
        """P7-03: Detect Active Directory ntds.dit volume shadow copy extraction."""
        events = [
            {
                "id": "ev-ntds-01",
                "process_name": "vssadmin.exe",
                "command_line": "vssadmin.exe create shadow /for=C:",
                "timestamp": "2026-09-04T03:00:00Z",
                "pid": 2100,
                "is_authorized_admin": False,
            },
            {
                "id": "ev-ntds-02",
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\temp\\ntds.dit",
                "timestamp": "2026-09-04T03:00:05Z",
                "ppid": 2100,
                "pid": 2105,
            }
        ]

        graph = self.causal_engine.evaluate_causality(self.tenant_id, self.case_id, events)
        self.assertGreaterEqual(len(graph.edges), 1)
        edge = [e for e in graph.edges if e.mechanism.mechanism_type == "VSS_NTDS_EXTRACTION"][0]
        self.assertEqual(edge.mechanism.mechanism_type, "VSS_NTDS_EXTRACTION")
        self.assertEqual(edge.competing_hypotheses[0].hypothesis_id, "hyp-scheduled-system-state-backup")
        self.assertEqual(edge.competing_hypotheses[0].status, "REFUTED")

        # State engine verifies CAP_NTDS_EXTRACTION
        entity = EntityRef(EntityCategory.DEVICE, "device-dc01", self.tenant_id)
        state = self.state_engine.evaluate_entity_state(self.tenant_id, entity, events)
        self.assertIn("CAP_NTDS_EXTRACTION", state.active_capabilities)
        self.assertEqual(state.classification, CapabilityStatus.CONFIRMED_ATTACK)

    def test_p7_04_asrep_roasting_causal_chain(self) -> None:
        """P7-04: Detect AS-REP Roasting targeting accounts without pre-authentication."""
        events = [
            {
                "id": "ev-asrep-01",
                "process_name": "powershell.exe",
                "command_line": "Get-ASREPRoast -Domain corp.local -Format Hashcat",
                "timestamp": "2026-09-04T04:00:00Z",
                "pid": 3000,
            },
            {
                "id": "ev-asrep-02",
                "process_name": "lsass.exe",
                "command_line": "lsass.exe AS-REQ processing",
                "timestamp": "2026-09-04T04:00:01Z",
                "event_code": "4768",
                "preauth_type": "0",
                "action": "kerberos.asrep_dump",
            }
        ]

        graph = self.causal_engine.evaluate_causality(self.tenant_id, self.case_id, events)
        asrep_edges = [e for e in graph.edges if e.mechanism.mechanism_type == "KERBEROS_ASREP_ROAST"]
        self.assertEqual(len(asrep_edges), 1)
        self.assertEqual(asrep_edges[0].competing_hypotheses[0].hypothesis_id, "hyp-legacy-kerberos-app-auth")

        entity = EntityRef(EntityCategory.DEVICE, "device-ws01", self.tenant_id)
        state = self.state_engine.evaluate_entity_state(self.tenant_id, entity, events)
        self.assertIn("CAP_ASREP_ROASTING", state.active_capabilities)

    def test_p7_05_adcs_certificate_template_abuse(self) -> None:
        """P7-05: Detect Active Directory Certificate Services (AD CS) template abuse (ESC1)."""
        events = [
            {
                "id": "ev-adcs-01",
                "process_name": "certify.exe",
                "command_line": "certify.exe find /vulnerable /domain:corp.local",
                "timestamp": "2026-09-04T05:00:00Z",
                "pid": 4100,
            },
            {
                "id": "ev-adcs-02",
                "process_name": "certreq.exe",
                "command_line": "certreq.exe -submit -attrib \"CertificateTemplate:WebServerESC1\\nSAN:upn=administrator@corp.local\"",
                "timestamp": "2026-09-04T05:01:00Z",
                "action": "pki.template_abuse",
            }
        ]

        graph = self.causal_engine.evaluate_causality(self.tenant_id, self.case_id, events)
        adcs_edges = [e for e in graph.edges if e.mechanism.mechanism_type == "CERTIFICATE_SERVICES_ENROLLMENT_RPC"]
        self.assertEqual(len(adcs_edges), 1)

        entity = EntityRef(EntityCategory.DEVICE, "device-ws02", self.tenant_id)
        state = self.state_engine.evaluate_entity_state(self.tenant_id, entity, events)
        self.assertIn("CAP_ADCS_ABUSE", state.active_capabilities)

    def test_p7_06_cloud_imds_token_theft(self) -> None:
        """P7-06: Detect Cloud Instance Metadata Service (IMDS) token scraping at 169.254.169.254."""
        events = [
            {
                "id": "ev-imds-01",
                "process_name": "curl.exe",
                "command_line": "curl.exe -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ProdWorkerRole",
                "timestamp": "2026-09-04T06:00:00Z",
                "pid": 5010,
            },
            {
                "id": "ev-imds-02",
                "process_name": "python.exe",
                "command_line": "python.exe exfil_s3.py --access-key AKIA... --secret ...",
                "timestamp": "2026-09-04T06:00:05Z",
                "action": "token_extracted",
            }
        ]

        graph = self.causal_engine.evaluate_causality(self.tenant_id, self.case_id, events)
        imds_edges = [e for e in graph.edges if e.mechanism.mechanism_type == "METADATA_SERVICE_TOKEN_EXTRACTION"]
        self.assertEqual(len(imds_edges), 1)

        entity = EntityRef(EntityCategory.CLOUD_RESOURCE, "cloud-vm-prod", self.tenant_id)
        state = self.state_engine.evaluate_entity_state(self.tenant_id, entity, events)
        self.assertIn("CAP_CLOUD_METADATA_ACCESS", state.active_capabilities)

        # Reachability projects cloud S3 vault as CURRENTLY_REACHABLE
        reach = self.reachability_engine.compute_reachability(
            self.tenant_id, self.case_id, [entity], [], state.active_capabilities
        )
        s3_path = [p for p in reach.paths if p.target_entity.category == EntityCategory.CLOUD_RESOURCE][0]
        self.assertEqual(s3_path.status, ReachabilityStatus.CURRENTLY_REACHABLE)

    def test_p7_07_ransomware_precursor_backup_destruction(self) -> None:
        """P7-07: Detect ransomware precursor volume shadow copy and backup catalog purge."""
        events = [
            {
                "id": "ev-vss-01",
                "process_name": "vssadmin.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "timestamp": "2026-09-04T07:00:00Z",
                "pid": 6001,
            },
            {
                "id": "ev-wbadmin-02",
                "process_name": "wbadmin.exe",
                "command_line": "wbadmin.exe delete catalog -quiet",
                "timestamp": "2026-09-04T07:00:10Z",
                "pid": 6005,
            }
        ]

        graph = self.causal_engine.evaluate_causality(self.tenant_id, self.case_id, events)
        self.assertTrue(any(e.mechanism.mechanism_type in ("VSS_SNAPSHOT_DELETION", "BACKUP_CATALOG_DELETION") for e in graph.edges))

        entity = EntityRef(EntityCategory.DEVICE, "device-srv-file01", self.tenant_id)
        state = self.state_engine.evaluate_entity_state(self.tenant_id, entity, events)
        self.assertIn("CAP_SHADOW_COPY_DELETION", state.active_capabilities)
        self.assertIn("CAP_BACKUP_TAMPERING", state.active_capabilities)

    def test_p7_08_hypervisor_vm_termination(self) -> None:
        """P7-08: Detect ESXi hypervisor VM process termination."""
        events = [
            {
                "id": "ev-esx-01",
                "process_name": "esxcli",
                "command_line": "esxcli vm process kill --type=force --world-id=104928",
                "timestamp": "2026-09-04T08:00:00Z",
                "pid": 7001,
            },
            {
                "id": "ev-esx-02",
                "process_name": "esxcli",
                "command_line": "esxcli vm process kill --type=force --world-id=104929",
                "timestamp": "2026-09-04T08:00:02Z",
                "pid": 7002,
            }
        ]

        graph = self.causal_engine.evaluate_causality(self.tenant_id, self.case_id, events)
        esx_edges = [e for e in graph.edges if e.mechanism.mechanism_type == "ESXI_VIRTUAL_MACHINE_KILL"]
        self.assertEqual(len(esx_edges), 1)

        entity = EntityRef(EntityCategory.VIRTUALIZATION_HOST, "host-esxi-01", self.tenant_id)
        state = self.state_engine.evaluate_entity_state(self.tenant_id, entity, events)
        self.assertIn("CAP_HYPERVISOR_COMPROMISE", state.active_capabilities)

    def test_p7_09_post_attack_residual_risk_evaluation(self) -> None:
        """P7-09: Separately answer: A) Is attack active? B) Can attacker continue/re-enter?"""
        # Scenario: Endpoint process was contained/terminated, but stolen Kerberos tickets remain unrevoked
        # and lateral paths to adjacent endpoints remain open in IKG.
        events = [
            {
                "id": "ev-tgs-stolen",
                "command_line": "rubeus.exe kerberoast /outfile:hashes.txt",
                "timestamp": "2026-09-04T09:00:00Z",
                "action": "kerberos.tgs_request",
            }
        ]
        containment = [
            {
                "action": "endpoint.terminate_process",
                "status": "ACTION_EXECUTED",
                "timestamp": "2026-09-04T09:15:00Z",
            }
        ]
        ikg_nodes = [
            {"id": "device::host-01", "type": "device"},
            {"id": "device::host-02", "type": "device"},
            {"id": "server::dc-01", "type": "server"},
        ]

        assessment, residual = self.progression_engine.evaluate_progression(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            events=events,
            causal_facts=[],
            capabilities=[],
            ikg_nodes=ikg_nodes,
            containment_actions=containment,
        )

        # A: Is the attacker still active? -> FALSE (Process was terminated/contained)
        self.assertFalse(residual.attack_is_active)
        self.assertEqual(assessment.phase, TemporalAttackPhase.POST_ATTACK)

        # B: Is the environment still vulnerable to re-entry or continuation? -> TRUE!
        self.assertTrue(residual.environment_is_vulnerable)
        self.assertEqual(residual.reentry_risk_level, EpistemicStatus.LIKELY)
        self.assertGreaterEqual(len(residual.exposed_unrevoked_credentials), 1)
        self.assertGreaterEqual(len(residual.open_lateral_traversal_paths), 1)
        self.assertIn("identity.revoke_kerberos_tickets", residual.recommended_remediation_locks)

    def test_p7_10_authoritative_invariance_and_deterministic_replay(self) -> None:
        """P7-10: Pipeline invariance and bit-identical deterministic progression replay."""
        authoritative_case = {
            "case_id": self.case_id,
            "verdict_band": "SUSPICIOUS",
            "verdicts": ["SUSPICIOUS_SCRIPT_EXECUTION"],
            "story": "PowerShell initiated service principal enumeration.",
            "ikg": {
                "nodes": [{"id": "device::host-01", "type": "device"}, {"id": "user::bob", "type": "user"}],
                "edges": [{"source": "user::bob", "target": "device::host-01", "relation": "LOGGED_INTO"}],
            }
        }
        case_snapshot = json.dumps(authoritative_case, sort_keys=True)

        events = [
            {
                "id": "ev-rep-01",
                "process_name": "powershell.exe",
                "command_line": "Get-NetUser -SPN",
                "timestamp": "2026-09-04T10:00:00Z",
            }
        ]

        # Replay Run 1
        a1, r1 = self.progression_engine.evaluate_progression(self.tenant_id, self.case_id, events, [], [])
        # Replay Run 2
        a2, r2 = self.progression_engine.evaluate_progression(self.tenant_id, self.case_id, events, [], [])

        # Assert bit-identical replay
        self.assertEqual(a1.to_dict(), a2.to_dict())
        self.assertEqual(r1.to_dict(), r2.to_dict())
        self.assertEqual(a1.risk_score, a2.risk_score)
        self.assertEqual(a1.completed_stages, a2.completed_stages)

        # Assert authoritative pipeline was NOT modified
        self.assertEqual(json.dumps(authoritative_case, sort_keys=True), case_snapshot)


if __name__ == "__main__":
    unittest.main()
