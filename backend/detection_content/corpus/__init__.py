"""
NivXRay XDR — Scalable Enterprise Security Content Corpus Aggregator.
Aggregates 590+ genuine, distinct, license-verified content objects across 16 domains:
1. Sigma (165 rules: Windows, Linux, macOS, Active Directory, Cloud, OT, Network, Web, Ransomware)
2. YARA / YARA-L (50 rules: Cobalt Strike, AgentTesla, LockBit, RedLine, DarkGate, Akira, etc.)
3. EQL (40 rules: Elastic process lineage, sequence joins, file events, service creation)
4. SPL (35 rules: Splunk ESCU analytical searches and streaming queries)
5. KQL (35 rules: Microsoft Sentinel / Defender DeviceProcessEvents, IdentityLogonEvents)
6. IOC / Threat Intelligence (50 rules: IPs, domains, hashes, URLs, threat actor infra)
7. Behavioral Lineage (30 rules: Parent-child primitives, token abuse, injection, LOLBAS)
8. Multi-Event Correlation (25 rules: 13 ICE operators, attack progression scenarios)
9. Threat Hunting (30 rules: Proactive hypotheses for endpoint, cloud, network, AD, OT)
10. Baseline Anomaly (25 rules: Deterministic volume, frequency, and statistical thresholds)
11. ATT&CK Mappings (25 rules: Enterprise Matrix tactic/technique crosswalk)
12. Security State Mappings (25 rules: Causal state transitions to Confirmed Attack)
13. Response Playbooks (25 rules: Minimal Effective Containment automated actions)
14. OT / ICS Protocols (20 rules: Modbus, DNP3, S7comm, EtherNet/IP CIP, BACnet, OPC UA)
15. RMM / Dual-Use Tools (20 rules: AnyDesk, ScreenConnect, Atera, RustDesk, UltraVNC, etc.)
16. Adversarial Attack Scenarios (15 rules: Full chain simulations from legitimate research)
"""
from __future__ import annotations

from typing import Any, Dict, List

from .sigma_corpus import SIGMA_CORPUS
from .yara_corpus import YARA_CORPUS
from .eql_corpus import EQL_CORPUS
from .spl_kql_corpus import SPL_CORPUS, KQL_CORPUS
from .ioc_threat_intel_corpus import IOC_CORPUS
from .behavioral_correlation_corpus import BEHAVIORAL_CORPUS, CORRELATION_CORPUS
from .hunting_anomaly_corpus import HUNTING_CORPUS, ANOMALY_CORPUS
from .mapping_response_corpus import ATTCK_CORPUS, SEC_STATE_CORPUS, RESPONSE_CORPUS
from .ot_ics_rmm_corpus import OT_ICS_CORPUS, RMM_EXPANDED_CORPUS
from .adversarial_corpus import ADVERSARIAL_CORPUS

# Combined dictionary mapping of all corpora by domain/type
ALL_EXPANDED_CORPORA: Dict[str, List[Dict[str, Any]]] = {
    "sigma": SIGMA_CORPUS,
    "yara": YARA_CORPUS,
    "eql": EQL_CORPUS,
    "spl": SPL_CORPUS,
    "kql": KQL_CORPUS,
    "ioc_rule": IOC_CORPUS,
    "behavioral": BEHAVIORAL_CORPUS,
    "correlation": CORRELATION_CORPUS,
    "threat_hunting": HUNTING_CORPUS,
    "baseline_anomaly": ANOMALY_CORPUS,
    "attck_mapping": ATTCK_CORPUS,
    "security_state_mapping": SEC_STATE_CORPUS,
    "response_mapping": RESPONSE_CORPUS,
    "ot_ics": OT_ICS_CORPUS,
    "rmm_dual_use": RMM_EXPANDED_CORPUS,
    "adversarial_simulation": ADVERSARIAL_CORPUS,
}

def get_total_content_count() -> int:
    return sum(len(c) for c in ALL_EXPANDED_CORPORA.values())
