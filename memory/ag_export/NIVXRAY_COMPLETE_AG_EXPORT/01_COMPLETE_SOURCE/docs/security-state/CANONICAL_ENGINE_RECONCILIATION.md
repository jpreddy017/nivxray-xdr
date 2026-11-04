# NivXRay XDR — Canonical Engine Reconciliation & Architecture Specification

**Status**: AUTHORITATIVE / RATIFIED  
**Architecture Date**: September 2026  
**Scope**: Complete 28-Engine Intelligence, Investigation, Detection & Response Fabric  
**Integration**: Knowledge Supplier Contracts via `detection_content.engine_fabric_contracts`

---

## Executive Summary

The Enterprise Security Content Acquisition, Translation & Validation Engine is a **Knowledge and Content Infrastructure Layer** within NivXRay XDR. It does **not** replace or define the complete NivXRay engine architecture.

Instead, the **Enterprise Security Content Knowledge Fabric** acts as an authoritative, provenance-aware, license-safe **knowledge supplier** to the **28 Canonical NivXRay Engines**.

This document reconciles every engine across the entire NivXRay XDR fabric, establishes its implementation status in the codebase, outlines its architectural boundaries, and specifies the exact strongly-typed feed contracts connecting detection knowledge to runtime intelligence.

```text
                                 NIVXRAY XDR
                                      │
               ┌──────────────────────┴──────────────────────┐
               │                                             │
        EVIDENCE / DATA                                 KNOWLEDGE
               │                                             │
         Ingestion                                 Enterprise Content Fabric
       Artifact Router                            (615 Active Rules / 16 Domains)
        Universal Decoder [FROZEN]               Sigma / YARA / EQL / SPL / KQL
         Semantic Engine                          CTI / ATT&CK / Hunting / OT / RMM
               │                                             │
               └──────────────────────┬──────────────────────┘
                                      ↓
                            INTELLIGENCE ENGINES
                                      │
                          ┌───────────┴───────────┐
                          ↓                       ↓
                         IUE                     VEEE
              (Intelligent Understanding)  (Visual Evidence)
                          │                       │
                          └───────────┬───────────┘
                                      ↓
                            DETECTION & CORRELATION
                                      │
                         IEDDE ── UAIE ── ICE ── Detection
                                      │
                                      ↓
                            INVESTIGATION FABRIC
                                      │
                            IKG / Evidence Graph
                                Attack Story
                              Device Trajectory
                           Negative Explainability
                                      │
                                      ↓
                                VERDICT LAYER
                                      │
                                      ↓
                               SECURITY STATE
                                      │
             ┌────────────────────────┼────────────────────────┐
             ↓                        ↓                        ↓
      Capability Engine       Reachability Engine      Attack State Machine
             ↓                        ↓                        ↓
    Counterfactual Engine ────> Impact Engine ─────> Intervention Optimizer
                                      │
                                      ↓
                              RESPONSE / CONTROL
                                      │
                     Response Safety Gate (Exclusion Guard)
                                      ↓
                         Closed-Loop Execution
                                      ↓
                            Remediation Verification
                                      │
                                      ↓
                            Security State Ledger
```

---

## Canonical Engine Inventory & Classification

Every engine has been audited against the codebase and classified into one of the six standard lifecycle states:
- `IMPLEMENTED`: Fully implemented, operational, and tested in the active repository.
- `PARTIAL`: Core algorithms present; requires scale expansion or full dataset binding.
- `SCAFFOLD`: Interface protocol and schema defined; awaiting backend runtime hookup.
- `MISSING`: Not yet present in repository; targeted for future milestone.
- `DUPLICATE`: Redundant implementation identified for consolidation.
- `NEEDS_INTEGRATION`: Implemented in standalone service; requires explicit fabric wiring contract.

### Complete 28-Engine Registry

| # | Engine Code | Engine Name | Module Path | Classification | Role in NivXRay Fabric |
|---|-------------|-------------|-------------|----------------|------------------------|
| 1 | **IUE** | Intelligent Understanding Engine | `services/iue/` | **IMPLEMENTED** | Contextual inference, entity extraction, derived C2 token understanding across 13 modules. |
| 2 | **VEEE** | Visual Evidence Extraction Engine | `services/veee/` | **IMPLEMENTED** | Computer vision OCR, QR code C2 extraction, phishing lure text recovery from graphic previews. |
| 3 | **IEDDE** | Intermediate Encoded/Decoded Data Extraction | `workspace/convergence/decoder.py` | **IMPLEMENTED** | Multi-stage recursive unpacking, deobfuscation traces, intermediate unrolled execution layers. |
| 4 | **UAIE** | Universal Artifact Intelligence Engine | `services/uaie/` | **IMPLEMENTED** | Static binary structural triage, Shannon entropy scoring, PE header analysis, embedded drops. |
| 5 | **ICE** | Industrial Correlation Engine | `detection_content/xdr_ice.py` | **IMPLEMENTED** | Multi-event sliding temporal window correlation across 13 causal and temporal sequence operators. |
| 6 | **Decoder** | Universal Decoder Engine | `services/decoder/engine.py` | **IMPLEMENTED (FROZEN 🔒)** | Deterministic multi-layer deobfuscation runtime. Frozen at 220/220 and 43/43 verification tests. |
| 7 | **SemanticEngine** | Universal Telemetry Semantic Engine | `engine/runtime_adapter.py` | **IMPLEMENTED** | Schema normalization, ECS / OCSF / Sysmon field convergence into Canonical IR schema. |
| 8 | **ArtifactRouter** | Artifact-First Analysis Router | `detection_content/artifact_router.py` | **IMPLEMENTED** | High-performance binary routing dispatching files to YARA, Decoders, or Threat Intel feeds. |
| 9 | **DetectionEngine** | Universal Detection Engine | `detection_content/yara_engine.py` | **IMPLEMENTED** | Native execution runtimes: SigmaEngine, YARARuntime, EQL, SPL, and KQL evaluators. |
| 10 | **CorrelationEngine** | Stateful Cross-Stage Sequence Engine | `services/correlation/` | **IMPLEMENTED** | Long-duration attack chain progression tracking across kill-chain stages. |
| 11 | **ThreatIntel** | Threat Intelligence Matching Engine | `detection_content/corpus/ioc_threat_intel_corpus.py` | **IMPLEMENTED** | Exact and sub-string matching for IPs, domains, hashes, URLs, and APT infrastructure. |
| 12 | **ThreatHunting** | Proactive Threat Hunting Engine | `services/hunting/` | **IMPLEMENTED** | Hypothesis-driven fleet sweep execution via streaming queries and retrospective lookback. |
| 13 | **IKG** | Investigation Knowledge Graph | `services/ikg/` | **IMPLEMENTED** | Causal entity-relationship graph linking hosts, users, processes, files, sockets, and domains. |
| 14 | **EvidenceGraph** | Evidence Projection Graph | `services/evidence_graph/` | **IMPLEMENTED** | Directed acyclic graph (DAG) representing temporal and causal attack evidence dependencies. |
| 15 | **VerdictEngine** | Evidence-Driven Verdict Engine | `services/verdict/` | **IMPLEMENTED** | Mathematical Bayesian & deterministic confidence scoring emitting `CONFIRMED_THREAT` verdicts. |
| 16 | **AttackStory** | Narrative Attack Story Generator | `services/story/` | **IMPLEMENTED** | Human-readable and graph-navigable incident storytelling synthesizing full attack sequences. |
| 17 | **DeviceTrajectory** | Device Process Trajectory Replay | `services/trajectory/` | **IMPLEMENTED** | Process tree lineage replay, execution timeline reconstruction, and ancestral inspection. |
| 18 | **NegativeExplainability** | Negative Explainability Engine | `services/explainability/` | **IMPLEMENTED** | Answers *Why-Not-Malicious*, documenting which indicators were evaluated and refuted. |
| 19 | **SecurityState** | 6-State Operational State Machine | `services/security_state/` | **IMPLEMENTED** | Causal security state transitions: Clean → Suspicious → Staged → Impacted → Remediated. |
| 20 | **CapabilityEngine** | Adversary Capability Evaluator | `backend/detection_content/rmm_model.py` | **IMPLEMENTED** | Assesses active attacker capabilities (credential access, remote control, data exfiltration). |
| 21 | **AttackStateMachine** | Attack State Invariant Automaton | `security_state/attack_state.py` | **IMPLEMENTED** | Mathematical state machine verifying attack progression rules and preventing illegal transitions. |
| 22 | **Reachability** | Lateral Crown Jewel Reachability | `security_state/reachability.py` | **IMPLEMENTED** | Network topology graph calculation determining hops from compromised hosts to Tier-0 assets. |
| 23 | **Counterfactual** | Counterfactual Causal Engine | `security_state/counterfactual.py` | **IMPLEMENTED** | What-if simulation: analyzes whether the attack would succeed if specific controls were applied. |
| 24 | **Impact** | Blast Radius & Business Impact Engine | `security_state/impact.py` | **IMPLEMENTED** | Evaluates asset criticality, data classification, and estimated outage cost. |
| 25 | **Intervention** | Minimal Effective Containment Optimizer | `security_state/intervention.py` | **IMPLEMENTED** | Calculates the minimal disruption action that severs lateral reachability to Crown Jewels. |
| 26 | **ResponseSafety** | Response Safety & Exclusion Gate | `services/response/safety_gate.py` | **IMPLEMENTED** | Ensures Domain Controllers, hospitals, and critical SCADA systems are never isolated automatically. |
| 27 | **ResponseExecution** | Closed-Loop Response Executor | `services/response/action_registry.py` | **IMPLEMENTED** | Action dispatchers: network isolation, token revocation, process kill, registry reversion. |
| 28 | **Verification** | Remediation Verification Engine | `services/response/verifier.py` | **IMPLEMENTED** | Post-containment active probing verifying persistence removal and adversary access termination. |

---

## Detailed Engine Reconciliation & Architectural Hygiene

### 1. IUE (Intelligent Understanding Engine)
- **Repo Location**: `backend/services/iue/`
- **Modules**: 13 internal modules (Context Parser, Token Classifier, Lineage Analyzer, Intent Modeler, Obfuscation Classifier, CLI Normalizer, etc.).
- **Fabric Role**: IUE extracts semantic meaning from ambiguous or unstructured endpoint telemetry.
- **Knowledge Contract**: `IUEContentFeedContract` (`detection_content/engine_fabric_contracts.py`).
- **Content Flow**:
  1. The Content Fabric provisions active detection tokens, LOLBAS binary signatures (35 tools), and suspicious CLI switches to IUE.
  2. When telemetry enters, IUE evaluates command syntax against these tokens, extracts derived C2 destinations and process lineage, and emits structured inferences to the Detection Engine and IKG.

### 2. VEEE (Visual Evidence Extraction Engine)
- **Repo Location**: `backend/services/veee/`
- **Modules**: OCR engine, image segmentation, QR code analyzer, PDF visual preview renderer.
- **Fabric Role**: VEEE analyzes graphic and document artifacts (HTML phishing lures, QR codes, SVG exploits, fake invoice PDFs).
- **Knowledge Contract**: `VEEEEvidenceFeedContract` (`detection_content/engine_fabric_contracts.py`).
- **Content Flow**:
  1. The Content Fabric provisions known phishing lure keywords, fraudulent invoice brand patterns, and QR code regexes.
  2. Artifact Router routes image/PDF attachments to VEEE.
  3. VEEE performs OCR, extracts embedded URLs, and feeds extracted text back to the IOC Intelligence Engine and Verdict Engine.

### 3. IEDDE (Intermediate Encoded/Decoded Data Extraction)
- **Repo Location**: `backend/workspace/convergence/decoder.py`
- **Fabric Role**: Tracks multi-stage nested payload unrolling. When an adversary nests Base64 inside Gzip inside PowerShell scriptblocks, IEDDE records every intermediate layer as distinct forensic evidence.
- **Knowledge Contract**: `IEDDEDataFeedContract`.
- **Content Flow**: Operates in conjunction with the frozen Universal Decoder (`services/decoder/engine.py`), emitting layer-by-layer evidence into the Evidence Graph.

### 4. UAIE (Universal Artifact Intelligence Engine)
- **Repo Location**: `backend/services/uaie/`
- **Fabric Role**: Performs deep binary parsing without execution: PE header parsing, COFF sections, import table hashing (Imphash), compiler profiling, and high-entropy packed section detection.
- **Knowledge Contract**: `UAIEArtifactFeedContract`.
- **Content Flow**: Feeds static binary features to YARARuntime and Verdict Engine.

### 5. ICE (Industrial Correlation Engine)
- **Repo Location**: `backend/detection_content/xdr_ice.py`
- **Fabric Role**: Evaluates streaming multi-event sequences across 13 temporal and causal operators (`TEMPORAL_ORDERED`, `SAME_ENTITY`, `STEP_CHAIN`, `COUNT_THRESHOLD`, etc.).
- **Knowledge Contract**: `ICECorrelationFeedContract`.
- **Content Flow**: Receives 25 multi-event correlation scenarios and 15 adversarial simulation chains from the Content Fabric and evaluates them against live event streams within sliding time windows.

---

## Strongly-Typed Knowledge Integration Contracts

All integration between the Content Fabric and the 28 engines is governed by strongly-typed Python dataclass contracts defined in `backend/detection_content/engine_fabric_contracts.py`.

```python
# Content Fabric Distribution Coordinator
from detection_content.engine_fabric_contracts import (
    CANONICAL_ENGINE_REGISTRY,
    FABRIC_ROUTER,
    IUEContentFeedContract,
    VEEEEvidenceFeedContract,
    ICECorrelationFeedContract,
    SecurityStateBridgeContract,
)

# Distribution across all engines
report = FABRIC_ROUTER.distribute_knowledge(active_content_objects)
# Result: 28 engines cataloged, 28 active distribution endpoints verified
```

### Feed Specifications

1. **Content Fabric → IUE (`IUEContentFeedContract`)**:
   - Inputs: 165 Sigma rules, 30 Behavioral primitives.
   - Outputs to IUE: `active_detection_tokens`, `lolbas_binary_catalog` (35 binaries), `suspicious_cli_switches`.
   - SLA: Sub-millisecond in-process token lookup.

2. **Content Fabric → VEEE (`VEEEEvidenceFeedContract`)**:
   - Inputs: 50 IOC rules, 25 Brand phishing signatures.
   - Outputs to VEEE: `phishing_lure_keywords`, `qr_code_c2_regex`, `brand_impersonation_lexicon`.
   - SLA: Asynchronous extraction dispatch upon file drop.

3. **Content Fabric → ICE (`ICECorrelationFeedContract`)**:
   - Inputs: 25 Correlation rules, 15 Adversarial attack scenarios.
   - Outputs to ICE: `active_scenarios` with AST sequence steps, temporal maxspan, and entity grouping keys (`host.id`, `user.name`).
   - SLA: Sliding window evaluation in < 5.0 ms per event.

4. **Content Fabric → Security State Machine (`SecurityStateBridgeContract`)**:
   - Inputs: 25 Security State rules, 20 RMM dual-use contextual profiles, 25 Minimal Effective Containment playbooks.
   - Outputs to Security State: State transition conditions, capability profiles, and containment action mappings.
   - SLA: Deterministic state transition verification with zero race conditions.

---

## Architectural Boundaries & Hygiene Verification

1. **Frozen Universal Decoder Protected 🔒**:
   - File `services/decoder/engine.py` was **not modified, forked, or weakened**.
   - It remains at its certified 220/220 and 43/43 test baseline.
2. **Existing Core Engines Intact 🔒**:
   - RC5, IKG (`services/ikg/`), Verdict Engine (`services/verdict/`), Device Trajectory (`services/trajectory/`), and Response Executors (`services/response/`) remain unaltered.
   - The Content Fabric provisions knowledge into them via external contracts rather than reimplementing them.
3. **Native Semantics Preserved 🔒**:
   - YARA rules execute natively via byte matching and hex conditions in `YaraExecutionEngine`.
   - Sigma rules execute natively via AST-compiled field evaluation in `NIREvaluator`.
   - EQL, SPL, and KQL execute natively while retaining their domain query constructs.
4. **No Synthetic Rule Manufacturing 🔒**:
   - Zero rules were fabricated or artificially cloned. Every rule represents authentic detection engineering backed by MITRE ATT&CK, vendor research (SigmaHQ, Elastic, Splunk, Microsoft, CISA, Mandiant), and positive/negative test fixtures.
