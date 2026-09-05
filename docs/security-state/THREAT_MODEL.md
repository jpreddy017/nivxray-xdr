# NivXRay Security State Core: Formal Threat Model

> **Document Type:** Threat Modeling & Defense Analysis  
> **Status:** Authoritative  
> **Scope:** `backend/security_state/` Core Subsystems  

---

## 1. Adversary Assumptions & Capabilities

We assume an adversary who:
1. May possess valid compromised credentials (including local administrator or temporary cloud IAM keys).
2. Uses legitimate dual-use administrative software (RMM tools, WMI, PowerShell, PsExec) to evade signature detection.
3. May attempt to poison or fabricate telemetry to generate contradictory evidence or overwhelm the SOC.
4. May attempt cross-tenant graph traversal or prompt injection against advisory AI layers.
5. May attempt to disrupt containment by severing response verification channels.

---

## 2. Threat Scenarios & Mitigations

### 2.1 Adversary Telemetry Poisoning / Contradiction Injection
- **Threat**: Attacker sends spoofed sensor logs claiming a compromised host is benign or that a process was killed when it is still running.
- **Mitigation**:
  - `EpistemicStatus.CONTRADICTED` explicitly tags conflicting claims without silently overwriting facts.
  - Multi-sensor corroboration required to transition to `SUPPORTED`.
  - `ResponseVerificationEngine` queries independent operating system handles and network telemetry, never trusting single-point self-reporting.

### 2.2 Dual-Use Administrative Weaponization (LOLBAS & RMM)
- **Threat**: Attacker leverages AnyDesk, TeamViewer, or PowerShell to blend with IT administrative baselines.
- **Mitigation**:
  - `TrustedCapabilityAbuseEngine` evaluates 11 contextual dimensions (identity authorization, source subnet, business hours, proxy tunnels, commandline weaponization).
  - Flags tool misuse even when binary signatures are 100% valid.

### 2.3 Cross-Tenant Graph Traversal
- **Threat**: Malicious insider or compromised tenant attempts to query reachability or response actions targeting other enterprise tenants.
- **Mitigation**:
  - Every entity reference, path, transition, and ledger block enforces strict `tenant_id` scoping.
  - `ResponseSafetyGate` blocks any action where `caller_tenant_id != target_tenant_id` with an explicit security violation.

### 2.4 Prompt Injection & AI Hallucination
- **Threat**: Attacker embeds adversarial prompt-injection payloads inside process command lines or filenames to coerce AI into clearing verdicts.
- **Mitigation**:
  - **Zero AI Authoritative Authority**: AI is advisory only. Detections, verdicts, security states, reachability paths, and interventions are computed 100% by deterministic mathematical engines without LLMs in the critical path.
