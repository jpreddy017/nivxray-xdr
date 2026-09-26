# NivXRay Impact Model Specification

> **Document Type:** Impact & Exposure Specification  
> **Status:** Authoritative  
> **Package:** `backend/security_state/impact/`  

---

## 1. Decoupling Verdict from Impact

NivXRay strictly separates two distinct engineering questions:
- **Verdict Engine**: *"Did an attack occur?"* (Based strictly on evidence: labels, confidence).
- **Impact Engine**: *"What is exposed?"* (Based on business context, criticality, and topology).

A noisy port scan on a mission-critical Domain Controller does not become "Malicious Execution" simply because the host is valuable. Conversely, confirmed ransomware execution on a test VM is still `Malicious` even though business impact is negligible.

---

## 2. Impact Dimensions

1. **`Asset Criticality`**: Tier 0 (DC, PKI, backups) vs Tier 1 (Production DB) vs Tier 2 (Workstations).
2. **`Blast Radius`**: Quantified count of directly and conditionally reachable connected nodes.
3. **`Ransomware Susceptibility`**: Measures whether attacker reachability intersects write permissions on file shares and immutable backup repositories.
4. **`Operational Disruption`**: Business downtime projection in operational hours.
