# NivXRay Validation Strategy & Golden Corpus

> **Document Type:** Validation Strategy  
> **Status:** Authoritative  
> **Package:** `backend/security_state/validation/`  

---

## 1. Golden Corpus Coverage (18 Scenario Categories)

| ID | Category | Key Challenge | Expected Evaluation |
| :--- | :--- | :--- | :--- |
| **SCN-01** | Benign Admin Activity | Standard admin commandline without weaponization | `AUTHORIZED_USE` |
| **SCN-02** | Legitimate RMM | RMM tool operated by verified support staff in business hours | `AUTHORIZED_USE` |
| **SCN-03** | Abused RMM | Headless/silent RMM installation via proxy tunnel | `CONFIRMED_ATTACK` |
| **SCN-04** | PowerShell Admin | Routine PowerShell feature query | `AUTHORIZED_USE` |
| **SCN-05** | Credential Abuse | Rundll32 LSASS memory dumping | `CONFIRMED_ATTACK` / `CREDENTIAL_ACCESS` |
| **SCN-06** | Lateral Movement | PsExec cross-host execution | `CONFIRMED_ATTACK` / `LATERAL_MOVEMENT` |
| **SCN-07** | Cloud Identity Abuse | Unsanctioned STS role assumption | `CONFIRMED_ATTACK` / `PRIVILEGE_ESCALATION` |
| **SCN-08** | SaaS Abuse | Headless Graph API mail extraction | `ABUSED_CAPABILITY` / `COLLECTION` |
| **SCN-09** | Backup Targeting | Shadow copy deletion via vssadmin | `CONFIRMED_ATTACK` / `IMPACT` |
| **SCN-10** | Hypervisor Targeting | Headless VM process termination on ESXi | `CONFIRMED_ATTACK` / `IMPACT` |
| **SCN-11** | Persistence | Scheduled task creation | `ABUSED_CAPABILITY` / `PERSISTENCE` |
| **SCN-12** | Defense Evasion | Hidden window & execution policy bypass | `ABUSED_CAPABILITY` / `DEFENSE_EVASION` |
| **SCN-13** | Multi-Stage Attack | Chained download &rarr; persistence &rarr; credential dump | Full Kill-Chain Progression |
| **SCN-14** | Contradictory Evidence | Conflicting telemetry sources | `CONTRADICTED` Epistemic Status |
| **SCN-15** | Missing Evidence | Zero telemetry on target entity | `UNSUPPORTED` Epistemic Status |
| **SCN-16** | False-Positive Scenario | Legitimate SCCM deployment | `AUTHORIZED_USE` |
| **SCN-17** | Counterfactual Intervention | Intervention reduces residual risk to $\le 10\%$ | Verified Path Severance |
| **SCN-18** | Response Verification Failure | Sockets remain active after isolation | `VERIFIED_INEFFECTIVE` / Pivot Detected |
