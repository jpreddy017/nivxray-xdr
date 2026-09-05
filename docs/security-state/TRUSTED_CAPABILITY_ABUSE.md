# NivXRay Trusted Capability Abuse Specification

> **Document Type:** Capability Abuse Modeling  
> **Status:** Authoritative  
> **Package:** `backend/security_state/capability/`  

---

## 1. The Dual-Use Dilemma

Attackers increasingly live off the land (LOLBAS) and abuse legitimate remote management tools (RMM, AnyDesk, TeamViewer, WMI, PowerShell). Traditional antivirus either:
- Flags all RMM tools (causing massive false positives for IT staff), or
- Whitelists signed admin software (letting attackers operate invisibly).

---

## 2. The 11-Dimensional Contextual Model

NivXRay evaluates capability usage across 11 dimensions simultaneously:

1. **`Capability`**: Specific tool identity (e.g. `powershell.exe`, `AnyDesk.exe`).
2. **`Identity`**: Initiating identity (system, administrator, standard user, contractor).
3. **`Authorization`**: Explicit role permissions for this specific tool.
4. **`Source`**: Ingress network location, corporate VPN vs foreign ASNs.
5. **`Destination`**: Target endpoint, internal management IP vs external dynamic DNS.
6. **`Time Window`**: Normal business/maintenance shift vs 3:00 AM on a weekend.
7. **`Business Context`**: Active change ticket vs unexpected execution.
8. **`Behavior Pattern`**: Interactive user UI session vs headless background command-line.
9. **`Sequence`**: Preceding and succeeding actions (e.g., download &rarr; execute &rarr; persist).
10. **`Privilege Level`**: Token privilege (Standard User vs Elevated vs SYSTEM).
11. **`Reachability`**: Target assets exposed to this active execution handle.

---

## 3. Capability Classifications

- `LEGITIMATE_CAPABILITY`: Software recognized as a valid administrative tool.
- `AUTHORIZED_USE`: Valid tool operated by authorized staff within normal operational baseline.
- `ANOMALOUS_USE`: Authorized staff or tool operating outside typical temporal or network baseline.
- `SUSPICIOUS_USE`: Anomalous parameters, obfuscation flags, or unrecognized source IP.
- `ABUSED_CAPABILITY`: Definite weaponization (e.g. reverse proxy tunnel, payload download).
- `ATTACK_CAPABLE`: Attacker maintains active execution handle.
- `CONFIRMED_ATTACK`: Confirmed malicious exploitation in progress.
