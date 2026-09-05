# NivXRay — Attack Traversal & Attack Lifecycle (locked architecture)

Status: **PLANNED CAPABILITY · NOT IMPLEMENTED**
Recorded: 2026-09-05 · Owner directive
Depends on: **Sensor Foundation** (P2)

---

## 1. Scope separation (locked)

Two distinct layers. They must not be merged, and P1.8 must not grow into
the second one.

| Layer | What it is | Status |
|---|---|---|
| **Cisco File Trajectory** | Vendor parity baseline | reference |
| **NivXRay Fleet File Trajectory** (P1.8) | Cross-endpoint *evidence view* of one file/artifact | ✅ COMPLETE for currently available telemetry |
| **NivXRay Attack Traversal** | Cross-host *causal* reconstruction | PLANNED |
| **NivXRay Attack Lifecycle** | Human-readable reconstruction of the intrusion, initial access → impact, every step evidence-backed | PLANNED |

P1.8 is **COMPLETE for the current substrate** and **NOT COMPLETE as the
ultimate Attack Traversal capability**. Those are different statements and
both are true.

Explicitly OUT of P1.8: attack traversal, attack lifecycle, blast radius,
lateral-movement reconstruction, defense-evasion reconstruction, cross-host
causal graph, security-state reconstruction.

## 2. Non-negotiable: projection, never a new engine

```
Canonical Evidence → IUE → ICE → Detection → Correlation → IKG → VEEE
                  → Verdict → Security State
                  → Attack Traversal PROJECTION → Attack Lifecycle UI
```

Attack Traversal & Lifecycle is an **investigation projection over
authoritative NivXRay reasoning output**. The following must NOT be created:

* `ArtifactTrajectoryCorrelationEngine`
* `RansomwareCorrelationEngine`
* `AttackLifecycleEngine`

No layer may invent relationships that IUE / ICE / IKG / VEEE did not
establish.

## 3. Artifact reference model (not SHA-256-first)

SHA-256 must not be the required identifier — this substrate has **zero**
file content digests.

```
artifactRef {
  type: 'sha256' | 'path_name' | 'artifact_id' | 'process' | 'command' | 'other'
  value: string
  epistemicState: evidence_present | inferred | no_evidence | unknown | unavailable
}
```

Today `path_name` resolves and is labelled `? PATH/NAME KEYED —
CONTENT-BLIND`. When the Sensor Foundation supplies real digests, the
`sha256` path lights up with no rework.

Attack Traversal must never be file-only: a renamed payload
(`payload.exe → svchost.exe → update.tmp → ransom.exe`) is still connected
through process, parent/child, command line, identity, network, timestamp,
host, artifact relationship, ATT&CK and correlation. **File Trajectory is
one entry point into Attack Traversal, not the whole capability.**

## 4. Lifecycle stages are per-stage epistemic states

Stage taxonomy: Initial Access · Execution · Credential Access · Discovery ·
Lateral Movement · Defense Evasion · Collection & Staging · Impact.

Each stage carries its own state and is **never** inferred from the incident
label:

```
INITIAL ACCESS      ? UNKNOWN
EXECUTION           ◆ EVIDENCE PRESENT
CREDENTIAL ACCESS   ◇ NO EVIDENCE
DISCOVERY           ◆ EVIDENCE PRESENT
LATERAL MOVEMENT    ◆ EVIDENCE PRESENT
DEFENSE EVASION     ◆ EVIDENCE PRESENT
COLLECTION          ◇ NO EVIDENCE
IMPACT              ? UNKNOWN
```

States: `◆ EVIDENCE PRESENT` · `◇ NO EVIDENCE` · `? UNKNOWN` ·
`○ NOT RUN` · `⊘ CAPABILITY UNAVAILABLE`.

## 5. Every hop must be explained, and unlinked hosts stay unlinked

Confirmed edge:

```
WS-001 ──[ 10:31:42 · SMB · T1021.002 · CORP\user · psexec.exe · <artifact> ]──▶ FILE-SRV-01
  ◆ Network connection observed   ◆ Process execution observed
  ◆ Same account observed         ◆ Same artifact/path observed
  ◆ Temporal relationship confirmed  ◆ ATT&CK T1021.002 mapped
  ◆ Source evidence: EVT-xxxx
  ? Parent process not observed   ? File content hash not observed
```

Cohort (today's reality):

```
WS-001      WS-004      FILE-SRV-01
   ○            ○              ○
Same artifact/path observed — lateral relationship NOT established.
```

**Traversal status**: `◆ CONFIRMED` · `? INFERRED` · `◇ COHORT ONLY` ·
`⊘ UNAVAILABLE`.
**Traversal basis**: network connection · process execution · artifact
transfer · shared identity · temporal relationship · *same filename only*
(which alone can NEVER produce an edge).

## 6. Forensic terminology rules (already enforced in P1.8)

* No "patient zero" and no "initial access" from an earliest record. Use
  `? EARLIEST OBSERVED HOST` and state the reason.
* `OBSERVED WINDOW` ≠ attack window. `TRUE ATTACK START/END ? UNKNOWN`,
  because telemetry may begin after compromise.
* Objective is never derived from a family name:
  `◆ EVIDENCE-SUPPORTED OBJECTIVE` / `? OBJECTIVE INFERRED` /
  `◇ OBJECTIVE NOT ESTABLISHED`, always with the supporting evidence list
  and the confidence source (DETERMINISTIC / VEEE).

## 7. The 7-W matrix (+ what we do not know)

| Question | Answer |
|---|---|
| WHAT? | artifact / activity |
| WHEN? | temporal sequence |
| WHERE? | hosts / network |
| WHO? | user / service / process |
| HOW? | execution / transfer mechanism |
| WHY? | evidence-supported objective |
| PROVES? | the exact evidence supporting the conclusion |
| **UNKNOWN?** | **what we explicitly do NOT know** |

## 8. Terminology roadmap

`Fleet File Trajectory` (parity today) → `Artifact & Attack Trajectory`,
composed of File · Artifact · Process · Device · Identity trajectories and
Network Traversal, all converging into **Attack Lifecycle**.

## 9. Sequence (locked)

```
P1.8   Fleet File Trajectory            ✅ COMPLETE (current telemetry)
P1.8a  Spread Watchlist                 useful now
P1.9   Investigation Export             useful now
P2     Sensor Foundation                unlock: device_iid, PID/PPID, file
                                        SHA-256, sockets, DNS, user/session,
                                        real-time telemetry
P2.x   Attack Traversal & Lifecycle     cross-host causal traversal, lateral
                                        movement, evasion, identity, network,
                                        ATT&CK progression, blast radius,
                                        lifecycle reconstruction
```

## 10. Product principle

* **Cisco File Trajectory** — parity baseline.
* **NivXRay Fleet File Trajectory** — cross-endpoint evidence view.
* **NivXRay Attack Traversal** — cross-host causal reconstruction.
* **NivXRay Attack Lifecycle** — human-readable reconstruction of the entire
  intrusion, initial access → impact, every step evidence-backed.

Task title to use when this is built:
**“P2.x — Unified Artifact Trajectory & Attack Traversal *Projection*”**
(never “Engine”).
