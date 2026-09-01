# NivXRay XDR · Autonomous Investigation Operating Model
> **Status**: Platform contract · established 2026-09-01.
> **Sits alongside**: `ARCHITECTURE.md`, `VISUAL_LANGUAGE.md`.
> **Ratifies**: 37 sections of the owner-issued Autonomous Investigation
> Operating Model. This document is the source of truth; the specification
> chat message is the source of intent.

---

## 0 · Definition (§37)

> NivXRay XDR is an evidence-first, autonomous and human-collaborative
> security investigation platform that continuously transforms
> multi-source telemetry into understanding, understanding into
> investigative actions, investigative actions into validated evidence
> and relationships, and those relationships into attack reconstruction,
> findings, deterministic verdicts, reports and recommendations —
> while allowing analysts to inspect, challenge, edit, enrich and
> extend every generated result without compromising the underlying
> evidence or provenance.

## 1 · Fundamental principle (§1, §16)

There is **no** "Auto-Investigate" button. Investigation is a native
operating behavior. The analyst does not start the machine; NivXRay
XDR starts investigating when the evidence warrants it. Any UI
implying a manual start is an anti-pattern and must be rewritten to
communicate **state**, not activation.

## 2 · One product, three planes (§2)

NivXRay XDR = Telemetry ⨉ Intelligence & Investigation ⨉ Operations &
Response. IUE, the Autonomous Investigation Plane, Correlation, ATT&CK,
AttackFlow, Attack Story and Analytics are **internal layers of
NivXRay XDR**, never separate products glued together.

## 3 · Architecture (§3, §35)

```
Enterprise Security Universe
        ↓
Collection / Ingestion Plane
        ↓
Evidence Plane (SSOT · Canonical · Provenance)
        ↓
Detection · Correlation · Enrichment
        ↓
IUE — Investigation Understanding Engine   ←── §4
        ↓
Autonomous Investigation Plane             ←── §7
   ├ Orchestrator · Planner · Hypothesis Mgr · Pivot Planner
   ├ Capability / Engine Selector · Playbook Selector
   └ Investigation State · Re-investigation Loop
        ↓
Investigation Capability Fabric            ←── §11
   (Endpoint · Network · Artifact · Identity · Intel engines)
        ↓
New Evidence → IUE → Re-correlation → IKG
        ↓
Attack Reconstruction (Process Tree · AttackFlow · Attack Story)
        ↓
Deterministic Verdict Engine               ←── §31
        ↓
Investigation Report + AI Narrative        ←── §21-§22
        ↓
Human Analyst (validate · challenge · edit · respond)
```

## 4 · IUE boundary (§4-§6)

IUE **understands**; it does not orchestrate. The four boundaries
are architecturally locked:

| Layer                 | Role                                     |
|-----------------------|------------------------------------------|
| IUE                   | Understand the current security context  |
| Orchestrator          | Decide **what** to investigate next      |
| Capability Fabric     | **Perform** the investigation            |
| IKG                   | Record the resulting knowledge           |
| Verdict Engine        | Emit the **governed** verdict            |

IUE consumes evidence, relationships, threat, and historical context
(§5) and answers the investigator's fundamental questions (§6). IUE
never fabricates evidence; it emits `UNKNOWN` or `NOT_OBSERVED` when
evidence is absent.

## 5 · Investigation lifecycle (§26)

```
CREATED → ELIGIBLE → QUEUED → INVESTIGATING → EXPANDING
       → WAITING_FOR_EVIDENCE → REINVESTIGATING → CONVERGING
       → ANALYST_REVIEW → COMPLETED
       ↺ (new evidence) → REOPENED → REINVESTIGATING → …
```

The lifecycle is a state machine, not a sequence. Any state can
transition to REOPENED when new evidence arrives.

## 6 · Evidence states (§27)

| State         | Meaning                                              |
|---------------|------------------------------------------------------|
| OBSERVED      | Direct telemetry                                     |
| SUPPORTED     | Evidence supports finding                             |
| CORRELATED    | Multiple evidence items connect                       |
| INFERRED      | Analytical inference                                  |
| HYPOTHESIS    | Investigation hypothesis                              |
| NOT_OBSERVED  | Specifically checked but not observed (**negative**) |
| UNKNOWN       | Insufficient evidence                                 |
| CONTRADICTED  | Evidence conflicts                                    |

Never collapse. `NOT_OBSERVED` is what makes negative investigation
possible (§28).

## 7 · Human ⨉ Machine investigation is one investigation (§15, §17)

There is one investigation, one IKG, one SSOT. The analyst does NOT
have "Start Auto-Investigation"; they have **entity-scoped
investigate actions** (Investigate Process · Host · User · IP · Domain
· File · Persistence · C2 · Network Path). Every human action becomes
part of the same investigation state.

## 8 · Editable, versioned intelligence (§23-§25)

Canonical evidence is immutable. **Everything generated on top of it
is editable**: Executive Summary, Investigation Summary, Findings,
Attack Story, Recommendations, Timeline, ATT&CK, etc. Analyst edits
never overwrite evidence; they are stored as versions:

```
Attack Story v1  · NivXRay XDR
Attack Story v2  · Analyst edited (identity, timestamp, reason)
Attack Story v3  · NivXRay XDR (post-new-evidence)
```

## 9 · Deterministic-first, AI-optional (§20)

Without AI, every layer (Rules, Analytics, Correlation, Playbooks,
Engines, IUE, IKG, ATT&CK, Verdict) still produces an operational
investigation. AI can assist with **hypothesis generation**,
**semantic reasoning**, **pivot prioritisation**, **anomaly
prioritisation**, **narrative generation** and **executive
summaries** — but AI **cannot** create evidence, telemetry,
relationships, events, ATT&CK mappings, or provenance.

## 10 · Verdict boundary (§31)

Autonomous Investigator ≠ Verdict Engine. Investigator emits
findings and evidence-backed relationships; the deterministic
Verdict Engine emits the governed verdict. Investigator may
contribute inputs, never override the boundary.

## 11 · Response boundary (§33)

Investigation runs automatically. Response is policy-controlled:
`Investigate Automatically → Recommend → Policy Check →
Auto / Approval Required → Execute`. Autonomous investigation must
NEVER silently become autonomous remediation.

## 12 · Cross-source, cross-incident (§13-§14)

A hash / IP / domain / user / host / process / technique found in
any incident automatically expands into an enterprise-wide
investigation across other hosts · users · incidents · historical
sightings · threat intelligence · campaigns. Seven correlated
alerts become **one evolving investigation**, not seven.

## 13 · UI contract (§16-§19, §34)

- **No "Auto-Investigate" button.**
- Investigation tab shows **state** — one of the §26 lifecycle
  states — rendered as a colour-coded dot chip:
  `● INVESTIGATING · ● CONVERGING · ● WAITING_FOR_EVIDENCE · …`
- **Investigation Activity feed** (§18): live log of what NivXRay XDR
  is doing right now (`14:32:08 ✓ Process ancestry reconstructed`).
- **Current Focus panel** (§19): the current investigative target
  and the "Why?" chain that led there.
- **Human investigation controls are entity-scoped** (§17), never
  "activate the machine".

## 14 · Rollout order

1. **Ratify the contract** (this document) · rename the tab to
   "Investigation Activity" with §26 state grammar. Ship 2026-09-01.
2. IUE service scaffolding · consumes existing Evidence Plane · emits
   §5 understanding artifacts.
3. Investigation Orchestrator scaffolding · consumes IUE · plans
   pivots · writes to `engine_executions`.
4. Investigation Capability Fabric v0 · reuse existing engines
   (Detection / Correlation / MITRE mapping) as first plugins.
5. Attack Story v2 + AttackFlow (Visual Language v1.2) — reads
   IKG + IUE + orchestrator state.
6. Editable / versioned intelligence layer (§23-§25).
7. Cross-incident intelligence (§14).
8. AI-optional narrative layer (§9, §22).

---

## Anti-patterns (rejected)

- Buttons named "Auto-Investigate", "Run Investigation",
  "Analyze Incident", "Start Enrichment".
- Any UI that hides investigation state behind a click.
- Any generated finding that cannot be traced back to evidence.
- AI-generated evidence, relationships, or ATT&CK mappings.
- Autonomous investigation escalating into unapproved remediation.
- Silent omission of "checked but not found" findings.
- Read-only summaries.

---

## 15 · IUE v0 · locked scope (Round 30)

Owner-locked for the next implementation cycle. IUE v0 MUST NOT
exceed these bounds:

```
Existing Evidence Plane  →  IUE v0  →  Persisted IUE State
```

**Boundary contract:**
- **No UI changes.** IUE v0 is a backend service only.
- **No AI dependency.** Deterministic reasoning only.
- **No Orchestrator yet** — v0 emits understanding; Round 31 will
  consume it.
- **No new external intelligence** (STIX/TAXII/OSINT stay deferred).
- **No verdict replacement.** The Verdict Engine boundary (§31)
  is untouched.

**v0 outputs (six understanding artifacts, all persisted):**
Investigation Context · Relationships · Threat Context ·
Historical Context · Known/Unknown · Investigation Gaps.

**Acceptance:** an investigation can move from *"Here is the
evidence"* to *"Here is what the evidence currently means, what is
connected, what is known, what is unknown, and where investigation
gaps exist."* Nothing more. Round 31 then decides what to
investigate next.

---

## 16 · 11-tab workspace grammar (analyst-question contract)

Each tab answers ONE analyst question. All tabs are views over the
same Investigation State — never independent pages.

| Tab                    | Question                                   |
|------------------------|--------------------------------------------|
| Executive              | What is happening?                          |
| Technical              | What exactly happened?                      |
| Evidence               | What proves it?                             |
| Investigation Activity | What is NivXRay XDR investigating/doing?    |
| MITRE                  | What adversary behaviours are supported?    |
| Attack Story           | How did the attack progress?                |
| Recommendations        | What should happen next?                    |
| Notes                  | What did humans add?                        |
| Timeline               | When did everything happen?                 |
| Related                | What else is connected?                     |
| Closure                | What was ultimately concluded / done?       |

Rules:
- Analyst workflow (Executive → Attack Story → Evidence → Technical
  → Investigation Activity → MITRE → Timeline → Related →
  Recommendations → Notes → Closure) is the reading order.
- No tab manually assembles the investigation — NivXRay XDR
  progressively populates all tabs from the shared Investigation
  State.
- Every generated block is editable (§23-§25) but never overwrites
  evidence.

---

## 17 · Threat Model Engine (v1.2 conceptual layer)

Beyond ATT&CK detection: NivXRay XDR continuously constructs and
investigates an **evidence-backed Threat Model** per incident.

```
Environment → Attack Surface → Threat Scenario → Attack Path
     ↓                                                ↓
  Evidence ← Autonomous Investigation ← IUE ← Threat Model
     ↓                                                ↓
  ATT&CK Mapping → Attack Story → Verdict → Response
```

**Attack Cycle** (14 stages) — evidence-driven, never fabricated
when unobserved: Reconnaissance · Resource Development · Initial
Access · Execution · Persistence · Privilege Escalation · Defense
Evasion · Credential Access · Discovery · Lateral Movement ·
Collection · Command & Control · Exfiltration · Impact.

**Attack Path state grammar** — three-state closed enum:
- `○ POSSIBLE`     · path is architecturally reachable
- `◐ SUPPORTED`    · evidence supports one or more hops
- `● OBSERVED`     · every hop is evidence-anchored
- `— NOT OBSERVED` · investigated and negative

**Threat Model Coverage** — 14-stage strip per incident with the
above states; observed stages get evidence rollups, unobserved
stages remain honest gaps.

**Threat Scenario Library** — reusable named scenarios (Phishing ·
Ransomware · Credential Theft · Insider · Living-off-the-Land ·
Supply Chain · Cloud Account Compromise · Identity Attack · Web
Application · Malware · C2 · Data Exfiltration · Lateral Movement ·
Privilege Escalation · Persistence · Defense Evasion). Scenario
match ≠ confirmed attack.

**UI placement (deferred to visual v1.2, not v0):**
- Executive tab: compact Threat Model progression strip.
- Attack Story tab: full interactive attack-cycle visualisation.
- MITRE tab: detailed ATT&CK mapping (existing v2 tab covers this).
- Investigation Activity: shows the Orchestrator filling threat-
  model gaps in real time.
- Related tab: cross-incident / campaign relationships.

---

## 18 · Branding

The product name is **NivXRay XDR** throughout — architecture,
UI, documentation, and implementation prompts. Never alternate
with just "NivXRay" as if they were two products.
