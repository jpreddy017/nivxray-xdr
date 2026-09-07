<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

# LAB VALIDATION PLAN — the operationalisation sequence

Derived from `08_VALIDATION/GA_READINESS_MATRIX.md`,
`01_REFERENCE/CISCO_TO_NIVXRAY_MAPPING.md` and
`00_PRODUCT/MATURITY_MODEL.md`. Adopts `memory/ROADMAP.md` and
`memory/NIVXFORGE_EDR_ROADMAP.md`.

**This is a plan, not work in progress.** No implementation was
performed in this documentation pass.

## 0 · The governing finding

We are the **inverse** of the reference product's starting position. It
had mature sources and built a platform; we have a mature platform and
**one** real source. Therefore: **real sources before more surface.**

Corollary: the dashboard redesign is sequenced *after* the sources,
because a beautiful dashboard over a blind sensor and unlabelled
incidents is the one combination that actively misleads its owner.

## 1 · Sequence

Owner's order is preserved. Two insertions are proposed with
justification, per the rule that reordering requires evidence.

| # | Step | Why here | Gate |
|---:|---|---|---|
| 0 | **This documentation pass** | architecture reconciled before more building | — |
| **1** | **Incident provenance labelling** *(proposed insertion)* | **Cheapest high-value item in the programme.** Until an incident says whether it is real, no user guide can be written honestly, no demo can be trusted and no analyst can answer *"is that real?"* It blocks A1, A2, G5 | `INTERNAL_ALPHA` |
| 2 | **P0-3 · Linux sensor recovery** | the pipeline that already works must be alive before a second platform is added; debugging two broken pipelines at once is the trap | `INTERNAL_ALPHA` |
| **3** | **Observability on going blind** *(proposed insertion)* | telemetry was lost for over 24 hours and **nothing alerted**. Without this, step 2 will silently regress and we will not know | `INTERNAL_ALPHA` |
| 4 | **P0-2B · Release isolation** | completes the containment pair through the same lifecycle | `LAB_VALIDATED` |
| 5 | **P0-2D · Isolation policy projection** | analysts must see containment rules before acting | `LAB_VALIDATED` |
| 6 | **P0-4 · Collector reconciliation** | integration health must be authoritative **before** it is used to judge a second domain | `LAB_VALIDATED` |
| 7 | **Windows sensor v0.1** — process/file/network, no third-party dependency | the real Windows endpoint the owner wants; lands in existing lanes with no backend change | `LAB_VALIDATED` |
| 8 | **Windows response identity basis** — PID + creation time | without it a Windows kill can be claimed but never verified, and the lifecycle will correctly refuse to call it success | `LAB_VALIDATED` |
| 9 | **Real Windows detection** from real activity on that box | proves the detection fabric against Windows-shaped telemetry | `LAB_VALIDATED` |
| 10 | **Rule platform applicability audit** | we do not know how many of the 98 rules assume Windows/Sysmon fields | `LAB_VALIDATED` |
| 11 | **Second independent telemetry domain** | endpoint data re-wrapped in CEF is **not** a second domain | `CLOSED_BETA` |
| 12 | **Cross-domain correlation → a real multi-source incident** | the first moment "XDR" is factually accurate | `CLOSED_BETA` |
| 13 | **Response action catalogue consolidation** | 16 stubs either get adapters or leave the catalogue | `CLOSED_BETA` |
| 14 | **Tenant scoping guard** across all routes | make the strongest security property structural, like endpoint identity | `CLOSED_BETA` |
| 15 | **UI completion incl. Control Center** | *only now.* Real projections, named absences, zero invented figures | `CLOSED_BETA` |
| 16 | Upgrade/rollback · backup/restore · HA · performance · DR · threat model | production hardening | `RC` |
| 17 | Alpha → Lab → Closed Beta → Pilot → RC → GA | per `MATURITY_MODEL.md` | — |

### Why steps 1 and 3 were inserted

Both are prerequisites for *knowing whether the later steps worked*.
Step 1 makes evidence attributable; step 3 makes failure visible. Adding
a Windows sensor to a platform that cannot label provenance and cannot
detect its own blindness would produce a demo we could not trust and an
outage we would not notice.

## 2 · Windows endpoint validation — the plan the owner asked about

**Answer to "is NivXForge EDR ready for a real Windows machine?" —
not yet.** The server side is ready; the producer does not exist.

| Ready | Not ready |
|---|---|
| enrolment/ingest APIs are platform-agnostic (`platform` already recorded) | **no Windows producer exists** |
| detection content is largely Windows/Sysmon-shaped | trajectory lanes cover only PROCESS/FILE/NETWORK — registry/service/USB events would ingest with **no lane to appear in** |
| response lifecycle, approval and audit are real | kill verification requires a `/proc` `start_ticks` identity basis |
| identity resolution is platform-neutral | isolation needs a WFP/firewall driver |

Minimum credible Windows test (after steps 2–3):

1. Enrol a real Windows box; verify `platform=WINDOWS` and last-delivery
   freshness.
2. Deliver real process/file/network evidence; assert it appears in
   Device Trajectory and Process Tree **with correct identity across all
   aliases**.
3. Fire a real detection from real activity on that machine.
4. Request `KILL_PROCESS`; execute; **verify** with the Windows identity
   basis. Anything less stays `EXECUTED`, never `VERIFIED`.
5. Declare isolation `BLOCKED` unless a host exists where a firewall
   rule can genuinely be applied **and verified**.

Open questions for the owner: Sysmon permitted on the test machine
(richest telemetry, but a third-party dependency)? Is the box reachable
from the platform? Packaged installer/service required, or is running a
script acceptable for the first test?

## 3 · Explicitly not in this plan

- Cloning the mockup dashboard before its data exists.
- The 34-point technology-adoption audit (deferred by owner directive
  until the P0s close).
- Any new engine. `ADOPT` / `WIRE` / `EXTEND` only.
- Any synthetic operational data, ever.
