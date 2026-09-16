<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

# GA READINESS MATRIX

Reconciles `memory/GA_BLOCKERS.md` (323 lines) against the generated
reality baseline. **Current stage: `ENGINEERING`.**

Status vocabulary: `MET` · `PARTIAL` · `NOT_MET` · `BLOCKED_ENVIRONMENT`
· `NOT_STARTED`.

## A · Product truthfulness

| # | Gate | Status | Evidence / gap |
|---|---|---|---|
| A1 | No synthetic operational data anywhere | `PARTIAL` | every incident is now **labelled**, so real and non-real are distinguishable; non-real data has not yet been quarantined out of the operational scope |
| A2 | Every incident carries provenance | **`MET`** | closed vocabulary, write-time gate, evidence-derived backfill, 27-gate proof — `scripts/p2_incident_provenance_proof.py` |
| A3 | No surface converts a named absence into an empty result | `PARTIAL` | `ENDPOINT_NOT_RESOLVED` enforced end-to-end on 3 EDR surfaces; `WINDOW_HONESTY_GAP` open |
| A4 | No capability claims more than its evidence | `MET` | `claim_is_honest` true for every registry entry |
| A5 | Every offered response action can execute | `NOT_MET` | 18 catalogued, 2 operational, 16 stubs |
| A6 | Documentation cannot contradict runtime | `MET` | `scripts/docs_reconcile.py` gate |
| A7 | Priority discloses its basis | `NOT_MET` | no asset-value input; basis undisclosed |

## B · Data plane

| # | Gate | Status | Gap |
|---|---|---|---|
| B1 | Linux endpoint continuously reporting | `NOT_MET` | telemetry stopped; see reality matrix for last delivery |
| B2 | Windows endpoint real and validated | `NOT_MET` | **no Windows producer exists** |
| B3 | macOS endpoint | `NOT_STARTED` | — |
| B4 | Second independent telemetry domain | `NOT_MET` | endpoint only; CEF-wrapped endpoint data does not count |
| B5 | Cross-domain correlation produces a real incident | `NOT_MET` | blocked by B4 |
| B6 | Integration health authoritative | `NOT_MET` | collector split-brain (P0-4) |
| B7 | Rejected evidence recorded, never dropped | `MET` | rejection store exists |

## C · Detection & investigation

| # | Gate | Status | Gap |
|---|---|---|---|
| C1 | Rules declare platform applicability and required fields | `NOT_MET` | unknown how many of 98 rules can fire on Linux telemetry |
| C2 | Detections attributed to authoritative evidence | `MET` | `raw_id` + `canonical_event_id` on real events |
| C3 | Investigation SSOT declared | `NOT_MET` | **inherited open question**: IUE record vs `workspace_cases` |
| C4 | Causal/counterfactual claims have an evidentiary standard | `NOT_MET` | highest over-claim risk in the product |
| C5 | Intelligence never degrades to `clean` | `PARTIAL` | providers live; staleness disclosure incomplete |

## D · Response

| # | Gate | Status | Evidence |
|---|---|---|---|
| D1 | Lifecycle refuses unverified success | `MET` | only `VERIFIED` is evidence-backed; `VERIFICATION_FAILED` observed live |
| D2 | Target identity binding prevents wrong-target action | `MET` | start-identity binding; recycled PID cannot satisfy verification |
| D3 | Approval separated from execution, audited | `MET` | response service + `xdr_audit_log` |
| D4 | Isolation operational and verified | `BLOCKED_ENVIRONMENT` | no `CAP_NET_ADMIN`; **never simulated** |
| D5 | Release isolation | `NOT_MET` | P0-2B, must reuse the same lifecycle |
| D6 | Blast radius, idempotency, rate limits, emergency stop | `NOT_STARTED` | `07_SECURITY/RESPONSE_SAFETY.md` |
| D7 | Windows identity basis for verification | `NOT_MET` | PID + creation time required |

## E · Security

| # | Gate | Status | Gap |
|---|---|---|---|
| E1 | Tenant isolation on every surface | `PARTIAL` | proven for incidents + all endpoint evidence; not proven across all routes |
| E2 | Object-level authorisation everywhere | `PARTIAL` | one IDOR found and closed; no systematic sweep |
| E3 | Foreign identifier indistinguishable from unknown | `MET` | proven; existence never disclosed |
| E4 | RBAC matrix complete | `NOT_MET` | no full route↔permission map |
| E5 | Secrets rotation + access audit | `NOT_MET` | store exists, lifecycle undefined |
| E6 | Audit tamper-evident | `NOT_MET` | audit exists, tamper evidence does not |
| E7 | Threat model | `NOT_STARTED` | a tool that can kill processes on managed hosts is a high-value target |
| E8 | External security review | `NOT_STARTED` | — |

## F · Operations

| # | Gate | Status | Gap |
|---|---|---|---|
| F1 | Alerting on going blind | `NOT_MET` | **telemetry was lost for >24h and nothing alerted** |
| F2 | Metrics, logs, traces | `PARTIAL` | structured logs only |
| F3 | Backup and restore tested | `NOT_STARTED` | never attempted |
| F4 | Upgrade and rollback tested (platform + fleet) | `NOT_MET` | per-release plans only; no sensor upgrade mechanism |
| F5 | HA | `NOT_MET` | single instance of every service |
| F6 | Performance measured at a declared fleet size | `NOT_MET` | corpus is ~8k events from 2 endpoints |
| F7 | DR | `NOT_STARTED` | — |
| F8 | Retention policy per store | `NOT_MET` | undefined |
| F9 | Install without engineering help | `NOT_MET` | no packaged installer |

## G · Documentation

| # | Gate | Status |
|---|---|---|
| G1 | Authoritative tree exists with truth layers | `MET` |
| G2 | All legacy docs reconciled | `MET` — 157 documents ledgered |
| G3 | Reconciliation gate green | `MET` |
| G4 | Every `SPEC_PENDING` doc completed by its stage | `NOT_MET` — 66 outstanding, each with a stage |
| G5 | User guides describe only usable functionality | `NOT_MET` — blocked on A2 |
| G6 | Screen specs sufficient for a new frontend team | `NOT_MET` |
| G7 | Cisco reference captures held where parity is claimed | `NOT_MET` — `REFERENCE_CAPTURE_REQUIRED` |

---

## Summary

| Band | `MET` | `PARTIAL` | `NOT_MET` / `NOT_STARTED` / `BLOCKED` |
|---|---:|---:|---:|
| A · truthfulness | 2 | 1 | 4 |
| B · data plane | 1 | 0 | 6 |
| C · detection/investigation | 1 | 1 | 3 |
| D · response | 3 | 0 | 4 |
| E · security | 1 | 2 | 5 |
| F · operations | 0 | 1 | 8 |
| G · documentation | 3 | 0 | 4 |

**Where we are strong:** response integrity, evidence attribution,
endpoint identity, cross-tenant non-disclosure, and self-honest capability
grading. These are the hard, unglamorous properties that make a security
product credible.

**Where we are weakest:** *sources* (B) and *operations* (F). Both are
about the world outside the codebase — real machines, real domains, real
running systems — which is precisely why they cannot be closed by writing
more platform.
