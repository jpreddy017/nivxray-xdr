# MASTER GATE (binding) — read FIRST, before any further code

**Locked 2026-06 by owner. Supersedes the feature-milestone view.**
Y3.1–Y3.4 / Y4 are milestones *inside* two programmes, not the programmes.

## Required order — DO NOT BUILD FIRST AND CLASSIFY LATER
`AUDIT → CLASSIFY → OWNERSHIP MATRIX → RUNTIME TRUTH → WIRE EXISTING
TECHNOLOGY → VALIDATE → UI/UX PARITY → REGRESSION → identify TRUE missing
capabilities → implement only what is genuinely missing`

**START HERE (next session): the PART B/L audit is DONE — read
`/app/memory/MASTER_OWNERSHIP_AUDIT.md` (MATRIX 2 + MATRIX 3 + the ORPHAN
WIRING WORKLIST) and `/app/memory/MASTER_PARITY_MATRIX.md` (MATRIX 1).
Delivered 2026-06, audit only, nothing wired. The programme is STOPPED at
`BUILD PRIORITISED WIRING WORKLIST → MY APPROVAL`. Do NOT start wiring or
any UI work until the owner approves the worklist. Superseded instruction
below (kept for the record):**

~~START HERE (next session, before any feature work): PART B/L — the
ownership + wiring audit.~~ Deliver MATRIX 2 (XDR / EDR / SHARED /
LEGACY-DUPLICATE / MISSING, with *wired?* + runtime proof per capability)
BEFORE more UI. Then MATRIX 1 (Cisco parity per screen) and MATRIX 3
(missing/blocked).

## Two failure modes explicitly forbidden
1. **Duplicate-engine**: "EDR needs its own detection engine" → NO. The
   authoritative fabric stays shared; products own only their *surface*.
2. **Orphan-engine**: "it exists but isn't wired, so build a simpler one"
   → NO. If it exists and is authoritative, **wire it**
   (e.g. `apps/nivxray-xdr-collector/`).

Rule: *exists + authoritative → wire · belongs to other product → wire
there · both need it → keep shared, expose two surfaces · truly absent →
then build.*

## Parity gate
NivXRay XDR ⇄ **Cisco XDR** reference · NivXForge EDR ⇄ **Cisco Secure
Endpoint/AMP** reference. 100 % *observable* parity — layout, IA,
navigation, typography/lettering, spacing, terminology, controls, charts,
states, interaction. "Looks close" is not acceptance: capture →
compare → record deviation → fix → repeat. Independent implementation; no
Cisco code/assets.

## Never
Fabricated telemetry/detections/metrics/observables to populate a
Cisco-looking screen · silent SPA fallback for a broken route (must be
`NOT_IMPLEMENTED`/`BLOCKED`) · a control shown operational because an API
contract, component or disconnected engine exists · merged product
consoles · cross-tenant leakage · claiming parity before proof.
`G-16 / FLOW-5` stays `REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED` and UI work
must never manufacture a second telemetry domain.

## Status vocabulary (only these)
`REAL_RUNTIME_VERIFIED` · `END_TO_END_VALIDATED` ·
`IMPLEMENTED_NOT_RUNTIME_VERIFIED` · `REFERENCE_CAPTURE_REQUIRED` ·
`BLOCKED` · `NOT_IMPLEMENTED` (+ `LEGACY/DUPLICATE` in the matrices).

## Regression gates that must not break
X1–X3/Y2 **22/22** · P0-F.13.5 **25/25** · Detection Attribution
**12/12** · `tests/edr` **330 pass** (3 known pre-existing
`test_p0_f4_endpoint_process_tree.py` failures).

## Standing corrections already accepted
Y3.1 is **behavioural only** — pivot-menu visual parity stays
`REFERENCE_CAPTURE_REQUIRED`. Casebook must project onto existing
`workspace_cases`/worklog; no second case engine.
See `/app/memory/XDR_EDR_PARITY_AUDIT.md`,
`/app/memory/Y0_CISCO_XDR_REFERENCE_INTAKE.md`,
`/app/memory/Y1_STATUS_REPORT.md`, `/app/memory/agent_learnings.md`.
