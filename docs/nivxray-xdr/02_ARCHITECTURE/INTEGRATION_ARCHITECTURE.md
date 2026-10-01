<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> **TARGET** contract. Nothing here claims a source exists. Real
> producers today: see `08_VALIDATION/REALITY_MATRIX.md`.

# INTEGRATION ARCHITECTURE — the NivXRay Integration Contract

The single most valuable thing to take from the reference product:
**make every source conform to one contract instead of writing a bespoke
architecture per vendor.** Evidence for the reference model:
`01_REFERENCE/CISCO_XDR_REFERENCE_MODEL.md` §3 (`PUBLICLY_DOCUMENTED`).

Adopts `memory/MIGRATION_DEPENDENCIES.md`,
`memory/VISION_ENTERPRISE_INTEGRATION.md`,
`memory/REFERENCE_ADAPTATION.md`.

## 1 · The contract

Every source or control plane — Linux EDR, Windows EDR, firewall, DNS,
email, identity, cloud, SIEM, third-party EDR, threat intelligence —
implements the same declared capability set. It declares **only what it
can actually provide**; a declaration is a promise the platform will
hold it to.

| # | Capability | Obligation | Failure semantics |
|---|---|---|---|
| 1 | `INGEST` | deliver raw evidence with provenance and tenant attribution | rejected evidence is **recorded**, never silently dropped |
| 2 | `DETECT` | act as a detection source, or declare that it is not one | a rule that cannot evaluate reports *not evaluated*, never *no detection* |
| 3 | `OBSERVE` | return sightings of an observable from its own data | unqueried ≠ not seen; "no sightings" is only sayable if the source was actually asked and answered |
| 4 | `DELIBERATE` | return a disposition: `clean` / `malicious` / `suspicious` / `unknown` | provider down or answer stale must yield `unknown`, **never `clean`** |
| 5 | `ENRICH` | add context to existing evidence | enrichment must carry its source and age |
| 6 | `ASSET_CONTEXT` | supply asset/device data for normalise → deduplicate → correlate | a device seen twice must not appear twice; dedup goes through the endpoint identity resolver |
| 7 | `HEALTH` | prove the integration actually works | health is the **authoritative probe result**, never a cached optimistic value |
| 8 | `RESPOND` | execute an action in its own control plane | an action it cannot perform must be declared `CAPABILITY_UNAVAILABLE` up front, not attempted and reported as success |
| 9 | `VERIFY` | supply post-action evidence that the action took effect | **no verification ⇒ no success.** This is our addition beyond the reference contract |
| 10 | `AUTOMATE` | be a workflow target | must not permit an action the operator could not authorise manually |
| 11 | `REFER` | deep-link back into the owning product with context preserved | a pivot must not strip endpoint, tenant or evidence context |
| 12 | `DASHBOARD` | supply real projections for Control Center tiles | **a tile with no data source shows a named absence, never a zero and never an invented number** |

Capability 9 (`VERIFY`) and the failure semantics column are where we
deliberately exceed the reference model. They exist because this
programme's recurring defect class was *claims exceeding evidence*.

## 2 · Declaration is machine-checked

An integration declares its capabilities against the existing capability
registry (`edr_plane/capability/inventory.py`, 135 entries). The registry
already records `telemetry_status`, `backend_status`,
`control_driver_status`, `ui_status`, `effective_state`, `gap_class` and
`is_operational` — so a declaration cannot exceed what is wired.

`scripts/docs_reconcile.py` fails when documentation claims a capability
is operational and the registry disagrees. **This is the mechanism that
stops "Windows sensor supported" from surviving in a document while no
Windows producer exists.**

## 3 · Source inventory against the contract

Legend: ✔ implemented · ○ declared/partial · ✗ absent

| Source | INGEST | DETECT | OBSERVE | DELIB | ENRICH | ASSET | HEALTH | RESPOND | VERIFY | AUTO | REFER | DASH |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **NivXForge EDR · Linux** | ✔ | ✔ | ○ | ✗ | ○ | ✔ | ○ | ✔¹ | ✔¹ | ✗ | ✔ | ○ |
| **NivXForge EDR · Windows** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Collector (syslog/CEF) `:8055` | ○ | ✗ | ✗ | ✗ | ✗ | ✗ | ○² | ✗ | ✗ | ✗ | ✗ | ✗ |
| Threat intelligence (7 providers) | ✗ | ✗ | ✗ | ✔ | ✔ | ✗ | ○ | ✗ | ✗ | ✗ | ✔ | ✗ |
| Third-party EDR (vendor wizard) | ○ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ○ | ✗ | ✗ | ✗ | ✗ |
| Network / DNS / email / identity / cloud | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |

¹ `KILL_PROCESS` only, with real independent verification bound to
process start identity. `ISOLATE_ENDPOINT` is `CAPABILITY_UNAVAILABLE`
(`BLOCKED_ENVIRONMENT`, no `CAP_NET_ADMIN`) and is **never simulated**.
² health exists but has a **known split-brain** (P0-4): reported status
can differ from reality, so it is not yet trustworthy.

**What this table shows:** exactly one source implements a meaningful
share of the contract, and it covers one platform of one domain. That is
the honest state of NivXRay as an *integration* platform.

## 4 · Adoption candidates from the reference model

| Pattern | Evidence | Value here |
|---|---|---|
| **Per-integration capability declaration** | `PUBLICLY_DOCUMENTED` | already have the registry — must make integrations declare *against* it |
| **`unknown` as a first-class disposition** | `PUBLICLY_DOCUMENTED` | prevents "no bad reputation" being read as "safe" |
| **Bulk/custom source upload**: create upload → `PUT` presigned URL → poll status | `PUBLICLY_DOCUMENTED` | genuinely useful for offline/batch sources; **does not exist here** |
| **Full vs delta asset sync + webhooks** | `PUBLICLY_DOCUMENTED` | the right shape for asset ingestion once a second product exists |
| **Distributed response** (platform orchestrates, product executes) | `PUBLICLY_DOCUMENTED` | **already our architecture** |

## 5 · Rules

1. A source declares capabilities; **the platform never assumes one.**
2. An undeclared capability is **absent**, not "probably works".
3. Adding a source must require **zero platform changes** — if it does,
   the contract is wrong, not the source.
4. A source never receives another tenant's data, and never asserts its
   own tenant.
5. `REFER` must preserve endpoint, tenant and evidence context. Pivot
   contracts are audited (14 audited; one defect found and fixed).
6. **A source that cannot answer must say so.** Every failure in this
   contract resolves to a *named absence*, never to an empty success.

## 6 · Open decisions

| # | Question | Blocks |
|---|---|---|
| 1 | Is the second domain a real network/DNS/firewall source, or third-party EDR? Endpoint data re-wrapped in CEF is **not** a second domain | correlation, `CLOSED_BETA` |
| 2 | Do we build a workflow engine or expose fixed audited playbooks? | `AUTOMATE` |
| 3 | Who writes the first third-party integration — us or a partner? | SDK strictness |
| 4 | Where does asset criticality come from with no CMDB? | prioritisation parity |
