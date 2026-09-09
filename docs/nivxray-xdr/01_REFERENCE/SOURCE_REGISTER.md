<!-- NIVX-DOC
layer: CURRENT_REALITY
status: AUTHORED
-->

# SOURCE REGISTER

Every source behind an architectural claim in this tree, with its
evidence class. **Phase 0 rule: inference is never presented as fact, and
never as Cisco's internal architecture.**

## Evidence classes

| Class | Meaning |
|---|---|
| `PUBLICLY_DOCUMENTED` | verified in this session against a public source, cited below |
| `OBSERVED_FROM_REFERENCE` | seen in owner-supplied reference material held in the repo |
| `OWNER_ASSERTED` | stated by the owner; not independently verified here |
| `INFERRED` | our reasoning from the above; explicitly a conclusion, not a source |
| `REFERENCE_CAPTURE_REQUIRED` | needed for a decision and **not currently held** |
| `RUNTIME_VERIFIED` | extracted from our own running system by `scripts/docs_reconcile.py` |

---

## A · Cisco XDR — external reference product

| # | Claim | Class | Source / note |
|---|---|---|---|
| A1 | Integration capabilities are a **modular capability model**, configured per integration | `PUBLICLY_DOCUMENTED` | Cisco XDR integration docs (`connect.xdr.security.cisco.com`), Cisco Live DEVNET-2236 (2025) |
| A2 | Capability set includes **Data Ingestion, Observe, Deliberate, Refer, Respond, Health, Automation** | `PUBLICLY_DOCUMENTED` | as A1 |
| A3 | **`Tiles` was renamed `Dashboards`** | `PUBLICLY_DOCUMENTED` | as A1 — *the owner's brief used the older name* |
| A4 | **`Device Insights` was renamed `Assets`**, and normalises/deduplicates/correlates endpoint data from integrated products via REST full/delta sync or webhooks | `PUBLICLY_DOCUMENTED` | Cisco Live BRKSEC-2596 (2024), BRKSEC-2754 (2022) |
| A5 | `Deliberate` returns dispositions **clean / malicious / suspicious / unknown** | `PUBLICLY_DOCUMENTED` | as A1 |
| A6 | Custom data ingestion is a **three-step REST flow**: create upload → `PUT` to presigned URL → poll status until `completed`/`failed` | `PUBLICLY_DOCUMENTED` | `developer.cisco.com/docs/cisco-xdr/custom-source-upload/` |
| A7 | `Data Ingestion` lands raw telemetry in an XDR **data warehouse** which then generates detections and incidents | `PUBLICLY_DOCUMENTED` | as A1 |
| A8 | Automation triggers include **Approval, Email, Incident, Schedule, Webhook** | `PUBLICLY_DOCUMENTED` | as A1 |
| A9 | Sub-components include **Control Center, Incidents, Investigate, Intelligence, Automation, Assets/Devices, Integrations/Client Management, Administration** | `OWNER_ASSERTED` + partially `PUBLICLY_DOCUMENTED` | owner brief cites Cisco DevNet; component *names* corroborated by A1/A4 sources, the full API-level decomposition was **not** re-verified here |
| A10 | **XDR is API-first and the Cisco UI is itself an API client** | `OWNER_ASSERTED` · `REFERENCE_CAPTURE_REQUIRED` | **NOT verified in this session.** Web search returned only generic API-first material, no Cisco source. See note below |
| A11 | **CTIM (Cisco Threat Intelligence Model) is XDR's common representation** across Cisco and third-party data | `OWNER_ASSERTED` · `REFERENCE_CAPTURE_REQUIRED` | **NOT verified in this session.** |
| A12 | SecureX went GA **June 2020**; XDR announced **April 2023** (beta, GA planned July); XDR GA **31 July 2023**; SecureX later phased out into XDR | `OWNER_ASSERTED` | owner brief cites Cisco Newsroom/Blogs; not re-verified here |
| A13 | Response is **distributed** — XDR decides/orchestrates, the source product executes (e.g. Umbrella domain block/unblock, email quarantine/release/delete) | `PUBLICLY_DOCUMENTED` (pattern) + `OWNER_ASSERTED` (specific actions) | A1 sources describe `Respond` executing actions via integrated products |
| A14 | Incident prioritisation combines **detection risk with asset value** | `OWNER_ASSERTED` | owner brief cites Cisco docs; not re-verified |
| A15 | Screen-level layout, columns, filters, empty states of any Cisco screen | `REFERENCE_CAPTURE_REQUIRED` | **no Cisco screen captures exist in this repository** |

### Note on A10 and A11 — read this before citing them

These are the two load-bearing claims in the owner's architectural
argument, and **neither was independently verified in this session.**
Per owner decision (2026-06, Blocker 2 = option a) they remain
`OWNER_ASSERTED` and are **not** to be labelled `PUBLICLY_DOCUMENTED`.

The NivXRay decisions they support stand on their own merits regardless:

- **API-first is adopted as NivXRay engineering doctrine**, independent
  of Cisco attribution. Justification is internal, not comparative: this
  repository contains a very large API surface against a small
  operational core (exact counts: `08_VALIDATION/REALITY_MATRIX.md`), and
  the recurring defect class in this programme has been *surfaces that
  assert more than their API can prove*. API-first is the fix for our own
  observed failure mode.
- **A common canonical representation is already implemented** here
  (canonical evidence + canonical event schema + provenance). We do not
  need CTIM verified to keep it, and we must not copy CTIM's schema.

If the owner supplies Cisco DevNet/CTIM references later, upgrade the
class **without changing document structure**.

## B · Owner-supplied reference material held in the repo

| # | Material | Class | Where |
|---|---|---|---|
| B1 | `XDR.pptx` (76 slides) mined into a delta audit | `OBSERVED_FROM_REFERENCE` | `memory/MASTER_CISCO_DELTA.md` |
| B2 | Cisco reference intake + gap matrices | `OBSERVED_FROM_REFERENCE` | `memory/Y0_CISCO_XDR_REFERENCE_INTAKE.md` |
| B3 | Secure Endpoint device-trajectory conformance study | `OBSERVED_FROM_REFERENCE` | `memory/AMP_TRAJECTORY_CONFORMANCE.md` |
| B4 | NivXRay home-dashboard mockup (owner-created, 2026-09-07) | `OBSERVED_FROM_REFERENCE` | session attachment — **this is a NivXRay mockup, not a Cisco screen** |
| B5 | NivXForge EDR Response screenshot showing `ENDPOINT_NOT_RESOLVED` | `OBSERVED_FROM_REFERENCE` | session attachment |

**B4 caveat, recorded so it cannot be misused:** the mockup's figures
(`1,248 Monitored Devices`, `42 New Detections`, `23 Users at Risk`,
`12 Cloud Accounts`, `Email 3/5`, `Malicious IPs 1,284,532`) have **no
data source in this platform**. It is a layout reference only. Using its
numbers would violate the no-synthetic-operational-data rule.

## C · Our own runtime — the only source for current reality

All `CURRENT_REALITY` numbers in this tree come from
`scripts/docs_reconcile.py`, which imports the live FastAPI app, reads
the capability registry, parses the frontend router and queries the
operational database. Class: `RUNTIME_VERIFIED`.

| Generated document | Extracted from |
|---|---|
| `08_VALIDATION/REALITY_MATRIX.md` | all of the below, consolidated |
| `08_VALIDATION/GENERATED_ROUTE_INVENTORY.md` | `server.app.routes` |
| `08_VALIDATION/GENERATED_CAPABILITY_MATRIX.md` | `edr_plane/capability/inventory.py` |
| `08_VALIDATION/GENERATED_ENGINE_REGISTRY.md` | `nivxray::*` identities + endpoint-keyed store contract |
| `08_VALIDATION/GENERATED_UI_ROUTE_INVENTORY.md` | `apps/nivxray-xdr/src/App.jsx` |
| `08_VALIDATION/GENERATED_PROOF_INVENTORY.md` | `scripts/*proof*.py` + `backend/tests/**` |

## D · Explicitly out of bounds

Cisco source code, private APIs, internal implementation, undocumented
proprietary behaviour, trademarks, logos and protected assets. We
implement **equivalent observable capability** independently. Cisco is a
reference for *product decomposition and operational discipline*, never a
source of implementation.
