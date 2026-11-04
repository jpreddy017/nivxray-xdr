<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> Describes the **external reference product's** integration model.
> Our contract derived from it: `02_ARCHITECTURE/INTEGRATION_ARCHITECTURE.md`.

# CISCO INTEGRATION MODEL

Evidence class: `PUBLICLY_DOCUMENTED` unless noted
(`SOURCE_REGISTER.md` A1–A8).

## 1 · The model

Integrations are **modular capabilities**, configured per integration on
an Integrations page, where an administrator can see which features each
integration supports. Cisco and third-party products alike declare
against the same set.

| Capability | Documented purpose |
|---|---|
| **Data Ingestion** | ingest and analyse raw telemetry and security events into the XDR data warehouse, which then generates detections and incidents |
| **Observe** | return sightings of an observable from the integrated product |
| **Deliberate** | provide a disposition for an observable: `clean`, `malicious`, `suspicious`, `unknown` |
| **Refer** | supply links to external resources / a pivot menu for an observable |
| **Respond** | execute response actions (e.g. host isolation, blocking IPs) via the integrated product, often through automation workflows |
| **Assets** *(formerly `Device Insights`)* | normalise, deduplicate and correlate endpoint data into a unified asset view, pulling device information via REST full/delta sync or webhooks |
| **Health** | prove the integration works |
| **Dashboards** *(formerly `Tiles`)* | surface metrics and statistics from the integrated product on the XDR dashboard |
| **Automation** | execute response playbooks and data-ingestion tasks via workflows; triggers include Approval, Email, Incident, Schedule and Webhook |

### Naming corrections
`Tiles → Dashboards` and `Device Insights → Assets`. The owner's brief
uses the older names; our contract uses the current ones.

## 2 · Custom source ingestion — a concrete adoption candidate

A three-step REST flow:

1. **Create upload** — `POST /api/sources/{sourceId}/uploads?format=…`
   returns an `uploadId` and a presigned URL.
2. **Upload file** — `PUT` the content (CSV, JSON or JSONL) to the
   presigned URL.
3. **Poll status** — `GET` the status endpoint with the `uploadId` until
   `completed` or `failed`.

**Why this matters to us.** It is the pattern for sources that cannot
stream — offline exports, batch feeds, forensic drops. Nothing
equivalent exists in NivXRay. It is cheap to add, it does not require a
new data model, and it is the lowest-effort route to a *second* evidence
source that is genuinely independent of the endpoint agent.

Caveat to record honestly: a batch file of endpoint data is **still the
endpoint domain**. This pattern widens *transport*, not *domain*.

## 3 · Why the model is the thing to copy

One contract, many technologies. An endpoint agent, a DNS/SWG product
and an email product implement overlapping subsets of the same
capability list despite sharing no technology. The platform therefore
needs no per-vendor architecture.

Applied to NivXRay: **Windows EDR, Linux EDR, firewall, DNS, email,
identity and cloud all become implementations of one platform contract.**

## 4 · What we deliberately do not copy

| Item | Reason |
|---|---|
| CTIM / Cisco schemas | we already have a canonical model; copying is unnecessary and legally unwise. Class: `OWNER_ASSERTED` + `REFERENCE_CAPTURE_REQUIRED` |
| Cisco endpoint names / paths | independent implementation |
| Connector count as a target | parity is observable capability, not connector volume |

## 5 · Where we exceed the model

Two additions, both driven by our own defect history rather than by
comparison:

1. **`VERIFY`** — a `RESPOND` capability must supply post-action
   evidence. No verification ⇒ no success.
2. **Named-absence failure semantics for every capability** — unqueried
   ≠ not seen; provider-down ≠ `clean`; unresolvable identifier ≠ empty
   result.
