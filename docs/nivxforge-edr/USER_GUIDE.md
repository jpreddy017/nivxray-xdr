# NivXForge EDR · User Guide

## What NivXForge EDR is

An independent endpoint detection and response product: its own
console, its own navigation, its own evidence stores. It publishes
detection findings to NivXRay XDR as **one detection source among
others** (peers include CrowdStrike, Defender, SentinelOne, Cortex). No
ordinary EDR operation routes into XDR. Where a cross-product pivot
exists it is explicitly labelled *Open in NivXRay XDR ↗*.

## The truth vocabulary

The console never renders a prettier word than the server's. Learning
six distinctions makes every surface readable.

| You see | It means | It does NOT mean |
|---|---|---|
| `NOT OBSERVED` / `NOT AVAILABLE` / `◇` | the fact was not recorded | zero, or clean |
| `NOT_EVALUATED` | an engine did not run on this evidence | the evidence was benign |
| `EVALUATED_NO_MATCH` | an engine ran and found nothing | nothing happened |
| `DELIVERED` | the platform handed a policy version over | the endpoint applied it |
| `APPLIED` | the endpoint acknowledged applying that exact config digest | the setting is being enforced |
| `NOT_ENFORCED` | the released connector cannot honour a requested setting | the setting is off by choice |

A number and an absence are never merged. `0` detections means
*evaluated and genuinely zero*; `NOT EVALUATED` means *we did not look*.

## Navigation

### Operations

* **Dashboard** — fleet posture from recorded facts.
* **Computers** — the enrolment and liveness grid. `CONNECTED` requires
  authenticated telemetry inside the connector's own declared cadence.
  Each status carries the server's basis sentence.
* **Detections** — detections derived from the platform's own detection
  content, with the rule and source that produced each one.
* **Events** — the estate-wide event explorer. See
  [Events Guide](EVENTS_GUIDE.md).

### Investigate

* **Device Trajectory** — the per-computer activity timeline.
* **Process Tree** — endpoint-keyed ancestry from canonical process
  identities, never pid alone.
* **Campaign Story** — the narrative composed from recorded evidence.
* **Hunt · Files · Network · Forensics · Live Query** — **NOT
  IMPLEMENTED.** Each destination is present and disabled, and states
  why. They are not enabled links into empty pages.

### Respond

* **Response** — the analyst response plane (isolation policy, actions,
  verification).
* **Policies** — the policy authority. See
  [Policy Guide](POLICY_GUIDE.md).
* **Exclusions** — declared protection blind spots. See
  [Exclusions Guide](EXCLUSIONS_GUIDE.md).

### Management

* **Downloads** — the connector release catalog and deployment
  workflow. See
  [Connector Deployment Guide](CONNECTOR_DEPLOYMENT_GUIDE.md).
* **Audit** — **NOT IMPLEMENTED** for the EDR plane in this wave.
  Policy and exclusion actions are recorded (`edr_policy_audit`, the
  exclusion `audit[]`) and are reachable through the API.

## Tenancy

Every tenant-scoped surface requires an explicit customer selection.
There is no default tenant and a request that names a tenant the
operator does not hold is refused outright rather than quietly
downgraded. A cross-tenant operator who names one tenant is scoped to
that tenant and nothing else.

## Themes

Light and dark are both release-quality and are driven by the same
token set. A surface that only reads correctly in one theme is a defect.

## Where the data comes from

| Surface | Store |
|---|---|
| Events, Detections | `edr_raw_events` (immutable, append-only, with appended derivations) |
| Computers | `edr_endpoints` (enrolment truth) |
| Device Trajectory, Process Tree | canonical observations |
| Policies | `edr_policies`, `edr_policy_versions`, `edr_policy_endpoint_state` |
| Exclusions | `edr_exclusion_sets`, `edr_exclusions` |
| Findings | `edr_findings` (detection fabric) |

Raw events are never overwritten. Every pipeline pass is appended as a
derivation, so a parser fix can be replayed and the record honestly
shows both what was believed before and after.
