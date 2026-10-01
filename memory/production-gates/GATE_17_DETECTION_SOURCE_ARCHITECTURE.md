# GATE 17 · DETECTION SOURCE ARCHITECTURE (vendor-neutral XDR intake)

Status: **DESIGN FROZEN · NOT IMPLEMENTED.** Nothing in this document is
built yet, and nothing existing was changed to produce it.

Owner architecture correction: do **not** invent a NivXForge-specific
EDR→XDR model. Reproduce the Cisco XDR *Detection Source* architecture,
in which Cisco Secure Endpoint is **one first-class endpoint detection
source among several** (Cisco documents CrowdStrike Falcon, Microsoft
Defender for Endpoint, SentinelOne Singularity, Palo Alto Cortex XDR and
others the same way), and the newer Findings Intake path accepts
external findings in a normalised schema (Cisco describes OCSF 1.4 for
that service, in beta as of Nov 2025).

Reference material named by the owner (Cisco official): *XDR Custom
Security Events / Detection Sources*, *XDR Custom Integration Guide*, and
the XDR integration pages for CrowdStrike Falcon, Microsoft Defender for
Endpoint, SentinelOne Singularity and Palo Alto Cortex XDR, plus the
current Cisco XDR data sheet's endpoint integration list.

## 1 · The three levels, kept distinct

```
LEVEL 1 — SOURCE PRODUCT
  NivXForge EDR | CrowdStrike | Defender | SentinelOne | Cortex | …
  emits its own Alert / Detection / Behavior, in ITS vocabulary
        │
        │  integration adapter (per product, per version)
        ▼
LEVEL 2 — NIVXRAY XDR
  Normalised SECURITY EVENT / DETECTION FINDING
  detection_source is a FIRST-CLASS, non-optional field
        │
        │  correlation: shared observables · overlapping time ·
        │               related attack patterns · entity resolution
        ▼
LEVEL 3 — NIVXRAY XDR
  INCIDENT (XDR-owned) → attack story → investigation → response
```

Rules that follow, and that the implementation must not blur:

* **Source identity is preserved on every finding.** A CrowdStrike
  detection is never relabelled as though NivXRay originated it, and
  NivXForge is not privileged in the record.
* **A source product's own incident is not imported as an XDR incident.**
  XDR incidents are produced by XDR correlation over findings.
* **Correlation does not require two vendors.** A single sufficiently
  severe finding may be promoted, with its supporting evidence — the
  "two products or no incident" rule is invented and is rejected.
* **NivXForge gets no private pathway.** It goes through the same
  adapter → intake → normalised finding → correlation chain. It may
  expose *richer capabilities*; it may not have a *different
  architecture*. This is the rule that stops NivXRay from becoming an XDR
  that only works with our own EDR.

## 2 · Capability discovery per integration (truthful, not assumed)

Every integration declares what it actually supports, and the console
renders unsupported as unsupported — never as "nothing found":

| capability | meaning |
|---|---|
| `DATA_INGESTION` | the source pushes/exports findings into XDR |
| `OBSERVE` | XDR can ask the source where/how an observable was seen |
| `DELIBERATE` | the source returns its own disposition/intelligence |
| `REFER` | XDR can deep-link into the source product's investigation |
| `ASSET_CONTEXT` | device/endpoint inventory for entity resolution |
| `RESPOND` | isolation / quarantine / block, per the source's authority |
| `AUTOMATION` | the source's actions are available to XDR workflows |
| `HEALTH` | XDR can verify the integration and its data health |

Example of the required honesty (this is the product rule, not a mock):
an integration offering `DATA_INGESTION · OBSERVE · REFER` but no
`RESPOND` must show host isolation as **NOT SUPPORTED BY THIS
INTEGRATION**, not as a disabled button with no reason and not as a
failure.

Health must obey the platform's existing truth rule: `CONNECTED ·
EVIDENCE INCOMPLETE` is a valid state; collapsing it to `HEALTHY` is not.

## 3 · Response authority across the boundary

```
NivXRay XDR  ──REQUEST──▶  authoritative response gateway
                                   │
                                   ▼
                          source product's own authority
                          (NivXForge EDR · or the third party)
                                   │
                                   ▼
                          endpoint execution → result
                                   │
                                   ▼
                          INDEPENDENT VERIFICATION
```

XDR may orchestrate; it may never bypass the endpoint authority. The
existing six-state rule is unchanged and applies to third-party sources
too: `REQUESTED ≠ APPROVED ≠ DISPATCHED ≠ EXECUTED ≠ RESULT_REPORTED ≠
VERIFIED`. *XDR requesting isolation is not an isolated endpoint.*

## 4 · No database coupling

XDR must not read NivXForge's Mongo collections as its integration
contract. The contract is a versioned, authenticated service/event
interface with a declared schema version on every finding — the same
interface a third-party adapter uses.

## 5 · Entity resolution

`NivXForge endpoint · CrowdStrike host · Defender machine · SentinelOne
agent · NDR device · identity device` → **entity resolution** → one
NivXRay device, with each contributing source cited. Same entity,
different analytical scope; the EDR view stays endpoint-deep, the XDR
view stays cross-domain.

## 6 · Prerequisites before implementation starts

1. The normalised finding schema, versioned, with `detection_source`
   mandatory (align with OCSF where it fits rather than inventing a
   private shape).
2. Gate 3's `Finding` contract as NivXForge's *outbound* projection —
   the two must agree on evidence references and on analysis vs
   observation time, which is why this is serialised with Gate 3 and
   Gate 6.
3. An integration registry with declared capabilities + health, in the
   same declarative style as the fabric's analyzer registry, so a
   structural test can assert that no integration silently claims a
   capability it does not implement.
4. A per-source adapter boundary (one module per product/version) with
   its own conformance tests against recorded, redacted sample payloads.
