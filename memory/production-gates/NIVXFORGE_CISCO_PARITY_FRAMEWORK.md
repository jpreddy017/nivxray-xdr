# NIVXFORGE ↔ CISCO SECURE ENDPOINT · PARITY ENGINEERING FRAMEWORK

Owner-set governing rule, 2026-09-29:

> **Never substitute a guess about Cisco internals for engineering evidence.**

Cisco's undisclosed source code, model weights, training data, confidential
signatures and secret algorithms are OUT OF SCOPE and unknowable. We do not
claim to have reproduced them. For every capability we establish the
OBSERVABLE CONTRACT from legitimately available material and then engineer an
independently owned NivXForge equivalent.

## PIPELINE

```
CISCO SECURE ENDPOINT / AMP
      ↓
PUBLIC ENGINEERING RESEARCH
      ↓
EVIDENCE CLASSIFICATION   DOCUMENTED / OBSERVED / INFERRED / NOT VERIFIED
      ↓
NIVXFORGE INDEPENDENT DESIGN
      ↓
IMPLEMENTATION
      ↓
TEST + REAL ENDPOINT PROOF
      ↓
OWNER ACCEPTANCE
```

## MANDATORY PARITY RECORD (one per subsystem)

```
CISCO_CAPABILITY
PUBLICLY_DOCUMENTED_BEHAVIOR
PUBLICLY_OBSERVABLE_INPUTS
PUBLICLY_OBSERVABLE_OUTPUTS
UNDOCUMENTED_INTERNALS
NIVXFORGE_EQUIVALENT
NIVXFORGE_IMPLEMENTATION
EVIDENCE_PROVENANCE
TEST_CORPUS
REAL_ENDPOINT_PROOF
PARITY_GAPS
```

No subsystem is accepted without one. `CISCO_AMP_TRAJECTORY_ENGINEERING.md` is
the first completed instance (Device Trajectory).

## SUBSYSTEM REGISTER

| Subsystem | Cisco name | NivXForge equivalent | Parity record |
|---|---|---|---|
| Sensor / connector architecture | Secure Endpoint connector | NivXForge Windows/Linux sensor | pending |
| File inspection pipeline | SHA-256 → local cache → engines → cloud lookup | NivXForge file inspection chain | pending |
| Static AV | TETRA | NivXForge static engine | pending |
| ML file detection | SPERO | **NivXForge ML File Engine** — own feature extractor, own trained model, calibrated score → evidence → verdict | pending |
| Similarity / family | ETHOS | NivXForge malware similarity engine | pending |
| Reputation | File reputation / disposition | NivXForge reputation service | pending |
| Behavioural | Behavioral Protection | NivXForge evidence-backed behavioural engine | pending |
| Exploit prevention | Exploit Prevention | NivXForge exploit mitigation | pending |
| Script | Script Protection / AMSI | NivXForge script engine | pending |
| Network | DFC / network monitoring | NivXForge network engine | pending |
| Correlation | Cloud IOC | **authoritative correlation engine with `contributing_event_refs[]`** | pending |
| Retrospective | 7-day retrospective | NivXForge retrospective re-evaluation | pending |
| Trajectory | Device / File Trajectory | DT2 | **DONE — CISCO_AMP_TRAJECTORY_ENGINEERING.md** |
| Response | quarantine / isolate / scan | NivXForge response plane | pending |
| Policy | policy / exclusions | NivXForge policy plane | pending |
| Transport | cloud ↔ endpoint | NivXForge collector transport | pending |
| Contracts | APIs / event schema | NivXForge EDR API | P2 backlog |

Explicitly NOT to be said about any of the above: "we copied SPERO", "we
reproduced TETRA", "Cisco-equivalent content identification" — unless the
parity record proves the equivalence from observable evidence.

## SEQUENCE (owner-set)

1. Finish Device Trajectory (DT2-3c → final Cisco parity audit).
2. **NivXForge Endpoint Engine Foundation** — sensor/file identity + hashing +
   local cache + reputation FIRST, because TETRA/SPERO/ETHOS/retrospective/IOC
   equivalents all depend on trustworthy endpoint evidence underneath.
3. Detection engines, then correlation, then response.

No production deployment until the owner accepts each stage.
