# D19 — DECLARATION BATCH 2 · CLOUD & IDENTITY LANES

Date: 2026-09-15 · **PREVIEW ONLY — no production deployment, no merge.**

```
cd /app/backend && python -m pytest tests/test_d19_cloud_identity_declarations.py -q
cd /app          && python scripts/p0_d19_cloud_identity_live_proof.py
```

## RESULT: **PASS**

| Proof | Result |
|---|---|
| `tests/test_d19_cloud_identity_declarations.py` | **35 passed** |
| `scripts/p0_d19_cloud_identity_live_proof.py` (real HTTP, preview) | **PASS** — 26/26 checks |
| Regression (26 files: D2–D19, ingest, pipeline, EDR, rounds) | **649 passed**, 12 failures — all pre-existing, verified identical on a stashed clean tree |

## WHAT THE GATE FOUND (and it was worse than "undeclared")

Pointed at the cloud/identity lane, the D17 contract found that these rules
were not merely undeclared — **they read fields NivX has never produced:**

| Rule | Read | Reality |
|---|---|---|
| DET-PE-003 | `cloud.policy` | exists nowhere in the evidence model |
| DET-CR-004 | `event_id`, `ticket_options` for RC4 | `event_id` is NivX's OWN evidence id; RC4 lives in `ticket_encryption` |
| DET-CR-005 | `preauth_type` | in the 4768 record, not in the model |
| DET-CR-006 | `network.destination_ip` | a spelling that exists nowhere; the field is `network.dest_ip` |
| DET-EM-001 | `principal_kind` | exists nowhere |

On real telemetry **none of these five could fire at all** — they only ever
matched hand-made dictionaries in their own fixtures. Declaring them as
written would have produced citations pointing at nothing, which is the exact
failure D8 exists to prevent.

## SO THE EVIDENCE WAS FIXED FIRST (D18's lesson, applied again)

The smallest genuine prerequisites — each one a field the source already
sends:

| Added | From |
|---|---|
| `AuthEntity.preauth_type` | Windows 4768 `PreAuthType` |
| `CloudContext.principal_type` | CloudTrail `userIdentity.type`, **verbatim** (IAMUser / AWSService / AssumedRole — provider vocabularies are not translated into each other) |
| `CloudContext.request_parameters` | CloudTrail `requestParameters`, verbatim |
| operator `serialized_contains_any_ci` | a cloud authorization decision lives inside a structured document; it is searched as TEXT and the declaration says so |

Then the predicates were pointed at the canonical fields — **every raw-shape
key was kept**, so nothing that worked before stops working — and only then
were the rules declared.

**Declaration coverage: 22/37 → 27/37.** `rule_version` 1 → 2 on all five.

## WHAT D19 REFUSED TO DECLARE

| Rule | Why |
|---|---|
| DET-PS-004 (M365 malicious inbox rule) | NivX has **no M365 / Graph audit DSM**. Not a missing field — a missing SOURCE. |
| DET-PE-002 (AD CS ESC1 abuse) | NivX has **no AD CS certificate DSM** (4886/4887). |

Both stay on the frozen ledger with the gap named in `TELEMETRY_GAPS`, and a
test asserts that no `certificate.*`, `cloud.rule_name`, `cloud.policy`,
`principal_kind` or `network.destination_ip` field was invented to make them
look supported.

## LIVE PROOF (preview, real HTTP, declared ingest)

| Delivered | Result |
|---|---|
| CloudTrail `PutUserPolicy` with `"Action":"*"` | DET-PE-003 · CITED on `cloud.action` + `cloud.request_parameters` |
| CloudTrail `PutUserPolicy` with `s3:GetObject` | evidence, **no detection** |
| Windows 4769, RC4 `0x17`, user SPN | DET-CR-004 · CITED on `source_event_id` + `authentication.ticket_encryption` + `authentication.service_name` |
| Windows 4769, AES `0x12` | evidence, **no detection** |
| Windows 4768, `PreAuthType=0` | DET-CR-005 · CITED on `authentication.preauth_type` |

D12 temporal semantics (EVTX = `OBSERVATION_TIME`), D14 tenant authority and
D15 declared routing are unchanged on all five deliveries.

## REMAINING DECLARATION DEBT (10 of 37)

Content/behaviour lane (8): `DET-EX-001`, `DET-IA-002`, `DET-DE-001`,
`DET-DE-003`, `DET-LM-002`, `DET-IM-004`, `DET-EM-002`, `DET-CC-002`.
Source-blocked (2): `DET-PS-004`, `DET-PE-002`.

**TEST/SYNTHETIC payloads. No real AWS account or domain controller
connected. Nothing deployed, no protected branch touched.**
