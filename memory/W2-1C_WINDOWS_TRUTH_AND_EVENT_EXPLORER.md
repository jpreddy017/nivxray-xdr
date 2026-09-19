# W2-1C · Windows channel truth model + Event Explorer + Defender DSM (2026-06)

Owner-approved execution: Shared Truth Contract → Lane G → Lane H →
Defender DSM. RBAC stays a separate pass. Lane B (real Windows host) is
independently waiting on the W2-R0 JSON and did not block any of this.

## 1 · Shared truth contract (serialized first)

`backend/services/windows_channel_truth.py` — the single server-side
authority. **Five dimensions, none derived from another:**

| Dimension | Values | Source of truth |
|---|---|---|
| Collection | NOT CONFIGURED · CONFIGURED · NOT OBSERVED · RECEIVING · GAP DETECTED · DEGRADED · ERROR · UNSUPPORTED | `xdr_canonical_events` + `xdr_collectors` |
| Parsing | NOT EVALUATED · SUPPORTED · PARTIAL · UNSUPPORTED · ERROR | platform declaration **and** measured `parser_ok`, side by side |
| Normalization / canonical evidence | same vocabulary | declaration **and** measured `xdr_canonical_evidence` rows |
| Detection **capability** | NOT AVAILABLE · PARTIAL · AVAILABLE | deployed content inventory × the capability tokens this channel's evidence provides |
| Detection **activity** | measured firings | `xdr_detection_matches` joined to the evidence the rule actually read |

**Owner correction #4 is implemented literally.** Capability never depends
on a rule having fired:

```
Security · Collection NOT CONFIGURED · Parsing SUPPORTED (measured NOT EVALUATED)
         · Normalization SUPPORTED  · Detection capability AVAILABLE (21 eligible rules)
         · Detections observed: null  (NOT MEASURED — not zero)
Acquired ✗   Understood ✗   Detectable ✓
```
Verified live on the preview backend. A tenant with applicable deployed
content and no attacks reports AVAILABLE capability and no activity, and
historical firings never prove present capability.

Other invariants enforced in code and asserted in tests:
* `NOT MEASURED` (`null` → `—`) is never rendered as `0`.
* `CONFIGURED` / `NOT OBSERVED` / `NOT CONFIGURED` are three different
  answers: authorized-but-no-window, authorized-and-alive-but-silent, and
  no authorization at all.
* A declaration contradicted by measurement raises
  `DECLARED SUPPORT CONTRADICTED BY MEASUREMENT`; the declaration is not
  quietly rewritten.
* `overview.composite_health` is **null** with the reason published —
  there is deliberately no green light.
* `overview.real_endpoint_proof` = **NOT PROVEN** until W2-R0…W2-R6.
* PARTIAL normalization caps capability at PARTIAL (classic PowerShell).

## 2 · Lane G · `Data Sources → Windows`

`GET /api/xdr/windows/{overview,channels,channels/{channel},devices,
devices/{origin},collectors,configuration}` — read-only,
`data_sources.read`.

UI `apps/nivxray-xdr/src/xdr/datasources/windows/` ·
`/xdr/data-sources/windows/:tab` · nav row under Data Sources.
Tabs: Overview | Devices | Channels | Collectors | Coverage | Health |
Configuration.

Channels table: Channel · Device(s) · Collection · Last Event · Events ·
Parsing · Normalization · Detection · Gap · Attention. The contextual pane
exposes collection state, last telemetry, providers, event IDs observed,
events delivered, parse status, normalization status, canonical evidence,
detection capability with the eligible rule list, queue/bookmark state,
collection gaps, profile and provenance.

`Acquired → Understood → Detectable` is computed by `_human_stages()`,
which **creates no new truth** — each stage carries the dimension it
stands on and drills into it. Asserted by
`test_the_summary_bar_cannot_manufacture_a_stage`.

**Device identity (owner directive #2).** `origin_computer` is recorded as
`evidence_origin` with `identity_state = EVENT_ASSERTED_ORIGIN`;
`collector_host` stays a separate fact; `canonical_device_id` is **null**
with the reason, and an `aliases` block is present for the stronger
identifiers to land in later (fqdn, domain, machine GUID, EDR device id,
enrolment identity, SID, cloud instance id, with IP/MAC as observations).
Unmatched origins report **EDR association: NOT ESTABLISHED**, never
`UNENROLLED`. OS/version/profile render only when a collector reported
them.

## 3 · Lane H · Event Explorer

`GET /api/xdr/events/search` · `/facets` · `/{event_id}` —
`evidence.read`. Reads `xdr_canonical_evidence`, so it is source-agnostic
from day one: Windows is the first population, not the schema boundary.
No Windows-specific event schema exists to replace.

Table: Time · Host · Channel/Source · Provider · Event ID/Type · User ·
Process · Activity · Level · Detection · Evidence. Filters ride the query
string, so every pivot is a shareable deep link, and Lane G pivots into it
(`Open in Event Explorer`, `Open host in Event Explorer`).

Pane: Summary | Fields | Raw | Normalized | Canonical Evidence |
Relationships | Detection | Provenance, above the explicit chain

```
Raw Event → Parsed Fields → Normalized Event → Canonical Evidence
          → Detection → Incident
```

each stage with its own state, evidence reference and — when it did not
happen — its reason. Raw rendered XML is displayed verbatim and labelled
immutable. No fixtures anywhere: an empty result is an empty result.

## 4 · Defender DSM

`detection_content/telemetry/windows_defender_dsm.py` ·
`windows-defender-evd` · aliases `microsoft_defender`, `defender`,
`windows_defender`. Covers 1006/1007/1008/1009/1015/1116/1117/1118/1119,
1150/1151 and 5001/5004/5007/5010/5012.

The boundary the owner asked for is explicit in the evidence:
`additional_fields.vendor_verdict` carries Microsoft's threat name,
severity, category and action **verbatim**, labelled as the vendor's own
claim, with an `authority_note` stating it is source evidence and is never
promoted to a NivXRay verdict. The DSM writes no verdict, promotes no
incident and does not invoke Command Intelligence.

Temporal handling differs from the other Windows channels *because the
format differs*: Defender states its own `Detection Time`, which IS the
activity instant, so the basis is `ACTIVITY_TIME` while `TimeCreated`
remains the observation. Asserted in the D12 cross-DSM suite.

## 5 · Verification (self-test only, per owner)

```
backend    tests/test_w2_windows_channel_dsms.py  + d12 + d15 + d21
           + p0_3 + phase2_telemetry + telemetry_adapters
           + n1_zeek + w1_forwarder + d13          337 passed, 14 skipped
collector  tests                                   134 passed
frontend   vite build                              clean, exit 0
live       /api/xdr/windows/* · /api/xdr/events/*  200 with a real token,
                                                   403 unauthenticated
smoke      /xdr/data-sources/windows/{channels,overview} and /xdr/events
           render with their test ids present; an unselected customer
           renders the server's fail-closed reason as TEXT, not a crash
```

The D12 guard gained samples for `m365-unified-audit` (pre-existing gap),
`windows-powershell-evd` and `windows-defender-evd`, and its `_strip_time`
helper now also strips nested `EventData` timestamps — without that the
Defender activity-time regression could not have been exercised.

## 6 · Still open

* Bookmark/queue position is `NOT AVAILABLE` and says why: the collector
  holds it locally and does not publish it yet (W2 contract C-4).
* Detection content targeting Security/PowerShell/Defender canonical
  evidence — capability is computed, not asserted, so it will move on its
  own as content lands.
* DSMs for Task Scheduler, WMI-Activity, AppLocker, System, Application
  (declared roadmap positions 1–5).
* Canonical NivX device identity + alias reconciliation (EDR device id,
  machine GUID, enrolment identity) — the seam exists, the resolver does
  not.
* RBAC / Group Access repair — the next independent pass.
* **Real Windows endpoint proof — NOT PROVEN.** Nothing in this change set
  alters W2-R0/R1 acceptance.
