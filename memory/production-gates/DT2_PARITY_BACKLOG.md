# DEVICE TRAJECTORY · CISCO PARITY BACKLOG (owner-approved, 2026-09-29)

Raised while closing the pre-DT2-3c parity gaps. Not to be worked inside the
DT2-3 chain unless the owner redirects.

## P1 · FILE CONTENT IDENTITY (sensor capability)

Cisco identifies a file's class from CONTENT — its cloud-queried set is a list
of type identities (MSEXE, MSOLE2, OOXML_WORD, POWERSHELL, SCRIPT, LNK, MBR,
REGISTRY, SETUP_INFO, SWF, ZIP, PDF, HTML_APP, ENCRYPTED_SCRIPT …; TAC 118711)
and File Trajectory exposes real file type, size, detection names, filenames
and signing-certificate information (Best Practices Guide).

NivXForge today derives the class from the observed path extension:

```
classification_basis = PATH_EXTENSION_DERIVED_NOT_CONTENT_IDENTIFIED
```

That label must stay visible until the sensor emits:

```
FILE OBSERVATION
  ├── observed path                  (have)
  ├── SHA-256 when available         (MISSING — 0 of 3298 observations carry one)
  ├── content / file type identity   (MISSING)
  ├── file size                      (MISSING)
  ├── signing information            (MISSING)
  └── provenance                     (have)
        ↓
CANONICAL FILE ARTIFACT
```

It is NOT to be called Cisco-equivalent content identification before then.

## P1 · FILE SIZE · P1 · EXECUTION CONTEXT

Cisco Event Details carries file size and execution context (User Guide p.403).
Neither is emitted by the NivXForge Windows sensor. `AmpEventDetails` states
the gap rather than blanking the field.

## P1 · SYSTEM / CONNECTOR LIFECYCLE TELEMETRY

Cisco's System band carries connector events: reboots, user-initiated and
scheduled scans, policy and definition updates, connector updates, connector
uninstall (p.403). NivXForge emits none, so the band renders empty. UI is
correct; the telemetry is missing.

## P1 · AUTHORITATIVE IOC CONTRIBUTOR-SET CONTRACT

DT2-3c's blue halo needs, per compromise:

```
compromise_event_id → contributing_event_refs[]
```

referencing the actual observations that satisfied the indicator. Cisco
computes this cloud-side over a 7-day retrospective window and enriches with
MITRE. NivXForge publishes no such set:

```
IOC_CONTRIBUTOR_PROVENANCE = MISSING
```

Until the contract exists the halo stays disabled. It must never be derived
from time proximity, same process, same SHA, same user, same window or
frontend adjacency.

## P1 · STRONGER PROCESS / FILE IDENTITY

Cisco resolves parent/child by SHA-256 file identity
(`file.parent.identity.sha256`). NivXForge currently downgrades to a PID
surrogate — `authority: DERIVED`, `downgraded: true`,
`CANONICAL_ACTOR_PROCESS_BINDING`. Replace with hash/ProcessGuid identity when
the sensor provides it.

## P1 · NORMALIZER DEFECT · `kind=detection` FOR SYSMON REGISTRY EVENTS
### STATUS: FIXED 2026-09-29 for NEW ingestion (no backfill)

Root cause found in `backend/v2/ingestion/canonical.py::_resolve_kind`: the
Sysmon Event ID never reached the CES for the collector path
(`event_id: null`), so `isinstance(eid, int)` was False, the heuristics could
not place the record, and the function's **catch-all default was
`"detection"`**. A kind was therefore being used as a verdict: 3100 Sysmon
registry observations were stamped as detections and drew navigator compromise
markers with no detection evidence at all.

Fixed:

```
SYSMON_KIND.get(eid, …)   default "detection" → "unclassified_telemetry"
WINSEC_KIND.get(eid, …)   default "detection" → "unclassified_telemetry"
registry heuristic        registry_value present → registry_value_set
                          else                   → registry_create
final catch-all           "detection" → "unclassified_telemetry"
```

Verified: sysmon 12 → `registry_create`, 13 → `registry_value_set`,
registry_key without an Event ID → `registry_create`, unplaceable →
`unclassified_telemetry`.

REMAINING: the 3100 already-stored observations keep `kind=detection` because
the standing ruling forbids modifying evidence. Presentation is safe — the
navigator requires `compromise_authority` — but a re-ingestion or an
owner-authorised reclassification is needed for those records to carry the
correct kind. **Requires an owner decision.**

Still open: the Event ID should also be carried into the CES on the collector
path so the deterministic map is used instead of the heuristics.

## P2 · TRAJECTORY API PARITY

Cisco's `GET /v1/computers/{connector_guid}/trajectory` accepts
`start_time`/`end_time`, exposes command-line and network examples, and since
June 2024 supports username search; the separate user-trajectory endpoint was
removed in favour of the main endpoint. Converge the NivXForge endpoint's
parameter surface and response shape.
