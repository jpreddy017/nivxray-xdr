# DEVICE TRAJECTORY V2 — PUBLIC REFERENCE ADDENDUM (DT2-0)

Fresh public research pass, reconciled against
`DEVICE_TRAJECTORY_V2_ARCHITECTURE.md`. **No architecture rewrite was
required**; the research refines wording and adds one distinction we had not
named explicitly (Activity vs Behavioral telemetry).

## Method and IP discipline

Sources consulted are Cisco **public** material only: Secure Endpoint User
Guide (docs.amp.cisco.com), Cisco support/TAC articles on identifying the
detection engine and troubleshooting Exploit Prevention, the Cisco Security
blog article on endpoint telemetry, Cisco Live TACSEC-2012 public deck, and
Cisco DevNet Secure Endpoint API material. **No Cisco source code, asset, CSS,
icon, font, branding or private protocol was obtained, inspected, copied or
required.** Nothing was decompiled or reverse engineered; no access control was
circumvented. Cisco's trajectory engine is not publicly released, so NivXForge
implements the operational semantics independently.

Source/license register: **no third-party source code was incorporated.**
Reference material is documentation and prose → **REFERENCE ONLY**. No
license obligation attaches to the NivXForge implementation, which is
original work in this repository.

## Classification matrix

| Reference capability | Public evidence | Class | Existing NivXForge | Phase-B design | Gap | Slice | Contract impact | Telemetry dep. | Acceptance |
|---|---|---|---|---|---|---|---|---|---|
| Events → Device Trajectory opens on that event | User Guide / TAC articles describe clicking the Device Trajectory icon from an event and landing on it | **[DOCUMENTED]** | focus API exists, no Events link | FocusTarget + row action | UI entry point | DT2-2 | `FocusTarget`/`FocusResolution` (**built**) | none | Story C |
| Activity Telemetry: processes, parent-child, files, network, "noise reduced" | Cisco blog distinguishes Activity vs Behavioral telemetry | **[DOCUMENTED]** | canonical observations | Observation model | none | DT2-0 | `Observation.activity_class` (**built**) | 8 families | §55 |
| Behavioral Telemetry: produced *after* detection-engine analysis, links malicious to benign activity | same blog | **[DOCUMENTED]** | detection attribution on rows | detections separate from observations | naming only | DT2-0 | `DetectionMarker` separate object (**built**) | deterministic engine | §55 |
| Event Details shows the responsible detection engine | TAC "identify detection engine" article | **[DOCUMENTED]** | `detected_by` present | inspector DETECTION tab | tab | DT2-4 | `DetectionMarker.engine/engine_version` (**built**) | engine metadata | Story B |
| Observables + Observed Activity summary | User Guide (Behavioral Protection events) | **[DOCUMENTED]** | observables/MITRE in pane | inspector SUMMARY/EVIDENCE | tabs | DT2-4 | unchanged | none | Story B |
| Filter trajectory by file name / threat / IP / GUID | Cisco Live deck | **[DOCUMENTED]** | substring `q` + kinds | field-scoped search | scoping | DT2-5 | `applied_search` declares current mode (**built**) | none | Story A |
| Trajectory API with time-range (`start_time`/`end_time`) | DevNet API material | **[DOCUMENTED]** | our own windowed API | `TrajectoryWindow` ranges | none | DT2-0 | requested/effective/available ranges (**built**) | none | §55 |
| Loads historical data on demand while scrolling; 30-day history; activity spikes | Cisco public blog/deck | **[DOCUMENTED]** | cursor + prefetch + 30-day band | density + window triple | controls | DT2-1/8 | `DensityBucket` (**built**) | none | Story D |
| Review activity before and after an IOC | Best-practice guidance | **[DOCUMENTED]** | manual scroll | jump prev/next + anchor | controls | DT2-1/6 | none | none | Story B |
| Command-line context on processes | User Guide / deck | **[DOCUMENTED]** | present | ProcessInstance | none | DT2-0 | `ProcessInstance.command_line` (**built**) | Sysmon 1 | Story A |
| Retrospective analysis / forensic snapshot as separate capabilities | Cisco public material | **[DOCUMENTED]** | not built | kept separate (§34 mandate) | future | post-DT2 | contracts are versionable, evidence immutable (**built**) | n/a | — |
| MATCH n OF m search navigation | not found publicly | **[INFERRED — REFERENCE BEHAVIOUR NOT VERIFIED]** | none | match cursor | UI+API | DT2-5 | shape reserved in `applied_search` | none | Story A |
| Keyboard shortcut set | not found publicly | **[INFERRED — NOT VERIFIED]** | none | §40 of architecture | UI | DT2-1/4 | none | none | Story A |
| Browser Back/Forward stepping investigation states | not found publicly | **[INFERRED — NOT VERIFIED]** | replace-only | PUSH/REPLACE rules | UI | DT2-1/2 | none | none | Story C |
| Timeline double-click semantics | referenced in public material, exact behaviour unverified | **[INFERRED — NOT VERIFIED]** | none | double-click = zoom to interval | UI | DT2-1 | none | none | Story D |
| Seven-state coverage truth (UNKNOWN-first) | no reference equivalent found | **[NIVXFORGE DESIGN DECISION]** | header sentence only | CoverageInterval | — | DT2-0 | `CoverageInterval` (**built**) | heartbeat/policy/parser | Story E |
| UNATTRIBUTED evidence preserved rather than hidden | no reference equivalent found | **[NIVXFORGE]** | implicit | owner decision §14 | — | DT2-0 | `attribution_state` (**built**) | none | §55 |
| Explicit identity authority / downgrade | no reference equivalent found | **[NIVXFORGE]** | guid binding exists | authority fields | — | DT2-0 | `identity_authority` (**built**) | ProcessGuid | §55 |
| Forbidden proximity-derived edges | no reference equivalent found | **[NIVXFORGE]** | lane proximity implied edges | evidence-backed only | — | DT2-0 | `FORBIDDEN_BASES` rejection (**built**) | none | §55 |

No aggregate parity percentage is produced.

## Reconciliation verdict

1. **Phase-B architecture stands.** Every documented reference behaviour maps
   to an already-planned slice; none contradicts the contract.
2. **One refinement adopted**: Cisco's public Activity-vs-Behavioral telemetry
   split is exactly our Observation-vs-DetectionMarker authority separation, so
   DT2-0 states it explicitly in `models.py` (`DetectionMarker` is analytical
   output and never mutates an `Observation`; NivXForge-derived ATT&CK is
   labelled `AUTHORITY_DERIVED`).
3. **Three behaviours remain unverified** (match navigation, keyboard set,
   Back/Forward stepping, timeline double-click) and are implemented as
   NivXForge decisions labelled NOT VERIFIED — not as Cisco facts.
4. **Two NivXForge capabilities exceed the public reference**: seven-state
   coverage truth with an UNKNOWN-first rule, and mandatory evidence
   references with forbidden derivation bases.
5. **No V1 substrate is replaced** (REPLACE: none, unchanged from Phase A/B).
