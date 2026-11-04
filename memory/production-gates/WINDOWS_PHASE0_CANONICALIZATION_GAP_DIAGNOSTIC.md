# WINDOWS PHASE-0 LIVE PROOF · CANONICALIZATION GAP — DIAGNOSTIC (A–F)

Mode: **READ-ONLY**. Nothing patched, nothing deployed, no restart, no
migration, no backfill. No production DB/API call was made (the production
admin password is owner-held and was not requested). No endpoint action;
`ep_1989031c8c1d0085812f` untouched. No token minted or consumed. No
credential, token, JWT or pepper appears below.

Method: the **real sensor code** (`agents/nivxforge-windows/nivxforge_sensor.py`)
was driven over a realistic `wevtutil qe … /f:RenderedXml /e:Events` stdout
containing a Sysmon **EventID 1** (Process Create, with ProcessGuid, Image,
CommandLine, Parent*) **and** a `System` / `Microsoft-Windows-Kernel-General`
**EventID 1**, then the resulting envelopes were pushed through the real
production code path `edr_plane.canonical_bridge.bridge()` against a
throwaway local database (`diag_scratch_ro`, dropped afterwards).

---

## A · EXACT LIVE EXECUTION PATH

```
sensor  nivxforge_sensor.collect()
        └─ _query_channel("Microsoft-Windows-Sysmon/Operational", after_record)
           wevtutil qe … /q:*[System[EventRecordID>N]] /c:100 /e:Events /f:RenderedXml
        └─ envelope {kind: WINDOWS_EVENT_LOG, winlog:{channel, record_id,
                     event_id, time_created, computer, provider, xml}}
        └─ outbox.jsonl (durable)  →  _drain()
           POST /api/edr/agent/telemetry  {payload: <json line>, source_kind: "sensor"}

backend routers/edr_enrollment.py::ingest                       (line 397-447)
        ├─ get_authenticated_endpoint  → tenant_id, endpoint_id (server-side)
        ├─ raw.RawEndpointEvent.build(... trust_state="AUTHENTICATED") → raw.append
        ├─ store.mark_reported()                      → last_telemetry_at
        └─ edr_plane.canonical_bridge.bridge()                  (line 444)
             ├─ next_generation()
             ├─ parse(payload)                                  (line 90)
             │    └─ winlog.is_windows_envelope() TRUE → _parse_windows()   (296)
             │         └─ edr_plane/windows_eventlog.py::to_canonical()     (293)
             │              ├─ parse_event_xml()   System + EventData        (140)
             │              └─ classify()  provider family + EventID         (186)
             │                   SUPPORTED[("sysmon",1)] = PROCESS            (69)
             ├─ bind_process_identity()  ProcessGuid → process_iid           (396)
             ├─ activity_identity()  channel+event_id+record_id (Windows)     (57)
             ├─ persist_live_observation()  → v2_shadow_observations
             │    kind = "process_create", xdr_canonical_evidence written
             ├─ detection: dsm → parser → normalizer → canonical_evidence →
             │    ssot → detection → … → framework_mapping
             └─ add_derivation(parser_state=OK, event_id=cev_<raw>_<gen>)

console/API  routers/edr_events.py::list_events → _row()                    (113)
             routers/edr_events.py::facets()  activity facet                 (296)
             routers/edr.py  detections (494) · process surface (568)
             edr_plane/response.py  response targeting (94)
```

Measured result of the live-shaped Sysmon 1 through `bridge()`:

```
canonicalized     : true
parser_state      : OK
canonical_event_id: cev_diagnostic0001_0
activity_type     : PROCESS
observation       : v2_shadow_observations · kind = "process_create"
                    process_iid minted from ProcessGuid, lineage_state present
collections written: v2_shadow_observations, xdr_canonical_evidence,
                     edr_finding_evaluations
detection         : evaluated=true, RULE_NO_MATCH → EVALUATED_NO_FINDING
```

**Canonicalization is NOT broken.** Sysmon 1 → canonical PROCESS works, on
the promoted production code, for the real sensor envelope.

---

## B · FIRST BROKEN BOUNDARY

**`backend/routers/edr_events.py::_row()` — line 126.**

```python
activity = operation = None
if payload.startswith("{"):
    env = json.loads(payload)
    activity  = env.get("activity")      # ← LINUX connector dialect only
    operation = env.get("operation")
```

The Windows envelope is `{"kind": "WINDOWS_EVENT_LOG", "winlog": {…}}` and
carries **no top-level `activity`**. So every Windows row is projected with
`activity = null` → the console prints **Activity: NOT STAMPED** and
**Operation: NOT AVAILABLE**.

The same Linux-dialect assumption breaks three further read paths:

| Boundary | Line | Effect on the live Windows endpoint |
|---|---|---|
| `edr_events.facets()` activity facet — Mongo `$regexFind` of `"activity"\s*:\s*"([A-Z_]+)"` over the RAW payload text | 322-326 | facet map empty → `activity_not_observed` = all 7 classes → **ACTIVITY CLASSES OBSERVED = 0**, PROCESS/NETWORK/FILE/REGISTRY/AUTH/MODULE/DNS **NOT OBSERVED** |
| `edr_events.list_events()` activity filter — same regex | 228-239 | filtering Events by PROCESS returns nothing for Windows |
| `routers/edr.py` detections row (`p.get("activity")`, `command_line`, `image_path`) | 494 | Windows detections render without activity/command line |
| `routers/edr.py` process surface: `if p.get("activity") != "PROCESS" or not p.get("command_line"): continue` | 568 | **every Windows process event is skipped** → empty process/trajectory surface |
| `edr_plane/response.py` target match: `ev.get("activity") != "PROCESS"` | 94 | a Windows process cannot be addressed by response targeting |

So: CONNECTED is true, canonical PROCESS evidence exists, and the
**projection layer cannot see it** — exactly the reported symptom set.

---

## C · EVIDENCE

1. **Sysmon 1 → PROCESS, proven on the promoted code** (local reproduction,
   output quoted verbatim in §A). `additional_fields.activity_type = "PROCESS"`,
   observation `kind = "process_create"`.
2. **Negative control holds.** The `System` / `Microsoft-Windows-Kernel-General`
   **EventID 1** in the same batch was refused:
   `WINDOWS_PROVIDER_NOT_SUPPORTED: provider 'Microsoft-Windows-Kernel-General'
   is not a supported Windows evidence source in this build`.
   Classification is provider-family + EventID (`windows_eventlog.SUPPORTED`,
   line 69), never the numeric id alone.
3. **Projection reads the raw payload, not the canonical evidence.**
   `edr_events.py:126`, `:233`, `:322-326`; `edr.py:494`, `:568`;
   `response.py:94` (quoted above).
4. **The canonical activity class is not persisted on the raw event.**
   `edr_plane/raw_events.py::Derivation` (line 36, `extra="forbid"`) has
   `parser_state`, `event_id`, `outcome`, `reason` — and **no activity
   field**. That absence is why the read path resorts to regexing raw text.
5. **Dedup is Windows-aware and is NOT collapsing the estate.**
   `activity_identity()` line 66-74 keys Windows records on
   channel + event_id + **EventRecordID**, so hundreds of distinct Sysmon
   records are distinct activities (a mass `DUPLICATE_OBSERVATION_OF_KNOWN_
   ACTIVITY` was considered and ruled out).
6. **Detection is not running on raw telemetry with canonicalization
   bypassed.** It runs inside `bridge()` after `canonical_evidence`
   (stage list in §A). On a parse failure the code records
   `DETECTION_NOT_EVALUATED` with an explicit "NOT_EVALUATED is not CLEAN"
   reason (`canonical_bridge.py` 477-501) — fail-closed and truthful.
7. **Secondary endpoint defect, real but NOT the cause (~1 record in 100).**
   `nivxforge_sensor._query_channel` splits stdout on `"</Event>"` and then
   takes `chunk[chunk.index("<Event"):]`. For the FIRST record of each
   `wevtutil` batch that index lands on the `<Events>` **wrapper**, so the
   emitted XML is `<Events><Event …></Event>` and the backend truthfully
   refuses it: `WINDOWS_EVENT_XML_MALFORMED: no element found`. Reproduced.
   Batch limit is 100 (`_query_channel(limit=100)`), so roughly one record
   per channel per cycle is lost — retained raw and replayable.
8. **Secondary: envelope `provider` / `time_created` are `None`.**
   `_attr()` expects double-quoted attributes; `wevtutil` emits
   single quotes (`Provider Name='Microsoft-Windows-Sysmon'`). Reproduced:
   `sensor provider: None`. Harmless today only because `classify()` prefers
   the provider parsed from the XML — the envelope fields are unreliable.

**Not verifiable from here (needs one authenticated read by the owner):**
whether production actually recorded `parser_state=OK` +
`canonical_event_id` for these records. Two read-only checks settle it:
`GET /api/edr/events?endpoint_id=ep_1989031c8c1d0085812f` (each row carries
`parser_state`, `canonical_event_id`, `detection.outcome`) and
`GET /api/edr/events/{raw_id}`. Expected, per §A: `parser_state=OK`,
`cev_…`, `DETECTION_EVALUATED_NO_MATCH`, with a small minority of
`FAILED / WINDOWS_EVENT_XML_MALFORMED` rows from defect 7.

---

## D · ROOT CAUSE

The Phase-0 Windows canonical bridge was promoted, but the **consumers of
that evidence were not**. Every activity-facing read path
(`edr_events._row`, the activity facet, the activity filter, `edr.py`
detections and process surface, `response.py` targeting) still infers
activity by reading the **Linux connector's top-level `"activity"` key out
of the raw payload text** instead of the canonical evidence the bridge
persisted. The Windows envelope has no such key, so canonical PROCESS
evidence exists and is simply never read.

Contributing (smaller, endpoint-side): the sensor leaks the `<Events>`
wrapper into the first record of each `wevtutil` batch, which the backend
correctly refuses as malformed XML, and `_attr()` cannot read
single-quoted attributes so the envelope's own `provider`/`time_created`
are absent.

---

## E · MINIMAL PATCH PROPOSAL (not applied)

1. **One resolver, no new mapping.** In `edr_plane/windows_eventlog.py` add
   `envelope_activity(envelope) -> (activity | None, reason)`, built on the
   existing `_provider_family()` + `SUPPORTED` table and the envelope/XML
   EventID. Unsupported provider or event id → `(None, <existing truthful
   refusal text>)`. `System`/Kernel-General EventID 1 therefore stays
   **not** PROCESS.
2. **`edr_events._row`**: `activity = env.get("activity") or
   envelope_activity(env)[0]`, and `operation` from the Windows
   file/registry operation where the record has one (a Sysmon 1 genuinely
   has no operation, so `NOT AVAILABLE` remains truthful there).
3. **`edr_events.facets` + activity filter**: generate the dialect-aware
   Mongo predicate/`$switch` branches **from `windows_eventlog.SUPPORTED`**
   so there is a single source of truth and no duplicated table. This makes
   the existing hundreds of events count immediately — no write-path change
   and **no backfill**.
4. **`routers/edr.py` (494, 568) and `edr_plane/response.py` (94)**: use the
   same resolver, so Windows process evidence appears in detections and the
   process/trajectory surface and is addressable by response. Response
   capability gating is untouched — the Windows sensor still declares no
   `ISOLATE_ENDPOINT`, so it stays fail-closed.
5. **Optional, additive (recommended next, not required):** record the
   canonical activity class on `Derivation` at ingest so later reads use
   stored canonical truth instead of re-deriving from raw text. Additive
   optional field; the read path keeps the derive fallback, so no backfill.
6. **Windows sensor (separate, endpoint-side):** parse the `wevtutil` batch
   as XML (or split on `"<Event "` boundaries) so the `<Events>` wrapper
   and any XML prolog can never be prepended to a record, and make
   `_attr()` accept single-quoted attributes. Mappings unchanged.

Invariants preserved: tenant isolation (every touched query stays
tenant-scoped; nothing widens authorisation), raw evidence immutable,
raw→canonical provenance unchanged (`raw_ref` + `cev_…`), deterministic
detection semantics unchanged (detection already runs on canonical
evidence), negative explainability preserved (unsupported provider/event id
still yields the existing refusal reason, and `activity_not_observed` is
computed from the dialect-aware facet rather than a dialect blind spot),
Linux behaviour unchanged (top-level `activity` still preferred),
existing Windows mappings unchanged, fail-closed retained (unknown
provider → nothing stamped, never guessed).

---

## F · REGRESSION TESTS TO ADD (with the patch, not before)

Fixture matching the REAL sensor envelope shape — `kind=WINDOWS_EVENT_LOG`,
`winlog.channel=Microsoft-Windows-Sysmon/Operational`,
`winlog.event_id="1"`, real single-quoted Sysmon RenderedXml with
ProcessGuid / Image / CommandLine / Parent* — plus a `System` /
`Microsoft-Windows-Kernel-General` EventID 1 negative fixture.

1. raw Sysmon 1 → `parser_state=OK`, canonical **PROCESS**, observation
   `kind=process_create`, `canonical_event_id` linked to `raw_id`.
2. the same raw event, projected by `edr_events._row`, is **stamped**
   `activity=PROCESS` (this is the failing assertion today).
3. the activity **facet** counts it under PROCESS and removes PROCESS from
   `activity_not_observed`; the activity **filter** `?activity=PROCESS`
   returns it.
4. `System` / Kernel-General EventID 1 → **NOT** PROCESS: refused with
   `WINDOWS_PROVIDER_NOT_SUPPORTED`, never stamped, and never counted in
   any facet.
5. Windows process evidence appears in the `edr.py` process/trajectory
   surface, and a Linux `{"activity":"PROCESS"}` payload keeps behaving
   exactly as now (no Linux regression).
6. sensor: a full `wevtutil /e:Events` batch (wrapper + prolog + N records)
   yields N envelopes whose XML each start at `<Event ` and all parse;
   single-quoted `provider`/`time_created` are read into the envelope.
7. tenant isolation: a Windows canonical PROCESS from tenant A is never
   projected, faceted or filtered into tenant B.

---

## STOP GATE

A–F returned for owner review. No patch, no deploy, no restart, no
migration, no backfill. Awaiting approve/reject.
