# ADR-0010q · P2 · Behavioral Evidence Ingestion · Slice-1 Blueprint

**Status**: 🟢 Slice-1 shipped (2026-08-12 · Session-19)
**Scope**: **First vertical slice only** — Sysmon Event 1 (Process Create) → canonical evidence → existing authoritative MITRE surface. NOT a full Sysmon suite. NOT a new engine.
**Owner authorization**: 2026-08-12 · Session-19 close ("Authorize P2").
**Companion**: ADR-0023 (four principles + P2 direction) · ADR-0010p (UI-DEF-02 convergence).

---

## 1. Architectural anchors (per owner's pre-code checklist)

| Anchor | Slice-1 decision |
|---|---|
| **Input formats** | Sysmon Windows Event XML (single `<Event>` or `<Events>` wrapper). No JSON, no NDJSON, no EVTX binary in Slice-1. |
| **Canonical event fields** | `event_id · time_created · host · user · process.image · process.pid · process.command_line · process.hashes · parent.image · parent.pid · integrity_level · logon_id`. Slice-1 emits ONLY Sysmon Event 1 fields. |
| **Normalization contract** | Adapter → `BehavioralEvidence` record: `{source, event_or_rule, field, observed_value, evidence_ref, confidence, corroboration}`. Same shape as the P0.2 evidence chain. |
| **Evidence provenance** | `source="sysmon.eid1"` · `event_or_rule="sysmon.process_create"` · `field` = Sysmon Data Name (`CommandLine`, `Image`, `ParentImage`, `Hashes`) · `observed_value` = raw sysmon value · `evidence_ref` = deterministic sha256[:12] of `sysmon.eid1|<command_line>|<pid>`. |
| **Process relationship representation** | Parent/child recorded as **evidence** in the record (`parent.image`, `parent.pid`) with an explicit **`corroboration`** dict listing which corroborating fields ARE present (image_path, hash, user, session_id, integrity_level, temporal_delta). If corroboration count `< 2`, the record carries `parent_child_uncorroborated=True` — analyst-visible, verdict-neutral. **Never elevated to "truth".** PPID spoofing (T1134.004) is explicitly documented as a first-class limitation. |
| **Correlation handoff** | The adapter's `command_line` field is passed into `services.die.api.analyze(command_line)` — the SAME authoritative MITRE surface UI-DEF-02 established. No parallel MITRE mapper. |
| **IKG integration point** | Slice-1 does NOT write into IKG. The behavioral evidence is returned on the response envelope as `evidence[]` alongside the MITRE-authoritative techniques. IKG persistence is a later slice under the shadow-flag governance of ADR-0008 §4.6. |
| **Security/validation boundaries** | XML input capped at 512 KB per request; XML parser used with `ET.parse` (defusedxml preferred for XXE protection — see §5). Sysmon `Event.System.EventID` must equal `1` in Slice-1; other event IDs deliberately rejected. |
| **Regression strategy** | Frozen 12-case corpus MUST remain unchanged (Slice-1 does NOT touch any endpoint the corpus exercises). A new focused test file covers: happy path · empty input · non-Event-1 rejection · PPID-spoof-uncorroborated flag · authoritative-MITRE handoff for a certutil-launched-by-explorer scenario. |

## 2. Non-goals (locked)

1. No parallel Process Tree engine.
2. No second MITRE mapper.
3. No second verdict/scoring engine.
4. No IKG writes in Slice-1.
5. No new `NIVX_FLAG_*` (Slice-1 is additive read-only route only).
6. No Workspace UI changes in Slice-1.
7. No coverage of Event IDs 3/5/7/11/12/13/22 in Slice-1.
8. No parallel or comparison against `v2/ingestion/normalizers/sysmon_xml.py` or `nivxforge/investigation/pipeline/normalizers/sysmon.py` (both shadow, both protected — Slice-1 is a fresh minimal path, not a rewrite).

## 3. Data flow (Slice-1)

```
Sysmon EVTX/XML paste
         ↓
[POST /api/behavioral/sysmon]           ← thin router, auth-gated
         ↓
services.behavioral.sysmon_adapter.py
    · parse (defusedxml)
    · validate Event.System.EventID == 1
    · extract Sysmon Event-1 fields
    · assemble BehavioralEvidence records
    · derive corroboration flags
         ↓
services.die.api.analyze(command_line)  ← reuse authoritative MITRE surface
         ↓
Response envelope:
  { events:            [BehavioralEvidence, …],
    mitre_techniques:  [ authoritative DIE catalogue output ],
    mitre_provenance:  { source: "die.analyzer_catalogue", ... },
    parent_child_evidence: { corroboration_flags, uncorroborated_count },
    limitations:       { ppid_spoofing: "T1134.004 not verifiable from XML alone" } }
```

## 4. Parent-child = evidence, not truth (ADR-0023 §3d)

Per owner rule #5-6: the `parent.image` / `parent.pid` fields are surfaced as **evidence records**, not consumed as ground truth for verdict logic. The adapter emits a `corroboration` dict per record listing which of these secondary fields are present alongside the parent-child claim:

- `parent_image_path` (full path, not just filename)
- `hashes` (MD5/SHA1/SHA256/IMPHASH)
- `user_session` (LogonId + User)
- `integrity_level`
- `temporal_delta` (time between parent and child event, when both are provided)

If `< 2` corroborating fields are present the record carries `parent_child_uncorroborated=True`. The Workspace can later render this flag as a UI-Truth warning ("insufficient corroboration for parent-child relationship"). The DIE analyzer / MITRE convergence pipeline never treats parent-child as an independent evidence source — only the `command_line` field feeds it.

## 5. Security boundaries

- **XXE**: Slice-1 attempts `defusedxml.ElementTree` first; falls back to `xml.etree.ElementTree` with resolve_entities disabled if defusedxml is not installed. External entities are refused; DTD declarations are refused.
- **Size**: request body capped at 512 KB (default; env `NIVX_SYSMON_MAX_BYTES`).
- **Auth**: endpoint requires `get_current_user` — same auth gate as `/api/analyze`.

## 6. Slice-1 test coverage

`backend/tests/canonical/api/test_p2_sysmon_adapter.py`:
1. Happy path — well-formed Sysmon Event 1 with certutil download → returns MITRE T1105, T1140, T1218 from authoritative surface + one behavioral evidence record with `event_or_rule="sysmon.process_create"`.
2. Empty XML input → 400 with `error="empty_input"`.
3. Non-Event-1 (Event 3 network connection) → 422 with `error="unsupported_event_id"`.
4. Well-formed Event 1 without ParentImage → `parent_child_uncorroborated=True`, `corroboration.count==1` (only integrity_level present).
5. Well-formed Event 1 with ParentImage + hashes + integrity level → `parent_child_uncorroborated=False`, `corroboration.count>=3`.
6. Authoritative MITRE handoff — the returned techniques equal `services.die.api.analyze(command_line).techniques[*].id`.

## 7. Regression protection

`backend/tests/canonical/api/test_p2_slice1_no_corpus_impact.py`:
- Frozen 12-case corpus regression signature (verdict + mitre + lolbins) MUST be byte-identical whether or not the `/api/behavioral/sysmon` endpoint is registered. Locked test to catch any accidental import-time side-effect on the shared `services.die.api.analyze` path.

## 8. What Slice-1 does NOT ship

- No IKG persistence.
- No shadow-flag promotion path.
- No behavioral verdict logic.
- No batch / streaming ingest.
- No support for events beyond ID 1.
- No Workspace UI panel.

## 9. Files touched — Slice-1 only

```
backend/services/behavioral/__init__.py                          (new · empty)
backend/services/behavioral/sysmon_adapter.py                    (new · adapter + evidence normalization)
backend/routers/behavioral.py                                    (new · POST /api/behavioral/sysmon)
backend/server.py                                                (one-line router include)
backend/tests/canonical/api/test_p2_sysmon_adapter.py            (new · 6 slice tests)
backend/tests/canonical/api/test_p2_slice1_no_corpus_impact.py   (new · corpus-signature invariant)
memory/adr/0010q-p2-slice-1-blueprint.md                         (this file)
```

## 10. Standing down after Slice-1

Report the exact evidence flow, test results, and remaining gaps. **Do NOT expand into Event 3 / 11 / 12-13 / 22 coverage without explicit owner authorization.**
