# ADR-0010v · P2 UI Slice-3 · Behavioral Timeline Persistence

**Status**: 🟢 SHIPPED (2026-02-15, Session-20)
**Owner directive**: P0 stabilisation task 1 of 4 — "Persist Behavioral Timeline"
**Scope**: Behavioral evidence survives page refresh + investigation reload,
using the existing canonical investigation/workspace_cases model. No second
data store. No new MITRE mapping. No new verdict logic.

---

## Problem

The Behavioral Evidence Timeline was transient — a page refresh, browser tab
switch, or "Reopen case" click reset the panel to empty. The analyst had to
re-paste the Sysmon XML or re-drop the `.evtx` blob to see the timeline again.
This broke UI-Truth: an authoritative evidence surface was being represented
as a client-side ephemeral view.

## Non-goals (locked)

- No parallel behavioral datastore. Reuse existing MongoDB.
- No client-side rehydration of rendered UI state (highlights, selections,
  scroll positions).
- No fabricated relationships on rehydrate — persistence must round-trip the
  EXACT backend envelope.
- No new MITRE mapping. No new verdict computation. No new correlation rules.

## Design

### Data model

New MongoDB collection `behavioral_evidence` keyed on `(user_email, case_id)`.
The stored document IS the exact response envelope produced by
`services.behavioral.sysmon_adapter.normalize_sysmon_xml` + `_build_response`
in `routers/behavioral.py`. That envelope already carries:

- `adapter`, `xml_parser`, `event_counts_by_id`
- `evidence[]` — canonical evidence records (evidence_ref, raw_refs, count,
  first_seen, last_seen, correlation_state, provenance)
- `parent_child_evidence.pairs[]` — ProcessGUID/parent/child + corroboration
- `network_evidence.connections[]` — tri-state correlation, dedup, IP canon
- `per_event_mitre[]` — authoritative technique ids (source: die.analyzer_catalogue)
- `mitre_technique_ids[]`
- `mitre_provenance` — surface = UI-DEF-02 authoritative
- `transport` — evtx transport metadata (when Slice-3 path was used)
- `limitations` — PPID spoofing, EID3 cap, etc.

Nothing rendered client-side is stored. Nothing inferred is stored. The
envelope is deterministic — evidence_ref, correlation_state, and per_event
technique arrays reproduce byte-identically across reload.

```
{
  "user_email":     str,
  "case_id":        str,                # workspace_cases.id
  "envelope":       { ... exact adapter envelope ... },
  "attached_at":    ISO8601,
  "updated_at":     ISO8601,
  "adapter_history": [                  # provenance chain (bounded to last 20)
    { "adapter_source": "sysmon.xml"|"sysmon.evtx"|"attach.explicit",
      "adapter":        "sysmon.slice2@1.0",
      "transport":      null|"evtx.transport@1.0",
      "event_count":    N,
      "record_count":   N|null,
      "at":             ISO8601 }
  ]
}
```

### Endpoints (new, additive-only)

| Method | Path                                     | Purpose |
|--------|------------------------------------------|---------|
| POST   | `/api/behavioral/attach`                 | Persist an envelope explicitly |
| GET    | `/api/behavioral/case/{case_id}`         | Reload persisted envelope (404 when absent) |
| DELETE | `/api/behavioral/case/{case_id}`         | Detach |

Additionally the two existing ingest endpoints accept an OPTIONAL `case_id`:

- `POST /api/behavioral/sysmon      { xml, case_id? }`
- `POST /api/behavioral/sysmon/evtx { evtx_base64, case_id? }`

When `case_id` is present the envelope is auto-attached after ingest. Legacy
callers that omit `case_id` behave identically to before (opt-in persistence).

### Frontend

`BehavioralTimeline` now takes a `caseId` prop (passed from `WorkspacePage`
using the existing `currentCaseId` state that already gates Find-Related, Save
Case, etc.). On mount / caseId-change it GETs the persisted envelope and
hydrates `response` state deterministically. On successful ingest it includes
`case_id` in the request so the backend auto-persists. A `detach` button lets
the analyst wipe the attached evidence for the current case; the UI resets
cleanly. Case cleared (caseId → null) also resets local hydrated state so the
panel starts fresh for the next investigation.

## Invariants preserved

1. **No second data store** — same MongoDB, additive collection.
2. **Canonical evidence only** — the persisted payload is the adapter's own
   envelope, not the rendered React state.
3. **Deterministic reload** — reload of the same envelope produces identical
   E1/E3 rows, evidence_ref values, correlation_state chips, dedup counts,
   raw_refs arrays, and authoritative MITRE technique ids.
4. **UI-DEF-02 authoritative surface untouched** — `per_event_mitre[]` is
   the source of truth in both the ingest response and the rehydrate response.
   The frontend still runs zero MITRE inference.
5. **Workspace isolation** — keyed on `user_email + case_id`. A second user
   requesting the same case_id gets 404 (regression-locked by
   `test_workspace_isolation_across_users`).
6. **Bidirectional link intact** — `nivx:mitre-selected` /
   `nivx:evidence-selected` CustomEvents fire off the rehydrated envelope the
   same way they do off a fresh ingest.
7. **Provenance chain preserved** — repeated ingests against the same case_id
   UPSERT rather than duplicate, and every ingest appends to
   `adapter_history` (bounded to last 20).

## Files changed

- `backend/routers/behavioral.py`
  - Added `sync_collection("behavioral_evidence")` proxy
  - Added `_attach_envelope`, 3 endpoints (`/attach`, `/case/{id}` GET+DELETE)
  - Extended `SysmonIn`, `EvtxIn` with optional `case_id`
  - Auto-attach hook after successful ingest when `case_id` supplied
- `frontend/src/components/investigation/BehavioralTimeline.jsx`
  - Component now takes `caseId` prop
  - Hydration `useEffect` fetches `/api/behavioral/case/{id}` on mount
  - `submitXml` / `submitEvtx` pass `case_id` when available
  - `detachEvidence` calls DELETE endpoint
  - Persistence status chip + "detach" button in the header
  - `summary-persist` chip in the summary strip
- `frontend/src/pages/WorkspacePage.jsx`
  - Passes `currentCaseId` to `BehavioralTimeline`
- `backend/tests/canonical/api/test_p2_uislice3_persistence.py` (NEW)
  - 8 focused regression tests

## Tests

`test_p2_uislice3_persistence.py` — 8/8 PASS. Coverage:

1. Ingest-with-case_id auto-persists and envelope round-trips.
2. Deterministic reload: two GETs return identical envelopes; evidence_ref
   sequence stable across reload.
3. Re-ingest UPSERTs; `adapter_history` grows; no duplicate rows.
4. Detach removes the row (200 delete, 404 GET after).
5. Workspace isolation — Bob cannot read Alice's case.
6. Unknown case_id → 404 with `no_behavioral_evidence` marker.
7. Explicit `/attach` accepts a caller-supplied envelope.
8. Ingest WITHOUT case_id does not create any persistence row (opt-in).

Full P2 + UI-DEF-02 regression: **65/65 PASS · 0 drift**.

## Limitations honestly recorded

- The frontend `submitXml/submitEvtx` set `persistMeta` optimistically after
  a successful ingest; it does not re-fetch the fresh `adapter_history` from
  the backend after the auto-attach. This is intentional (one fewer round
  trip); the accurate history is visible on the next page load / caseId
  change. Not a correctness bug — history is bounded, monotonic, and
  regenerable on demand.
- `case_id` in `SysmonIn`/`EvtxIn` is unauthenticated w.r.t. the workspace
  case doc — we do not verify that the case_id exists in `workspace_cases`
  for the current user. This matches the existing pattern for other
  behavioral routes and is safe because retrieval is scoped on user_email
  regardless. If a caller supplies an arbitrary string it can only shadow
  their own future case creation, never leak across users.
- Only Sysmon Event 1/3 + EVTX transport are behavioral producers today.
  Slice-4 (Event 22), Slice-5 (Event 11), and non-Sysmon adapters (WMI,
  Syslog, firewall, DNS, EDR) are LOCKED per owner directive and will use
  the same persistence contract when authorised (see ADR-0010w · Source
  Agnostic Audit for the neutral contract).

## Global locks confirmed

- Sysmon Event 22 — LOCKED.
- Sysmon Event 11 — LOCKED.
- Sandbox parser boundary — LOCKED.
- Real Investigation Proof Phase B — LOCKED.
- No new MITRE mapper.
- No new verdict/scoring logic.
- Workspace UI outside the timeline scope — UNTOUCHED.
