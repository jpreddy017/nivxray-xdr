# STEP 1 · WORKLOG ADOPTION CHECK — AUDIT ONLY

**Nothing was built. No notes collection, no notes service, no parallel
worklog was created.** Read-only inspection of the repository, the live
registration table, the live Mongo stores and one authenticated read
probe.

Verdict up front: **`M-1` was mis-classified as `MISSING`. The
authoritative append-only, actor-attributed, per-incident worklog store
already exists, is already API-projected and is already consumed by the
UI.** One sub-capability is genuinely absent, and the audit also surfaced
a **P0 cross-tenant read defect** on the incident detail route.

---

## 1 · THE AUTHORITATIVE STORE — IT EXISTS

| Question | Answer | Evidence |
|---|---|---|
| **Authoritative owner** | **NivXRay XDR** — the incident record | `routers/incidents.py` |
| **Existing store** | **`workspace_cases.incident_state_history[]`** — an append-only array on the incident document. Entry shape: `{from, to, at, actor, note}` | `routers/incidents.py:1071-1079` |
| **Existing API** | `PATCH /api/incidents/{id}/state` writes it (`$push`, never `$set`); `GET /api/incidents/{id}` projects it as **`state_history`** | `routers/incidents.py:1078` and `:360` |
| **Existing UI** | **`xdr/pages/incidents/record/tabs/TimelineTab.jsx:26`** already renders it as a table: `Timestamp · Transition · Actor · Note` | live source |
| **Author / timestamp semantics** | `actor` = the authenticated principal's email; `at` = `datetime.now(timezone.utc).isoformat()`; entries are appended, never mutated; an idempotent transition writes **no** entry | `:1060-1079` |
| **Case association** | the entry lives **on** the incident document, so association is structural — it cannot be orphaned from its incident | schema |
| **Real data** | **563** docs in `workspace_cases`, **278** carry `incident_state`, **262** carry a non-empty `incident_state_history`; sample shows 7 real transitions with real actor emails | live Mongo |
| **Analyst free text** | the entry **already has a `note` field** (`max 500`), and `ClosureTab.jsx` already sends one — it makes a closure note **mandatory** and packs disposition + root cause into it | `ClosureTab.jsx:7,47,59` |

### The correction this forces on the baseline
`routers/incidents.py:30` is `_col = sync_collection("workspace_cases")`.

**`workspace_cases` IS the authoritative XDR incident store** — the very
same collection that also holds the 563 decoder-lineage analysis runs
(`input`/`output`/`verdict`/`engine`/`reached_shellcode`). The XDR
incident is that document **additively extended** with `incident_state`,
`incident_state_history`, `incident_assignee`, `incident_priority`,
`xdr_pipeline`.

Two consequences:
1. `MASTER_OWNERSHIP_AUDIT` §2.1 called `workspace_cases` a "case store
   (561 rows)". That is **imprecise** — it is the incident store *and* the
   analysis-run substrate. Corrected here.
2. `MASTER_GATE`'s instruction that the Casebook must project onto
   "existing `workspace_cases`/worklog" is **right about the collection
   and wrong about the object**: there is no separate "worklog" — the
   worklog *is* `incident_state_history`. `v2_cases` (37 docs:
   name/status/tags/counts) and the `v2_case_*` collections (**all 0
   docs**) are **not** it, and `v2/case_engine` is only `schema.py` +
   `store.py` — collection names and index specs, **no case behaviour**.

### Candidates I ruled OUT — and why (so nobody repurposes them later)
| Candidate | Rows | Why it is NOT the worklog |
|---|---|---|
| `investigations.notes` | 616 docs, **0** with a non-empty note | a single free-text **string** on a decoder-lineage analysis run; no author, no timestamp, no append, no tenant, no incident linkage |
| `investigation_cases.state_history` | 91 docs, **empty list on every one** | the L1/L2 lineage's **UI workspace** persistence (`active_lens`, `filters`, `scroll_positions`, `timeline_position`) — `LEGACY-DUPLICATE` in Matrix 2 |
| `v2_cases` / `v2_case_*` | 37 / **0** | case header only; the detail collections were never written |
| `summary_overrides.analyst_notes` | **2** docs, both empty | a single analyst override of generated narrative, keyed by `cio_id`/`case_id`; single-valued, not a history |
| `xdr_audit_log` | 8 594 docs, tamper-evident (`prev_sig`/`sig`), tenant-scoped, 6 298 on tenant `default` | genuinely append-only and attributed, **but** `resource_kind` has **0** rows for `incident` — it is the platform/admin audit trail (`api_key`, `collector`, `role`, `secret`, `response_execution`…). It is the right home for **cross-product action history**, not for the incident worklog |
| `pending_training_notes` | 172 | learner lineage, unrelated |

---

## 2 · FINAL CLASSIFICATION — `M-1` splits three ways

| # | Capability | Status | Existing component → consumer path |
|---|---|---|---|
| **M-1a** | Worklog **action history** (state transitions, attributed, timestamped) | **`IMPLEMENTED_NOT_RUNTIME_VERIFIED` · already wired — ADOPT, DO NOT BUILD** | `workspace_cases.incident_state_history[]` → `_project_detail()` → `incident.state_history` → `TimelineTab.jsx`. A Cisco-style **Worklog** tab is a **re-presentation of an existing projection**, not a new store |
| **M-1b** | Analyst note **attached to a state change** | **`ORPHAN — field exists, one producer only`** | the `note` field exists and is enforced by `ClosureTab`, but **0 of 262** live histories carry a note, because only the closure transition ever sends one. `patch_assignee` and the operations patch append **no** history entry at all |
| **M-1c** | Standalone analyst note **without** a state change | **`MISSING`** — genuinely. `NotesTab.jsx` is honest about it and keeps browser-local drafts | when approved, it must **extend the same append-only array** (e.g. an entry with `from == to == null`), **never** a new notes collection |

**So: do not create a notes store.** Two thirds of `M-1` is adoption of
something that already works; the missing third is one additional entry
kind on an array that already exists.

---

## 3 · P0 DEFECT FOUND DURING THIS AUDIT — CROSS-TENANT INCIDENT READ

Not on the approved worklist, but it outranks STEP 2–4 in severity, so I
am reporting it rather than proceeding past it.

```
GET /api/incidents/{incident_id}      → routers/incidents.py:993-995
PATCH /api/incidents/{id}/state       → routers/incidents.py:1055
PATCH /api/incidents/{id}/assignee    → routers/incidents.py:1088
        _col.find_one({"id": incident_id})      # no tenant predicate
```

**Proven at runtime (read-only):** an `analyst@nivx-live.com` session
requests `inc_2305c71cd8f54dc38e55`, whose `tenant_id` is **`default`**:

```
HTTP 200
id = inc_2305c71cd8f54dc38e55
state_history = 7 entries, including the actor email admin@nivxray.com
```

`GET /api/incidents` (the queue) **is** correctly scoped — the analyst
cannot see these in the list — so this is a direct-object-reference leak
on the **detail** route only, across **254** `default`-tenant incidents.
The two `PATCH` routes use the identical unscoped predicate, so the same
principal can very likely **transition another customer's incident and
write its own email into that customer's worklog**. I did **not** execute
a PATCH to confirm — that would be a state-changing action, which your
audit rules forbid.

This is the store the Worklog tab would surface. Wiring a Worklog tab on
top of an unscoped read would put one customer's analyst names and
triage notes on another customer's screen, so in my judgement it must be
fixed before, or together with, any Worklog adoption.

---

## 4 · P0 FIX APPLIED AND PROVEN (owner decision **1C** + **2C**)

`scripts/p0_w_incident_tenant_authorization_proof.py` → **25/25 PASS**.

### The full-router audit you asked for (tenant/authorization only, no refactor)
Every `_col` access in `routers/incidents.py` was audited. **Six** by-id
lookups carried the defect, not the three already known:

| Line (pre-fix) | Route | Defect | Now |
|---|---|---|---|
| 995 | `GET /{incident_id}` | no tenant predicate · `get_current_user_optional` → **anonymous read** | scoped |
| 1021 | `GET /{incident_id}/understanding` | no tenant predicate · anonymous | scoped |
| 1055 | `PATCH /{incident_id}/state` | no tenant predicate | scoped |
| 1075 | `update_one({"id": ...})` (state + worklog push) | **write** could escape the scope of the read | writes through the scoped filter |
| 1092 / 1098 | `PATCH /{incident_id}/assignee` + its `update_one` | no tenant predicate | scoped |
| 1135 / 1157 | `PATCH /{incident_id}/operations` + its `update_one` | no tenant predicate · `get_current_user_optional` → **anonymous write** | scoped |

`_col.find(q, …)` (the queue, line 1019) was **already** correctly scoped
through `services.dashboard_lenses._scope` and was left alone.

### What was added — no new authorization model
`_incident_scope_predicate(email)` + `_authorized_incident(id, user)`
reuse the **existing authoritative** `resolve_tenant_scope()` the queue
already uses. Cross-tenant roles keep `all_tenants`; everyone else is
constrained to `tenant_id ∈ scope.tenant_ids`; an unauthenticated
principal resolves to nothing. `_authorized_incident` returns the query
alongside the document so **every subsequent write reuses the same
filter** and cannot escape the scope that authorised the read.

**Not-found semantics, as you required:** out-of-scope returns
`404 {"error": "incident_not_found", "id": …}` — byte-identical to a
genuinely non-existent id (proof 15), so no response ever discloses that
another customer's incident exists. No `403` is used.

### Proof (live, both accounts)
- **Negative** — `analyst@nivx-live.com` on the `default` incident:
  `GET` **404**, `PATCH /state` **404**, `PATCH /assignee` **404**,
  `PATCH /operations` **404**, `GET /understanding` **404**; no
  `state_history` and no actor email in any rejection body.
- **No mutation** — state, assignee and priority unchanged; the
  `state_history` is **byte-identical** (7 entries), so **no worklog entry
  was created** by the rejected attempts.
- **Anonymous** — read and write both **404**; the previously
  unauthenticated `operations` write is closed.
- **Positive** — `analyst@default.com` still reads the incident with its
  full history, still transitions it (`200`), and the transition appends
  **exactly one** entry attributed to `analyst@default.com` with the
  analyst note persisted and `from → to` recorded.
- **Queue unchanged** — the incident is still absent from the `nivx-live`
  queue (1 visible) and still present in `default`'s (255 visible).
- **UI** — the record renders normally for the owning tenant at
  `/xdr/incidents/inc_2305c71cd8f54dc38e55`.

### One honest disclosure
The controlled positive test moved `inc_2305c71cd8f54dc38e55` from `new`
to `in_progress`. `LIFECYCLE_TRANSITIONS` has **no edge back to `new`**,
so a true revert is impossible through the legal API — and I did **not**
write to Mongo directly to fake one, because that would have broken the
append-only worklog and the lifecycle state machine this phase is meant
to be protecting. The transition stands as a legitimate, attributed
analyst action. The proof script now uses the reversible
`in_progress ↔ on_hold` round-trip, so re-running it is non-destructive.

### Regression — no regression accepted
`X1–X3/Y2 22/22` · `P0-F.13.5 25/25` · `Detection Attribution 12/12` ·
`P0-W F-1/F-2 27/27` · `backend/tests/edr` **330 passed** (the same 3
pre-existing `test_p0_f4` failures). The queue/lens/MSS suites show
**6 failed / 35 passed both before and after** the change — verified by
reverting `routers/incidents.py` to `HEAD`, re-running, and restoring.
They are pre-existing data-dependent assertions, not a regression.

---

## 5 · STOP

STEP 1 is complete (**adopt, do not build**) and the P0 authorization
defect it uncovered is **fixed and proven**. STEP 2 (response-service
deployment) has **not** been started.

