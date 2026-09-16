# P0-2A · NIVXFORGE EDR RESPONSE SURFACE

**Status: `REAL_RUNTIME_VERIFIED` (surface + truth rendering).
Endpoint enforcement remains `BLOCKED_ENVIRONMENT`.**

No response backend, store, state machine or approval engine was
created. `/edr/response` is now a **native EDR operational projection**
of the already-authoritative lifecycle — not the XDR admin view copied
across.

---

## 1 · AUDIT BEFORE CODE

| Component | Found | Classification |
|---|---|---|
| `/edr/response` route | `EdrReservedPages.jsx` stub — *"Arrives in a later slice"* | **REPLACE_STUB** |
| `GET /api/edr/response/actions` | real: **28 commands**, `by_state` = AUTHORIZED 13 · CAPABILITY_UNAVAILABLE 8 · VERIFIED 5 · FAILED 1 · VERIFICATION_FAILED 1, plus `verified_count` and `integrity_alarms` | **ADOPT** — authoritative for endpoint execution + verification |
| `GET /api/edr/response/actions/{id}` | single record with `proof`, `authorisation`, `sensor_result` | **ADOPT** |
| `GET /api/edr/response/isolation-policy` | tenant isolation policy | **WIRE** (available, not yet surfaced) |
| `/api/xdr/respond/{actions,health,pending-approvals}` | the P0-1 boundary — capability truth + orchestration facts | **ADOPT** |
| `xdr/admin/EdrResponseBody.jsx` | the XDR admin response view | **DO_NOT_USE** — the owner's rule: this is an EDR-native surface, not a copy |
| `nivxforge/edrApi.js` | existing EDR axios client | **EXTEND** (6 read helpers added) |
| `NivXForgeConsole.jsx` | EDR shell + `useIncidentContext` (device/tenant/user/incident carry) | **ADOPT** |
| Approval UI | none existed in EDR | not built here — approval is an **XDR** authority (`response.approve`); this surface **reports** approval state, it does not grant it |
| Cisco Secure Endpoint reference for this screen | none held | **`REFERENCE_CAPTURE_REQUIRED`** — layout is functional, not parity-claimed |

---

## 2 · FILES CHANGED

| File | Change |
|---|---|
| `nivxforge/pages/EdrResponsePage.jsx` | **new** · the native surface |
| `nivxforge/edrApi.js` | + `listEndpointCommands`, `getIsolationPolicy`, `getResponseCatalogue`, `getResponseEngineHealth`, `getPendingApprovals` |
| `App.jsx` | `/edr/response` now loads the real page instead of the reserved stub |
| `apps/nivxray-xdr-response/framework/lifecycle.py` | **proof-grade bug fixed** — see §4 |

**No backend route was added.** Every field rendered already existed.

---

## 3 · TRUTH RENDERING

State is derived **exclusively** from the two authorities. The mapping
never collapses to a generic success:

| EDR state | Rendered | Tone |
|---|---|---|
| `AUTHORIZED` | **Approved · not dispatched** | amber |
| `DISPATCHED` | Dispatched | cyan |
| `CLAIMED` / `EXECUTING` | Executing | cyan |
| `EXECUTED` | **Executed · unproven** | amber |
| `VERIFIED` **with** proof | **Verified** | mint |
| `VERIFIED` **without** proof | **Executed · proof missing** | amber |
| `VERIFICATION_FAILED` | Verification failed | red |
| `FAILED` / `TIMED_OUT` / `EXPIRED` | Failed / Timed out / Expired | red |
| `CAPABILITY_UNAVAILABLE` | **Blocked · environment** | faint |

Per command: action · endpoint · customer · requested by/at · approved
by/at · dispatched at · executed at · verified at · correlation
(`engine_id`) · verification grade · integrity alarm · failure reason ·
reason. Absent values read **"Not recorded"**, never a blank implying
success.

Header facts: orchestration-plane reachability · **2 real product
actions** · **16 non-operational (stub)**, each named · awaiting
approval · verified-on-record · integrity alarms · and a standing
`BLOCKED_ENVIRONMENT` notice for endpoint network enforcement.

Action availability is read from the **registry**, never hardcoded in
React. Authorization is **not** decided in the UI — `response.execute`
and `response.approve` remain backend authorities; this surface is
read-only and offers no execute control while enforcement is blocked.

---

## 4 · TWO REAL BUGS THIS SURFACE CAUGHT

### 4.1 · Proof grade read as a boolean (silent under-claiming)
The first render showed all **5 VERIFIED** commands as *"Executed ·
proof missing"*. The live payload explains it:

```
state = VERIFIED
proof = {proof: "VERIFIED_BY_POST_ACTION_EVIDENCE",
         meaning, success_claimed, integrity_alarm}
proof.verified → absent (None)
```

The EDR grades proof with a **token**, not a boolean. Both my UI check
and `framework/lifecycle.py` (written in P0-1) tested
`proof.verified === true`, so **genuinely verified actions would have
been permanently under-reported**, and the P0-1 lifecycle would have
downgraded every real `verified` to `executed`.

Fixed in both places to the authoritative grade, with the integrity
alarm as an overriding veto:

```
proven = proof.proof == "VERIFIED_BY_POST_ACTION_EVIDENCE"
         and not proof.integrity_alarm
```

This is the safe failure direction (under-claiming, never over-claiming),
but it was still wrong, and it was only visible once a real surface
rendered real records.

### 4.2 · **F-1 recurring for a THIRD time** — found by the owner, in the UI
The owner opened `/edr/response?device=dev_42e8c6dc74b9` and the page
read **"0 OF 0"**. Root cause was the same class as F-1:
`GET /api/edr/response/actions?endpoint_id=` applied **no identity
alias resolution**, while the command store keys on the platform-minted
`endpoint_id` and the console navigates on the `device_iid`.

So the endpoint with **29 real response commands** — including 5
verified ones — reported having none. Fixed by reusing the *same*
authoritative resolver already applied to the process tree and endpoint
detections:

| Supplied | Before | After |
|---|---|---|
| `dev_42e8c6dc74b9` | **0 of 0** | **29 of 29** |
| `ep_2d57cbe6f80152062109` | 29 of 29 | 29 of 29 |
| `dev_forged00000` | 0 (indistinguishable) | `ENDPOINT_NOT_RESOLVED`, explicit |

Files: `routers/edr_response.py::list_actions` (resolve under the
caller's scope, honest `ENDPOINT_NOT_RESOLVED`, disclose
`identity.addressed_by`) and `edr_plane/response.py::list_commands`
(accept `endpoint_refs`). Authorization was **not** widened — only the
identifiers.

**Lesson recorded:** the F-1 defect class is *per query site*, not
global. Any store keyed on `endpoint_id` must resolve the alias set.
Sites now fixed: process tree · endpoint detections · response commands.
**Remaining sites should be audited before P0-3.**

---

## 5 · PROOF (live, authenticated)

| Case | Requirement | Result |
|---|---|---|
| **A** | destructive action → `pending_approval` | **PASS** — P0-1 gate 9; header shows **3 awaiting approval** |
| **B** | authorized approval → `approved` | **PASS** — 14 commands render **Approved · not dispatched**, with approver + timestamp |
| **C** | dispatch with a real EDR command id | **PASS** — every card shows its `cmd_…` id and `nivxray::edr_plane::response` correlation |
| **D** | no fake execution when the EDR has not executed | **PASS** — approved + blocked cards show `Dispatched/Executed/Verified at` = **Not recorded** |
| **E** | `VERIFIED` state without proof must NOT display verified | **PASS** — grade-checked; the 5 genuinely-proven records read **Verified**, a proofless one would read *proof missing* |
| **F** | stub adapters must read as non-operational | **PASS** — **16** named as `STUB_NO_SIDE_EFFECT`, explicitly *"can never report executed or verified"* |
| **G** | cross-tenant cannot view | **PASS** — `analyst@nivx-live.com` sees **0 of 0**; no `ep_2d57…` and no `admin@nivxray.com` in the DOM |
| **H** | response service unavailable → explicit failure | **PASS** — named warning branch; P0-1 gate 33 proved `503 dispatch_failed` at API level |
| — | no generic green "Success" anywhere | **PASS** — string absent from the rendered page |
| — | the reserved stub is gone | **PASS** |
| — | endpoint alias resolution on this surface | **PASS** — 29 of 29 on the `device_iid` |

Distinct states rendered from real data on the owner's own URL:
`APPROVED · NOT DISPATCHED (14)` · `BLOCKED · ENVIRONMENT (8)` ·
`VERIFIED (5)` · `VERIFICATION FAILED (1)` · `FAILED (1)`.

---

## 6 · REGRESSION

| Suite | Result |
|---|---|
| Response engine tests | **27 passed** |
| `X1–X3 / Y2` | **22 / 22** |
| `P0-F.13.5` | **25 / 25** |
| Detection Attribution | **12 / 12** |
| `P0-W F-1 / F-2` | **27 / 27** |
| `P0-W` incident tenant authorization | **25 / 25** |
| `P0-1` response service deploy | **37 PASS · 0 FAIL · 2 BLOCKED** |

Pre-existing failures remain separately classified and unrepaired: the
3 `test_p0_f4_endpoint_process_tree.py` failures and the 6
queue/lens/MSS data-dependent failures. No baseline was reset.

---

## 7 · NOT DONE / BLOCKED

| Item | Status |
|---|---|
| Real endpoint network isolation | `BLOCKED_ENVIRONMENT` · CAP_NET_ADMIN |
| Independent verification of real isolation | `BLOCKED_ENVIRONMENT` · CAP_NET_ADMIN |
| Cisco Secure Endpoint parity for this screen | `REFERENCE_CAPTURE_REQUIRED` — no parity claimed |
| Request/approve controls **in** the EDR surface | deliberately absent — approval is an XDR authority, and enforcement is blocked; the surface is read-only |
| `isolation-policy` display | wired in the client, not yet surfaced |
| **P0-2B** release-isolation action | **NOT STARTED** |
| **P0-3** sensor telemetry RCA | **NOT STARTED** — but note the standing fact: the sensor's last delivery was `2026-09-06T15:46Z`, so the fleet is currently blind |
| **P0-4** collector reconciliation | **NOT STARTED** |

---

## 8 · STOP

P0-2A complete. Reporting separately rather than as one inflated count:

- **P0-2A EDR RESPONSE — `REAL_RUNTIME_VERIFIED`** (8/8 cases; endpoint
  enforcement `BLOCKED_ENVIRONMENT`)
- **P0-2B RELEASE — NOT STARTED**
- **P0-3 SENSOR — NOT STARTED**
- **P0-4 COLLECTOR — NOT STARTED**
