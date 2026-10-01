# P0-1 · RESPONSE SERVICE DEPLOY

Proof: `scripts/p01_response_service_deploy_proof.py` →
**37 PASS · 0 FAIL · 2 BLOCKED** (39 gates).

**No second response implementation was created.** The existing plane was
deployed and connected. No new response store, no new collection, no new
state machine, no new registry, no new approval logic.

---

## 1 · ARCHITECTURE DISCOVERED (read-only trace, first)

| Concern | Where it already lived | Verdict |
|---|---|---|
| Action catalogue | `framework/registry.py` · `ActionSpec` (18 actions, 6 domains, `required_permissions`, `approval_required`, `destructive`, `reversible`) | reused |
| Request → approval → dispatch → result flow | `framework/executor.py` · `QUEUED → RUNNING → WAITING_APPROVAL → EXECUTING → FORWARDING_EVIDENCE → SUCCEEDED` + 5 failure states | reused |
| **Response SSOT** | `framework/execution_store.py` — **sqlite**, WAL, one row per `(tenant, invoker_kind, invoker_id, execution_id)` idempotency key, 20 columns incl. approval, adapter result, evidence/audit refs | **RETAINED. No new store.** |
| Tenant scoping | the idempotency key is tenant-first; every read requires the full key | reused |
| Audit / evidence persistence | `framework/forwarder.py` → `POST /api/xdr/response-evidence` on the base backend (the engine **never** writes SSOT itself) | reused |
| Adapters | `framework/adapters.py` — **18 Phase-1 stubs**, `_stub_ok()` returning deterministic success | **the one real gap** |
| Verification | **absent from the engine**; `SUCCEEDED` meant "adapter returned + evidence forwarded" | extended, see §3 |
| **Endpoint execution + verification** | **already authoritative in the EDR**: `edr_plane/response.py` — `REQUESTED → DISPATCHED → EXECUTED → VERIFIED / VERIFICATION_FAILED`, with `proof_of()` and an explicit `CLAIMED_VERIFIED_WITHOUT_EVIDENCE` guard | **adopted, not duplicated** |

### The decisive finding
Every adapter was a stub. Deploying the engine as-is and routing XDR
through it would have let an operator receive `SUCCEEDED` for an
endpoint isolation **that never left the service**. The endpoint domain
therefore had to be connected to the product that already owns
execution *and* verification before anything could be called dispatched.

---

## 2 · COMPONENTS REUSED vs FILES CHANGED

### Reused unchanged
`ExecutionStore` (SSOT) · `Executor` state machine · approval workflow ·
idempotency · `EvidenceForwarder` · `ActionRegistry` + all 18 `ActionSpec`
rows · `edr_plane/response.py` (execution + verification) ·
`routers/edr_response.py` · `resolve_tenant_scope` · the XDR RBAC
permission catalogue.

### Files changed
| File | Change |
|---|---|
| `apps/nivxray-xdr-response/framework/nivxforge_edr.py` | **new** · the real endpoint adapter. Dispatches to `POST /api/edr/response/actions`, reads the record back, and carries the EDR's `state` + `proof` **verbatim**. Executes nothing itself. |
| `apps/nivxray-xdr-response/framework/lifecycle.py` | **new** · the authoritative lifecycle, **derived** from the retained SSOT row. Zero schema change. |
| `.../framework/registry.py` | `ActionSpec.dispatch_mode`; `default()` swaps the stub adapter for the real one on the three endpoint actions — same specs, same ids. |
| `.../framework/executor.py` | passes `action_id` / `execution_id` / acting bearer into the adapter ctx; attaches `response_lifecycle` to every projection. Bearer held **in memory only**, never persisted. |
| `.../routes/actions.py` | exposes `dispatch_mode`, `adapter_status`, `simulation_only`, `authoritative_for_execution`. |
| `.../tests/test_engine.py` | two tests asserted stub `SUCCEEDED` for `endpoint.isolate`; they now assert the **approval lifecycle** and the new invariants. |
| `backend/routers/xdr_respond_boundary.py` | **new** · the service boundary. |
| `backend/server.py` | registers the boundary router (2 lines). |
| `backend/.env` | `XDR_RESPONSE_SERVICE_URL`, `XDR_RESPONSE_SERVICE_TIMEOUT`. |
| `/etc/supervisor/conf.d/xdr_response.conf` | **new** · the deployment. |

---

## 3 · SERVICE TOPOLOGY

```
NivXRay XDR console  (frontend, :3000)
        │  /api/xdr/respond/*          only :8001/:3000 traverse the ingress
        ▼
backend  (:8001)  routers/xdr_respond_boundary.py
        │  no state · no registry · no approval logic · FAILS CLOSED
        ▼
Response Engine  (:8056, supervisor `xdr_response`, own sqlite SSOT)
        │  approval · idempotency · dispatch decision · evidence
        ▼
NivXForge EDR  (POST /api/edr/response/actions, on :8001)
        │  OWNS endpoint execution AND verification
        ▼
endpoint  ──►  proof_of()  ──►  evidence + audit  ──►  XDR
```

The boundary is a boundary, not a second engine: it forwards the acting
analyst's bearer so the **source product** performs its own scoping, and
it re-derives no authorization.

---

## 4 · TENANT + APPROVAL CONTROLS

- **Tenant and invoker are taken from the session** and overwrite anything
  the client sent, so a caller cannot request an action in another
  customer's name (gate 13).
- **The approver is the session principal**, never the request body — this
  is what makes the approval audit trustworthy (gate 15).
- **Authorization is derived from the existing models, never invented.**
  The engine speaks `role:scope`; XDR speaks `resource.action`. The
  boundary translates between the two **existing** catalogues: without
  `response.execute` **no scope is issued at all** and the engine refuses
  on its own authority. `response.approve` is required separately, which
  yields real **separation of duties** (gates 9b/9c): a recommend-only
  analyst can neither execute nor approve.
- The basis of every decision is disclosed as `authorization_basis`
  (`xdr_user_roles_assignment` when the granular store holds an
  assignment, otherwise `builtin_role:<name>`, otherwise
  `no_role_definition:<role>`). Nothing is granted silently.
- **The acting bearer is never persisted.** An execution resumed after a
  restart therefore fails closed with `no_acting_principal` rather than
  acting outside a real principal's scope.

---

## 5 · THE STATE MODEL — five facts kept distinct

`framework/lifecycle.py` derives the operational vocabulary from the
retained SSOT row plus the EDR's authoritative record:

```
requested → pending_approval → approved → dispatched → executing → executed → verified
exceptions: rejected · cancelled · dispatch_failed · execution_failed
            · timed_out · verification_failed · simulated
```

The four invariants are enforced **as data**, in `facts{}`, so no consumer
can infer them wrongly:

| Invariant | How it is made impossible to violate |
|---|---|
| `approved ≠ dispatched` | approval sets only `facts.approved`; `dispatched` requires the adapter to have handed the action over |
| `dispatched ≠ executing` | `executing` requires the EDR to report `CLAIMED`/`EXECUTING` |
| `executing ≠ executed` | `executed` requires the EDR's own `EXECUTED` |
| `executed ≠ verified` | `verified` requires `edr_proof.verified == True`; a `VERIFIED` EDR state **without** proof is downgraded to `executed` |

Two further protections:
- The engine's terminal `SUCCEEDED` maps to **`dispatched`** for a real
  product dispatch — never `executed`.
- A stub adapter terminates at **`simulated`** and can never reach
  `dispatched`, `executed` or `verified`. The catalogue reports
  `2 REAL_PRODUCT_API · 16 STUB_NO_SIDE_EFFECT`, every stub marked
  `NOT_CONNECTED` / `simulation_only`.

---

## 6 · END-TO-END PROOF

| # | Gate | Result | Evidence |
|---|---|---|---|
| 1–2 | Independent service deployment, separate process | **PASS** | supervisor `xdr_response` RUNNING on `:8056`, pid distinct from `backend` |
| 3 | Engine health / readiness | **PASS** | `HTTP 200`, 18 actions |
| 4 | Primary backend reaches it through the intended boundary | **PASS** | `/api/xdr/respond/health` → `reachable: true` |
| 5 | No anonymous surface | **PASS** | GET 403 · POST 403 |
| 6–7 | Real vs stub declared; no stub can read as available | **PASS** | 2 real / 16 stub, all stubs `NOT_CONNECTED` |
| 8 | Destructive action requires approval and names its executor | **PASS** | `authoritative_for_execution: nivxforge-edr` |
| 9 | Destructive action parks in `pending_approval`, does not dispatch | **PASS** | `facts.dispatched == false` |
| 9b–9c | **Separation of duties** — recommend-only analyst cannot execute or approve | **PASS** | 403 · `required_permission: response.execute` / `response.approve` |
| 10 | `approved ≠ dispatched` before approval | **PASS** | no executed/verified fact |
| 11–12 | Wrong tenant cannot approve or even see the execution | **PASS** | 403 · absent from its pending list |
| 13 | Client-supplied `tenant_id` never honoured | **PASS** | session tenant wins |
| 14 | Owning tenant sees its own pending approval | **PASS** | present |
| 15 | Approval attributed to the session principal | **PASS** | `approved_by = admin@nivxray.com` |
| 16–17 | **Real dispatcher handoff** (no stub could satisfy it) | **PASS** | `dispatch_mode: REAL_PRODUCT_API`, EDR accepted, `authoritative_for_execution: nivxforge-edr` |
| 18–19 | `dispatched ≠ executed`, `executed ≠ verified` | **PASS** | EDR `state: AUTHORIZED`, `proof: AUTHORISED_NOT_YET_SENT`, lifecycle `dispatched` |
| 20 | Correlation request → dispatch → result | **PASS** | `execution_id` ⇄ `edr_command_id` ⇄ `endpoint_id` ⇄ `tenant_id` |
| 21–22 | Command independently retrievable from the EDR; wrong tenant cannot read it | **PASS** | 200 owning · 4xx foreign |
| 23 | The EDR refuses to grade an unexecuted command as verified | **PASS** | proof withheld |
| 24 | Immutable approval decision — no re-approval | **PASS** | 409 |
| 25–26 | Duplicate dispatch is idempotent and creates **no second endpoint command** | **PASS** | `idempotent_replay: true`, same `edr_command_id` |
| 27 / 27b | Result persisted under the full tenant-scoped key; wrong tenant refused | **PASS** | 200 / 4xx |
| 28–29 | A product refusal stays a refusal; a failed action never carries executed/verified | **PASS** | no false success |
| 30 | Authoritative state survives a **response-service restart** | **PASS** | same state + `edr_command_id` reloaded |
| 31–32 | Canonical evidence + audit refs, full attribution queryable | **PASS** | `evidence_ref`, `audit_ref`, `forwarding_state: forwarded`, requester + approver + timestamps + tenant |
| 33 | With the engine **DOWN** the boundary **FAILS CLOSED** | **PASS** | `503 response_engine_unavailable`, `lifecycle: dispatch_failed` — never a silent success |
| 34 | Returns to service afterwards | **PASS** | reachable |
| **35** | **Real network isolation on the endpoint** | **BLOCKED · CAP_NET_ADMIN** | `CapEff 00000000a80405fb` — not simulated, not mocked, not written around |
| **36** | **Independent verification of real isolation** | **BLOCKED · CAP_NET_ADMIN** | no post-action containment probe can run, so **no isolation may be graded VERIFIED** |

---

## 7 · REGRESSION

| Suite | Result |
|---|---|
| Response engine own tests | **27 passed** (2 corrected: they asserted stub `SUCCEEDED` for a now-real action; they now assert the approval lifecycle + the new invariants) |
| `X1–X3 / Y2` | **22 / 22** |
| `P0-F.13.5` | **25 / 25** |
| Detection Attribution | **12 / 12** |
| `P0-W F-1 / F-2` | **27 / 27** |
| `P0-W` incident tenant authorization | **25 / 25** |
| `backend/tests/edr` + lifecycle + incident queue + response evidence | **367 passed, 3 failed** — the same pre-existing `test_p0_f4` trio |

**Baselined separately, not repaired in this step:** the 3 pre-existing
`test_p0_f4_endpoint_process_tree.py` failures, and the 6 pre-existing
queue/lens/MSS data-dependent failures.

**One proof correction worth naming:** `p0_w_f1_f2_wiring_proof.py`
briefly showed 23/27 mid-session. Cause was **not** a regression — the
sensor's last delivery was `2026-09-06T15:46Z` and the proof's 24-hour
default window slid past it. The proof now requests an explicit window,
because it exists to test **identity resolution**, not sensor uptime.
Separately worth recording: **the endpoint sensor has stopped delivering
telemetry** (no `edr_raw_events` in the last 24h).

---

## 8 · UNRESOLVED BLOCKERS

| Blocker | Effect | Status |
|---|---|---|
| `CAP_NET_ADMIN` absent | no real host isolation and no independent verification of isolation in this pod | `BLOCKED` — **not convertible to PASS here** |
| 16 of 18 actions have no product adapter | the non-endpoint domains (firewall, DNS, mail, cloud, identity) cannot execute | `NOT_IMPLEMENTED`, declared `STUB_NO_SIDE_EFFECT` — same dependency as `B-1`/`D-13` |
| `endpoint.release` has no `ActionSpec` | isolation cannot be lifted through the engine (only through the EDR directly) | gap, deliberately not invented in this step |
| Isolation requires a configured verification target | the EDR returns `VERIFICATION_TARGET_NOT_CONFIGURED` | honest pre-condition, unchanged |
| Ingress exposes only `:8001`/`:3000` | the console can only reach the engine via the boundary | by design |

---

## 9 · IS THE RESPONSE SERVICE PRODUCTION-CAPABLE INDEPENDENT OF ENDPOINT-ENFORCEMENT PRIVILEGES?

**Yes for the response plane; no for endpoint enforcement — and the two
must not be conflated.**

**Production-capable now:** independent deployment, health/readiness,
authenticated-only access, tenant isolation on read *and* write,
separation of duties, immutable approval attribution, idempotent
dispatch, request⇄dispatch⇄result correlation, real handoff to the
authoritative endpoint product, durable state across restart, canonical
evidence + audit persistence, and a boundary that fails closed.

**Not capable in this pod:** actually containing a host, and proving it
was contained. Those need `CAP_NET_ADMIN` on a privileged host and are
reported `BLOCKED`.

The state model is what makes that split safe to ship: a UI reading
`response_lifecycle.facts` **cannot** render containment from an accepted
or dispatched action, because `executed` and `verified` are separate
facts that only the endpoint product can set.

---

## 10 · STOP

P0-1 complete. **P0-2 (EDR Response Surface) not started** — it now has a
stable contract to build against: `response_lifecycle.lifecycle`,
`.facts{}`, `.dispatch_mode`, `.authoritative_for_execution` and
`.edr{command_id, state, proof}`.

Untouched by design, per your rules: `incident_state_history[]` was **not**
redesigned (worklog propagation is P1), and the Case/Investigation stores
gained **no** response state.
