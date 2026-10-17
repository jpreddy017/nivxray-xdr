# A0_MICROTASK_MIGRATION_PLAN

Mode: READ-ONLY proposal. **Nothing here has been implemented.** Each task is
one independently reviewable change with its own gate.

## Ordering principle

Verified correctness and security risks first, then contracts, then product
separation. Two hard constraints shape the order:

1. **The Stage 2B staging pin.** `deploy/stage1-staging/source.json` pins
   application commit `593b3e9f`, and `prepare.py` fails if HEAD drifts
   outside `deploy/stage1-staging/`. Any application change re-pins the package
   and invalidates the bundle already sent to Hetzner. So **A1 and A2 should
   either precede the Hetzner run or wait until it completes** — this is an
   owner decision, not a technical one.
2. **Separating databases before contracting the joins** would make XDR hunting
   return empty results instead of errors. Contracts come before separation,
   always.

---

### A1 · Make security test suites audit their own repository

| | |
|---|---|
| **Objective** | Replace hardcoded `/app/backend` roots in security tests with a repository-relative root so the suite audits the tree under test |
| **Files** | `backend/tests/test_p0prod1_secret_policy.py` (lines 30, 50, 224, 265, 302); audit the other 316 test literals, change only this suite |
| **Preserve** | Every existing assertion and its intent; inside a container the resolved path must remain `/app` |
| **Security risk** | **Low, and it reduces risk** — today the suite can pass while the repository is unexamined |
| **Prerequisites** | none |
| **Tests** | `pytest tests/test_p0prod1_secret_policy.py` from a checkout **and** from `/app`; both must behave identically |
| **Acceptance** | Suite runs against the checkout; previously-passing assertions still pass; the `XDR_AUDIT_MASTER_SECRET` refusal still fires when unconfigured |
| **Rollback** | Revert one file |
| **Complexity** | **S** |

### A2 · Fix routes that read paths absent from the image

| | |
|---|---|
| **Objective** | Stop serving routes that read `/app/memory`, `/app/deck_assets` and `/app/backend/...`, which do not exist in the staging image |
| **Files** | `backend/routers/deck_download.py` (16, 32, 50-52), `backend/routers/audit_downloads.py`, `backend/services/platform_metrics.py:42` |
| **Preserve** | The routes' behaviour where the asset genuinely ships; **fail explicitly (404/503 with a stated reason) when it does not** — never a stack trace |
| **Security risk** | Low. Do not "fix" it by copying `/app/memory` into the image — those are engineering records, not product assets |
| **Prerequisites** | none |
| **Tests** | new: asset-absent → explicit status, not 500; existing download tests unchanged |
| **Acceptance** | Backend starts and these routes behave predictably with the staging file layout |
| **Complexity** | **S** |

### A3 · Bring security suites into the release gates

| | |
|---|---|
| **Objective** | Gate the tenant, collector-auth, webhook and provenance suites so release evidence covers them |
| **Files** | `tools/rocket-validation/run.py` (`GATES`); possibly a Mongo-backed gate harness |
| **Preserve** | Gate hermeticity — gates currently run with `MONGO_URL=''` so Mongo tests skip; a new `security` gate needs an ephemeral Mongo, not a relaxed assertion |
| **Security risk** | **Medium** — a badly built harness could make these suites *appear* to pass. A skipped test must be reported as skipped |
| **Prerequisites** | A1 |
| **Tests** | the new gate itself, plus proof that disabling a control makes it fail |
| **Acceptance** | `run.py --gate security` runs `test_collector_plane_auth.py`, `test_edr_route_tenant_authority.py`, `test_xdr_webhooks.py`, `test_d11_ingest_provenance.py`, `test_v2_isolation.py`, `test_phase2_1_tenant_isolation.py` with 0 failures and **0 silent skips** |
| **Rollback** | Remove the gate entry |
| **Complexity** | **M** |
| **Note** | This converts six register items from UNVERIFIED to verified. It is the highest-value task in this plan |

### A4 · Vendor the private wheel against a reviewed digest

| | |
|---|---|
| **Objective** | Remove build-time dependency on a single-vendor CDN |
| **Files** | `backend/requirements-integrations.txt`, `deploy/stage1-staging/backend.Dockerfile`, README |
| **Preserve** | `--require-hashes`; the `included`/`excluded` posture and its image-level proof |
| **Security risk** | Low; it narrows the supply chain. Does **not** fix the unsigned-artefact concern (#11) — only attestation would |
| **Prerequisites** | A decision on where the reviewed wheelhouse lives |
| **Tests** | `test_package.py` extended; offline build with no index reachable |
| **Acceptance** | Build succeeds with the integration index unreachable; tampered digest still refused |
| **Complexity** | **S** |

### A5 · Define the EDR query contract (design only, no code)

| | |
|---|---|
| **Objective** | Specify `v1` tenant-scoped EDR endpoints covering exactly what XDR reads today: endpoint resolve, raw-event query, observation query, detections |
| **Files** | a contract document; **no source change** |
| **Preserve** | the `edr_raw_events.raw_id ↔ xdr_canonical_events._id` join key must survive the boundary, or evidence provenance breaks |
| **Security risk** | High if designed wrong — this contract carries tenant scope. It must take tenant from the authenticated service identity, never from a client-supplied selector |
| **Prerequisites** | A0 approval |
| **Tests** | contract examples and negative cases, reviewed before implementation |
| **Acceptance** | Owner approves the contract; every XDR→EDR dependency in A0_CROSS_PRODUCT_DEPENDENCIES §1 maps to exactly one endpoint |
| **Complexity** | **M** |

### A6 · EDR service identity

| | |
|---|---|
| **Objective** | Give XDR→EDR calls a dedicated service credential, exactly as the response engine already has |
| **Files** | new EDR auth dependency; `deploy/stage1-staging/*.env.example` (names only) |
| **Preserve** | Fail-closed: missing config → 503, wrong credential → 401; analyst authority must never be forwarded as service authority |
| **Security risk** | **High** — this is a new authentication surface |
| **Prerequisites** | A5 |
| **Tests** | mirror `test_rocket_response_admission.py` for the EDR boundary |
| **Acceptance** | Service credential grants no analyst authority; absent credential fails closed |
| **Complexity** | **M** |

### A7 · Implement the EDR read API behind the contract

| | |
|---|---|
| **Objective** | Serve A5's endpoints from the existing EDR plane, reusing `services/edr/endpoint_query.endpoint_predicate` — **not a reimplementation** |
| **Files** | new `routers/edr_query_v1.py`; no XDR change yet |
| **Preserve** | Tenant-scoped predicates; results identical to today's direct reads |
| **Security risk** | High — cross-tenant leakage |
| **Prerequisites** | A5, A6 |
| **Tests** | equivalence: API result == current direct-read result for the same inputs; cross-tenant request denied and audited |
| **Acceptance** | Byte-equivalent results plus a cross-tenant denial test |
| **Complexity** | **L** |

### A8 · Switch XDR search to the contract

| | |
|---|---|
| **Objective** | Replace the direct reads in `xdr_search.py` with contract calls |
| **Files** | `backend/routers/xdr_search.py` (31-32, 148, 156, 305-328) |
| **Preserve** | Result shape, hrefs, tenant scoping. **If the EDR plane is unreachable, hunting must say so explicitly — never return an empty result set** |
| **Security risk** | High — scoping is enforced by the predicate being replaced |
| **Prerequisites** | A7 |
| **Tests** | before/after equivalence; EDR-unavailable → explicit source-health degradation, not silence |
| **Acceptance** | Identical results with EDR present; explicit, visible degradation with EDR absent |
| **Complexity** | **L** |

### A9 · Switch provenance and evidence bridge to the contract

| | |
|---|---|
| **Objective** | Remove the last direct EDR reads |
| **Files** | `services/incident_provenance.py` (19, 142-144), `services/evidence_bridge.py` (46, 99) |
| **Preserve** | **Evidence integrity** — a provenance trace that silently loses its raw-row attestation is worse than one that fails |
| **Security risk** | **Highest in this plan** — evidence integrity is a release blocker |
| **Prerequisites** | A7, A8 |
| **Tests** | `test_d11_ingest_provenance.py`, `test_xdr_round23_5_provenance_lockin.py`, `test_provenance_graph_and_adapter_contract.py` must pass **in the A3 gate** |
| **Acceptance** | Provenance chains verify end to end through the contract; incomplete data reported explicitly |
| **Complexity** | **L** |

### A10 · Service profiles

| | |
|---|---|
| **Objective** | `NIVXRAY_SERVICE_PROFILE=xdr\|edr\|workspace\|combined` selects which routers register |
| **Files** | `backend/server.py` registration block; `deploy/stage1-staging/compose.yml`; env examples |
| **Preserve** | `combined` must be byte-identical to today. Shared controls (auth, tenancy, audit) must be present in every profile |
| **Security risk** | Medium — a profile that accidentally drops an auth router would be severe. Test the negative |
| **Prerequisites** | A9 (otherwise splitting the database empties XDR hunting) |
| **Tests** | per profile: expected routes present, other products' routes absent, auth/tenancy/audit always present |
| **Acceptance** | Three profiles start, serve only their own surface, and keep every shared control |
| **Complexity** | **M** |

### A11 · Separate the Workspace plane

| | |
|---|---|
| **Objective** | Run NivXMachines on its own profile and database |
| **Files** | profile wiring; contract for `workspace_cases`, which `session_context.py:24` and `evidence_bridge.py:262` read from XDR |
| **Preserve** | XDR investigation features that read `workspace_cases` must keep working or degrade explicitly |
| **Security risk** | Medium — `users` is still shared; this task does **not** split identity |
| **Prerequisites** | A10 |
| **Tests** | Workspace routes absent from the XDR profile; `workspace_cases` access contracted |
| **Acceptance** | Workspace runs standalone; XDR states its Workspace dependency honestly |
| **Complexity** | **M** |

### A12 · Third-party EDR ingest (the commercial goal)

| | |
|---|---|
| **Objective** | Promote the `edr` collector protocol from SCAFFOLD to a real adapter using the existing vendor registry |
| **Files** | `routers/xdr_collectors.py:180`, a new vendor adapter registered via `detection_content/xdr_vendor_registry.register_vendor` |
| **Preserve** | The `CONNECTED` evidence gate — a third-party source must earn `CONNECTED` through received/parsed/normalized counters like every other source |
| **Security risk** | Medium — new external credentials and inbound data |
| **Prerequisites** | A5 (canonical contract), A3 (gated provenance tests) |
| **Tests** | adapter tests following the Cortex pattern; normalization into `xdr_canonical_events` with provenance |
| **Acceptance** | A third-party EDR source ingests, normalizes, earns `CONNECTED` honestly, and is tenant-scoped |
| **Complexity** | **L** |

---

## Identity: deliberately not planned yet

Splitting the shared `users` collection and the JWT is **not** in this plan.
Tenancy, RBAC and audit are shared code, and A0.5 locks tenant isolation
contracts. Identity federation deserves its own assessment before any task
touches it. Attempting it inside a product-split task would risk the one set of
controls currently closest to verified.

## RECOMMENDED FIRST MICRO-TASK

**A3 — bring the security suites into the release gates.**

Not A1, despite A1 being smaller. A3 is first because six items in the blocker
register are "FIX PRESENT BUT UNVERIFIED" purely for want of a harness: the
controls appear to exist, but no release evidence exercises them. Until that is
fixed, every later task is judged against incomplete evidence, and a regression
in tenant isolation or webhook replay protection would not be caught by any
gate. A1 is a prerequisite and should land in the same review window.

**IMPLEMENTATION PERFORMED: NONE.**
