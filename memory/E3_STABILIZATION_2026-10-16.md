# E3 clean stabilization sprint — evidence record

Date: 2026-10-16
Isolated workspace: `/app/rocket-p0/src`
Branch: `engineering/e3-stabilization`
Evidence (outside the source tree): `/app/rocket-evidence/e3/`
Disposition: **NO-GO for release or production** (unchanged)

## P0 · Source verification

| Claim | Reported by Work | Independently verified here |
|---|---|---|
| SHA-256 | `8cf3f8ad9c1a61b0c3fab8e6f4e7ab59d56d2d947651f2abb6d4f0f4eb006239` | MATCH |
| Bundle size | — | 23,462,740 bytes |
| Commit | `b1240bbaeb41ee206a755e9b27f77c2d90920970` | MATCH |
| Tree | `38a96a2fed3fd8c8819a387292268ead128ac4ca` | MATCH |
| History | complete, self-contained | `git bundle verify` → "records a complete history" |
| Alternates | none | none; `git fsck` clean |
| Root commits | 1 | 1 (history sanitized; original `3aebddc2` objects absent by policy) |
| Snapshot self-check | PASS | `SECURE_EXPORT/verify_snapshot.py` → PASS, 5,652 source files |

`SOURCE_DIFFERENCES.json`: 12,480 original files → 5,652 retained, 5,523
byte-identical, 129 sanitized, 6,828 artifacts removed. **All 129 sanitized
files are tests, scripts or workflows — no production source file was
modified by sanitization.** `PRESERVATION.json` declares all seven repair
families byte-identical, consistent with that.

## P1 · Decoder, Snappy, benchmark

**Checkout-coupled child-process import shadowing (root cause of the
"36 RC4.x failures" class).** 102 source files hardcoded
`sys.path.insert(0, "/app/...")`. Where a foreign checkout exists at `/app`,
the spawned decoder worker imported the wrong `services` package and died with
`ModuleNotFoundError: services.decoder.isolated`, surfacing as
`DecodeLimitExceeded: Decoder worker stopped without a complete result`.
Work's new diagnostics proved it was not resource exhaustion:
`phase=incomplete_result exception=none exitcode=1 signal=0 maxrss_kib=85356
as_limit=1073741824 cpu_limit=25`. Replaced with `NIVXRAY_REPO_ROOT`-relative
resolution, default `"/app"` so prior behaviour is unchanged. 32 → 0 failures.

**Snappy.** `python-snappy==0.7.3` is pinned in
`backend/tests/command-automatic-requirements.txt`; it was not unpinned.
Installed with `libsnappy-dev`. `test_command_resource_limits.py` 30/30 pass;
command gate 371+1-fail → 372/0.

**Benchmark.** Dominant cost was `services/decoder/base/xor_brute.py` — a
different module from the `backend/ops_extended.py` Work optimized, reached via
the orchestrator plugin path (20.6M + 17.2M generator calls). Applied the same
equivalent `bytes.translate` treatment to english/column scoring, single-byte
crack, repeating-key XOR and the polish pass (which now replaces only the
column stride instead of rebuilding the whole plaintext per candidate).
Differential test: 256 multi-byte cracks plus all scorers, **0 mismatches**
against the pre-change implementation.

| RC3.0 gate | Before | After | Threshold |
|---|---|---|---|
| avg latency | 652 ms | **391 ms** | ≤ 500 ms |
| chain complete | 30/31 (96.8%) | 30/31 (96.8%) | ≥ 96.7% |
| verdict precision | 30/31 | 30/31 | ≥ 15/31 |
| false-positive IOCs | 0 | 0 | 0 |
| Verdict | FAIL | **PASS** | thresholds unchanged |

Unchanged: 1 GiB `RLIMIT_AS`, 25/26 s CPU limits, 25 s worker deadline,
concurrency, process-group termination, key space, search order, tie-breaking.

## P2 · Tenant/RBAC and A0.5

`hexdump==3.3`, `python-evtx==0.8.1` and `PyJWT` are all pinned application
dependencies in `backend/requirements.txt`; installing them is dependency
closure, not a prerequisite bypass. **Original A0.5 executed for the first
time**: 72 tests, 66 pass, 5 failures, 1 duration error.

The 5 failures are all cases where current behaviour is **stricter** than the
original assertions. None is a bypass. All require an owner contract decision
and none was weakened:

1. `test_trisk1_principal_with_no_tenant_scope_fails_closed` — expects code
   `ACCESS_DENIED`, gets `TENANT_NOT_RESOLVED`. Both deny. Label contract.
2. `test_cross_tenant_admin_with_explicit_tenant_still_works` — expects 200,
   gets 403 `user-not-provisioned`. Role-only platform admin vs
   provisioned-principal. **Confirmed as live runtime behaviour**, not a test
   artifact: `/api/xdr/rbac/users` returned 403 `TENANT_NOT_RESOLVED` for the
   real seeded admin on the isolated stack.
3-4. `...manipulate_authority_via_query_or_header[tenant_id|customer_id]` —
   original expects foreign selectors to be **ignored** (200), current code
   **rejects** them (403 `SCOPE_SELECTOR_CONFLICT`, `fail_closed: true`).
5. `test_client_cached_effective_access_object_is_not_authority` — expects 403,
   gets 422. Still denied, but schema validation precedes authorization, so the
   test's intent is not actually exercised. Worth a harness fix, not a product change.

`test_the_guard_is_not_vacuous` **passes** but needs ~216 s; it errored only on
a 90/120 s timeout. Not a defect.

**Hermeticity finding:** the validation runner set `NIVX_AI_ENABLED=false`, but
L3 is gated by a different switch (`NIVX_L3_DISABLE`), so isolated runs
attempted outbound LLM dispatch and **reached `api.anthropic.com`** (observed
`authentication_error`, i.e. the request was delivered). The runner now sets
`NIVX_L3_DISABLE=1`. Product gating was not changed.

## P3 · Backend-to-response admission

The mismatch Work marked BLOCKED was worse than a mismatch: `_call` in
`routers/xdr_respond_boundary.py` sent **no `Authorization` header at all**, so
every call to the now fail-closed engine would 401. The backend now presents
`RESPONSE_ENGINE_SERVICE_CREDENTIAL` and fails closed with the existing 503
honesty note when it is unset. The analyst bearer is never delegated and the
credential conveys no analyst authority: the derived RBAC `authorization_basis`
and the engine's own approval states are untouched.

Proven against the real standalone engine on loopback:

| Case | Result |
|---|---|
| No credential configured | backend 503, honesty note, **no transport attempted** |
| Wrong credential | engine **401** `invalid_service_credential` |
| Correct credential | **422** schema rejection — admitted, nothing executed |
| Analyst bearer present in request | never forwarded |
| Engine execution records after all probes | **0** in every state; forwarder `not_wired` |

New `backend/tests/test_rocket_response_admission.py` (6 tests) in the
boundaries gate.

## P4 · Isolated Mongo and real partial trace

MongoDB 7.0.43 started on `127.0.0.1:37017` with fresh disposable storage —
the `EPERM` that blocked Work does not apply in this environment. The platform
instance on 27017 was not touched.

`server.py` gained `NIVX_EDR_WORKERS_DISABLED=1`, which suppresses the durable
EDR processing supervisor and logs that the deployment is not processing EDR
events. Unset keeps deployed behaviour. This clears the RUNBOOK blocker that
previously prevented running the monolithic app in isolation; verified in the
live log.

`tools/rocket_e2e/partial_trace.py` — **6/6 PASS** on a fresh
`rocket_e2e_<hex>` database:
- both tenant-bound synthetic analysts authenticate with real JWTs
- analyst A sees only `inc_rocket_a`; analyst B only `inc_rocket_b`
- both scopes are `authority=server`, `basis=SINGLE_AUTHORIZED_TENANT`
- no response action is dispatchable: 503 with
  `dispatched/executing/executed/verified = false`

Safety guards: 9/9. No response action was requested, approved or executed.

## P5 · Regression and release assessment

| Gate | Tests | Failures |
|---|---:|---:|
| decoder | 147 | 0 (6 skipped) |
| command | 372 | 0 |
| tenant | 104 | 0 |
| boundaries | 107 | 0 |
| response | 39 | 0 |
| **Total** | **769** | **0** |

Plus RC3.0 benchmark PASS, A0.5 72 tests (5 contract failures), partial trace
6/6, safety guards 9/9. Counts overlap across scopes; do not sum as unique tests.

**Not executed here:** frontend Vitest and Vite build (no `node_modules`;
Work's 420/0 and build PASS stand on their host), authenticated browser
acceptance, correlation-rule evidence linkage, native evidence timeline,
analyst verdict, approved simulated response roundtrip, Mongo concurrency,
target-host resource gates, exact candidate packaging.

**Platform caveat:** this host is **Linux ARM64, CPython 3.11.17**. Work
validated on x86-64 / CPython 3.12.14. Neither is target-host proof, and the
latency figures in particular are not comparable across these hosts.

## HOLDs — all preserved, none waived

Egress denial is **not** kernel-enforced in this pod (proven by the outbound
LLM call reaching Anthropic), so the harness attestation
`host_and_workload_external_egress_denied` cannot truthfully be set and
FULL_E2E stays **BLOCKED**. Also still open: the A0.5 authorization contract,
collector missing-signature acceptance/replay durability, credential/runtime
hygiene and owner rotation, NCI permission/service delegation, legacy cache
exposure/migration, real Mongo concurrency/reconciliation, CI-09 and related
security gates, SDK provenance, production/release and EDR feature development.

No push, merge, PR, deployment, production or customer connection, real
containment, purchase or infrastructure change occurred.
