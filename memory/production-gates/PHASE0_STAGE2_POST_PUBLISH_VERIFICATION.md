# PHASE 0 PRODUCTION PROMOTION — STAGE 2 · POST-PUBLISH VERIFICATION (READ-ONLY)

Mode: **READ-ONLY**. Zero production DB writes. No Vercel action. No org/tenant/token/endpoint.
No secret read or changed. Response authority untouched (**FAIL-CLOSED**).

RESULT: **PHASE 0 PRODUCTION PROMOTION — STAGE 2: PASS**
with the implementation evidence honestly classified as **PRESENT_IN_PUBLISHED_SOURCE**
(not yet live-proven — by your own instruction, no production telemetry was created).

## 1 · Identity

| Field | Value |
|---|---|
| PRODUCTION PUBLISH | Publish 100 (Live) |
| PRODUCTION BUILD | `10f49a6` (previous: `4e76891`) — owner-attested from Manage Publishes |
| SOURCE REMOTE HEAD | `8f370c7d` |
| PHASE0 COMMIT | `bea8852b` — ancestor of both remote HEAD and the local published tree |

`10f49a6` is **not** a git SHA (`git cat-file -t 10f49a6` → invalid; GitHub → "No commit found"),
exactly like the previous `4e76891`. It is an **Emergent internal build id**, so build↔commit
identity is established indirectly and stated as such:

1. Emergent publishes the **pod `/app` tree**. `git merge-base --is-ancestor bea8852b HEAD` →
   **true**, and `git diff bea8852b HEAD -- backend apps` is **EMPTY** ⇒ the published tree's
   Phase 0 code is byte-identical to the preview-proven implementation.
2. That same code is byte-identical to remote `8f370c7d` (10/10 SHA-256 matches, Stage 1).
3. The build id **changed** `4e76891` → `10f49a6`, and the publish is **Live** — so a new
   image was built and rolled out after Phase 0 entered the tree.

## 2 · Health and route parity

```
PRODUCTION HEALTH: PASS   GET /api/health → {"status":"ok","service":"nivxray-api"} (HTTP 200)
ROUTES EXPECTED:   862
ROUTES ACTUAL:     862
ROUTES MISSING:    0   (set difference vs the pre-publish snapshot: [])
ROUTES ADDED:      0   ([])
OpenAPI sha256:    8c04168feebf43f0  — byte-identical before and after the publish
```

That byte-identity is the **expected and correct** result: Phase 0 adds no route and changes
no Pydantic response model. It confirms **no regression**, and by design proves nothing about
Phase 0 — which is why §3 is classified the way it is.

## 3 · Phase 0 implementation — PRESENT_IN_PUBLISHED_SOURCE

Every item below is verified in the published tree (and its behaviour proven by the focused
test suites in §5), **not** by executing production canonicalisation:

| Item | Status |
|---|---|
| `WINDOWS_EVENT_LOG` envelope dispatch | PRESENT_IN_PUBLISHED_SOURCE |
| Sysmon 1 → PROCESS | PRESENT_IN_PUBLISHED_SOURCE |
| Sysmon 3 → NETWORK | PRESENT_IN_PUBLISHED_SOURCE |
| Sysmon 11 → FILE | PRESENT_IN_PUBLISHED_SOURCE |
| Sysmon 12 → REGISTRY | PRESENT_IN_PUBLISHED_SOURCE |
| Sysmon 13 → REGISTRY | PRESENT_IN_PUBLISHED_SOURCE |
| Sysmon 22 → DNS | PRESENT_IN_PUBLISHED_SOURCE |
| Security 4688 → PROCESS | PRESENT_IN_PUBLISHED_SOURCE |
| Security 4624 → AUTHENTICATION | PRESENT_IN_PUBLISHED_SOURCE |
| `DETECTION_NOT_EVALUATED` on canonicalisation failure | PRESENT_IN_PUBLISHED_SOURCE (`canonical_bridge.py` L490/712/726) |
| `investigability` | PRESENT_IN_PUBLISHED_SOURCE (`telemetry_freshness.py` L70/199) |
| `RAW_ONLY_NOT_INVESTIGABLE` | PRESENT_IN_PUBLISHED_SOURCE |
| ProcessGuid authoritative handling | PRESENT_IN_PUBLISHED_SOURCE (GUID never fabricated) |
| `PID_ONLY_NOT_AUTHORITATIVE` fallback | PRESENT_IN_PUBLISHED_SOURCE |
| raw → canonical provenance | PRESENT_IN_PUBLISHED_SOURCE (`raw_ref` + `canonical_event_id` carried into `raw_event`) |

Loaded module check on the published tree: `from edr_plane import windows_eventlog` → OK,
declaring exactly `{(sysmon,1),(sysmon,3),(sysmon,11),(sysmon,12),(sysmon,13),(sysmon,22),
(winsec,4624),(winsec,4688)}` — the eight authorised families, no more.

### Why no zero-write live proof exists (measured, not assumed)
- Phase 0 adds **no route** and **no response model** → OpenAPI cannot reveal it.
- `/api/edr/telemetry/freshness` would return the `investigability` block, but production has
  **zero enrolled endpoints**, so `endpoints: []` and the Phase 0 keys never appear.
- `/api/v2/parse` and `/api/rc5/parse` are the only parse-style surfaces; both require admin
  auth and neither invokes the Windows canonical bridge (`v2/routers/parse.py` is the
  command-line adapter only).
- Every other path into the bridge is an authenticated **write** (telemetry ingest / enrolment).
  A failed enrolment probe would itself write a rejection record — so it was **not** attempted.

**Conclusion: live execution proof necessarily arrives with the first authorised Windows
endpoint.** That is the order you chose, and it is the correct one.

## 4 · Security boundaries (production, read-only GETs only — zero writes)

```
AUTH:            PASS — /api/edr/{findings,audit,events,policies,exclusions,telemetry/freshness}
                        all refuse unauthenticated: HTTP 403 {"detail":"Not authenticated"}
TENANT ISOLATION:PASS — no unauthenticated path reaches tenant-scoped data; registry authority
                        unchanged in source; isolation suites green (§5)
RBAC:            PASS — /api/xdr/tenants + /api/xdr/organizations →
                        403 {"code":"ACCESS_DENIED","permission":"tenants.read","reason":"unauthenticated"}
ENDPOINT AUTH:   PASS — enrolment/telemetry surfaces unchanged by Phase 0; hardening suite green.
                        NOT probed live because a rejected enrolment writes a rejection record.
AUDIT:           UNCHANGED — audit route present and protected (403 unauth); contents require
                        authorised access, so not read
RESPONSE AUTHORITY: FAIL-CLOSED — `edr_plane/response.py` last changed in `901f5651` (P0-A),
                        i.e. untouched by Phase 0; authority suite green. NOT probed live
                        (any probe would be a response action)
```

## 5 · Behavioural evidence for the published code

`215 passed, 1 skipped` (the one skip is the credential-gated live admin suite, P0-PROD-1
policy) across: `test_phase0_windows_canonical_bridge`, `test_p0c_durable_findings`,
`test_p0a_response_authority`, `test_cross_tenant`, `test_p0prod2_enrollment_hardening`,
`test_phase2_1_tenant_isolation`, `test_sec001_002_auth_hardening`, `test_d14_tenant_authority`,
`test_p0_3_telemetry_freshness`. The stale `oracle` harness-debt test was **not** touched and
**not** included; no production code was changed for it.

## 6 · Counters

```
DB MIGRATIONS:                            0
DB BACKFILLS:                             0
PRODUCTION DB WRITES CAUSED BY PROMOTION: 0  (no migration exists; startup performs no Phase 0 write)
ORGANIZATIONS CREATED:                    0
TENANTS CREATED:                          0
TOKENS CREATED:                           0
ENDPOINTS ENROLLED:                       0
RESPONSE ACTIONS:                         0
SECRETS READ / CHANGED:                   0 / 0  (EDR_AUTH_PEPPER never accessed)
VERCEL DEPLOYMENTS / RETRIES:             0 / 0
CODE CHANGED:                             0
ROLLBACK REQUIRED:                        NO
ROLLBACK PERFORMED:                       NO
```

```
PRODUCTION CAN NOW CANONICALIZE WINDOWS TELEMETRY:
PRESENT_IN_PUBLISHED_SOURCE_NOT_LIVE_PROVEN
```

Next: **Stage 3 — promote the two Vercel production consoles from the same verified source**,
then verify the served `TelemetryFreshness-*.js` chunk on both hosts contains
`RAW_ONLY_NOT_INVESTIGABLE`, then the NivX Machines tenant, then the first real Windows host.
