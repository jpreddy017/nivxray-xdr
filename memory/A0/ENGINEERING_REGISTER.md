# NIVX ENGINEERING REGISTER — autonomous recovery milestone

Branch `engineering/f1-v2-dependency` · worktree `/app/rocket-p0/f1`
Entry point: A3 `62a2c658f638f118920aad4853c3747eeda801ec` / tree `71a64740…`
Final candidate: **`d5bceb8` / tree `22e59d7bc32c46baff846c989d7409f53d2e9ba1`**

Evidence: `/app/rocket-evidence/f1-final/` (junit XML + logs per gate).
Nothing was deployed, merged, pushed, migrated, re-pinned or waived.

---

## Task register

| ID | Root cause | Fix | Files | Result | Commit |
|---|---|---|---|---|---|
| **F1-a** | Canonical telemetry and PowerShell parsing lived in the optional `v2` tree | Extracted the dependency-light leaves into owned modules, shims left at the old paths | `backend/telemetry/*`, `backend/services/decoder/ps_{ast,recovery}.py` | 27 → 15 unwrapped imports; gates green | `04730d9` |
| **F1-b** | The "delete `v2` and RC5 keeps running" contract was false: four routers imported it unconditionally and were mounted unconditionally. The remaining 15 offenders were all production features inside the legacy tree, so leaf-by-leaf migration only relocates the same import | Retired the namespace: `git mv backend/v2 backend/nivx_engine`, rewrote every import site (260 files), made the engine router mount unconditional, rewrote the isolation gate to assert the stronger invariant (no `backend/v2`, no `v2.*` import anywhere incl. tests) | `backend/nivx_engine/**`, `backend/server.py`, `backend/tests/test_v2_isolation.py`, +257 | `test_v2_isolation` **3 passed**; 906 backend/security 0 fail | `7c2bb3c` |
| **F1-b fallout** | `telemetry/canonical.py` kept a relative `from .mitre_map import tag` after F1-a moved it out of `v2/ingestion` | Moved `mitre_map` with it | `backend/telemetry/mitre_map.py` | `test_validation_pack`, `test_ingestion_phase4` green | `7c2bb3c` |
| **S1** | `tenant_registry.authoritative()` resolves tenancy ONLY when `NIVX_TENANT_REGISTRY_ENFORCE` is set. Unset is the documented default (only `deploy/stage1-staging/compose.yml` sets it) and means a missing `X-Tenant-Id` becomes the literal tenant `"default"`. P0-FIX-5A fixed the EDR plane in 2026 and left the collector, ingest and RBAC planes behind — so five collector reads answered **200 with no tenant resolved** | All three planes moved to `authoritative_required()`; `authorize_tenant` reordered so AUTHORISATION precedes the registry; structural guard added | `routers/collector_authz.py`, `routers/xdr_ingest.py`, `routers/xdr_rbac.py`, `services/tenant_registry.py` | 8 previously-200 reads now 403 `TENANT_REQUIRED`; tier-2 **104 passed** | `80eb83c` |
| **F2** | Suites expected `TENANT_NOT_FOUND` where the server answers `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` for a tenant the principal does not hold | Resolved in favour of the non-enumerating implementation (the ladder `edr_tenancy` already documents). Tests updated with the reason; a tenant the principal DOES hold keeps its precise code; added a test asserting the refusals for an unheld-registered and an unregistered tenant are byte-identical | `tests/test_collector_plane_auth.py`, `tests/test_b4b5_tenant_registry_authority.py` | 16 tier-2 failures → 0 | `80eb83c` |
| **F3** | 59 non-test modules hardcoded `/app/backend`, true of the Emergent container only. `routers/benchmark.py` additionally mutated `sys.path` at import time, defaulting to `/app` — which is what had been masking an import-shadowing bug | `backend/paths.py` (`BACKEND_DIR`, `NIVX_BACKEND_DIR` override); 15 runtime modules migrated; benchmark imports lazily with an honest 503; collector landing serves `framework.*`/`routes.*` through a scoped meta-path finder and touches `sys.path` not at all; guard test over 1284 runtime sources | `backend/paths.py`, `routers/{benchmark,xdr_collector_landing,deck_download,static_docs,batch_test,ops,cases,documents,audit_downloads,lab,multilayer_battery}.py`, `services/platform_metrics.py`, `detection_content/*`, `corpus_refresh.py`, `finetune/export_dataset.py`, `tests/test_f3_installation_paths.py` | guard green; `xdr_state/outbox.db` un-tracked (caught by the stage2b hygiene gate) | `d5bceb8` |
| **F4** | `POST /api/xdr/rbac/users` needs `users.create` resolved against `xdr_users` **for that tenant**, so a new tenant has nobody who may create its first principal; `seed_admin()` writes only the authentication record. Operators and the harness inserted the two Mongo rows by hand | `scripts/bootstrap_tenant_admin.py` — CLI, not an endpoint (a bootstrap route must work before any principal exists, so it could only be protected by a replayable shared secret). Ticketed, audited, idempotent, single-tenant, `platform_admin` refused, `--dry-run` | `backend/scripts/bootstrap_tenant_admin.py`, `tests/test_f4_tenant_bootstrap.py` | 8 new tests in the mandatory gate | `7c9fc84` |

Rollback: every task is a separate commit on an isolated worktree; `git revert`
per row, or `git reset --hard 62a2c658` for the whole milestone. The source
worktree `/app/rocket-p0/src` and the frozen staging pin are untouched.

---

## Final gate evidence — `d5bceb8`

```
boundaries   136   0 fail
command      372   0 fail
decoder      147   0 fail   6 skipped
response      39   0 fail
security     118   0 fail   1 skipped      <- was 108 with 1 FAILURE at A3
tenant       104   0 fail
                  ------
            916 backend+security, 0 failures, 0 errors, 7 skipped
frontend     420 passed (25 files)
build        vite production build OK
tier-2       104 passed, 9 skipped         <- was 16 failures
```

The A3 mandatory security gate is **green for the first time**; the single
blocker (`test_v2_isolation`) is closed and the inventory grew 108 → 118.

---

## Open — not fixed in this milestone

| # | Item | Status |
|---|---|---|
| A0-11 | `emergentintegrations 0.2.0` unsigned, single-vendor CDN, no attestation | **CONFIRMED OPEN** · hash-pinned only |
| A0-12 | `deck_download`/`audit_downloads` read `/app/memory`, `/app/deck_assets` — absent from the image (`COPY backend/ /app/`) | **PARTIAL** · the `/app/backend` half is fixed; these two fail honestly with 404, verified by reading the handlers, so they are a packaging gap not a fault |
| A0-14 | ~601 backend test files, 38 gated | **PARTIAL** · security gate 6 → 8 suites; the bulk is still ungated |
| — | 316 `/app/backend` literals in TEST files | **OPEN** · the four structural guards that scanned the deployed tree are fixed; data-path literals remain |
| — | `POST /api/benchmark/refresh` is public and re-runs the whole corpus plus a network feed refresh | **OPEN FINDING** · unauthenticated compute amplification; `frontend/src/pages/BenchmarkPage.jsx` calls it unauthenticated, so gating it is an owner decision |
| A0-9 | Kernel-enforced egress denial | **BLOCKED** · needs the isolated Hetzner host |
| — | XDR↔EDR separation (Priority 4), cloud portability (Priority 5) | **NOT STARTED** |

## Staging package

Frozen pin still verifies from `/app/rocket-p0/src`: `Pinned source verified`.
`prepare.py --verify-only` **refuses this candidate** — admission control
working as designed. Unlike A1/A3, this milestone changes **255 backend
non-test files inside the build context**, so merging requires an
owner-approved re-pin and a fresh bundle. Neither was performed.

**RELEASE STATUS: NO-GO.** Security HOLDs stand.
