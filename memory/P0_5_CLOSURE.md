# P0.5 — CLOSED WITH DOCUMENTED TEST-INFRASTRUCTURE DEBT (2026-06-20)

Exit condition set by the owner: **no unresolved NEW REGRESSION attributable
to the current security changes**, the auth/tenant/API-key/audit/collector
gates still passing, every remaining relevant failure classified *with
evidence*, and the Run-3 evidence preserved. No further long full-suite run
was launched for cosmetic green.

## 1 · Run-3 evidence (preserved, complete)

| Run | Outcome | Log |
|---|---|---|
| Run 1 | 11 404 passed · 493 failed · 271 errors · 264 skipped (1:22) | `test_reports/full_regression_p0_5.log` |
| Run 2 | killed by wall clock at 79 % — recorded **INCOMPLETE**, never interpreted | `test_reports/full_regression_p0_5_run2.log` |
| **Run 3** | **11 453 passed · 462 failed · 291 errors · 264 skipped · 15 xfailed (1:13:34)** — completed | `test_reports/full_regression_p0_5_run3.log` |

Run 3 is the authoritative baseline: **155 failing files · 753 failing
tests**.

## 2 · Classification — 0 NEW REGRESSION

`python3 scripts/classify_backend_regression.py --log test_reports/full_regression_p0_5_run3.log`

| Bucket | Files | Tests | Evidence |
|---|---|---|---|
| `NEW_REGRESSION` | **0** | **0** | nothing attributable to this wave |
| `NEEDS_REVIEW` | **0** | **0** | the 60 unresolved files of run 1 are all now resolved by evidence |
| `PRE_EXISTING_PROVEN_PREWAVE` | 7 | 57 | the file exercises a surface this wave changed **and** produces a byte-identical outcome on the pre-wave tree `b4dfc4b0` |
| `PRE_EXISTING_UNRELATED` | 41 | 174 | fails in ISOLATION and never touches a changed surface |
| `TEST_DEFECT_STALE_AUTH` | 86 | 276 | drives gated endpoints without `/api/auth/login`, and/or still asserts identity via `X-Principal-Id` — broken by the P0-SEC hardening of **2026-09-09**, long before this wave |
| `ENVIRONMENT` | 21 | 246 | passes alone, fails only inside the full run |

Evidence artefacts: `test_reports/p0_5_isolation.json` (60 files re-run one
at a time, `scripts/p0_5_isolation_sweep.py`) and
`test_reports/p0_5_prewave_attribution.json`
(`scripts/p0_5_prewave_attribution.py`, pre-wave worktree at `/tmp/prewave`
= `b4dfc4b0`).

### The 7 files that *could* have been this wave's fault — all cleared
Surfaces changed by the wave: `routers/xdr_{api_keys,audit_log,collectors,
rbac,access}.py` + `services/access_authority.py`.

| File | Pre-wave | HEAD | Verdict |
|---|---|---|---|
| `test_xdr_data_sources_collectors.py` | 20 errors | 20 errors | PRE_EXISTING |
| `test_xdr_correlation.py` | 17 errors | 17 errors | PRE_EXISTING |
| `test_xdr_content_pipeline.py` | 8 failed / 15 passed | 8 failed / 15 passed | PRE_EXISTING |
| `test_edr_context_p0_f13_3.py` | 5 failed / 1 passed | 5 failed / 1 passed | PRE_EXISTING |
| `test_collector_api_key_adversarial_regression.py` | 5 failed / 9 passed / 4 errors | identical | PRE_EXISTING |
| `test_p1_machine_credential_hardening.py` | 3 failed / 8 passed | identical | PRE_EXISTING |
| `edr/test_cross_tenant.py` | 1 failed / 11 passed | identical | PRE_EXISTING |

The first two fail for one reason: their `_clean_slate` fixture calls
`POST /api/xdr/rbac/users` with `_hdrs(ADMIN)` — **header identity plus the
bootstrap bypass**, both deleted in 2026-09-09. The platform answers
`403 ACCESS_DENIED · reason=unauthenticated`, which is the correct
fail-closed answer.

`edr/test_cross_tenant.py::test_v11_body_tenant_id_never_trusted` is worth
naming because it *sounds* like a tenancy defect and is not: the request is
**refused** (`403 ACCESS_DENIED · collectors.enroll · unauthenticated`); the
test only fails because it asserts the older, narrower refusal shape
(expects the tenant id or `TENANT_ISOLATION` in the body, or a 422). The
security outcome is stricter than the assertion, not weaker.

## 3 · Security gates — PASSING

One process, serial, security plane + the two ex-poisoners together:

```
tests/test_moe_panel.py test_restore_equivalence_live.py
tests/test_p0_security_gate.py test_xdr_audit_log.py test_xdr_secrets.py
tests/test_xdr_webhooks.py test_xdr_api_keys.py test_collector_api_key_auth.py
tests/test_xdr_rbac.py test_xdr_rbac_enforcement.py test_p0sec_rbac_fail_closed.py
→ 227 passed · 3 failed · 4 errors  (all 7 in the two pre-existing LIVE suites)
```

The nine gate suites alone: **193 passed · 0 failed**
(`test_reports/p0_5_security_gate_close.log`). Auth, tenancy, API keys,
audit and collectors are all covered by `test_p0_security_gate.py`
(6 outcomes × 6 planes).

## 4 · Two REAL test-infrastructure defects found and fixed

Both were process-wide environment mutations inside test modules — the
actual mechanism behind most of the "shared-database contention" noise.

1. **`tests/test_restore_equivalence_live.py` repointed the database for the
   whole run.** At **import** time it did
   `os.environ["MONGO_URL"]/["DB_NAME"] = …test_database`, so every suite
   collected after it talked to the **preview** database instead of
   `nivxray_ci_local` — wrong data *and* a live-write hazard. Now scoped to a
   module fixture that restores the previous values.
   Proof (read-only): importing the module leaves
   `DB_NAME=test_database` on the pre-wave tree and `nivxray_ci_local` at
   HEAD. The suite's own outcome is unchanged (3 failed / 1 passed, live
   ingress — pre-existing, deliberately not masked).
2. **`tests/test_moe_panel.py` blanked `EMERGENT_LLM_KEY` permanently** to
   force static mode, so every later suite calling `validate_config()` died
   with `RuntimeError: NivXRay config error — missing required env var(s):
   ['EMERGENT_LLM_KEY']`. That is what erroed `test_xdr_secrets`,
   `test_xdr_webhooks`, `test_xdr_audit_log`, `test_xdr_round18_5/18_6/20`
   in the full run. Now set and restored around the single call.
   Proof: with the key blanked, `test_xdr_audit_log` raises exactly that
   RuntimeError; after the fix the poisoner and the victim pass together
   (6 passed).

## 5 · Documented debt (carried, NOT called green)

* **86 files · 276 tests `TEST_DEFECT_STALE_AUTH`** — must be migrated to
  verified JWT sessions (`tests/_verified_session.py` is the pattern). Each
  is a test speaking the pre-2026-09-09 dialect, not a product defect.
* **41 files · 174 tests `PRE_EXISTING_UNRELATED`** — decoder/corpus/live
  suites failing for their own reasons (missing fixtures, live ingress,
  benchmark drift). Untouched by this wave.
* **21 files · 246 tests `ENVIRONMENT`** — pass alone. The two mutations in
  §4 were the dominant cause; the residue is shared-collection contention
  between suites that clean by `{}` rather than by their own keys.
* The L3 `llm_decoder` shutdown hang (`NIVX_L3_DISABLE=1` in tests) is
  tracked separately and is NOT part of P0.5.

**P0.5 = CLOSED WITH DOCUMENTED TEST-INFRASTRUCTURE DEBT.**
