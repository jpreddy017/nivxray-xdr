# FROZEN PYTEST BASELINE · PRE-P0-PROD-2

Purpose: freeze the **pre-existing** backend test failures so that later
production gates (P0-PROD-2 onward) can distinguish *new regressions*
from *carried debt*. Nothing in this file is a claim that the suite is
healthy — it is a claim about what was already broken **before** the
next gate opened.

- Captured: 2026-06 (P0-PROD-1 pre-next-gate cleanup)
- Machine-readable twin: `BASELINE_PYTEST_PRE_P0PROD2.json`
- Generator: `backend/tools/freeze_pytest_baseline.py <junit.xml>`

## 1 · EXACT CAPTURE COMMAND

```
cd /app/backend
REACT_APP_BACKEND_URL=<preview backend url> \
python -m pytest -q -p no:cacheprovider --continue-on-collection-errors \
  -rfE --junitxml=/tmp/baseline.xml \
  --ignore=tests/test_investigation_quality.py \
  --ignore=tests/test_rule_detection_playbook_expansion.py \
  --ignore=tests/test_s2mini_engine_depth_authz.py
```

`pytest.ini` addopts (`-n 2 --dist loadscope -m "not slow"`) apply
unchanged. Duration: 2872 s (47 m 52 s).

## 2 · HEADLINE TOTALS (authoritative baseline)

| Metric | Count |
|---|---|
| tests collected/run | 12,767 |
| passed | 11,807 |
| **failed** | **547** |
| **errored** | **128** |
| skipped | 270 (+15 xfail) |

## 3 · WHY THIS DIFFERS FROM THE "28 FAILED / 18 ERRORS" FIGURE

The `28 failed / 18 errors` number quoted during P0-PROD-1 came from a
**scoped** run (the subsets exercised while implementing the secret
policy), not from a whole-suite run. This document supersedes it with a
full-suite, node-id-exact capture. **The delta is scope, not new
breakage** — the only production code touched since that scoped run is
the P0-PROD-1 secret policy, and none of the errors below trace to it
(see §5).

## 4 · MODULES EXCLUDED FROM THE RUN (pre-existing collection defects)

These three modules abort collection and, under `-n 2`, abort the whole
session. They are excluded so a baseline can exist at all, and are
carried as debt:

1. `tests/test_investigation_quality.py` — `import file mismatch`
   (duplicate module basename).
2. `tests/test_rule_detection_playbook_expansion.py` — `ImportError:
   cannot import name 'ImpactScoringEngine' from
   'security_state.impact.engine'`.
3. `tests/test_s2mini_engine_depth_authz.py` — parametrises test IDs
   with the xdist **worker id**, so gw0/gw1 collect different node ids
   (`Different tests were collected between gw1 and gw0`). Harness
   defect, not a product defect.

## 5 · DOMINANT FAILURE CLUSTERS (top modules)

Failures (156 modules total):

| Module | Failures |
|---|---|
| tests/test_training_corpus.py | 44 |
| tests/test_real_world_battery.py | 31 |
| tests/test_a05_tenant_scope_contract.py | 24 |
| tests/test_collector_api_key_auth.py | 15 |
| tests/test_intelligence_policy_live.py | 15 |
| tests/test_p0_dedupe_hardening.py | 12 |
| tests/test_vendor_benchmark_regression.py | 12 |
| tests/test_fixture_regression_matrix.py | 11 |
| tests/test_p0_ingest_idempotency.py | 11 |
| tests/test_p1_evidence_namespace_bridge.py | 11 |

Errors (15 modules total) — all are **setup-phase harness faults**, none
raised by `security/secret_policy.py`:

| Root cause (setup) | Modules |
|---|---|
| `RuntimeError: Event loop is closed` | xdr_secrets, xdr_webhooks, xdr_audit_log, canonical/api/test_p11_upload_bridge |
| `AttributeError: '_Cached' object has no attribute 'raise_for_status'` | v13x_e2e, iedde_endpoint, phase94_api_contract, lab_narrative, confusion_matrix |
| `ACCESS_DENIED / unauthenticated` during fixture admin bootstrap | xdr_correlation, xdr_data_sources_collectors, xdr_detection_content |
| `DuplicateKeyError` on `workspace_*` seed | incident_numbering_and_filters |
| Missing fixture file `/tmp/SEP.csv` | csv_edr_investigation |

## 6 · HOW LATER GATES MUST USE THIS

A later gate is regression-free only if, for the same command in §1:

1. No node id appears in `failed`/`errored` that is **absent** from
   `BASELINE_PYTEST_PRE_P0PROD2.json`, and
2. `tests/test_p0prod1_secret_policy.py` stays fully green (28/28).

Fixing baseline entries is welcome; the file is a ceiling, not a quota.
