# Frontend Applications, Design System & Operational Prototypes

**Category Directory**: `10_UI_UX/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 582 files  
**Total Category Size**: 6.91 MB  
**Total Lines of Code / Documentation**: 164,868 lines  

---

## Purpose & Scope

Enterprise React frontend, Vite-powered applications, XDR shell, design tokens, and interactive operational prototypes.

## Frontend Architecture & User Experience

NivXRay provides high-density, low-latency operational interfaces designed for Tier-1 to Tier-3 SOC analysts:

### Main Frontend Surfaces:
1. **NivXRay XDR Shell**: `apps/nivxray-xdr/src/` — React 18 / Vite single-page application with dark-mode security aesthetic, active key routing, and contextual drawers.
2. **Investigation Workspace Page**: `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` — Truth-hardened 8-tab operational investigation hub.
3. **Evidence Explorer Page**: `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` — High-speed search and tabular inspection of raw/derived artifacts.
4. **Legacy & Component Library**: `frontend/src/components/` — Reusable security widgets, graph visualizers, and timelines.
5. **Interactive Operational Prototype**: `docs/uiux/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` — Zero-dependency standalone HTML prototype providing live simulations of EDR fleet management, process trees, live query, and sandbox detonation.


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/DEPLOY.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/DEPLOY.md) | 6,026 | 128 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/Dockerfile`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/Dockerfile) | 670 | 0 | `other` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/INGEST_CONTRACT.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/INGEST_CONTRACT.md) | 6,603 | 165 | `specification` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/README.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/README.md) | 4,712 | 97 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/__init__.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/__init__.py) | 0 | 0 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/base.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/base.py) | 6,453 | 154 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/dedup.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/dedup.py) | 1,866 | 52 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/delivery.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/delivery.py) | 4,811 | 120 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/delivery_worker.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/delivery_worker.py) | 4,460 | 121 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/outbox.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/outbox.py) | 16,789 | 388 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/parsers.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/parsers.py) | 4,411 | 127 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/registry.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/registry.py) | 1,771 | 50 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/rest_poller.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/rest_poller.py) | 7,545 | 176 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/runtime.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/runtime.py) | 5,753 | 123 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/scheduler.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/scheduler.py) | 1,578 | 49 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/store.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/store.py) | 5,175 | 140 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/syslog.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/syslog.py) | 6,655 | 157 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/webhook.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/framework/webhook.py) | 5,820 | 141 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/main.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/main.py) | 7,485 | 168 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/pytest.ini`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/pytest.ini) | 47 | 3 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/requirements.txt`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/requirements.txt) | 78 | 4 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/__init__.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/__init__.py) | 0 | 0 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/collectors.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/collectors.py) | 1,376 | 44 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/connectors.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/connectors.py) | 9,669 | 228 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/data_sources.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/data_sources.py) | 1,513 | 35 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/outbox.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/outbox.py) | 4,118 | 115 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/preflight.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/preflight.py) | 3,424 | 88 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/telemetry_health.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/telemetry_health.py) | 1,813 | 53 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/webhooks.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/routes/webhooks.py) | 2,431 | 64 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/__init__.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/__init__.py) | 227 | 6 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_outbox.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_outbox.py) | 9,218 | 240 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_parsers.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_parsers.py) | 2,613 | 75 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_preflight.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_preflight.py) | 2,893 | 81 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_rest_poller.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_rest_poller.py) | 3,996 | 116 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_routes.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_routes.py) | 2,987 | 82 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_syslog.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_syslog.py) | 4,165 | 123 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_webhook.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-collector/tests/test_webhook.py) | 3,083 | 91 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/Dockerfile`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/Dockerfile) | 198 | 0 | `other` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/README.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/README.md) | 2,530 | 60 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/RESPONSE_INGEST_CONTRACT.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/RESPONSE_INGEST_CONTRACT.md) | 5,428 | 138 | `specification` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/adapters.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/adapters.py) | 10,532 | 164 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/execution_store.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/execution_store.py) | 11,884 | 263 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/executor.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/executor.py) | 22,687 | 465 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/forwarder.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/forwarder.py) | 4,050 | 102 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/registry.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/registry.py) | 1,613 | 48 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/vendor_adapters.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/framework/vendor_adapters.py) | 19,397 | 383 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/main.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/main.py) | 4,176 | 102 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/pytest.ini`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/pytest.ini) | 47 | 3 | `configuration` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/requirements.txt`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/requirements.txt) | 96 | 6 | `documentation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/routes/actions.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/routes/actions.py) | 1,972 | 42 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/routes/approvals.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/routes/approvals.py) | 2,569 | 69 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/routes/execute.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/routes/execute.py) | 6,612 | 154 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/routes/executions.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/routes/executions.py) | 1,137 | 27 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/tests/__init__.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/tests/__init__.py) | 95 | 2 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/tests/test_engine.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/tests/test_engine.py) | 14,173 | 312 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr-response/tests/test_vendor_adapters.py`](../01_COMPLETE_SOURCE/apps/nivxray-xdr-response/tests/test_vendor_adapters.py) | 4,237 | 109 | `test` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/.env.example`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/.env.example) | 78 | 0 | `other` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/.gitignore`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/.gitignore) | 780 | 0 | `other` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/Dockerfile`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/Dockerfile) | 2,471 | 0 | `other` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/apps/nivxray-xdr/README.md`](../01_COMPLETE_SOURCE/apps/nivxray-xdr/README.md) | 9,666 | 240 | `documentation` | `PRE_EXISTING` |

*... and 522 more files. Refer to [`UI_UX_MANIFEST.json`](./UI_UX_MANIFEST.json) for the exhaustive JSON catalog.*
