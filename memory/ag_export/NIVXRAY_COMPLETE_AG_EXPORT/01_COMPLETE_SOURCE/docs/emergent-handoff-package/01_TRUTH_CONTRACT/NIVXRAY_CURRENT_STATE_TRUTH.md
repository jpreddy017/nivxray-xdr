# NivXRay XDR · CURRENT-STATE FORENSIC ARCHITECTURE & IMPLEMENTATION TRUTH AUDIT

> **Mode:** Strict READ-ONLY forensic audit. No source code, tests, configs, or UI were modified during this audit.
> **Date:** 2026-02 (post-Sprint 1 · post-B3 decoder migration)
> **Auditor rule:** Honest State — every claim below is backed by a file path, a grep hit, a git-log entry, or a live-pod curl. **Runtime + code evidence is authoritative over any documentation.** Where memory-doc claims and live code disagree, this audit records what the code + live pod says. Anything absent, mocked, stubbed, or contradicting documentation is called out explicitly.
> **Companion machine-readable artifact:** [`NIVXRAY_CURRENT_STATE.json`](./NIVXRAY_CURRENT_STATE.json)
>
> ### Truth Vocabulary (8-state · applied throughout)
> Every component below is graded against ONE of the following. This vocabulary is stricter than the legacy `MATURE/PRODUCTION/INTEGRATED/…` scale (which is retained for backwards continuity with the 360° audit) and is the authoritative grading for the Antigravity boundary contract.
>
> | Grade | Meaning |
> |---|---|
> | **IMPLEMENTED + WORKING** | Code exists, tests pass, wired into the live pod, observable via `curl` or logs. Ready for integration boundary. |
> | **IMPLEMENTED BUT INCOMPLETE** | Code + tests exist but a documented sub-capability is missing (e.g., correlation engine present but no efficacy corpus). |
> | **STUB / MOCK / SCAFFOLD** | Endpoint, class, or module exists and returns a shape but no real logic — often intentionally, gated by a capability flag. |
> | **IMPLEMENTED BUT NOT WIRED** | Code exists (often high quality) but is not reachable from any live route / not registered / not called. |
> | **IMPLEMENTED BUT NOT PRODUCTION-SAFE** | Works, but has a known safety issue (secrets in `.env` only, no rate limit, no idempotency, no cross-tenant filter, mutable evidence store, single-node dependency). |
> | **MISSING** | Not present anywhere in code. |
> | **DUPLICATE / FRAGMENTED** | Same capability exists in multiple modules with drift; needs consolidation. |
> | **CANDIDATE FOR NEW TECHNOLOGY** | Missing or fragmented AND on the sanctioned roadmap for a net-new build (e.g., Antigravity module target). |
>
> **Legacy grades still used (for continuity):** `MATURE` (code + tests + integration + prod) · `PRODUCTION` (deployed, no soak) · `INTEGRATED` (real 3rd-party wiring, no prod evidence) · `TESTED` (has tests, no integration) · `CODE` (code exists, no tests) · `PARTIAL` (stub) · `MOCK/STUB` · `PLANNED` (docs only) · `ABSENT`.

---

## Executive Summary

NivXRay is a large FastAPI+React monorepo that combines:
1. A **market-differentiating deterministic Universal Decoder** (fully migrated to `services/decoder/base/`, DDO-orchestrated, CI-audited, 195/195 tests passing excluding the intentional mal-20 behavioural FN).
2. A **wide XDR surface plane** — 128 backend router modules, 717 documented API paths (792 operations in `/api/openapi.json`), 35 top-level React pages, three companion Docker apps (`nivxray-xdr`, `nivxray-xdr-collector`, `nivxray-xdr-response`).
3. A **P0-graded GA gap-list** captured in `GA_BLOCKERS.md`: 11 blockers, of which P0-E (observability) / P0-H (route consistency + OpenAPI) / P0-F (docker-compose floor) closed in Sprint 1. **P0-C (enterprise OIDC), P0-A (real telemetry connectors), P0-D (multi-tenant isolation with adversarial tests), P0-B (real response actions), P0-I (detection efficacy), P0-G, P0-J, P0-K remain open.**

The honest maturity picture: **investigation surface is genuinely product-grade; response / connectors / observability were until Sprint 1 significantly behind; observability now sits at 72% (P0-E closed); deployment floor is docker-compose ready (P0-F closed); enterprise identity, multi-tenant enforcement, real vendor telemetry, and real response executors are the four largest remaining GA gaps.**

---

# PART I · 57-POINT STRICT AUDIT INDEX

Each row records: **finding · evidence · truth status · gap vs documentation**.

## Section A · Repository Topology & Inventory (Points 1-5)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **1** | Repo layout / monorepo boundaries? | `/app/backend/` (FastAPI · 1,899 .py files · 394,831 LOC), `/app/frontend/` (React 19 CRA · 261 source files · 797 MB incl. node_modules), 3 companion `/app/apps/` deployable services, `/app/deploy/` (Sprint 1 docker-compose floor), `/app/memory/` (14 MB · 250+ MD docs), `/app/tests/`, `/app/scripts/`, `/app/docs/`. | `fd`, `du`, `ls /app` |
| **2** | Git branch state & recent history? | Active branch **`feature/rc2`**. Recent commits: P0-I clarification (d71b406b), Sprint 1 close (d05525b5, 9dca5fb2), 360° audit (0a76b530), B3 completion chain (ca38ec86…c9132de2). Branches `main`, `feature/plugin-decoder-engine`, `feature/rc2`. | `git log --oneline -30`, `git branch -a` |
| **3** | Backend router module count? | **128** modules under `/app/backend/routers/` (excluding `__pycache__`). | `ls routers/` |
| **4** | Backend HTTP surface size? | **717 documented paths / 792 operations** exposed via `/api/openapi.json` (595 KB). Router-source `@router.<verb>` declaration count: **714**. | `curl /api/openapi.json` → `paths` count; `grep -rEh '@router\.' routers/` |
| **5** | Frontend surface size? | **35 top-level pages** in `src/pages/`, **261 total source files** (`.jsx/.js/.tsx/.ts`), 133 npm deps. React 19 + shadcn/UI + Radix + Tailwind + XY-Flow + React Query. All pages code-split via `React.lazy`. | `frontend/src/pages/`, `frontend/package.json`, `frontend/src/App.js` |

## Section B · Backend Architecture & Wiring (Points 6-15)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **6** | Main app entrypoint & structure? | `/app/backend/server.py` (908 lines) — imports 128 router modules, mounts under `/api` and (for a subset of XDR routers) directly under `app`. Uses `APIRouter(prefix="/api")` composition. FastAPI title `NivXRay API` v `1.0.0-rc`. | `server.py` L1-260 |
| **7** | Middleware stack? | Order: `ObservabilityMiddleware` (P0-E · JSON logs + Prometheus counters) → `RequestHardeningMiddleware` (security) → `GZipMiddleware` (≥4 KB) → `CORSMiddleware` (env-driven origins). | `server.py` L165, L640, L648, L657 |
| **8** | Startup / shutdown hooks? | Cortex scheduler start/stop, XDR collector landing bootstrap, LOLBAS refresh, `init_database()`, `seed_admin()`, `validate_config()` all triggered from `@app.on_event("startup")`. Import-time contract: `deps.py` performs zero side-effects at import — all Mongo, secrets, LLM SDKs are lazy. | `server.py` L526-696; `deps.py` L1-70 |
| **9** | Health probes? | `GET /api/health` (liveness, in-process) · `GET /api/health/deep` (Mongo ping + LLM key + disk headroom) · root `/health` alias for kubelet. Live: `HTTP 200 → {"status":"ok"}`. | `server.py` L177-240; `curl localhost:8001/api/health` |
| **10** | Observability endpoint? | `GET /api/metrics` returns Prometheus text-format with real counters (`nivxray_http_requests_total{method,route,status}`) and histograms (`nivxray_http_request_duration_seconds`). Live-verified. | `server.py` L188-190; `observability/__init__.py`; `curl /api/metrics` |
| **11** | OpenAPI surface? | `openapi_url="/api/openapi.json"`, `docs_url="/api/docs"`, `redoc_url="/api/redoc"`. Live: `HTTP 200`, 595 KB, 717 paths. P0-H closed. | `server.py` L161-163 |
| **12** | Config validation? | `validate_config()` in `deps.py` enforces required env vars: `MONGO_URL, DB_NAME, JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, EMERGENT_LLM_KEY`. Fail-fast on startup, non-blocking on test import. | `deps.py` L48-60 |
| **13** | Feature flags? | 30+ `NIVX_*`/`NVX_*` flags in `.env` (engine mode, budget bounds, adapters, artifact store, verdict engine v3, VEEE, canonical UIL/DIE, RC5 diagnostic, evidence graph metrics, etc.). No central flag manager — direct `os.environ` reads. | `.env` (masked keys enumerated) |
| **14** | Router prefix conventions? | Two prefix patterns observed. Modern XDR routers use full `/api/xdr/*` prefix; older routers use bare prefixes (`/incidents`, `/audit`, `/deck`) and are wired under the shared `api = APIRouter(prefix="/api")`. Route consistency baseline reached in P0-H (response actions aliased at `/api/response/*`). | `grep -rEh 'APIRouter\(prefix=' routers/` |
| **15** | Dependency count / bloat? | Backend `requirements.txt`: **218 packages** (includes SIEM parsers `evtx`, PE analyzers `capstone`, chromium `playwright`, transformers `huggingface_hub`, LLM `emergentintegrations==0.2.0`, PDF/DOCX pipelines, `prometheus_client==0.26.0` added Sprint 1). Frontend: 133 packages incl. React 19, XY-Flow, Radix, Tailwind. | `requirements.txt` head; `frontend/package.json` |

## Section C · Data Persistence Layer (Points 16-20)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **16** | Storage backend? | **MongoDB** (motor async + pymongo sync). Single-node per pod. Env `MONGO_URL` + `DB_NAME` (`test_database` fallback in RBAC/secrets modules). No replica set observed. | `deps.py`; `routers/xdr_rbac.py` L76-84 |
| **17** | Collection inventory (routers layer)? | 17+ distinct collections referenced via `sync_collection("...")` and direct `db.<name>` access: `workspace_cases`, `investigations`, `investigation_cases`, `investigation_ssot`, `batch_runs`, `behavioral_evidence`, `decode_feedback`, `iocs`, `lab_attempts`, `lab_stats`, `learner_payloads`, `learner_versions`, `privacy_audit`, `tenant_privacy_settings`, `users`, `xdr_audit_log`, `xdr_saved_views`, `xdr_users`, `xdr_roles`, `xdr_groups`, `xdr_user_roles`, `xdr_data_sources`, `xdr_secrets`, `xdr_recommendations`, `xdr_events`, `settings`, `engine_executions`, `learning_events`, `regression_corpus`, `sample_library`, `prod_health`. | `grep -rE 'sync_collection\("[a-z_]+"\)'` |
| **18** | Canonical case document? | `workspace_cases` is the single authoritative record. Incidents are a **projection** (`routers/incidents.py`) — additive fields (`incident_state`, `incident_assignee`, `incident_priority`, `incident_state_history`) stored on the same doc. Deterministic projection, no parallel `incidents` collection. | `routers/incidents.py` L1-40 |
| **19** | Retention / TTL policy? | **ABSENT**. No `db.<coll>.create_index([("...", 1)], expireAfterSeconds=...)` observed in routers. No retention router. P0-G blocker. | grep in `routers/` for TTL — no hits |
| **20** | Backup / restore / immutability? | **ABSENT**. No `mongodump` runner, no WORM / hash-chain evidence store. Provenance is recorded per document but underlying storage is mutable. P0-G blocker. | code-scan; `NIVXRAY_XDR_360_AUDIT.md` §2.7 |

## Section D · Authentication & Security (Points 21-25)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **21** | Auth mechanism? | Email + password (bcrypt) + own-signed JWT via `PyJWT`. `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/change-password`. Force-password-change gate on first admin login via `ADMIN_FORCE_PASSWORD_CHANGE=true`. | `routers/auth.py`; `deps.py` |
| **22** | Rate limiting? | Sliding-window `LOGIN_LIMITER` from `security.rate_limit`, keyed by `(email, client_ip)`. Returns HTTP 429 with `Retry-After` header. Both spraying and targeted probing throttled. | `routers/auth.py` L32-63 |
| **23** | SSO / SAML / OIDC? | **ABSENT.** No `authlib` / `python-jose` (beyond own signing) / `pysaml2` in `requirements.txt`. P0-C is the sanctioned blocker. Integration playbook captured earlier in session but **implementation not started**. | `grep authlib pysaml2 requirements.txt` → none |
| **24** | Secrets store? | `routers/xdr_secrets.py` bound to Mongo (`xdr_secrets` collection). Not KMS/HSM. Cortex vendor secrets stored per-tenant. `.env` remains the pod bootstrap layer. **Post-GA migration to KMS/Vault noted as backlog** in `GA_BLOCKERS.md` §P0-C secret handling. | `xdr_secrets.py`; `GA_BLOCKERS.md` L110-116 |
| **25** | Audit log? | Tamper-evident append log at `routers/xdr_audit_log.py`. `emit_audit()` invoked from admin routes and RBAC-enforced writes. Per-tenant partitioning. **Not** SIEM-shipped — structured JSON logs (P0-E) provide the SIEM pipeline instead. | `routers/xdr_audit_log.py`; `emit_audit` referenced across routers |

## Section E · Multi-Tenancy & RBAC (Points 26-29)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **26** | Tenant scoping model? | `X-Tenant-Id` + `X-Principal-Id` headers extracted by `_principal(req)` in every XDR router. Fallback tenant = `"default"`. Docs stamp `tenant_id` on write. | `routers/xdr_rbac.py` L321-330; `routers/xdr_data_sources.py` L55-64 |
| **27** | Tenant isolation enforcement? | **PARTIAL.** `xdr_ingest.py` proves the pattern: rejects mixed-tenant batches with `TENANT_ISOLATION_VIOLATION` 403 and validates header-vs-collector-doc tenant match. **BUT** — no global `find*/update*` filter middleware. Not every route calls `require_permission`. **Adversarial cross-tenant negative test is ABSENT.** P0-D blocker. | `routers/xdr_ingest.py` L108-160; NO test file `test_*cross_tenant*` matched |
| **28** | RBAC surface? | `routers/xdr_rbac.py` — 20+ resource groups × 27 action verbs. Fixed vocabulary, kebab-case, wildcard `*.*` support. Enforced via `require_permission("resource.action")` FastAPI dependency. **Denied requests** return `{"code":"ACCESS_DENIED", ...}` and emit `ACCESS_DENIED` audit event. Bootstrap mode: zero-user tenants allow all ops so first user can be seeded. | `routers/xdr_rbac.py` L46-190, L460-500 |
| **29** | Built-in roles? | 11 immutable, cloneable starter roles: `platform_admin`, `tenant_admin`, `soc_manager`, `l3_investigator`, `l2_investigator`, `l1_analyst`, `threat_hunter`, `detection_sme`, `responder`, `auditor`, `read_only`. | `test_credentials.md`; `routers/xdr_rbac.py` |

## Section F · Telemetry Ingestion & Collectors (Points 30-34)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **30** | Data-source catalogue? | 16 kinds hardcoded in `SOURCE_KINDS` of `routers/xdr_data_sources.py`: `generic_syslog, cef_syslog, leef_syslog, windows_event_fwd, sysmon_wef, generic_webhook, generic_rest, aws_cloudtrail, gcp_audit_logs, azure_activity, office365_activity, kafka_topic, otlp_logs, edr_stream, ndr_stream, file_ingest`. Live: `count=0`. | `routers/xdr_data_sources.py` L60-100; `curl /api/xdr/data-sources` |
| **31** | Collector implementations? | Separate app `apps/nivxray-xdr-collector/` (3,407 LOC). Framework at `framework/{syslog,webhook,rest_poller,dedup,delivery,delivery_worker,outbox,parsers,registry,runtime,scheduler,store}.py`. Routes: `collectors, connectors, data_sources, outbox, preflight, telemetry_health, webhooks`. Purely a transport plane — never makes security decisions. | `apps/nivxray-xdr-collector/main.py`, `framework/*` |
| **32** | Real vendor pollers connected? | **ABSENT.** Live: `/api/xdr/collectors` returns `count=0`. `edr.py` router is a **projection over existing cases**, not a real EDR feed. No Okta / Entra / CrowdStrike / MDE / SentinelOne poller found. P0-A blocker. | `curl /api/xdr/collectors`; `routers/edr.py` |
| **33** | CONNECTED evidence-gate? | `POST /api/xdr/ingest/telemetry` correctly refuses to flip a collector to CONNECTED until real telemetry flows (RBAC-gated, mixed-tenant rejected, tenant-match validated). Design is honest — CONNECTED is never fabricated. | `routers/xdr_ingest.py` L108-180 |
| **34** | Canonical envelope schema? | `CanonicalEnvelope` Pydantic model in `xdr_ingest.py`: `tenant_id, collector_id, data_source_id, source_event_id, collection_method, canonical_schema, raw, normalized, parser_ok, normalized_ok, received_at`. Persisted to `xdr_events` — described in-code as a "minimal projection · not the SSOT". | `routers/xdr_ingest.py` L83-105 |

## Section G · Detection, Correlation & Response (Points 35-40)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **35** | Detection content? | `detection_content/` holds `xdr_action_registry.py`, `xdr_credential_vault.py`, `xdr_mitigation_intelligence.py`, `engine_classifier.py`, `sigma_strict.py`. `routers/xdr_detection_content.py` + `routers/xdr_rule_studio.py` (20 rule routes) + `routers/xdr_correlation.py` are wired. | `ls detection_content/`, `ls routers/xdr_*` |
| **36** | Correlation engine? | `services/correlation_engine.py` present; verdict lives in `verdict_stage2` router. Attack Story / Attack Graph services provide multi-event primitives. **No labelled multi-event replay corpus** and no `precision/recall/F1` measurement — P0-I blocker. | `services/correlation_engine.py`; `NIVXRAY_XDR_360_AUDIT.md` §2.10 |
| **37** | Response action registry? | `detection_content/xdr_action_registry.py` declares **13 actions** with honest capability flags: `ENDPOINT_ISOLATE, ENDPOINT_RELEASE_ISOLATION, IP_BLOCK, IOC_ADD_WATCHLIST, COLLECT_FORENSIC_SNAPSHOT, OSINT_ENRICH_IP, OSINT_ENRICH_URL, OSINT_ENRICH_DOMAIN, OSINT_ENRICH_HASH, APPLICATION_ALLOW_LIST_ADD, PROCESS_EXCLUSION_ADD, PATH_EXCLUSION_ADD, THREAT_EXCLUSION_ADD`. Every action currently reports `capability_available=false` (no `XDR_INTEGRATION_*` env vars set). | `detection_content/xdr_action_registry.py`; live `/api/response/actions` |
| **38** | Response route mounting? | P0-H closed: response endpoints now aliased at `/api/response/*` via `routers/response_alias.py`. Legacy `/api/admin/content-supply-chain/response/*` remains additive for backwards compatibility. Live: `curl /api/response/actions` returns 13 actions with honest flags. | `routers/response_alias.py`; live curl |
| **39** | Response executor app? | Separate app `apps/nivxray-xdr-response/` (2,242 LOC). Routes: `actions, approvals, execute, executions`. Framework: `adapters, execution_store, executor, forwarder, registry, vendor_adapters`. Boundary contract in `main.py` — response engine reports back to base backend via evidence/audit/timeline forwarder. **All vendor adapters are stubs** — P0-B blocker. | `apps/nivxray-xdr-response/main.py`; `framework/vendor_adapters.py` |
| **40** | Rule Studio? | 20 routes at `/api/xdr/rule-studio` — real content authoring surface. Tied to `xdr_correlation`. Rule lifecycle (definition, versioning, enable/disable, severity, ATT&CK mapping, evidence requirements) is coded but efficacy metrics not measured. | `routers/xdr_rule_studio.py` |

## Section H · Universal Decoder (Points 41-45)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **41** | Architecture? | Universal Deterministic Decode Orchestrator (DDO) at `services/decoder/orchestrator.py`. Bounded depth (`MAX_DEPTH=6`), evidence-driven signature dispatch, static-only, no execution, no network. Public entry: `from services.decoder import decode_universal`. | `services/decoder/orchestrator.py`; `services/decoder/__init__.py` |
| **42** | Plane-A codec families (migrated)? | 7 codec families live in `services/decoder/base/`: `encoding.py` (URL, unicode-escape, HTML-entity, base32, base85, octal-ascii, decimal-ascii), `base64_codec.py`, `compression.py` (GZIP, Zlib), `crypto.py` (RC4, AES-CBC), `transform.py` (byte-array-XOR-loop), `xor_brute.py` (repeating-key XOR), `powershell_encoded_command.py`. B3 migration complete, byte-identical parity with legacy snapshots. | `services/decoder/base/`; `B3_4_FINAL_VALIDATION_REPORT.md` |
| **43** | DDO signature dispatch? | 14 registered signatures (regex → codec fn). Includes 7 from Plane-A migration: `base.ps_encodedcommand`, `base.byte_array_xor_loop`, `base.gzip`, `base.zlib`, `base.xor_brute`, `base.rc4`, `base.aes_cbc`. GZIP/Zlib fire only on `@@RAWBYTES@@` sentinel from upstream base64 peel — zero false-fires on benign text. | `services/decoder/orchestrator.py` L74-125 |
| **44** | Analyzers (structural)? | `services/analyzers/pe.py` (PE binary) + `services/analyzers/shellcode.py` (raw shellcode). Separated in Gate 2D-B3.2 from prior monolithic decoder. | `services/analyzers/` |
| **45** | Test coverage? | 729 test files under `backend/tests/`. Key suites: `tests/corpus/` **76/76 pass + 1 intentional mal-20 FN**, `tests/decoder_harness/` **59/59 pass** (includes DDO dispatch matrix + B3.3 dependency audit), `tests/observability_tests/` **28/28 pass** (Sprint 1 P0-E/H/F), `test_decoder_bridge.py + test_intelligence_policy.py + test_phase2_final_gate.py` **32/32 pass**. Combined: **195/195 pass** (excl. mal-20). Frozen snapshot hashes: `12378d11…8bac` (Snapshot #1), `6427903e…7897` (Snapshot #2). | `SPRINT_1_CHECKPOINT.md` L113-125; `B3_4_FINAL_VALIDATION_REPORT.md` |

## Section I · Observability (Sprint 1 P0-E) (Points 46-48)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **46** | Structured logging? | `observability._JsonFormatter` — stable envelope keys: `ts, level, logger, msg, trace_id, tenant_id, route, method, status, latency_ms`. `install_json_logging()` installed BEFORE `basicConfig`, idempotent. Every root-logger record is SIEM-shippable JSON. | `observability/__init__.py` L85-160 |
| **47** | Metrics? | Own `CollectorRegistry` (avoids library-default collisions). Three metrics: `nivxray_http_requests_total{method,route,status}` counter, `nivxray_http_request_duration_seconds{method,route}` histogram (SOC buckets: 5ms → 10s), `nivxray_http_requests_in_flight{method}` counter. Cardinality-safe: routes use path templates via `APIRoute.path`. | `observability/__init__.py` L40-80 |
| **48** | Trace / request-id propagation? | `ObservabilityMiddleware` honours inbound `x-request-id` and `traceparent`, mints a 16-char hex fallback. Emits `x-request-id` on response. `request.state.trace_id` + `request.state.tenant_id` populated for downstream handlers. **No OpenTelemetry SDK** — grepped `opentelemetry` → 0 hits. | `observability/__init__.py` L155-230 |

## Section J · Frontend (Points 49-53)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **49** | Framework & routing? | React 19 + CRA + BrowserRouter (v6) + Route-based lazy-loading via `React.lazy`. Initial bundle = shell + LoginPage. Auth wrapper `<Protected>` guards every non-login route. Wildcard `*` redirects to `/`. | `frontend/src/App.js` |
| **50** | Page inventory (top-level)? | 35 pages: `WorkspacePage, CommandAnalyzerPage, AdminPage, ModelStudioPage, SampleLibraryPage, ThreatIntelPage, ThreatModelPage, CorrectionsAdminPage, KnowledgeBasePage, DocsPage, DocumentsPage, BatchTestPage, MitreHeatmapPage, LabPage, IEDDETracePage, HistoryPage, InvestigationsPage, InvestigationDetailPage, InvestigationSummaryPage, InvestigationInputDetailPage, InvestigationSessionPage, ComparePage, PlatformHealthPage, TrainingInboxPage, LearnerPage, BenchmarkPage, MultiLayerBatteryPage, AnalystWorkspacePage, AnalystRC5Page, DeviceTrajectoryPage, AutoInvestigatePage, EvidenceExplorerPage, LoginPage, DashboardPage, AdminPage`. | `frontend/src/pages/` |
| **51** | Route structure? | 60+ routes across three lanes: `/` (base NivXRay SPA), `/v2/*` (v2 investigation workspace shell), `/nivxforge/*` (NivxForge platform · dashboard, investigate, threat-intel, hunting, knowledge, reports, history, governance). `/investigate/*` is the Analyst Workspace Shell. `/xdr/*`, `/incidents/*` are extracted into the standalone `apps/nivxray-xdr/` per `XDR_SEPARATION_HANDOFF.md`. | `frontend/src/App.js` L146-234 |
| **52** | Design system? | shadcn/UI at `frontend/src/components/ui/`, Radix primitives, Tailwind CSS, Lucide icons, Sonner toasts, `@xyflow/react` for graph canvas, `@tanstack/react-query` for data. `design_guidelines.json` + `NIVXRAY_VISUAL_GRAMMAR.md` present. **UI is under absolute freeze** per `GA_BLOCKERS.md` — no frontend edits permitted during P0-C. | `frontend/src/components/ui/`, `frontend/package.json` |
| **53** | Companion frontend? | `apps/nivxray-xdr/` — standalone Vite + React 18 SPA (separate package, own Dockerfile, own `vercel.json`). Consumes existing NivXRay backend `/api/*`. Reuses `/api/auth/login`. Boundary rule locked: MUST NOT import from `/app/frontend/src/`. | `apps/nivxray-xdr/package.json`, `apps/nivxray-xdr/README.md` |

## Section K · Deployment, Release & CI (Points 54-57)

| # | Question | Finding | Evidence |
|---|---|---|---|
| **54** | Docker floor (P0-F closed)? | `deploy/docker-compose.yml` — 3 services (mongodb v7, backend, frontend) with healthchecks, dependency ordering (`service_healthy`), named volume `nivxray-mongo-data`, `${ADMIN_PASSWORD:?}` required at parse time. `deploy/backend.Dockerfile` (non-root uid 1001) + `deploy/frontend.Dockerfile` (nginx SPA history fallback). `deploy/.env.example` blank ADMIN_PASSWORD by design. `deploy/README.md` operator playbook. | `deploy/`, `SPRINT_1_CHECKPOINT.md` §P0-F |
| **55** | Kubernetes / Helm? | **ABSENT.** No `deploy/helm/`, no `k8s/`, no `Chart.yaml`. P0-J blocker (HA + StatefulSet + PVC + ingress + HPA + probes + ServiceMonitor). | `ls deploy/` |
| **56** | CI/CD workflows? | 4 active `.github/workflows/*.yml`: `docs-screenshots.yml`, `rc4x_quality_gate.yml`, `rc5_gates.yml`, `rc5_golden_corpus_gate.yml` (plus a retired `.retired` file). **No deploy pipeline.** SBOM absent. | `.github/workflows/` |
| **57** | Release documentation & changelogs? | Rich: `/app/RELEASES.md` (32 KB), `/app/RELEASE_NOTES_2026-02-16.md`, `/app/V1_5_0_RELEASE_METRICS.md`, `/app/memory/CHANGELOG.md`, 250+ MD files in `/app/memory/` documenting phase gates (RC2/RC4/RC5/B3). **Doc-to-code ratio is high** — the 360° audit flagged this as a signal that some documented capabilities may not be code-backed. Every P0 must be closed against CODE + TEST + INTEGRATION + PRODUCTION evidence, not against a memory doc. | root + `memory/` MD inventory |

---

# PART II · DOMAIN-SYNTHESIZED ARCHITECTURE NARRATIVE

## Domain 1 — Product Boundary & Positioning

NivXRay is a **detection + response + investigation platform ("XDR Operational Fabric")** built on a market-differentiating **deterministic Universal Decoder + evidence graph** moat. It is intentionally **NOT** an EDR agent, **NOT** a full SIEM, **NOT** a TIP, **NOT** a SOAR. Ownership boundaries (per `GA_BLOCKERS.md` §2.12):

- **BUILD:** deterministic decoder, investigation graph/SSOT, attack story narration, lightweight vendor telemetry pollers, lightweight response executors.
- **INTEGRATE:** sandbox (Cuckoo/Any.Run/VMRay), TIP (TAXII feeds), object storage (S3/MinIO), SIEM (as data source), SSO (via `authlib` OIDC generic client · Okta / Entra / Google Workspace org / Auth0).
- **DEFER:** own EDR agent (2-year project alone).
- **DON'T BUILD:** full SIEM replacement, own SOAR platform, own MISP replacement.

## Domain 2 — Backend Composition

The backend is a **monolithic FastAPI process with pluggable routers**, not micro-services. Router count is very high (128 modules · 717 paths) — this is a scale signal, not necessarily an architectural concern, but does argue for eventual sub-namespace refactors (already implicit in `/api/xdr/*` vs older bare-prefix routers).

Three companion apps live in `/app/apps/`:
1. **`nivxray-xdr`** — standalone tenant-facing XDR SPA (Vite + React 18). Consumes existing backend.
2. **`nivxray-xdr-collector`** — dedicated FastAPI collection/transport plane. Receives events, canonicalizes them, forwards to base backend via `POST /api/xdr/ingest/telemetry`. Never makes security decisions.
3. **`nivxray-xdr-response`** — dedicated FastAPI response engine. Owns execution state machine, approval store, vendor adapters, forwards evidence/audit/timeline back to base backend.

Each companion has its own Dockerfile, `main.py`, `framework/`, `routes/`, `tests/`, `requirements.txt`. The base backend's `xdr_cortex_*` routers wire the Cortex-branded ingest/actions/wizard/scheduler as a special-case vendor pack.

## Domain 3 — Universal Decoder (Product Moat)

The decoder is the **strongest surface** in the codebase and the reason NivXRay's audit scores investigation at 86%.

- **Runtime:** `services/decoder/base/` (Plane-A codecs) + `services/decoder/orchestrator.py` (DDO). Legacy `recursive_decoder.py` and plugin adapters have been reduced to **strict re-export shims** (Gate 2D-B3 completion). CI-audited via `tests/decoder_harness/test_b3_3_dependency_audit.py`: **zero forbidden edges from authoritative to legacy code paths.**
- **Invariants (enforced at type level via `RECONSTRUCTION_INVARIANTS`):** `static_only=True`, `execution=False`, `network_access=False`, `attck_promotion=False`, `bounded_depth=True (MAX_DEPTH=6)`, `deterministic_order=True`, `provenance_required=True`.
- **Signature dispatch** is what distinguishes DDO from CyberChef-style speculative "Magic" — every decode attempt is justified by an evidence signature in the input. False-reconstruction is prevented by (a) each decoder validates its own output printability, (b) DDO stops when no signature matches, (c) DDO never emits a layer that would replace non-garbage text with garbage.
- **Snapshots:** two frozen byte-identical parity snapshots (`12378d11…8bac`, `6427903e…7897`) survived the entire B3 migration untouched.
- **Deliberately deferred:** B3.5, Gate 2E, Gate 2F. No new codecs. No Bash Plane-B semantics. Owner-locked.

## Domain 4 — Authentication, Authorization & Multi-Tenancy

Current state (P0-C ABSENT):
- **Auth:** email + password (bcrypt) + own-signed JWT. Force-password-change on first login. Sliding-window per-key rate limit.
- **Secret handling for admin bootstrap:** `.env` with `ADMIN_EMAIL`, `ADMIN_PASSWORD` (both rotated in the SEC-001/002 security audit — do NOT paste values in public docs), `ADMIN_FORCE_PASSWORD_CHANGE`. `seed_admin()` runs on backend startup.
- **RBAC:** `xdr_rbac.py` — 20+ resources × 27 actions, wildcard `*.*`, `require_permission("resource.action")` FastAPI dependency, `check_access(tenant_id, principal_id, permission)` core primitive, denial emits `ACCESS_DENIED` audit event. **Bootstrap grace mode:** zero-user tenants allow all ops so first user can be provisioned; enforcement engages as soon as one user exists.
- **11 immutable starter roles** (`platform_admin` … `read_only`).

Gaps toward GA:
- **P0-C (SSO/OIDC):** must integrate `authlib` OIDC generic client with claim/domain validation, JIT provisioning against `xdr_user_roles`, `OIDC_ALLOWED_DOMAINS` gate, unique `(oidc_issuer, oidc_subject)` index. **UI is frozen** — deliver backend + API contract only, document required UI as backlog. **Personal Google login DOES NOT close this blocker** per owner clarification.
- **P0-D (multi-tenant isolation):** `_principal(req)` + tenant_id stamping is universal, but **no global `find*/update*` middleware** and **no adversarial negative test**. `xdr_ingest.py` proves the tenant-isolation pattern (rejects mixed-tenant batches, verifies collector-tenant match) — this same pattern must extend to every collection access.

## Domain 5 — Telemetry & Detection Pipeline

Data flow when a real vendor is CONNECTED (target state):

```
Vendor tenant → OAuth/API-key handshake → xdr_secrets
              → collector poller (delta cursor + backoff)
              → framework/parsers → framework/registry
              → POST /api/xdr/ingest/telemetry
              → CanonicalEnvelope validation → tenant match → xdr_events
              → CONNECTED gate flips
              → correlation_engine + attack_story + attack_graph + IKG
              → verdict_stage2 + detection_content + rule_studio
              → workspace_cases (with incident_state projection)
              → analyst workspace → response recommendation
              → approval → apps/nivxray-xdr-response/execute
              → vendor_adapters.<vendor>.<action>()
              → evidence forwarder → base backend timeline/audit
```

Current state per link:
- **collectors, xdr_secrets, ingest endpoint, canonical envelope, CONNECTED gate:** CODE + tested. **Zero real vendors configured.**
- **correlation/attack story/verdict/rule studio:** all CODE, no efficacy measurement.
- **response executors:** honest capability flags, all `capability_available=false` on this pod (no `XDR_INTEGRATION_*` env vars). Route now consistent at `/api/response/*` (P0-H).
- **workspace_cases projection:** MATURE. 6 live incidents observed on the pod via `/api/incidents`.

Blockers preventing this flow from being end-to-end proven:
- **P0-A:** implement 3 real pollers (Okta System Log → CloudTrail → CrowdStrike/MDE). Prove CONNECTED-through-investigation loop.
- **P0-B:** wire 5 real response executors against at least one EDR (isolate host, kill process, block IP, reset user creds, quarantine file).
- **P0-I:** author labelled multi-event replay corpus, nightly regression producing `tests/detection_efficacy/report_YYYYMMDD.json` with precision/recall/F1/ATT&CK-coverage/FP-rate.

## Domain 6 — Observability & Operations

Post-Sprint 1 state:
- **JSON logs on stdout** with stable envelope (`trace_id, tenant_id, route, method, status, latency_ms`) — SIEM-shippable.
- **Prometheus scrape** at `/api/metrics` with cardinality-safe route templates, three metrics, own registry.
- **Health probes** at `/api/health` (cheap liveness) and `/api/health/deep` (Mongo/LLM/disk readiness). Root `/health` alias for kubelet.
- **Audit log** per tenant, tamper-evident, `emit_audit()` from all admin/RBAC-enforced writes.

Still ABSENT:
- OpenTelemetry (distributed tracing).
- Alert routing (PagerDuty / Opsgenie / Slack).
- Central log aggregation (logs are on-pod only).
- Queue/worker monitoring — because no queue framework (`celery/arq/dramatiq`) is in requirements.

## Domain 7 — Deployment & Release

- **Development pod:** supervisor-managed FastAPI (`uvicorn`) + CRA (`yarn start`) + local MongoDB, single-process, no HA.
- **Docker-compose floor (Sprint 1 P0-F closed):** reproducible baseline — mongo:7 + backend + frontend, healthchecks, dependency ordering, non-root containers, named volume for Mongo persistence, env-driven config, ADMIN_PASSWORD required at parse time.
- **Kubernetes/Helm (P0-J):** ABSENT. Prerequisites: StatefulSet+PVC for Mongo replica set, ingress, HPA baseline, ServiceMonitor for Prometheus, liveness/readiness probes, tested rolling upgrade.
- **CI:** 4 GitHub workflows scoped to quality gates + docs screenshots. **No deploy pipeline.** SBOM absent (P0-K covers this).

## Domain 8 — Documentation Footprint & Honest-State Discipline

`/app/memory/` contains **250+ MD files**, many describing phase gates (RC2/RC4/RC5), architectural directions, capabilities, roadmaps, and audits. The **doc-to-code ratio is a known risk signal** — a capability documented in `memory/` is not necessarily code-backed. Every P0 in `GA_BLOCKERS.md` explicitly requires **CODE + TEST + INTEGRATION + PRODUCTION** evidence to close, not a memory-doc reference.

**Honest-state invariants (owner-locked, cross-cutting):**
- No fabricated data, no mocked UI states presented as real, no manufactured telemetry, no fake CONNECTED gates.
- `capability_available=false` MUST remain visible so decision engines and UIs honestly reflect absence.
- **NO EVIDENCE → NO DETECTION CLAIM.** Correlation MUST NEVER manufacture missing events. Every detection MUST point back to canonical evidence.
- LLM (Emergent Universal Key · Claude Sonnet 4.5) is used only for narration — never for authoritative decode, never for verdict, never in the critical path.

---

# PART III · GAP ANALYSIS SUMMARY (mapped to `GA_BLOCKERS.md`)

| ID | Blocker | Current State | Sprint 1 Delta | Remaining Effort |
|---|---|---|---|---|
| P0-A | Real vendor telemetry connectors (×3) | ABSENT — 0 configured, 0 CONNECTED | — | L (quarter) |
| P0-B | Real response actions (×5) | Registry PARTIAL, executors ABSENT | route-alias fixed | M for first vendor |
| P0-C | SSO / OIDC | ABSENT — playbook captured, IMPL not started | STOPPED for owner scope | S–M |
| P0-D | Multi-tenant isolation with adversarial tests | PARTIAL — pattern proven in ingest; no global filter, no negative test | — | M |
| **P0-E** | **Prometheus + JSON logging** | **CLOSED (Sprint 1)** | +54 | — |
| **P0-F** | **Docker Compose floor** | **CLOSED (Sprint 1)** | +26 | — |
| P0-G | Retention / backup / restore | ABSENT | — | M |
| **P0-H** | **Route consistency + OpenAPI** | **CLOSED (Sprint 1)** | +6 (surface honesty) | — |
| P0-I | Detection efficacy + correlation eng. | PARTIAL — decoder corpus only, no XDR labelled corpus | — | M (or L if corpus must be built) |
| P0-J | HA / failover baseline | ABSENT — single Mongo, single supervisor | — | M |
| P0-K | Security pen-test baseline | NOT AUDITED | — | S–M |

**Overall heuristic maturity indicator:** Pre-Sprint 1 = ~48% · Post-Sprint 1 = ~54%. Not a certification — a decision-support indicator only.

---

# PART IV · KNOWN LIMITATIONS OF THIS AUDIT

- **Read-only.** No code, tests, config, or UI modified. No new tests authored. No smoke tests beyond four `curl` calls (`/api/health`, `/api/metrics`, `/api/openapi.json`, `/api/response/actions`, `/api/incidents`, `/api/xdr/data-sources`, `/api/xdr/collectors`).
- **No load test, no pen test, no cross-tenant adversarial test, no accessibility audit, no 8-hour SOC-analyst UX evaluation.** Those are separate P0 items.
- **Doc-vs-code drift NOT exhaustively reconciled.** `/app/memory/` has 250+ MD docs; only a purposeful sample was cross-referenced. When memory doc and code disagree, this audit records what the **code + live pod** says.
- **57 audit points chosen for maximum forensic coverage** across topology, backend, data, auth, tenancy, ingest, detection, response, decoder, observability, frontend, and deployment. Numbering is stable — the companion JSON preserves the same indices for machine consumption.

---

## END · READ-ONLY FORENSIC AUDIT DELIVERED

---

# PART V · COMPONENT TRUTH TABLE (8-STATE GRADING — AUTHORITATIVE FOR ANTIGRAVITY BOUNDARY CONTRACT)

Every discoverable component is graded against the 8-state vocabulary. Runtime/code evidence is authoritative; documentation claims are noted where they diverge.

## V.1 · Authoritative Runtime (base backend + observability + decoder + investigation)

| Component | Location | Grade | Evidence · Divergence from docs |
|---|---|---|---|
| FastAPI app entrypoint | `backend/server.py` | **IMPLEMENTED + WORKING** | 908 LOC · 128 routers wired · live `curl /api/health` = 200 |
| Health probes (liveness + deep readiness) | `server.py` L177-240 | **IMPLEMENTED + WORKING** | live 200; Mongo/LLM/disk checks composed |
| Observability middleware (JSON logs + trace-id) | `observability/__init__.py` | **IMPLEMENTED + WORKING** | 8 P0-E tests pass; live JSON envelopes on stderr |
| Prometheus `/api/metrics` | `server.py` L188 + `observability/__init__.py` | **IMPLEMENTED + WORKING** | live scrape returns `nivxray_http_requests_total{...}` |
| OpenAPI surface (`/api/openapi.json`, `/api/docs`, `/api/redoc`) | `server.py` L161-163 | **IMPLEMENTED + WORKING** | live 200 · 595 KB · 717 paths |
| Request hardening middleware | `server.py` L640; `security/` | **IMPLEMENTED + WORKING** | tests: `test_request_hardening.py` |
| Universal Decoder — DDO orchestrator | `services/decoder/orchestrator.py` | **IMPLEMENTED + WORKING** | 14 sigs · MAX_DEPTH=6 · 59/59 harness tests |
| Plane-A codecs (7 families) | `services/decoder/base/` | **IMPLEMENTED + WORKING** | byte-identical parity snapshots; B3.3 dep audit clean |
| PE + Shellcode analyzers | `services/analyzers/{pe,shellcode}.py` | **IMPLEMENTED + WORKING** | corpus 76/76 pass |
| Investigation composer | `services/reasoning/investigation_composer.py` (via `/api/investigation/summary`) | **IMPLEMENTED + WORKING** | deterministic projection · no LLM |
| Attack Story / Attack Graph | `services/attack_story/`, `services/attack_graph/`; routers same | **IMPLEMENTED + WORKING** | UI wired · 6 live incidents surface |
| Device Trajectory | `services/activity/projector.py`; `routers/edr.py` | **IMPLEMENTED + WORKING** | v2 trajectory routes reachable |
| Canonical Evidence Recovery | `services/canonical_evidence_recovery.py` | **IMPLEMENTED + WORKING** | referenced across pipeline · provenance mandatory |
| Auth (email + password + JWT + rate-limit + force-change) | `routers/auth.py`; `security/rate_limit.py` | **IMPLEMENTED + WORKING** | admin login live · 429 lockout verified |
| RBAC (20 res × 27 verbs + wildcards) | `routers/xdr_rbac.py` | **IMPLEMENTED + WORKING** | 11 starter roles · `require_permission` dependency active |
| Audit log (tamper-evident) | `routers/xdr_audit_log.py`; `emit_audit()` | **IMPLEMENTED + WORKING** | called from admin/RBAC/secrets/webhooks routes |
| Secrets Store (Mongo-backed) | `routers/xdr_secrets.py` | **IMPLEMENTED BUT NOT PRODUCTION-SAFE** | Mongo storage; bootstrap `.env` acceptable ONLY for integration tests per owner rule — production must migrate to KMS/Vault |
| Data-source catalogue (16 kinds) | `routers/xdr_data_sources.py` | **IMPLEMENTED + WORKING** | live: `count=0` (no data sources configured yet — expected) |
| Canonical ingest endpoint | `routers/xdr_ingest.py` | **IMPLEMENTED + WORKING** | tenant-isolation enforced · mixed-collector batches rejected 400 |
| Rule Studio (20 routes) | `routers/xdr_rule_studio.py` | **IMPLEMENTED BUT INCOMPLETE** | rule lifecycle coded; **no efficacy metrics** (P0-I gap) |
| Correlation engine | `services/correlation_engine.py`; `routers/xdr_correlation.py` | **IMPLEMENTED BUT INCOMPLETE** | primitives exist; **no labelled multi-event replay corpus**, no precision/recall/F1 |
| Verdict Stage-2 | `routers/verdict_stage2.py`; `services/verdict_stage2/` | **IMPLEMENTED + WORKING** | Verdict Engine v3.1 · corpus tests validate |
| Incident projection | `routers/incidents.py` (from `workspace_cases`) | **IMPLEMENTED + WORKING** | 6 live incidents · deterministic projection |
| Response action registry | `detection_content/xdr_action_registry.py` | **STUB / MOCK / SCAFFOLD** | 13 actions declared with honest `capability_available=false` — every executor references an `edr.*` / `firewall.*` integration that is NOT set on this pod |
| Response route alias (`/api/response/*`) | `routers/response_alias.py` | **IMPLEMENTED + WORKING** | Sprint 1 P0-H fix; legacy `/admin/content-supply-chain/response/*` retained additively |

## V.2 · Companion Apps

| Component | Location | Grade | Evidence · Divergence from docs |
|---|---|---|---|
| `nivxray-xdr` standalone SPA | `apps/nivxray-xdr/` | **IMPLEMENTED BUT NOT WIRED** | separate Vite+React 18 build; consumes base backend `/api/*`; own Dockerfile + `vercel.json`; NOT part of the current live pod supervisor stack |
| `nivxray-xdr-collector` FastAPI service | `apps/nivxray-xdr-collector/` | **IMPLEMENTED BUT NOT WIRED** | 3,407 LOC · framework fully implemented (syslog/webhook/rest_poller/dedup/delivery/outbox/scheduler); NOT started on the live pod |
| `nivxray-xdr-response` FastAPI service | `apps/nivxray-xdr-response/` | **IMPLEMENTED BUT NOT WIRED** | 2,242 LOC · executor + adapters + approval store; NOT started on the live pod; vendor adapters are stubs |

## V.3 · Enterprise Identity (P0-C target)

| Component | Location | Grade | Evidence |
|---|---|---|---|
| OIDC login (`/api/auth/oidc/login`) | — | **MISSING** | no `authlib` in `requirements.txt`; no route |
| OIDC callback (`/api/auth/oidc/callback`) | — | **MISSING** | — |
| OIDC logout (`/api/auth/oidc/logout`) | — | **MISSING** | — |
| JIT provisioning against `xdr_user_roles` | — | **MISSING** | — |
| `OIDC_ALLOWED_DOMAINS` gate | — | **MISSING** | — |
| Unique `(oidc_issuer, oidc_subject)` index | — | **MISSING** | — |
| SAML/pysaml2 | — | **MISSING** — deferred by owner beyond OIDC |
| Grade for the whole P0-C surface | `GA_BLOCKERS.md §P0-C` | **CANDIDATE FOR NEW TECHNOLOGY** | `authlib` playbook captured; implementation not started; UI frozen |

## V.4 · Real Vendor Telemetry (P0-A target)

| Component | Location | Grade | Evidence |
|---|---|---|---|
| Okta System Log poller | — | **MISSING → CANDIDATE FOR NEW TECHNOLOGY** | first-target per owner sequencing |
| AWS CloudTrail S3-notification poller | — | **MISSING → CANDIDATE FOR NEW TECHNOLOGY** | second target |
| Microsoft Defender for Endpoint OR CrowdStrike Falcon poller | — | **MISSING → CANDIDATE FOR NEW TECHNOLOGY** | third target |
| SentinelOne / Entra ID / Google Workspace pollers | — | **MISSING** | later sprints |
| Delta-cursor + backoff + rate-limit runtime | `apps/nivxray-xdr-collector/framework/{runtime,scheduler,rest_poller}.py` | **IMPLEMENTED BUT NOT WIRED** | framework primitives exist; no vendor-specific pollers registered |
| Normalizers to canonical event schemas | `services/normalization/`, `services/canonicalizer/` | **IMPLEMENTED BUT INCOMPLETE** | schemas exist for LOLBAS/MITRE/PowerShell; vendor-specific mappers missing |

## V.5 · Real Response Executors (P0-B target)

| Component | Location | Grade | Evidence |
|---|---|---|---|
| `ENDPOINT_ISOLATE` executor | `apps/nivxray-xdr-response/framework/vendor_adapters.py` | **STUB / MOCK / SCAFFOLD → CANDIDATE FOR NEW TECHNOLOGY** | registry entry exists; no real EDR call |
| `IP_BLOCK` executor | same | **STUB / MOCK / SCAFFOLD** | firewall adapter missing |
| Kill process, reset credentials (Okta/Entra), quarantine file | same | **MISSING** | 3 of 5 GA-required real actions absent |
| Approval workflow | `apps/nivxray-xdr-response/routes/approvals.py` | **IMPLEMENTED BUT INCOMPLETE** | shape wired; end-to-end approval → execute → audit → recompute not yet tested against a real vendor |
| Recompute-after-action | present in `content_supply_chain.py` | **IMPLEMENTED BUT INCOMPLETE** | callable; not validated against real executor |

## V.6 · Multi-Tenant Enforcement (P0-D target)

| Component | Location | Grade | Evidence |
|---|---|---|---|
| Per-request tenant extraction (`_principal`) | ~60 files use it | **IMPLEMENTED + WORKING** | universal pattern |
| Ingest cross-tenant guard | `xdr_ingest.py` | **IMPLEMENTED + WORKING** | proven pattern · 403 with `TENANT_ISOLATION_VIOLATION` |
| Global `find*/update*` tenant filter middleware | — | **MISSING** | no wrapper enforces `tenant_id` on every Mongo op |
| `require_tenant()` dependency | — | **MISSING** | analogous to `require_permission` but tenant-scoped |
| Adversarial cross-tenant negative test | — | **MISSING** | no `test_*_cross_tenant*` file matched |
| Tenants router (provisioning + admin surface) | — | **MISSING** |

## V.7 · Data Lifecycle (P0-G target)

| Component | Location | Grade |
|---|---|---|
| Per-tenant retention policy | — | **MISSING** |
| Mongo TTL indexes | — | **MISSING** |
| Nightly `mongodump` runner | — | **MISSING** |
| Restore drill | — | **MISSING** |
| Tenant purge / GDPR-delete workflow | — | **MISSING** |
| Evidence immutability (hash-chain / WORM) | — | **MISSING** (provenance recorded but underlying Mongo is mutable) |

## V.8 · Deployment / HA / Security-Baseline (P0-F ✓ · P0-J / P0-K open)

| Component | Location | Grade |
|---|---|---|
| Docker Compose floor | `deploy/docker-compose.yml`, `deploy/{backend,frontend}.Dockerfile` | **IMPLEMENTED + WORKING** (Sprint 1 P0-F) |
| Kubernetes / Helm manifest | — | **MISSING → CANDIDATE FOR NEW TECHNOLOGY** (P0-J) |
| Mongo replica set with automatic failover | — | **MISSING** |
| Stateless backend ≥2 replicas behind ingress | — | **MISSING** |
| Zero-downtime rolling upgrade test | — | **MISSING** |
| Dependency vulnerability scan (Grype / Trivy) | — | **MISSING** |
| OWASP Top-10 ZAP baseline | — | **MISSING** |
| Auth adversarial tests (token replay, IDOR, priv-esc) | — | **MISSING** |
| SBOM | — | **MISSING** |

## V.9 · Duplicates / Fragmented Surfaces (candidates for consolidation)

| Cluster | Modules | Grade | Note |
|---|---|---|---|
| Incident routing | `routers/incidents.py`, `routers/incident_summary.py`, `routers/incident_threat_model.py`, `xdr_dashboard.py` (`/incidents` prefix used by 8 routers with different tags) | **DUPLICATE / FRAGMENTED** | intentional — separated by concern; deterministic projection is authoritative |
| Investigation storage | `investigation_cases`, `investigations`, `investigation_ssot`, `workspace_cases` collections | **DUPLICATE / FRAGMENTED** | owner-locked: `workspace_cases` is the sole authoritative record; other collections are lifecycle-specific projections |
| Response routes | legacy `/api/admin/content-supply-chain/response/*` + new `/api/response/*` alias | **DUPLICATE / FRAGMENTED** (transitional) | Sprint 1 kept both additively; deprecate legacy after clients migrate |
| Frontend lanes | base `/`, `/v2/*`, `/nivxforge/*`, `/investigate/*`, plus standalone `apps/nivxray-xdr/` | **DUPLICATE / FRAGMENTED** | multiple SPAs share the backend; consolidation is UX-choice, not a technical blocker (UI freeze applies) |
| Cortex-branded routers | `xdr_cortex_actions`, `xdr_cortex_ingest_routes`, `xdr_cortex_wizard`, `xdr_vendor_wizard` | **IMPLEMENTED + WORKING** but tightly coupled to one vendor | vendor generalization pending |

## V.10 · Antigravity-Ready Boundary Recommendations

Only components that are **IMPLEMENTED + WORKING** should be integration boundaries for any new Antigravity module. Anything **STUB / MOCK / SCAFFOLD** or **IMPLEMENTED BUT NOT WIRED** must first be lifted to WORKING (or replaced) before it can be a stable contract point. Concrete boundaries confirmed stable:

- `POST /api/auth/login` + JWT bearer (until P0-C ships OIDC alongside).
- `GET /api/health`, `GET /api/health/deep`, `GET /api/metrics`, `GET /api/openapi.json` — SRE + observability contracts.
- `POST /api/xdr/ingest/telemetry` — canonical ingest contract with tenant guard.
- `GET /api/xdr/data-sources`, `GET /api/xdr/collectors` — catalogue + honest-state count endpoints.
- `GET /api/response/actions` — honest capability-flag registry (13 actions).
- `services/decoder.decode_universal(...)` — Python-level deterministic decode entry point.
- RBAC `require_permission("resource.action")` dependency — for any new privileged route.
- Observability envelope — any new module MUST emit logs through the same root logger and metrics through the same `REGISTRY` in `observability/__init__.py`.

---

## END · READ-ONLY FORENSIC AUDIT DELIVERED

Two artifacts written this session (documentation only, no application code touched):

- `/app/memory/NIVXRAY_CURRENT_STATE_TRUTH.md` (this document)
- `/app/memory/NIVXRAY_CURRENT_STATE.json`

No new endpoints, no schema changes, no test files, no refactors, no UI edits. The absolute UI freeze and no-decoder-scope-creep rules were honoured.

Awaiting owner return with the revised, implementation-grade Antigravity master prompt.
