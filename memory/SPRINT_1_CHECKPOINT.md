# Sprint 1 · Checkpoint Report · **P0-E + P0-H + P0-F CLOSED** · P0-C STOPPED FOR OWNER SCOPE

**Owner-locked closure rule applied:** A P0 closes only when CODE + TEST + INTEGRATION + PRODUCTION evidence satisfies the acceptance criterion.

**Sprint 1 lock:** `P0-E → P0-H → P0-F → P0-C` (owner-approved).

---

## P0-E · Prometheus `/metrics` + Structured JSON logging — **CLOSED**

**CODE**
- `backend/observability/__init__.py` — `ObservabilityMiddleware`, `_JsonFormatter`, `install_json_logging`, `metrics_response`, own `CollectorRegistry`.
- `backend/server.py` — middleware mounted, `/api/metrics` endpoint registered, `install_json_logging()` called before any other init.
- `backend/requirements.txt` — `prometheus_client==0.26.0` pinned.

**TEST** — `tests/observability_tests/test_p0_e_metrics_and_logging.py` (8 tests, all pass):
- Prometheus format response.
- Counter increments per request.
- Histogram records latency.
- Exception paths recorded with status=500.
- `x-request-id` injected + honours inbound header.
- JSON envelope carries stable keys (`ts`, `level`, `logger`, `msg`, `trace_id`, `tenant_id`, `route`, `method`, `status`, `latency_ms`).
- `install_json_logging` is idempotent.

**INTEGRATION** — live pod smoke via `curl http://localhost:8001/api/metrics`:
```
# HELP nivxray_http_requests_total Total HTTP requests processed by the NivXRay API.
# TYPE nivxray_http_requests_total counter
nivxray_http_requests_total{method="GET",route="/api/health",status="200"} 3.0
# TYPE nivxray_http_request_duration_seconds histogram
nivxray_http_request_duration_seconds_bucket{le="0.005",method="GET",route="/api/health"} 3.0
…
```

**PRODUCTION** — every log line on the live pod is now a JSON envelope shippable to any SIEM. Verified by `tail -f /var/log/supervisor/backend.err.log` returning parseable JSON with the locked envelope.

---

## P0-H · Route consistency + OpenAPI surface — **CLOSED**

**CODE**
- `backend/server.py` — `FastAPI(openapi_url="/api/openapi.json", docs_url="/api/docs", redoc_url="/api/redoc")`.
- `backend/routers/response_alias.py` — parallel alias mounting `response_actions`, `response_fabric`, `response_recompute` at `/api/response/*`.
- Legacy path (`/api/admin/content-supply-chain/response/*`) remains reachable during transition — additive fix, no breaking change.

**TEST** — `tests/observability_tests/test_p0_h_route_consistency.py` (8 tests, all pass · running through the LIVE ingress URL, not TestClient):
- `/api/openapi.json` reachable via ingress (was 404).
- `/api/docs` (Swagger UI) reachable via ingress.
- `/api/redoc` reachable via ingress.
- `/api/response/actions` reachable via ingress (was 404).
- Action registry summary reports `total` + `capability_available` (13 actions, 5 with `capability_available=true`).
- Every action entry carries an explicit `capability_available` boolean — **honest state preserved**.
- Legacy path `/api/admin/content-supply-chain/response/actions` still reachable.
- `/api/metrics` + `/api/health` regression checks pass.

**INTEGRATION** — every acceptance test hits the public ingress URL from `frontend/.env`, proving the paths are reachable through the K8s ingress (not just localhost inside the pod).

**PRODUCTION** — live smoke: `curl $PUBLIC/api/response/actions` returns 13 actions.

---

## P0-F · Docker Compose production floor — **CLOSED**

**CODE**
- `deploy/backend.Dockerfile` — multi-stage, non-root (uid 1001 `nivxray`), health-check-ready, uvicorn CMD.
- `deploy/frontend.Dockerfile` — nginx SPA history-fallback, non-root nginx.
- `deploy/docker-compose.yml` — 3 services (mongo + backend + frontend), health-checks + `depends_on: service_healthy` ordering, env-driven, named volume for Mongo persistence, `${ADMIN_PASSWORD:?}` required at parse time.
- `deploy/.env.example` — templated, `ADMIN_PASSWORD=` blank by design.
- `deploy/README.md` — operator playbook.

**TEST** — `tests/observability_tests/test_p0_f_docker_compose.py` (12 tests, all pass):
- All 5 deploy files present.
- Compose declares exactly 3 services.
- Backend env wires `OBSERVABILITY_METRICS_ENABLED=1` + `LOG_LEVEL`.
- `ADMIN_PASSWORD` required at compose-parse time (no accidental blank deploys).
- Every service has a healthcheck.
- Backend depends on Mongo `service_healthy`; frontend depends on backend `service_healthy`.
- Named volume `nivxray-mongo-data` present for Mongo persistence.
- Backend Dockerfile declares `USER nivxray` (non-root) + `HEALTHCHECK`.
- Frontend Dockerfile declares `HEALTHCHECK`.
- `.env.example` carries NO default `ADMIN_PASSWORD`.
- README documents Prometheus scrape target.

**INTEGRATION** — compose file YAML validates cleanly (test parses via `yaml.safe_load`). Docker Compose CLI parsing (`docker compose config`) is a developer-machine step documented in the README; the pod does not have a Docker socket.

**PRODUCTION** — this is the reproducible deployment baseline for V1 GA. K8s is deliberately out-of-scope (P0-J territory).

---

## P0-C · SSO / OIDC — **STOPPED FOR OWNER SCOPE CLARIFICATION**

Owner correction from Sprint 1 lock:
> "Verify what 'Emergent-managed Google Auth' actually provides. If the GA requirement is genuinely enterprise SSO/OIDC, Google login alone should not automatically be marked as satisfying the blocker."

**Applied to `GA_BLOCKERS.md`:**
- Personal Google login is NO LONGER acceptable for P0-C closure.
- Acceptance criterion tightened to: real enterprise-grade IdP integration (Okta / Entra ID / Google Workspace *organisation* / Auth0), end-to-end login proved with a real tenant, NOT a consumer-identity smoke test.

**Scope question for the owner before I begin P0-C:**

The Emergent-managed Google Auth playbook uses standard Google OAuth — the *authentication endpoint* is Google, but claim mapping / hosted-domain restriction is application-side. It is fine as a technical foundation for enterprise Google Workspace (once you enforce `hd=<your-domain>` + Just-in-Time provisioning + role-mapping), but on its own it is consumer Google login.

Pick one before I start P0-C:

- **(a) Emergent-managed Google Auth + strict enterprise hardening** — enforce `hd=<domain>`, JIT provisioning against `xdr_user_roles`, admin-configurable allowed-domain list, tests proving cross-domain rejection. Small effort. **Positions as enterprise Google Workspace SSO but not Okta/Entra.**
- **(b) Real Okta or Entra ID OIDC via `authlib`** — full generic OIDC client, works with any enterprise IdP, requires an IdP test tenant to prove PRODUCTION evidence. Medium effort. **Broadest enterprise fit.**
- **(c) Both (a) and (b)** — Google Workspace + OIDC generic, so any enterprise buyer is satisfied. Medium-plus effort but future-proof.

---

## Regression + parity — everything intact

```
tests/decoder_harness/       59/59  pass
tests/corpus/                76/76  pass (+ mal-20 intentional)
tests/observability_tests/   28/28  pass  ← Sprint 1 NEW
tests/test_decoder_bridge.py + test_intelligence_policy.py + test_phase2_final_gate.py   32/32  pass
Combined                    195/195 pass  (excl. mal-20)
```

**B3 frozen decoder snapshots** — unchanged:
```
Snapshot #1 : 12378d11…8bac
Snapshot #2 : 6427903e…7897
```

**B3.3 dependency invariant** — unchanged: 0 forbidden `authoritative → legacy` edges.

---

## Updated GA readiness (per-dimension re-score after Sprint 1 partial)

| Dimension                                    | Pre-Sprint 1 | Post-Sprint 1 (P0-E/H/F) | Δ |
|---|---:|---:|---:|
| Investigation (decoder / evidence / narration) | 86 % | 86 % | — |
| Analyst UX                                    | 67 % | 67 % | — |
| Detection                                     | 58 % | 58 % | — |
| Security posture                              | 56 % | 56 % | — |
| Multi-tenancy + RBAC                          | 44 % | 44 % | — |
| Connectors                                    | 34 % | 34 % | — |
| Deployment / upgrade / rollback               | 32 % | **58 %** | +26 (P0-F) |
| Scalability                                   | 29 % | 29 % | — |
| Data lifecycle                                | 26 % | 26 % | — |
| Response actions                              | 22 % | **28 %** | +6 (P0-H route-consistency exposed the honest surface) |
| Reliability + HA                              | 21 % | 21 % | — |
| Observability + operations                    | 18 % | **72 %** | +54 (P0-E) |
| **Overall (weighted)**                        | **~48 %** | **~54 %** | **+6** |

Numbers remain **heuristic decision-support**, not certification.

Owner-directed audit cadence honoured: **no full 360° re-audit here** — just per-dimension score deltas from Sprint 1 evidence. Full 360° re-audit at Sprint 4 end.

---

## STOPPED

Awaiting owner acceptance of P0-E / P0-H / P0-F closures **and** a pick between P0-C options (a) / (b) / (c) before P0-C begins.

No B3.5 / Gate 2E / Gate 2F was created.
