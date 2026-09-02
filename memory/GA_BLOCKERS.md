# NivXRay XDR · V1 GA Blockers · P0 Only

> **Owner-locked closure rule (2026-02):**
> No P0 is considered CLOSED merely because code exists.
> A P0 closes only when **CODE + TEST + INTEGRATION + PRODUCTION**
> evidence satisfies the item's acceptance criterion.
>
> **Audit cadence:** Do NOT re-run the entire 360° after every
> tiny sprint. Instead: `sprint → P0 acceptance evidence →
> continue`. Perform one full 360° GA audit at the end of Sprint 4.
>
> **Do NOT optimize the % score as a management target.** It is a
> directional indicator only. The real GA target is a finite
> acceptance checklist: security + tenancy + real telemetry +
> evidence integrity + detection/correlation + response +
> observability + deployment + reliability + recovery +
> operational readiness. When every P0 on this file is CLOSED with
> full CODE + TEST + INTEGRATION + PRODUCTION evidence, that is
> GA. Not "when the percentage hits 100 %".


**Source:** `NIVXRAY_XDR_360_AUDIT.md` (2026-02, read-only + smoke-test verification)
**Rule:** an item is on this list **only** if it genuinely prevents V1 GA. Nice-to-haves live in the ROADMAP, not here.
**Format:** `current maturity → V1 GA target → exact remaining work → effort estimate → dependencies`.
**Effort scale:** S = 1 sprint (≈ 1–2 weeks) · M = 2–3 sprints · L = 1 quarter · XL = > 1 quarter.

---

## P0-A · Real Vendor Telemetry Connectors *(largest gap)*

**Current maturity:** `ABSENT` for real vendors.
Framework code (`apps/nivxray-xdr-collector/framework/{syslog,webhook,rest}.py`) is INTEGRATED; catalogue lists 18 kinds; **0 configured, 0 CONNECTED** on the live pod. `edr.py` is a read-only projection over existing cases, not an EDR feed.

**V1 GA target:** At least **3 real, evidence-CONNECTED** vendor pollers streaming into the canonical evidence pipeline. Suggested first three:
1. **Okta System Log** (identity)
2. **AWS CloudTrail via S3-notification** (cloud)
3. **Microsoft Defender for Endpoint or CrowdStrike Falcon** (endpoint)

**Strict acceptance criterion (owner-locked 2026-02):**
A connector is CLOSED only when the full loop is proved end-to-end:

```
Real vendor tenant → OAuth/API-key succeeds
    → CONNECTED gate flips (via /api/xdr/ingest/telemetry)
    → Canonical ingestion (schema conform)
    → IKG / correlation surface receives the event
    → Detection / verdict pipeline fires (or explicitly skips)
    → Investigation workspace surfaces the event
    → Analyst can act on it
```

Not sufficient: OAuth succeeded and a poller row exists.

**Remaining work per vendor (repeatable pattern):**
- OAuth / API-key handshake stored in `xdr_secrets`.
- Poller task (delta-cursor + backoff + rate-limit).
- Normalizer to canonical event schema (already exists for lolbas / mitre).
- Evidence CONNECTED transition via `POST /api/xdr/ingest/telemetry`.
- Health probe surfaced under `/api/xdr/collectors`.
- Integration test with a recorded vendor response fixture.
- **End-to-end test** proving the CONNECTED-through-investigation loop above.

**Effort:** **M per vendor** — so 3 vendors ≈ 1 quarter.
**Dependencies:** Secrets Store (present) · Ingest evidence gate (present · good design) · vendor tenant with test data.

---

## P0-B · Real Response Actions (isolate / kill / block)

**Current maturity:** `PARTIAL`. `detection_content/xdr_action_registry.py` has an honest capability-flag registry — every action reports `capability_available = false` because no `XDR_INTEGRATION_*` env var is set on this pod. Route mount inconsistency: the response endpoints are at `/api/admin/content-supply-chain/response/{id}` instead of `/api/response/{id}`.

**V1 GA target:** At least **5 real actions** wired end-to-end against one EDR:
- Isolate host
- Kill process
- Block IP / URL at firewall
- Reset user credentials (Okta / Entra)
- Quarantine file

Every action must go through the existing approval + audit + timeline pipeline (already coded).

**Remaining work:**
- Fix the route prefix (mount `xdr_cortex_actions_router` at `/api/response` for the analyst-facing route, or update the frontend to the current path).
- Implement the 5 concrete executors calling real vendor APIs.
- End-to-end test: incident → recommendation → approval → execute → audit-log → recompute.

**Effort:** **M** for the first vendor, **S** for each subsequent vendor.
**Dependencies:** P0-A (at least one vendor must be wired for both telemetry AND response so the loop is symmetric).

---

## P0-C · SSO / SAML / OIDC

**Current maturity:** `ABSENT`. Auth is email + password (bcrypt) with per-user records in `db.users`. No `authlib` / `pysaml2` / `python-jose` OIDC beyond own JWT signing.

**V1 GA target:** Enterprise buyers won't accept an XDR without enterprise SSO. Minimum: real **OIDC** integration with at least one enterprise IdP — **Okta**, **Microsoft Entra ID**, **Google Workspace**, or **Auth0**. Personal Google login (or any consumer identity) is **NOT** sufficient for this P0.

> **Owner clarification (2026-02):** Google authentication ≠ enterprise OIDC/SSO readiness.
> The P0-C blocker closes only when the wired IdP is one an enterprise CISO would accept
> (Okta / Entra ID / Google Workspace org / Auth0). Personal Google login satisfies auth
> but does NOT satisfy the enterprise SSO acceptance criterion.

> **Owner correction (absolute UI freeze):** P0-C is a BACKEND / AUTH /
> SECURITY gate only. NO frontend changes of any kind — no SSO button,
> no login page edit, no `/auth/signed-in` UI, no navigation, no styling,
> no new frontend dependency. If the OIDC production acceptance test
> genuinely cannot complete without frontend modification, deliver the
> backend OIDC capability + API contract, document required UI as
> backlog, STOP at the integration boundary.

> **Secret handling (owner-locked):**
> `/app/backend/.env` is acceptable ONLY as the immediate integration-
> test secret mechanism (must be `.gitignore`-protected, never
> committed, never pasted in chat). For the eventual production
> architecture, migrate to a real secret-management mechanism (KMS /
> Vault / cloud SM) rather than relying permanently on a pod-local
> `.env`. **This migration is a FUTURE item, NOT part of P0-C.**

**Remaining work:**
- Add `authlib` (OIDC client) via the captured playbook.
- Backend routes: `/api/auth/oidc/login`, `/api/auth/oidc/callback`, `/api/auth/oidc/logout` — feature-flagged off when env vars absent.
- Shared `issue_app_jwt()` refactor so OIDC + password paths mint identical tokens.
- JIT provisioning with unique `(oidc_issuer, oidc_subject)` index — no silent account takeover by email.
- Encrypted refresh-token storage via existing KMS/Fernet helper.
- Claim / domain / tenant validation via `OIDC_ALLOWED_DOMAINS`.
- **Acceptance:** end-to-end login via a real enterprise IdP tenant with an assigned workforce test user. NOT satisfied by a consumer-identity smoke test.

**Effort:** **M** (real enterprise OIDC + role-mapping + JIT).
**Dependencies:** none blocking — can ship in parallel with connectors.

---

## P0-D · Multi-tenant Isolation (proved with tests)

**Current maturity:** `PARTIAL`. `tenant_id` referenced across 60 backend files; docs stamped with tenant on write. NO enforced query filter middleware. NO cross-tenant negative test.

**V1 GA target:**
- Central `require_tenant()` dependency that every non-admin route uses.
- MongoDB collection access wrapped so `find*` / `update*` always inject `tenant_id`.
- Explicit test: Tenant A user cannot read Tenant B incidents (assert 403 / empty).
- Tenant provisioning + admin surface (a `tenants` router).

**Effort:** **M**.
**Dependencies:** none blocking.

---

## P0-E · Prometheus `/metrics` + Structured Logging

**Current maturity:** `ABSENT`. `grep -c prometheus requirements.txt` = 0. No `/metrics` endpoint. Only `logging.getLogger` stdlib.

**V1 GA target:**
- `prometheus_client` in requirements.
- `/metrics` endpoint exposing: request counts, latency histograms, decoder invocations, ingest counters, response-action counts, worker queue depth.
- Structured JSON logging (`structlog` or stdlib JSONFormatter) with a stable envelope (`trace_id`, `tenant_id`, `route`, `latency_ms`).
- Docker log-driver-friendly stdout.

**Effort:** **S**.
**Dependencies:** none.

---

## P0-F · Kubernetes / Helm Manifest (or docker-compose floor)

**Current maturity:** `ABSENT`. Three individual Dockerfiles exist for the three apps. No K8s / Helm / docker-compose.

**V1 GA target:**
- `deploy/docker-compose.yml` as the floor (backend + collector + response + mongo + nginx).
- `deploy/helm/nivxray/` chart with:
  - Deployment + Service per app
  - StatefulSet + PVC for MongoDB
  - Ingress
  - HPA baseline
  - Liveness / readiness probes
  - ServiceMonitor for Prometheus

**Effort:** **S** for docker-compose, **M** for Helm chart.
**Dependencies:** P0-E (probes reference `/metrics` and `/api/health`).

---

## P0-G · Data Retention / Backup / Restore

**Current maturity:** `ABSENT`. Ingest → correlate → investigate paths work; retention is undefined; no backup runner; no restore tested.

**V1 GA target:**
- Per-tenant retention policy (default 90 days hot, then archive).
- Mongo TTL indexes on ingest / audit collections.
- Nightly `mongodump` script + tested restore.
- GDPR-style "delete tenant" workflow.

**Effort:** **M**.
**Dependencies:** P0-D (tenant boundary).

---

## P0-H · Route Consistency + OpenAPI Surface

**Current maturity:** `PARTIAL`. `/api/openapi.json` returns `{}` on the live pod (FastAPI auto-docs are disabled or hidden). Several routers have inconsistent prefixes (response actions at `/admin/content-supply-chain/response` rather than `/response`).

**V1 GA target:**
- Enable OpenAPI at `/api/openapi.json` + `/api/docs` (locked behind admin auth).
- Audit + normalize route prefixes so the analyst-facing paths match the documented intent.
- Publish a versioned OpenAPI schema in `docs/`.

**Effort:** **S**.
**Dependencies:** none.

---

## P0-I · Detection Efficacy Measurement

**Current maturity:** `PARTIAL`. The corpus tests (76/76 + intentional mal-20) measure **decoder** accuracy, not XDR detection efficacy.

**V1 GA target:**
- Precision / recall / F1 computed over a labelled telemetry replay corpus (not fixture text).
- Per-technique ATT&CK coverage reported.
- False-positive rate on a labelled benign-telemetry corpus.
- Nightly regression report checked in as `tests/detection_efficacy/report_YYYYMMDD.json`.

**Effort:** **M** (assumes a labelled telemetry corpus exists; if not, add **L** to build one).
**Dependencies:** P0-A (real telemetry is nice-to-have to seed the corpus).

---

## P0-J · HA / Failover baseline

**Current maturity:** `ABSENT`. Single supervisor-managed backend + single-node Mongo per pod.

**V1 GA target:**
- Mongo replica set (3 members) with automatic failover proven under kill-primary test.
- Stateless backend scaled to ≥ 2 replicas behind ingress.
- Deploy manifest supports rolling upgrade with zero downtime (verified with a scripted redeploy).
- Backup + point-in-time restore drill documented.

**Effort:** **M**.
**Dependencies:** P0-F (Helm chart with StatefulSet).

---

## P0-K · Security Pen-Test Baseline

**Current maturity:** `NOT AUDITED`.

**V1 GA target:**
- OWASP Top-10 automated scan (ZAP baseline) on staging.
- Dependency vulnerability scan (Grype / Trivy) on the built container.
- Auth flow adversarial tests (token replay, IDOR, permission escalation).
- Sign-off report checked in as `docs/SECURITY_PENTEST_YYYYMMDD.md`.

**Effort:** **S** for the automated part; **M** if adding manual pen-test.
**Dependencies:** P0-D (multi-tenant boundary must be enforced before pen-test is meaningful).

---

## Rollup

| # | Blocker | Effort | Depends on |
|--:|---|---|---|
| P0-A | Real vendor telemetry connectors (×3) | L | Secrets Store ✓ |
| P0-B | Real response actions (×5) | M | P0-A |
| P0-C | SSO (OIDC minimum) | S | — |
| P0-D | Multi-tenant isolation (proved) | M | — |
| P0-E | Prometheus `/metrics` + JSON logging | S | — |
| P0-F | K8s / Helm (or docker-compose floor) | S–M | P0-E |
| P0-G | Retention / backup / restore | M | P0-D |
| P0-H | Route consistency + OpenAPI | S | — |
| P0-I | Detection efficacy measurement | M | P0-A (soft) |
| P0-J | HA / failover baseline | M | P0-F |
| P0-K | Security pen-test baseline | S–M | P0-D |

**Total ≈ 1 quarter** if the team parallelises: connectors + SSO + observability + K8s in one lane, tenancy + retention + pen-test in another, detection efficacy in a third.

**Sequencing recommendation for a single-team 3-sprint plan (my ranking · owner may reorder):**

- **Sprint 1** — P0-E (Prometheus + JSON logging) · P0-H (route consistency + OpenAPI) · P0-F (docker-compose floor) · P0-C (SSO via Emergent-managed Google Auth).
- **Sprint 2** — P0-D (multi-tenant isolation with tests) · P0-A start (Okta first, smallest OAuth surface).
- **Sprint 3** — P0-A finish (2 more vendors) · P0-B (5 response actions on the wired vendor) · P0-K (automated pen-test scan).
- **Sprint 4** — P0-G (retention + backup) · P0-J (HA on Helm) · P0-I (efficacy corpus + reporter).

After Sprint 4 the P0 list is empty. That is V1 GA.

---

## Not on this list (deliberately)

Items catalogued in the audit but **not** blockers:
- mal-20 behavioural-inference failure (deferred, single scenario).
- Additional Plane-A codecs (RC4/AES positive corpus).
- Bash Plane-B semantics.
- Advanced hunting DSL.
- Cross-tenant threat intel (MSSP mode).
- AI-assisted narration expansion.

Anything not on this list is not a V1 GA blocker.
