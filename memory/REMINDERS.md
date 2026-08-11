# NivXRay · REMINDERS

**Purpose**: durable ledger of everything partially executed / pending / skipped as of end of Session-9.
Read this whenever a session opens if you want the full backlog, not just the P0 directive.

**Last updated**: 2026-08-11 · Session-9 close
**Companion documents**: ADR-0007 (truth) · ADR-0008 (strategy) · ADR-0009 (routes) · ADR-0010 (blueprint) · ADR-0011 (TweetFeed) · PRD.md (directive at head)

---

## 🔴 IMMEDIATE NEXT (unblocked, waiting for a session to open on it)

- [x] **P0 · Security Hardening Gate** — 🟢 CLOSED 2026-08-11 · Session-10 · ADR-0010b PASS.
  - [x] Login/API auth rate-limit on `/api/auth/login` (sliding window · 5 fails / 5 min · 15 min lockout)
  - [x] Explicit CORS allow-list (wildcard mode forces credentials off)
  - [x] Zip / decompression-bomb guard on `/api/upload` (ratio ≤ 200:1)
  - [x] Archive recursion / depth / file-count / expanded-size limits (depth 3 · 512 entries · 50 MB total · 16 MB per-entry)
  - [x] Path-traversal blocked (`../`, absolute, backslash)
  - [x] Safe fail-loud for malformed archives (structured `archive_refused` response block)
  - [x] Regression + security tests locking each guard (22 new tests · full canonical suite: 136 pass / 5 skip / 0 fail)
  - [x] ADR-0010b evidence report at `/app/memory/adr/0010b-security-hardening-gate.md`
  - **Verdict**: 🟢 PASS · P1 readiness confirmed YES.

- [ ] **P1 · Server-Side File Mode** — NOW UNBLOCKED. Next session opens here.

---

## 🟡 PARTIALLY EXECUTED — deliberately incomplete

- [ ] **PDF determinism CI** — Markdown + STIX byte-locked; PDF intentionally `pytest.skip`ped.
  - Needs: reportlab metadata normaliser (strip creation timestamp / xref drift) + follow-up CI test.
  - Trigger: any session after P0 closes.
- [ ] **Route Classification second pass** — 87 UNKNOWN routes remain in ADR-0009.
  - Needs: (a) template-literal grep in FE (backticks + `${…}`), (b) backend-internal caller scan, (c) 7-day access-log window.
  - Output: ADR-0012 with the actionable sunset list.
- [ ] **TweetFeed integration** — evaluation done (ADR-0011), backlog until P0 + P1 close.
  - Bundle A (9th provider) + B (Threat-Hunting corpus) + C (campaign context) in one focused session.
  - Add `NIVX_FLAG_TI_TWEETFEED=disabled|shadow|enabled` per ADR-0008 §4.6 governance.
  - Watchlist semantics only (never drives verdicts alone).
- [ ] **Customer deck PDF handoff** — PPTX built; a print-to-PDF version for offline handoff not generated. Customer can do this themselves from PowerPoint. Not blocking.
- [ ] **Customer-deck branding** — placeholder colors; embed customer logo before external send.

---

## 🔴 PENDING — sequenced roadmap after P0

- [ ] **P1 · Server-Side File Mode** (ADR-0008 §5.2)
  - Backend file store (file_id · sha256 · size · mime · original_filename · uploaded_by · uploaded_at · provenance).
  - `services/input_router.py` between store and analyzers.
  - New `routers/files.py` (`POST/GET/DELETE /api/files`).
  - Frontend flow returns `file_id`; panels resolve on demand.
  - Removes 32 KB / 256 KB / 512 KB ceilings — file bytes never touch React state.
- [ ] **P2 · Sysmon / EVTX Adapter** (ADR-0008 §5.3)
  - Add `python-evtx` dep.
  - Adapter feeds canonical event bag.
  - Existing Timeline + Query panels consume without code changes.
- [ ] **P2b · Splunk `_raw` CSV recognizer** — extend `csv_edr_analyzer.py`.
- [ ] **P3 · Shadow-pipeline replay & promotion** (ADR-0008 §4)
  - IKG (Case Engine flag) — persistence writer live end-to-end; provenance parity; Timeline/AttackChain/AttackStory re-projectable to byte-identity.
  - Verdict Engine v3 — replay pack vs canonical projection; explainable-delta report; `soc_balanced` profile locked; ≥10 negative-explainability patterns; CI parity test.
  - Case Engine — 30-day dual-write; read cutover behind per-tenant flag (future).
  - Adapters — cannot promote until P1 exists.
  - Artifact Store — coupled with P1 (its persistence layer).
- [ ] **P4 · Broader EDR/XDR + TweetFeed A+B+C**
  - CrowdStrike · Defender · SentinelOne · Cisco XDR · Cisco AMP · Splunk · Sentinel · QRadar · Elastic connectors.
  - TweetFeed integration as scoped in ADR-0011.
  - VirusTotal integration on IOC panel (currently DISCONNECTED).
  - Attack Story panel wire-up on Workspace (backend done; UI absent).
  - OSINT reputation panel wire-up (VT + AbuseIPDB).
- [ ] **P5 · Enterprise readiness**
  - Multi-tenant model (schema + `tenant_id` + middleware).
  - SSO / SAML / OIDC.
  - Audit trail surfacing (`v2_audit_log`).
  - Air-gapped installer + offline LLM path.
  - Docker Compose / Helm chart / packaged distributable.

---

## ⚪ SKIPPED — with rationale

### Skipped in service of P0 lock
- [ ] Starting Security Hardening in Session-9 (owner kept it read-only)
- [ ] Starting Server-Side File Mode (owner: not in same change set as P0)
- [ ] Deleting DEPRECATED/DUPLICATE routes (needs owner sign-off + 60-day sunset)
- [ ] Adding `NIVX_FLAG_TI_TWEETFEED` (governance requires ADR entry)

### Not-near-term features
- [ ] Multi-tenant / SSO / SAML / Google OAuth
- [ ] EDR adapters (CrowdStrike, Defender, SentinelOne, Cisco XDR/AMP)
- [ ] SIEM connectors (Splunk, Sentinel, QRadar, Elastic)
- [ ] STIX/TAXII **pull** ingestion (after determinism CI proves end-to-end)
- [ ] VirusTotal integration
- [ ] Cross-case / fleet hunt (needs corpus)
- [ ] Saved-query UI (needs `saved_queries` collection)
- [ ] Sandbox / subprocess isolation for hostile-input parsers (its own session; ADR-0010b will document residual risk)

### Audit-marked UNKNOWNs (finish next docs pass)
- [ ] XSS `dangerouslySetInnerHTML` frontend audit (ADR-0007 §12.15)
- [ ] Mongo TTL / retention index verification (§13)
- [ ] Backup arrangement inventory (§13)
- [ ] `.github/workflows/` CI inventory (§34)
- [ ] `docs/WHITEPAPER.md` + `docs/SECURITY.md` drift audit (§22)
- [ ] Nivxforge placeholder-page relabelling (§22)
- [ ] `ARCHITECTURE_v2.md` reconciliation to shadow-status (§22 major drift)
- [ ] `requirements.txt` vs live `pip freeze` audit (§11.6)
- [ ] 87 UNKNOWN routes second-pass (ADR-0009 §7)

### Cleanup / hygiene
- [ ] Prune 5 unused heavy Python deps: `googleapiclient` · `google-genai` · `stripe` · `boto3` · `botocore`
- [ ] Dedup/delete 4 legacy root-level Python siblings: `chain_analyzer.py` · `command_analyzer.py` · `commandline_miner.py` · `investigation_report.py`
- [ ] `WorkspacePage.jsx` refactor (4,306 → panels; use PanelErrorBoundary per panel)
- [ ] Structured logging (JSON) + log rotation
- [ ] Prometheus / OTEL / tracing wiring
- [ ] `_nightly_benchmark_loop` → k8s CronJob (currently asyncio-sleep-24h)
- [ ] Prod-shape uvicorn (`--workers N --no-reload`) for production deploys
- [ ] Frontend e2e Playwright suite (Playwright dep present, no active `frontend/tests/`)

### Explicitly protected — never touch without a matching regression test
- [ ] RC5/DIE service code (`services/die/*` + `canonical/*`)
- [ ] Workspace behavior (`test_workspace_isolation_guard.py`)
- [ ] Shadow-flag state (no promotion outside ADR-0008 §4 criteria)
- [ ] `/api/*` route add/delete/rename (needs ADR-0009 §7 second pass first)
- [ ] Mongo schema (no unilateral changes)
- [ ] `.env` / feature flags (governance via ADR-0008 §4.6)

---

## 🟢 SESSION-9 NET RESULT (locked baseline)

- 5 planning/documentation artifacts produced: ADR-0007-ext · ADR-0008 · ADR-0009 · ADR-0010 · ADR-0011 + HTML index + PPTX deck
- 1 CI gate shipped: `test_report_determinism.py` (6 pass, 1 documented skip)
- 0 shipping code paths changed
- 0 Mongo schema changes
- 0 routes added / deprecated / deleted / admin-gated
- 0 flags added / promoted
- Canonical API suite: 114 pass · 5 skipped
- **Nothing is blocked. Every deferral is intentional and sequenced.**

---

## 📌 How to open the next session cleanly

The first line of the next session should be:

> **"Start P0 Security Hardening Gate."**

That is the only next-move authorised by this REMINDERS file. Anything else must first appear here as a checked-off or newly-added item, with a rationale.

*End of REMINDERS.md.*
