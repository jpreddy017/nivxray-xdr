# NivXRay · REMINDERS

**Purpose**: durable ledger of everything partially executed / pending / skipped as of end of Session-9.
Read this whenever a session opens if you want the full backlog, not just the P0 directive.

**Last updated**: 2026-08-12 · Session-19 close (standing-down after final 12-case regression GREEN)
**Companion documents**: ADR-0007 (truth) · ADR-0008 (strategy) · ADR-0009 (routes) · ADR-0010 (blueprint) · ADR-0011 (TweetFeed) · ADR-0023 (P2 direction + four principles) · ADR-0010l (Item 5) · ADR-0010m (UI-DEF-02 design directive) · ADR-0010n (final regression gate GREEN) · PRD.md (directive at head)

---

## 🛑 STANDING EXECUTION INSTRUCTION (owner-locked 2026-08-12)

**We are currently standing down. Do NOT make any code, UI, architecture, workflow, or memory changes unless an explicit "Start Item N" instruction is provided.**

### Current verified state
```
Item 1  Risk calibration        ✅ PASS
Item 2  Deterministic narrative ✅ PASS
Item 3  Recursive decode        ✅ PASS
UI-DEF-01                       ✅ PASS
Item 4  T1562.004 DIE signature ✅ PASS
Item 5  TI latency bound        ✅ PASS  (ADR-0010l, 2026-08-12)
12-case FINAL regression        ✅ GREEN (ADR-0010n, 2026-08-12)
UI-DEF-02  MITRE convergence    🛑 STOP-AND-REPORT (ADR-0010o, 2026-08-12)
                                    Convergence works but the DIE catalogue
                                    is missing 7 LOLBIN → technique
                                    mappings; 3/12 corpus cases dropped
                                    Malicious → Suspicious. Owner must
                                    choose Option A / B / C before proceeding.

P2 Behavioral Evidence          🔒
```

### Locked execution order (do not break this sequence)
```
[Item 4 ✅] → [Item 5 ✅] → [12-case regression ✅] → [UI-DEF-02 🛑 STOP] → P2
```

### Four architectural principles — non-negotiable (ADR-0023 §3a-§3e)
1. **Cruise-Missile Guidance** — pursue the evidence chain, never stop at the first indicator
2. **UI-Truth** — a UI must never display a stronger claim than the evidence supports
3. **MITRE Convergence** — one authoritative MITRE technique surface (do not maintain competing interpretations)
4. **Evidence-Producer Constraint** — P2 telemetry produces evidence, never interprets it
5. **No Opportunistic Improvement** — every change must fall under an explicit owner-authorised work item

### Preview vs Prod note
The recent diagnostic (ADR-0010j) established that the underlying DIE output is identical between environments: `techniques → T1562.001 + T1564.003`, `preprocessor.stages → 1`. The visible top-panel divergence is projection/build layer, not analytical. **Do NOT modify UI-DEF-02 early just to make Preview visually match Prod.** Prod redeployment is a separate deployment decision — if authorised, deploy the already-validated Preview build only, no new behaviour, no procedure change.

### What the next agent MUST do
**Nothing.** Wait for the owner's explicit "Start UI-DEF-02" instruction. When it arrives:
- Implement the design directive locked at ADR-0010m (14 tactic lanes structurally present; populated only where evidence-backed; NO "No Evidence" clutter; 6-lane Evidence Trajectory kept separate; one authoritative MITRE surface feeds both views).
- Preserve the frozen 12-case corpus (do NOT rerun the gate — it is GREEN as of ADR-0010n).
- Stop again for authorisation before P2.

**Do NOT** re-run the 12-case regression · open P2 · modify the working investigation procedure · introduce new features because they appear useful · "improve" anything opportunistically.

**UI-DEF-02 design is locked**: `/app/memory/adr/0010m-ui-def-02-attack-chain-design-note.md`. Do NOT invent a new design or re-negotiate the empty-lane visual language.

---

## 🔴 IMMEDIATE NEXT (unblocked, waiting for a session to open on it)

- [x] **P0 · Security Hardening Gate** — 🟢 CLOSED 2026-08-11 · Session-10 · ADR-0010b PASS.
  - [x] Login/API auth rate-limit (5 fails / 5 min · 15 min lockout · N×401 then 429 semantic locked)
  - [x] Explicit CORS allow-list (wildcard mode forces credentials off)
  - [x] Zip / decompression-bomb guard (ratio ≤ 200:1)
  - [x] Archive recursion / depth / file-count / expanded-size limits (depth 3 · 512 entries · 50 MB total · 16 MB per-entry)
  - [x] Path-traversal blocked (`../`, absolute, backslash)
  - [x] Safe fail-loud for malformed archives (structured `archive_refused`)
  - [x] Regression + security tests (22 new · full canonical suite green)
  - [x] ADR-0010b evidence report
  - **Verdict**: 🟢 PASS · P1 readiness confirmed YES.

- [x] **P1 · Server-Side File Mode** — 🟢 CLOSED 2026-08-11 · Session-11 · ADR-0010c PASS.
  - [x] Streaming SHA-256 ingest (1 MB chunks · RSS delta -52 KB on 50 MB upload)
  - [x] Race-safe dedup (unique index on `(tenant_id, sha256)` · concurrent-uploads test passes)
  - [x] Controlled retention (application-driven sweep · pin protects · 30-day TTL default)
  - [x] Tenant-ready identity (`tenant_id` in every row; dedup scoped per tenant)
  - [x] Server-side upload cap (200 MB · `NIVX_FILES_MAX_UPLOAD_BYTES`)
  - [x] Input Router (content-magic-first routing to LIVE analyzers only · unsupported → deterministic)
  - [x] 7 new endpoints under `/api/files/*` (all auth-gated, no path leaks)
  - [x] 19 new tests · full canonical suite: 156 pass / 5 skip / 0 fail
  - [x] ADR-0010c evidence report
  - **Verdict**: 🟢 PASS · P2 readiness confirmed YES.

- [ ] **P2 · Behavioral Evidence Ingestion** — 📌 REFRAMED per ADR-0023 (2026-08-12).
  **NOT** "add a Sysmon parser". P2 = telemetry adapter producing canonical behavioral evidence (process creation + parent-child relationships) that feeds the *existing* Evidence/IKG → Correlation → ATT&CK/Verdict → Attack Story → Report pipeline. Parent-child is **evidence, not truth**; PPID spoofing is a first-class limitation.
  **BLOCKED** until all five ADR-0010e §10 remediations pass regression against the frozen 12-case corpus (`/app/memory/experiments/rip/`).
  Full locked decision: `/app/memory/adr/0023-p2-behavioral-evidence-ingestion.md`.

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
- [ ] **P2 · Behavioral Evidence Ingestion** (ADR-0023 · reframed 2026-08-12; supersedes ADR-0008 §5.3 scope)
  - **First telemetry adapter**: Sysmon / EVTX / Windows Security event streams (`python-evtx` for EVTX parsing).
  - Emits **canonical behavioral evidence records** into the graph (not standalone verdicts).
  - Event schema deferred to source-of-truth references: `Windows_LOLBAs_360_Training-1(2).pdf` (Sysmon Event 1/3/7/8/10/11/12-13/15/17-18/19-21/22/25) + `Windows Security Log Encyclopedia_new.pdf` (4624/4625/4648/4672/4688/4697/4720/4732/4756/4768/4769/4776/5140/5145/1102).
  - PPID spoofing (T1134.004) inherited as explicit first-class constraint — kernel-callback ETW + session/integrity checks required to reason on ancestry.
  - Do **NOT** create a parallel Process Tree engine or separate product.
  - **Precondition gate** (all five must pass regression against the frozen 12-case corpus): risk-score recalibration · deterministic narrative · recursive decode · T1562.004 signature · bounded TI latency.
- [ ] **UI-DEF-02 · MITRE Mapper Convergence** (owner sequence-locked 2026-08-12 · ADR-0023 §3c)
  - Root cause: `/api/analyze::mitre_map` (regex) and `services.die.api.analyze::techniques` (analyzer-catalogue) emit different technique sets for the same input (verified on pb-01 · rip-08). Two competing MITRE truths per input.
  - Target end-state: one authoritative technique surface consumed identically by Verdict, Narrative, Attack Story, Report.
  - **DO NOT start UI-DEF-02 out of order.** Sequence: Item 4 → Item 5 → 12-case regression → THEN UI-DEF-02.
  - Provenance chips (which mapper produced which technique) may be added as a diagnostic *during* convergence, but must NOT be treated as the permanent solution.
- [ ] **UI-Truth Principle enforcement** (ADR-0023 §3b, locked 2026-08-12)
  - Standing rule: a UI must never display a stronger claim than the underlying evidence supports.
  - Applies to: verdict pills · confidence bars · attack-chain colouring · lane / tactic labeling · narrative wording.
  - When evidence is missing / insufficient / ambiguous, the UI MUST admit uncertainty visibly (neutral colour, "Unclassified" label, "additional evidence required" language).
  - Enforceable at design-review + regression against the frozen 12-case corpus + Phase-B pb-01.
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
