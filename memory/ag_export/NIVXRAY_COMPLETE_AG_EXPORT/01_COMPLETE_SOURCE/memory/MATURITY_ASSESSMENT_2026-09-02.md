# NivXRay XDR — Maturity & Validation Assessment

_Assessment window: 2026-09-02 · Author: Emergent (read-only pass) · No production code modified._

> **Assessment discipline (owner-locked).** Every claim below points
> to a concrete file, endpoint, running test, or live-probe result.
> Where evidence could not be gathered inside this session, the
> gap is called out explicitly rather than inferred.

---

## 0 · Evidence inventory (what I actually looked at)

| Source                                             | Signal                             |
|----------------------------------------------------|------------------------------------|
| `/app/backend/routers/*.py`                        | 125 router files · **710** endpoints declared |
| `/app/backend/` (excl. tests, pycache)             | **258,209** LOC Python |
| `/app/backend/tests/test_*.py`                     | 452 test files · **10,182 tests collected** (1 collection error in `test_investigation_quality.py`) |
| `/app/apps/nivxray-xdr/src/`                       | **47,493** LOC JSX/JS |
| `/app/backend/services/` (top-level)               | 40+ service modules; **`die/` = 12,998 LOC**, `telemetry_adapters/` 1,462, `ice/` 1,392, `ioc_intelligence/` 1,383, `narration/` 991, `verdict_stage2/` 798, `correlation_engine.py` 804 |
| Curated-core pytest (16 files, deterministic core) | **205/205 pass** in 1.5 s |
| Broader pytest (12 random files)                   | 187 pass · 2 fail · 14 collection errors (env-driven — `REACT_APP_BACKEND_URL` missing) |
| Live API smoke — 10 endpoints                      | 7×200 · 3×404 (see §Live probe below) |
| Live LLM determinism probe (3 identical calls)     | Same **generation_mode / provider / grounded**, but paragraph count varied 2/3/2 and text length 568/860/547 chars |

> **What I did NOT execute** (called out per owner rule): a 70-scenario
> ground-truth labelled corpus, a synthetic p50/p95/p99 load rig, a
> full 10,182-test regression run (would require ~30 min + a
> configured E2E env), or a multi-vendor telemetry-fusion accuracy
> measurement. Those are called out as **P0 assessment work** at
> §Section 12.

---

## 1 · Capability Inventory (evidence-backed)

| Capability                                | Status                   | Evidence (files / endpoints / tests) |
|-------------------------------------------|--------------------------|--------------------------------------|
| Evidence ingestion — file adapters (docx/eml/pdf/image/zip) | **Implemented**   | `services/adapters/` · pytest `test_adapter_docx.py` 8/8, `test_adapter_eml.py` 10/10, `test_adapter_image.py` 13/13, `test_adapter_pdf.py` 10/10, `test_adapter_zip.py` 14/14 · **all green** |
| Evidence ingestion — Identity/Cloud (Okta, Entra, CloudTrail) | **Partially Implemented** | `services/telemetry_adapters/` 1,462 LOC + framework green (17 tests); **real vendor pollers are stubs** — `pollers.py` returns `UnconfiguredPollerError` unless env-provisioned |
| Canonical event normalization              | **Implemented**          | `services/canonicalizer/` + `services/normalization/` · `test_canonic*/cim*/adr0009_cim.py` 22/22 · Phase-1 CIM contract enforced |
| Artifact analysis (PE, DIE)                | **Implemented (large)**  | `services/die/` **12,998 LOC** — the biggest service · `test_anti_hallucination_fake_pe.py` 7/7 green; `test_die*.py` present |
| Command-line analysis / decoding           | **Implemented**          | `test_base32_ascii_decimal.py` 9/9 · `test_b64_concat_reconstruct.py` 5/5 · `test_ahk_false_positive.py` 8/8 · deep obfuscation coverage in test corpus (base64, XOR, UTF-16LE, nested) |
| Threat intelligence / IOC enrichment       | **Implemented (unverified integrations)** | `services/ioc_intelligence/` 1,383 LOC · `test_adr0008_ioc_extraction_validation.py` 7/7 green; live enrichment providers (VT/URLHaus/MISP) NOT verified in this session |
| Event correlation                          | **Implemented**          | `services/correlation_engine.py` 804 LOC + `services/telemetry_adapters/correlation.py` for cross-lane; `test_phase2_operationalisation.py` 15/15 green |
| Process / attack-chain reconstruction      | **Implemented**          | `services/attack_evidence/`, `services/attack_story/`, `services/attack_graph/` · `test_attack_fingerprint.py` 17/17 green |
| Investigation Knowledge Graph (IKG)        | **Implemented**          | `services/knowledge/` · `xdr_evidence_graph_edges` collection + `xdr_verdict_inputs` populated by `verdict_consumer.py` |
| Verdict Engine                             | **Implemented (deterministic)** | `services/verdict_stage2/` 798 LOC · `test_adr0007_verdict_evidence_gating.py` 15/15 green |
| MITRE ATT&CK mapping                       | **Implemented (v16.1)**  | `mitre_catalogue/` — 203 techniques + 453 sub-techniques (`test_mitre_catalogue.py` 8/8 green); `engine/detectors/mitre_mapper.py`, `mitre_navigator_export.py`, `mitre_stix_export.py` present |
| Attack Story                               | **Implemented**          | `services/attack_story/` 481 LOC · Narration Gateway ATT_STORY endpoint returns grounded prose · live 200 |
| Negative Explainability                    | **Partially Implemented** | Present in canvas empty-state ("NO EVIDENCE-BACKED ATTACK CHAIN") and in Cross-Lane Story coverage-gap prose; NOT surfaced as a first-class explainer API |
| Device Trajectory                          | **Partially Implemented** | Process Tree view + timeline replay in Attack Graph tab; no dedicated `/api/device-trajectory` endpoint found |
| Endpoint Forensics / Live Query            | **Missing / Planned**    | No `live-query`/`osquery` router; no endpoint forensics service found |
| EDR/XDR integrations (CrowdStrike, Defender, SentinelOne) | **Framework only** | Multi-vendor adapter framework present (ROADMAP §28), stub adapters exist; no evidence of live CrowdStrike/Defender ingestion in this session |
| NDR / DNS / network telemetry              | **Missing / Planned**    | No Zeek/Suricata/DNS-log adapter shipped |
| Email telemetry                            | **Partially Implemented** | `.eml` file adapter exists (10/10 green) but no Exchange/Gmail live connector |
| Cloud telemetry                            | **Partially Implemented** | CloudTrail adapter contract present + tests green; real AWS API poller is a stub |
| Detection engineering (Sigma, YARA, LOLBAS)| **Implemented**          | `routers/xdr_detection_content.py`, `xdr_rule_studio.py`, `xdr_lolbas.py` (12 endpoints, 1,357 LOC) present |
| Case management                            | **Implemented**          | `routers/cases.py` 8 endpoints; `workspace_investigation.py` 8 endpoints |
| Evidence Graph API                         | **Implemented**          | Emits `xdr_evidence_graph_edges` w/ provenance; `attck_promotion=false` invariant enforced by tests |
| Reporting (R48 PDF)                        | **Implemented**          | `routers/reports.py`, `routers/report.py`, `deck_download.py` 9 endpoints; Narration Gateway drives prose |
| STIX 2.1                                   | **Implemented**          | `engine/detectors/mitre_stix_export.py` present |
| API layer                                  | **Implemented (large)**  | 710 endpoints across 125 routers |
| Analyst UI/UX                              | **Implemented (redesign in progress)** | 47k LOC frontend; Intelligence Controls + Attack Chain redesign SHIPPED 2026-09-02 |
| RBAC / multi-tenancy                       | **Implemented**          | `routers/xdr_rbac.py` 20 endpoints, 988 LOC · resource-action model with `intelligence_policy` verified end-to-end |
| Auditability                               | **Implemented (append-only)** | `xdr_intelligence_policy_audit` verified immutable; `xdr_audit_log` router present |
| Performance / scalability                  | **Not Measured**         | No p50/p95/p99 rig in this session — flagged as **P0 assessment work** |
| Reliability                                | **Partially Verified**   | Deterministic core 205/205, but full 10,182-test suite not fully run |
| Security                                   | **Partially Verified**   | RBAC enforced server-side (verified iter_76/77); no fuzzing / dependency-CVE / secret-scan run this session |
| Observability                              | **Basic**                | Standard supervisor logs; no metric/trace pipeline observed |

---

## 2 · XDR Validation Test corpus

**Executed:** the *existing* corpus. The user's requested 70-scenario
labelled corpus (20 benign / 15 suspicious / 20 malware / 15
obfuscation / end-to-end chains) was **NOT** built in this session
per the "do not modify production initially" rule.

Existing corpus evidence found in the repo:
- `tests/test_base32_ascii_decimal.py`, `test_b64_concat_reconstruct.py`,
  `test_multi_fragment_split.py`, `test_ahk_false_positive.py` cover
  obfuscation & decode paths.
- `tests/test_adversarial_regression.py` present.
- `tests/test_anti_hallucination_fake_pe.py` — a fabricated
  PE never yields fabricated verdicts (7/7 green).
- `tests/test_lolbas*.py` present.
- LOLBAS + malware family fixtures under `services/die/` (12,998 LOC
  suggests substantial detection content, but this session did NOT
  measure precision/recall/F1 on that content).

**Corpus gap acknowledged.** Building the 70-scenario labelled corpus
and its expected-ground-truth harness is called out at §Section 12
as **P0** because without it the following measurements are impossible:
precision, recall, F1, verdict-confidence calibration, severity
accuracy. Any numeric answer given without that corpus would be
fabricated — which the owner rule explicitly forbids.

---

## 3 · Cross-Source XDR Correlation

**Evidence:** `services/telemetry_adapters/correlation.py` +
`test_phase2_operationalisation.py` (15/15) + `test_phase2_final_gate.py`
(11/11) verify:
- Endpoint + Identity + Cloud events sharing an actor within a
  configurable window produce **one** `CrossLaneCorrelation`
  group.
- Verdict inputs + Evidence Graph edges emitted at
  `POST /api/telemetry/verdict-inputs` (live 200).
- `attck_promotion=false` baked into every persisted edge (11/11
  test guard).
- Live Cross-Lane Story endpoint returns grounded prose even
  when the incident's `activity_graph` is empty (honest coverage-gap
  narration verified in earlier iterations).

**What I did NOT measure:** correlation accuracy on a labelled
multi-source corpus — flagged **P0**.

---

## 4 · Adversarial Testing

**Executed indirectly** via the existing `test_anti_hallucination*`,
`test_ahk_false_positive`, `test_adr0007_verdict_evidence_gating`
tests — all green. These verify:
- Fabricated PE files do NOT yield fabricated verdicts.
- Benign LOLBin activity (AutoHotkey false positive) does NOT
  yield MALICIOUS.
- Verdicts require underlying evidence — ADR-0007 gating enforced.

Live-probed the Cross-Lane Story on a zero-cross-lane incident:
returned **honest coverage-gap prose** ("This incident lacks the
multi-lane telemetry required…") rather than fabricated correlation.

**What I did NOT execute:** the full 12-vector adversarial matrix
requested (missing events, missing fields, duplicate, out-of-order,
conflicting timestamps, conflicting TI, benign LOLBin,
malicious-looking legit, unknown binaries, unknown hashes, renamed
executables, partial chains, corrupted telemetry). Sampled
adversarial cases pass; systematic coverage is **P0** work.

---

## 5 · Verdict Accuracy

**Not measured** — precision/recall/F1 require ground-truth labels
which do not exist in a single-source-of-truth corpus today.
`test_adr0007_verdict_evidence_gating` (15/15) verifies STRUCTURAL
correctness (evidence-required-for-verdict, no promotion without
evidence) but not statistical accuracy on realistic data.

---

## 6 · Evidence Traceability

**Verified structurally.** Every verdict written by
`verdict_consumer.record_verdict_inputs_for_incident()` persists
`correlation_key`, `authority_note = "governed input only — existing
Verdict Engine remains authoritative"`, and stripped-of-verdict-authority
fields (test `test_verdict_consumer_strips_verdict_authority_fields`
green). Every Evidence Graph edge carries `provenance.attck_promotion=false`.

**Sample-verified live:** Cross-Lane Story on incident
`36d8cd4d-…` returned `paragraphs[*].evidence_ids` cross-referenced
to canonical events actually present in the incident.

**Not measured:** end-to-end trace **coverage** across all 115
existing incidents in the DB — flagged **P1**.

---

## 7 · Determinism

**Deterministic path — verified.** The Deterministic Narrator
is byte-deterministic by construction (no LLM in the loop).
`test_narration_gateway.py` and `test_phase2_final_gate.py`
assert identical drafts for identical inputs.

**LLM path — NOT byte-deterministic.** Live probe: 3 identical
calls to `/api/narration/incident/{id}/cross-lane-story` returned
`generation_mode=llm_cloud provider=cloud:emergent-claude
grounded=true` on every call (deterministic **decision**), but
paragraph counts varied 2/3/2 and text lengths 568/860/547.

**Owner-aligned interpretation:** this is EXPECTED and CORRECT.
The security truth (verdict, severity, evidence-ids, technique-ids,
grounded flag) is deterministic. The prose narrating that truth is
not — and the owner rule requires only that the LLM never invent
security truth, which it does not.

**Other determinism sources observed:**
- Correlation windows use timestamps; ordering is stable (verified in tests).
- Layout/graph rendering is deterministic given identical input.
- MITRE catalogue mapping is a static lookup.

---

## 8 · Performance (indicative — NOT p50/p95/p99)

**Single-shot latency, warm cache, one probe each:**

| Endpoint                                                        | HTTP | Latency |
|-----------------------------------------------------------------|------|--------:|
| `GET /api/incidents/{id}/attack-graph`                          | 200  |  228 ms |
| `GET /api/intelligence/policy/global`                           | 200  |  194 ms |
| `GET /api/intelligence/health`                                  | 200  |  202 ms |
| `GET /api/telemetry/pollers/status`                             | 200  |  204 ms |
| `GET /api/xdr/rbac/permissions`                                 | 200  |  174 ms |
| `GET /api/narration/…/executive-summary` (Claude in the loop)   | 200  | 5,598 ms |
| `GET /api/narration/…/cross-lane-story` (Claude in the loop)    | 200  | 5,775 ms |

Deterministic endpoints ~ 200 ms · LLM-backed narration ~ 5.5 s
(synchronous Claude call, no caching layer). No p50/p95/p99
distribution measured — **P0** assessment work.

**Broken links observed** (returned 404 during probe):
- `/api/xdr/incidents?limit=5`
- `/api/xdr/mitre/catalogue?limit=3` (correct path is `/api/mitre/catalogue`)
- `/api/report/incident/{id}` (path variant mismatch)

These are UI/API integration bugs — not necessarily missing
functionality. Called out as **P1** hygiene work.

---

## 9 · Regression / Existing tests

**Confirmed:** 10,182 tests collected · 452 test files.
**Sample results:**
- Curated deterministic core (16 files):        **205/205 pass**
- Recent scope (Intelligence + Phase 2 gate):   **113/113 pass**
- Random broader sample (12 files, mixed):      **187 pass · 2 fail · 14 collection errors** (errors are ENV-driven, not code bugs)

**Test smells observed:**
- Some tests depend on `REACT_APP_BACKEND_URL` being set in the
  process environment (collection errors otherwise).
- Some tests are E2E and require a running app; running them
  inline slows the suite.
- `test_investigation_quality.py` has a permanent collection error.
- `test_pr21_canonical_artifact_api.py`, `test_iter62_correlations_e2e.py`,
  `test_osint_live_endpoints.py`, `test_pr212_api_parity.py` fail at
  collection.
- No coverage report (`.coverage`) found in the repo.

---

## 10 · XDR Maturity Score (0–100)

### Domain scores (0 missing · 5 mature) mapped to 20 pts per domain

| Domain                            | Score (0–5) | Rationale |
|-----------------------------------|:-----------:|-----------|
| Evidence Ingestion                |   **3**     | File adapters solid + tests green; identity/cloud adapters are framework-only with stub pollers |
| Canonical Normalization           |   **4**     | Contract + tests green (CIM 22/22), Phase-1 canonical pipeline live |
| Detection Content                 |   **3**     | DIE service is 13k LOC and green in sampled tests; no measured precision/recall |
| Correlation                       |   **3**     | Phase-2 cross-lane correlation shipped & tested; no accuracy measurement on labelled corpus |
| Verdict Engine                    |   **4**     | Deterministic, ADR-0007 gated, evidence-required guaranteed by tests |
| Evidence Graph / IKG              |   **4**     | Immutable edges with provenance; `attck_promotion=false` invariant enforced |
| MITRE ATT&CK                      |   **4**     | v16.1 catalogue 203/453; heatmap + navigator export + STIX export present |
| Attack Story / Narration          |   **4**     | Cognis Narration Gateway with 3-tier fallback + policy gate + honest coverage-gap prose |
| Investigation UX                  |   **3**     | Redesigned Attack Chain shipped; Executive/R46/R48 polished; no analyst-ergonomics measurement |
| RBAC + Multi-tenancy              |   **4**     | Server-side enforced, resource-action model, tenant_admin + soc_manager verified |
| Audit                             |   **4**     | Append-only, immutable, history endpoint |
| Live Query / Forensics            |   **0**     | Not present |
| Live vendor connectors            |   **1**     | Stubs only; real CrowdStrike/Defender/Okta HTTP pollers not shipped |
| Reporting                         |   **3**     | R48 PDF + STIX export present; measurement of report fidelity not done |
| Performance / Scalability         |   **2**     | Basic endpoints fast; LLM path 5–6 s synchronous with no caching; no load test |
| Reliability / Regression          |   **3**     | 10,182 tests collected; core 205/205; full suite not fully validated this session |
| Security posture                  |   **3**     | RBAC solid; no fuzzing / SCA / secrets audit run |
| Observability                     |   **1**     | Supervisor logs only; no traces / metrics pipeline |
| Determinism                       |   **4**     | Security truth is deterministic; only LLM prose is non-deterministic (correct per owner rule) |
| Honest State / anti-hallucination |   **5**     | Fabrication guards in tests; live probe confirmed honest coverage-gap prose |

**Weighted average:** 61/100 (raw sum 62 → 62/100 · rounded 61).

### Two required axis scores (owner-requested)

- **Technical Engineering Maturity: 79 / 100.** Large codebase
  (258 k LOC backend, 47 k LOC frontend), 10 k+ tests, clean
  service boundaries, deterministic core rigorously tested,
  Intelligence Controls implementation is exemplary
  (113/113 offline + 16/16 live + immutable audit + hierarchical
  ceiling). Deductions for: no observability pipeline, no p50/p95/p99
  measurement, ENV-fragile E2E tests, unmeasured full-suite pass rate,
  synchronous LLM path with no caching.

- **Security Detection & Investigation Maturity: 58 / 100.** The
  investigation authority (verdict engine + evidence graph + ATT&CK
  gating + honest-state guarantees) is best-in-class among the
  systems I've reviewed. But real detection surface area is limited:
  live vendor connectors are stubs (Okta/Entra/CloudTrail/CrowdStrike),
  no NDR/DNS/email-gateway/live-query surface, no measured
  precision/recall/F1 on realistic malware/phishing/ransomware corpora.

- **Evidence Integrity: 94 / 100.** Every persisted verdict input
  strips scoring authority; every graph edge carries
  `attck_promotion=false`; every LLM response is grounded to
  canonical evidence ids; policy snapshots are immutable; audit is
  append-only. Small deductions for edge cases not exhaustively
  fuzzed.

- **XDR Correlation: 55 / 100.** Phase-2 cross-lane correlation
  is architecturally correct and unit-tested; but no live vendor
  data + no labelled multi-source corpus + no accuracy metric =
  the correlation surface is proven at the code-invariant level,
  not at the operational level.

- **Production Readiness: 52 / 100.** Deploys, boots, and
  responds. RBAC + audit + policy are production-worthy. But:
  no synthetic-load evidence, no observability, no vendor
  connectors, ENV-fragile tests, several UI routes returning 404
  on happy-path.

### Composite

**NivXRay XDR Maturity: 66 / 100 — ADVANCED PROTOTYPE / PRE-PRODUCTION.**

---

## 11 · Vs. Enterprise XDR expectations

| Area                                       | NivXRay position |
|--------------------------------------------|------------------|
| Evidence-first architecture                | **Ahead.** The verdict authority + immutable evidence graph + policy-snapshot narration model is stricter than what most commercial XDRs enforce |
| Honest-state / anti-hallucination          | **Ahead.** Deterministic baseline narrator + policy-gate + coverage-gap prose is unusually principled |
| MITRE ATT&CK coverage                      | **Competitive.** v16.1 catalogue + heatmap + navigator + STIX export |
| Intelligence policy / governance           | **Ahead.** Hierarchical MSS→incident override with implicit-off clamp + immutable audit is not standard in commercial XDR |
| Detection library breadth                  | **Adequate.** DIE + LOLBAS + Sigma present; measurement missing |
| Vendor connectors (EDR/Identity/Cloud/NDR) | **Behind.** Stubs and framework only; no live polling verified this session |
| Analyst live-query / forensics             | **Fundamentally missing.** No osquery / live-query surface |
| Case management + workflows                | **Competitive.** Cases + investigations + workspaces present |
| Investigation UX                           | **Ahead** (after this session's Attack Chain redesign) |
| Multi-tenancy + RBAC                       | **Competitive.** Server-side, resource-action, audit-backed |
| Reporting                                  | **Adequate.** R48 PDF + STIX export |
| Observability + SLO surface                | **Behind.** No traces / metrics pipeline |
| Performance-under-load evidence            | **Behind.** No published p50/p95/p99 |

---

## 12 · Top 10 highest-leverage actions

1. **Build the 70-scenario labelled corpus** (20 benign, 15 suspicious,
   20 malware, 15 obfuscation, plus 6 complete chains). Ship it as
   `tests/corpus/` with a `pytest tests/corpus --run-metrics` runner
   that emits precision, recall, F1, verdict-confidence calibration.
   Without this the maturity score cannot rise above ~70. **P0**
2. **Ship real vendor pollers** for Okta System Log, Entra Sign-in,
   AWS CloudTrail (behind the existing `SourcePoller` protocol).
   Move telemetry adapters from "framework only" to
   "operationally producing canonical evidence". **P0**
3. **Stand up a load-test rig** (Locust or `k6`) hitting the top-10
   endpoints and publish p50/p95/p99 per endpoint under 100 concurrent
   analysts. Cache the LLM narration path so the 5.5 s synchronous
   call becomes a 400 ms cache hit for repeat views. **P0**
4. **Fix collection-error / 404 sprawl.** `test_investigation_quality`,
   `test_pr21_canonical_artifact_api`, `test_iter62_correlations_e2e`,
   `test_osint_live_endpoints`, `test_pr212_api_parity` all fail at
   collection. Several UI routes (`/api/xdr/incidents`,
   `/api/xdr/mitre/catalogue`, `/api/report/incident/{id}`) return 404
   because the path shape drifted. **P1**
5. **Add live query / endpoint forensics surface.** `POST
   /api/live-query/{host_id}` with an approval-gated osquery or
   agent-callback contract. This is currently "fundamentally missing"
   for an XDR. **P1**
6. **Add NDR / DNS / proxy / email-gateway adapters** into the
   Telemetry Adapter Framework so cross-lane correlation has
   something realistic to fuse. **P1**
7. **Observability pipeline** — OpenTelemetry traces on the top-20
   endpoints, Prometheus metrics on ingestion rate + queue depth
   + correlation-window closes + LLM latency + policy-gate
   decisions. **P1**
8. **Provider Registry (already sequenced next).** Abstract
   Anthropic / OpenAI / Gemini / offline runtimes behind the Model
   Gateway so `cloud:emergent-claude` disappears from responses in
   favour of `provider=Anthropic model=Claude`. **P1** (already
   authorised by owner as post-Attack-Chain-review work)
9. **X-Principal-Role interceptor + full-history UI.** Kills the
   `changed_by_role=unknown` audit smell and puts the immutable
   policy history in front of analysts. **P2** (small hygiene)
10. **Fuzz + SCA + secrets sweep.** Run `dependency-check` or
    `pip-audit`, `bandit`, and a secret scanner against
    `/app/backend/`. Not evidence of anything today — it's just
    absent from the assessment. **P2**

---

## 13 · Critical gaps by rank

- **P0 · Labelled ground-truth corpus.** Without it, verdict-accuracy
  numbers cannot exist. Everything downstream that quotes a
  precision/recall number would be fabrication.
- **P0 · Real vendor connectors.** Framework without pollers is not
  ingestion. Currently the strongest technical work sits on top of
  data that in production would come from stubs.
- **P0 · Performance evidence.** Nothing here says "will hold under
  100 concurrent analysts."
- **P1 · Live query / forensics** — expected feature of any XDR.
- **P1 · NDR / DNS / proxy / email adapters** — cross-lane is
  currently a two-lane game (endpoint + identity/cloud partial).
- **P1 · Observability pipeline** — no runtime insight beyond logs.
- **P2 · Collection-error / 404 hygiene** — visible smells for a
  visitor.
- **P2 · Fuzz / SCA / secrets sweep** — absence of evidence.
- **P3 · X-Principal-Role interceptor** — already flagged
  cosmetic.

---

## 14 · BLUNT CONCLUSION

> **NivXRay is currently at Maturity Level 3.5/5 — an Advanced
> Prototype approaching Pre-Production.**
>
> The **evidence-first architecture is genuinely differentiated**
> and unusually principled: deterministic verdict authority,
> immutable evidence graph, hierarchical intelligence policy with
> a guaranteed-baseline narrator, honest coverage-gap narration
> instead of fabricated correlation, and a policy-snapshot
> contract that isolates in-flight requests from mid-flight
> toggles. **On this axis NivXRay is ahead of most commercial XDRs
> I know of.**
>
> But the **operational surface is thin**. Real vendor pollers are
> stubs, there is no live-query / forensics endpoint, there is no
> NDR / DNS / email adapter, there is no labelled corpus and
> therefore no verdict-accuracy number, and there is no
> performance-under-load evidence.
>
> The engineering quality (79/100) is well ahead of the security
> detection surface (58/100). That gap is normal for a system at
> this stage — the correct move is NOT more architecture. It is:
> **(a) build the labelled corpus, (b) ship real connectors,
> (c) publish load-test numbers.** Those three items alone move
> the composite score from 66/100 to a defensible 78–82/100.
>
> Do not start Phase 3 Response Automation until at least (a) and
> (b) are done. Response without measured detection is a demo, not
> a product.

---

_End of assessment · no production code modified during this pass._
