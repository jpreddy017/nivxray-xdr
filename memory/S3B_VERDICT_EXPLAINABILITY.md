# S3-B · VERDICT EXPLAINABILITY — 2026-06-21

**Status: DONE · PROVEN.** One 4-line backend authorization change + one new
frontend surface. No new verdict engine, no frontend-computed verdict, no
duplicated negative-explainability logic.

Proof: `scripts/p1_s3b_verdict_explainability_proof.py` → **32 PASS · 0 FAIL**
(`test_reports/p1_s3b_verdict_explainability_proof.txt`) ·
`backend/tests/test_s2mini_engine_depth_authz.py` → **22 passed in 31 s**
(`test_reports/s3b_focused_tests.txt`) · `yarn build` **PASS**. No screenshots.

## EXISTING AUTHORITY (inventoried before coding)

| question | authority | field |
|---|---|---|
| verdict · risk · confidence | **the incident's own verdict authority** — `GET /api/incidents/:id/summary` | `deterministic_verdict {label · risk_score · confidence · contributing_signals · engine · provenance: workspace_cases.verdict_stage2}` |
| supporting evidence | causal analysis (S2-mini read) | `verdicts.device.evidence_breakdown[] {signal · reason · weight · processes[] · events[]}` + `explainability.positive.reasons[] {kind · weight · text · detail}` |
| contradictory / negative evidence | the engine's own hypothesis tester | `explainability.negative_patterns[]` → `GET /api/v2/cases/{id}/investigation/explain/{pattern}` → `{matches · have_required · missing_required · have_supporting · missing_supporting · reasons[kind=missing] · verdict_line}` |
| missing / not-observed evidence | incident summary | `evidence_gaps[] {claim · state: no_matching_evidence \| not_connected · searched[] · reason · note}` |
| analysis completeness | **NONE EXISTS** in this build | — (the frontend `investigation/completeness.js` is a frontend computation and was deliberately NOT used) |

## MINIMAL AUTH CHANGE

Exactly one route: `GET /api/v2/cases/{case_id}/investigation/explain/{pattern_id}`
moved from `require_admin` to `Depends(engine_case_read)` — the **same**
S2-mini authority (`authenticated principal → server-resolved tenant →
the case_id must BE an incident this principal is authorized for → read`).
Read-only; `profile` remains a read parameter. No engine mutation,
configuration or administrative capability was exposed, and admin behaviour is
unchanged. Nothing else in the backend was touched.

## VISIBLE UI

New `IncidentVerdictExplainability`, mounted on the **Overview** tab above the
existing collapsed engine panel:
1. **Verdict header** — verdict chip + `Risk · Confidence · Analysis
   completeness · Contributing signals`, with the line *"Confidence is how
   strongly the evidence supports this conclusion. It is not a statement that
   the analysis is complete."* Live: `SUSPICIOUS · risk 70 · confidence medium
   · analysis completeness NOT AVAILABLE (no completeness measure is recorded
   by the platform) · 2 signals`.
2. **Why this verdict** — one row per recorded reason:
   `Supports the current verdict · What the engine recorded · Weight · Basis`.
   Basis is **Evidence cited** or, for a reason the engine states without an
   event (e.g. a coverage statement), *"coverage statement · no event cited"*.
   Row expansion reveals the cited event frames, the entities and the field
   each value was read from.
3. **Evidence limiting a stronger conclusion** — the engine's own hypotheses
   (Ransomware · Credential Theft · Lateral Movement · Persistence ·
   C2 Beaconing) under progressive disclosure. Expanding one asks the engine
   and renders its `verdict_line`, what WAS observed for that hypothesis, and
   each absent required/supporting behaviour tagged **NOT OBSERVED**.
4. **Visibility and evidence gaps** — two SEPARATE groups:
   *Searched · not observed* (`no_matching_evidence`, with the capabilities
   searched) and *Visibility gaps · telemetry not available*
   (`not_connected`). Live: 2 and 4 respectively.

No engine/profile selector is exposed. Engine internals (engine id,
provenance, causal band/score/confidence, association authority) stay under
Technical details.

## EXPLAINABILITY SEMANTICS (asserted live, not merely written)

- `NOT OBSERVED ≠ ABSENT` — *"A behaviour the engine looked for and did not
  find is NOT OBSERVED — it is not proof the behaviour did not happen"*.
- `MISSING TELEMETRY ≠ NEGATIVE EVIDENCE` — the two gap groups come from
  different states of a different authority and are never merged; the proof
  asserts both group headers and both notes are present
  (*"Absence of evidence is not evidence of absence"* and *"Missing telemetry
  is NOT negative evidence"*).
- `CONFIDENCE ≠ ANALYSIS COMPLETENESS` — completeness reads **NOT AVAILABLE**
  with its reason and is never derived from confidence.
- `NOT AVAILABLE ≠ CLEAN` / `NOT ASSOCIATED ≠ BENIGN` — an incident with no
  causal analysis shows one honest state plus *"No causal explanation is NOT a
  benign finding"*, while the verdict above still stands on its own authority.
- No conclusion without evidence: a claim with no cited event is labelled by
  its real authority instead of being rendered as an observation.

## PROVENANCE

Every supporting row carries its event-frame references, its entity
references, and the exact source field, reachable by row expansion. A row with
no event frame says so in words. The verdict block cites its engine and its
`workspace_cases.verdict_stage2` provenance under Technical details.

## TENANT / RBAC PROOF (real JWTs — part 1 of the proof, 12 PASS)

anonymous → **403** · own-tenant analyst → **200** with the engine's own
`verdict_line` + `missing_required[]` · cross-tenant → **404** · admin →
**200** (unchanged) · engine-native case: admin 200 / analyst **404** ·
`?tenant_id=`, `?customer=`, `X-Tenant-Id`, `X-Principal-Id` → **404** ·
analyst still cannot create an engine case or list the engine registry
(**403**). Backend guard extended with 4 new cases (22 passed).

## FILES CHANGED

New: `apps/nivxray-xdr/src/xdr/incidents/IncidentVerdictExplainability.jsx` ·
`scripts/p1_s3b_verdict_explainability_proof.py`.
Changed: `backend/v2/routers/investigation.py` (one route's dependency) ·
`backend/tests/test_s2mini_engine_depth_authz.py` (+4 cases for the new
authority) · `src/lib/incidentsApi.js` (+1 read) ·
`src/xdr/pages/XdrIncidentDetailPage.jsx` (+1 import, +1 mount).

## FOCUSED TEST RESULTS

- `p1_s3b_verdict_explainability_proof.py` — **32 PASS · 0 FAIL** (12
  authorization + 20 DOM).
- `tests/test_s2mini_engine_depth_authz.py` — **22 passed in 31 s**.
- `yarn build` — **PASS**.
- Incident tabs still render (overview · story · evidence · activity).
- No broad regression run (not required).

## RESIDUALS

1. **No authoritative Analysis Completeness measure exists.** The surface
   states `NOT AVAILABLE` with the reason rather than inventing one. Making
   completeness real is a backend deliverable, not a UI one.
2. The engine's causal band (`informational`, score 20, confidence 45) can
   differ from the incident's own verdict (`suspicious`, risk 70). The
   incident verdict is the headline authority; the causal assessment is
   disclosed under Technical details with its own numbers. **No third verdict
   is computed** — but the two authorities disagreeing is a real product
   question for the owner.
3. Carried P0 security residual, untouched: `response-executions` trusts a
   client-supplied `tenant_id`.
4. Playwright browsers and `/tmp` are wiped periodically in this container —
   re-run `python -m playwright install chromium` before a DOM proof.
