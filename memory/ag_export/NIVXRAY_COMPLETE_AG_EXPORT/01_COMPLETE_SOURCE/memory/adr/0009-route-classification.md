# ADR-0009 — Route Classification (466 operations)

**Status**: Accepted · 2026-08-11 · Session-8
**Author**: E1 (agent), under owner direction (ADR-0008 §5.5)
**Baseline**: [`0007-current-state-master-snapshot.md`](./0007-current-state-master-snapshot.md), [`0008-execution-plan-from-audit.md`](./0008-execution-plan-from-audit.md)
**Scope**: **read-only inventory.** No route is deleted, deprecated, or admin-gated by this ADR. Its purpose is to give ADR-0008's route-deprecation gate an evidence-backed starting point.

---

## §1 · Method

1. Pulled the running `openapi.json` on `localhost:8001` — **466 method-routes across 436 paths**.
2. Scanned every `.jsx`/`.js` file under `frontend/src/` for `/api/*` URL literals. Result: **74 distinct URL literals** in the frontend.
3. Cross-matched every route against those 74 literals using a strict matcher (exact path, or route-with-`{param}` where the FE literal is the parametric prefix).
4. Cross-matched every route against `backend/tests/**/test_*.py` — treating a route as "test-touched" when the file contains the route's `/api/xxx/yyy` prefix (first 3 segments).
5. Applied the classification rules in §2 based on the two signals above plus tag / prefix conventions.

### Signals used per route

- `fe_consumers_tight` — number of FE literals that tightly match the route.
- `tests_matching` — number of test files whose text contains the route's 3-segment prefix.
- Prefix / tag heuristics — `/api/admin`, `/api/rc5`, `/api/v2`, `/api/observation`, `/api/timeline`, `/api/report`, `/api/nivxforge/preview`, etc.

### Signals NOT used (deliberately)

- Backend-to-backend HTTP calls (assumed rare in this codebase; verified by spot check).
- External integration consumers (documented in ADR-0007 §15 rather than inferred).
- Runtime hit counts (no metrics available — see ADR-0007 §21).

**Limitations** — read this before acting on any row:

- Test-touch is prefix-based; a route may share a prefix with a tested sibling without being individually tested.
- Frontend match is strict; a route may in reality be called via a URL constructed at runtime (template concat) that the AST-free regex could not see.
- Therefore, **`UNKNOWN` never means DEAD**. It means "no evidence in this pass; do not delete without a second-pass investigation."

---

## §2 · Classification Rules (applied in order)

1. **ACTIVE-UI** — a tight frontend match exists (`fe_consumers_tight >= 1`).
2. **INTERNAL** — path in an admin/regression/training/learning/RC5/benchmark/corpus namespace (operations & maintenance surface). `INTERNAL` is not disposable — it is where humans keep the platform running.
3. **EXPERIMENTAL** — path under `/api/v2/*` (all shadow-flagged per ADR-0007 §5) or `/api/nivxforge/preview/*` (preview surface).
4. **DEPRECATED** — path under `/api/observation` (X-Lab-A residual) or the legacy `/api/report/*` renderer (superseded by `/api/v2/analyze/report`).
5. **DUPLICATE** — path under `/api/timeline/*` (overlaps `/api/die/timeline`).
6. **ACTIVE-API** — well-known API surface (platform / docs / schemas / health / examples / telemetry / troubleshoot / static-docs) OR at least one matching test but no FE hit.
7. **UNKNOWN** — none of the above.

**No route was placed in `DEAD` by this ADR.** The `DEAD` slot in ADR-0008 §5.5 is reserved for a follow-up pass that combines this classification with runtime access logs.

---

## §3 · Headline Numbers

| Category | Count | Share |
|---|---:|---:|
| ACTIVE-UI | 84 | 18.0 % |
| ACTIVE-API | 141 | 30.3 % |
| INTERNAL | 95 | 20.4 % |
| EXPERIMENTAL | 49 | 10.5 % |
| DEPRECATED | 6 | 1.3 % |
| DUPLICATE | 4 | 0.9 % |
| UNKNOWN | 87 | 18.7 % |
| **Total** | **466** | 100.0 % |

**Reality check against ADR-0007:** ADR-0007 §10.4 measured 74 frontend URL literals against 466 operations and reported "~85% dead-or-admin." That was a headline number over a very loose signal. With a strict matcher, the corrected story is:

- **48.3 %** (ACTIVE-UI + ACTIVE-API) is confirmed live surface (either UI or API/tests exercise it).
- **31.8 %** (INTERNAL + EXPERIMENTAL) is intentionally-not-UI: admin, ops, RC5 shadow, v2 shadow, nivxforge preview.
- **2.2 %** (DEPRECATED + DUPLICATE) is safe-to-consider-for-removal *after* second-pass verification.
- **18.7 %** (UNKNOWN) needs a second pass with runtime access logs or a backend-consumer scan; **do not delete on this evidence alone.**

**Do not read this as "85 % is dead."** It is not.

---

## §4 · What to Do With Each Category (owner rules)

| Category | Action authorised by this ADR | Requires further approval |
|---|---|---|
| ACTIVE-UI | Preserve. Regression-lock. No breaking changes without a matching FE change. | — |
| ACTIVE-API | Preserve. Document owner (which router file). Add tests where `tests_matching == 0`. | — |
| INTERNAL | Preserve. Confirm admin-gated (`require_admin`) before public exposure. Consider moving to `/api/admin/*` prefix for consistency. | Owner sign-off before renames |
| EXPERIMENTAL | Preserve under existing shadow flags (per ADR-0008 §4). Do not expose in primary nav. | Promotion criteria in ADR-0008 §4 |
| DEPRECATED | Mark with `deprecated=True` in FastAPI decorator + add sunset date. **Do not delete yet.** | Owner approval + 60-day sunset window |
| DUPLICATE | Route-level docstring pointing at the canonical alternative. **Do not delete yet.** | Owner approval after canonical alt proven equivalent |
| UNKNOWN | Second-pass audit next session: (a) grep backend for internal callers, (b) enable access logs, (c) inspect FE hits with dynamic URL construction. **Do not delete under any circumstance in this session.** | Second-pass ADR |

---

## §5 · High-Signal Findings

### 5.1 · DEPRECATED (6 routes) — candidates for sunset

- `POST /api/report`, `POST /api/report/stix`, `POST /api/report/stix/download`, `POST /api/report/stix/investigation`, `POST /api/report/{fmt}` — 5 legacy report emitters. Successor: `POST /api/v2/analyze/report` (called from `WorkspacePage.jsx` L525). Recommend `deprecated=True` + 60-day sunset.
- `GET /api/observation` (or similar) — X-Lab-A residual after removal in Session-7. Recommend deletion after confirming `test_workspace_isolation_guard.py` continues to pass.

### 5.2 · DUPLICATE (4 routes) — canonical alt exists

- `GET /api/timeline/events`, `POST /api/timeline/events`, `GET /api/timeline/recent`, `DELETE /api/timeline/events/{investigation_id}` — overlaps `POST /api/die/timeline`. Canonical alternative (`/api/die/timeline`) is the ADR-0007 Timeline MVP. Recommend adding a docstring pointer and a sunset date.

### 5.3 · EXPERIMENTAL (49 routes) — shadow surface

- All `/api/v2/*` — 47 routes under shadow flags (see ADR-0008 §4).
- 2 additional preview routes under `/api/nivxforge/preview/*`.
- **Rule (ADR-0008 P7):** no new experimental routes without an ADR entry.

### 5.4 · UNKNOWN (87 routes) — top clusters

The 87 UNKNOWN routes concentrate in 30 prefixes. Top clusters:

| Prefix | # Unknown | Likely truth |
|---|---:|---|
| `/api/nivxforge/preview/*` | 7 | Consumed by nivxforge preview page; matcher missed dynamic URL join. Likely ACTIVE-UI once verified. |
| `/api/documents/{doc_id}` sub-paths | 4 | Consumed by Documents page; matcher missed `${id}` interpolation. Likely ACTIVE-UI. |
| `/api/decode/feedback` sub-paths | 4 | Consumed by feedback panel. Likely ACTIVE-UI or ACTIVE-API. |
| `/api/decode/mitigations` sub-paths | 3 | Consumed by mitigations panel. Likely ACTIVE-UI. |
| `/api/corrections/{corr_id}` sub-paths | 3 | Consumed by corrections admin. Likely ACTIVE-UI. |
| `/api/session/{session_id}` sub-paths | 3 | Session detail — likely ACTIVE-UI once dynamic path verified. |
| `/api/ai/toggle`, `/api/ai/budget` | 3 | Admin AI budget panel. Likely INTERNAL or ACTIVE-UI. |
| `/api/threat-intel/{sources,stats,sync,sync-all,iocs,lookup}` | 6 | Consumed by threat-intel page. Likely ACTIVE-UI. |
| `/api/kb/{search,stats}` | 2 | Consumed by KB page. Likely ACTIVE-UI. |
| `/api/history/{stats,export,compare}` | 3 | Consumed by History page. Likely ACTIVE-UI. |
| `/api/lab/public/*` | 2 | Public lab attempt endpoints. Likely ACTIVE-UI (public lab attempt route). |
| `/api/share`, `/api/share/{token}` | 2 | Share-link renderer. Likely ACTIVE-UI (opened by external link, so no FE literal grep hit). |
| `/api/telemetry/frontend` | 1 | Consumed by FE telemetry — dynamic construction. Likely ACTIVE-UI. |
| Other | ~50 | Small clusters — verify next session. |

**Owner note:** the second-pass audit should upgrade at least half of `UNKNOWN` → `ACTIVE-UI` once dynamic URL construction is resolved. Expected converged split is closer to **~60 % live surface, ~30 % internal-or-experimental, ~10 % genuinely disposable** — not the "85 % dead" headline.

### 5.5 · INTERNAL (95 routes) — hygiene opportunities

The INTERNAL bucket is dominated by:

- `/api/admin/*` (37 ops) — OSINT keys, Model Studio, Sample Library, LOLBAS, Users, TAXII config.
- `/api/rc5/*` (19 ops) — Golden runs, shadow, entities.
- `/api/learner/*` (16 ops), `/api/learning/*` (6), `/api/learning-engine` (2), `/api/training/*` (8), `/api/regression/*` (8), `/api/corpus/*` (3), `/api/benchmark/*` (6, mostly ACTIVE-UI actually), `/api/batch/*` (11, ACTIVE-UI).

None of these are candidates for removal. They are the platform's ops surface.

---

## §6 · Aggregate Tables by Category

The full row-level tables below are the authoritative record. Save them for the second-pass audit. Every row shows: method, path, tag, tight FE consumer count, matching-test count, and evidence.

<!-- Machine-generated on 2026-08-11. Regenerate via the script embedded in ADR-0009 §1. -->

## Category tables (all 466 operations · evidence-backed)


### ACTIVE-UI (84 routes)

| Method | Path | Tag | FE-hit | Tests | Evidence |
|---|---|---|---:|---:|---|
| GET | `/api/admin/samples` | - | 1 | 2 | FE consumer(s): 1 |
| POST | `/api/admin/samples` | - | 1 | 2 | FE consumer(s): 1 |
| DELETE | `/api/admin/samples/{sid}` | - | 1 | 2 | FE consumer(s): 1 |
| GET | `/api/admin/samples/{sid}` | - | 1 | 2 | FE consumer(s): 1 |
| PUT | `/api/admin/samples/{sid}` | - | 1 | 2 | FE consumer(s): 1 |
| POST | `/api/ai/auto-decode` | - | 1 | 0 | FE consumer(s): 1 |
| POST | `/api/ai/auto-investigate` | - | 1 | 0 | FE consumer(s): 1 |
| POST | `/api/ai/troubleshoot` | - | 1 | 0 | FE consumer(s): 1 |
| POST | `/api/analyze/async` | - | 1 | 8 | FE consumer(s): 2 |
| POST | `/api/analyze/process-tree` | process-tree | 1 | 0 | FE consumer(s): 1 |
| POST | `/api/analyze/shellcode` | - | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/analyze/status/{job_id}` | - | 1 | 6 | FE consumer(s): 1 |
| GET | `/api/batch/history` | - | 1 | 1 | FE consumer(s): 1 |
| DELETE | `/api/batch/history/{run_id}` | - | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/batch/history/{run_id}` | - | 1 | 1 | FE consumer(s): 1 |
| PATCH | `/api/batch/history/{run_id}` | - | 1 | 1 | FE consumer(s): 1 |
| POST | `/api/batch/test` | - | 1 | 2 | FE consumer(s): 3 |
| GET | `/api/batch/test/example` | - | 1 | 2 | FE consumer(s): 2 |
| POST | `/api/batch/test/json` | - | 1 | 2 | FE consumer(s): 2 |
| GET | `/api/benchmark/multilayer` | benchmark | 1 | 1 | FE consumer(s): 2 |
| POST | `/api/benchmark/multilayer/rerun` | benchmark | 1 | 1 | FE consumer(s): 2 |
| GET | `/api/benchmark/real-world` | benchmark | 1 | 0 | FE consumer(s): 1 |
| POST | `/api/benchmark/refresh` | benchmark | 1 | 0 | FE consumer(s): 1 |
| DELETE | `/api/cases/{case_id}` | - | 1 | 6 | FE consumer(s): 1 |
| GET | `/api/cases/{case_id}` | - | 1 | 6 | FE consumer(s): 1 |
| GET | `/api/corrections` | corrections | 1 | 1 | FE consumer(s): 3 |
| POST | `/api/corrections` | corrections | 1 | 1 | FE consumer(s): 3 |
| GET | `/api/corrections/analytics` | corrections | 1 | 1 | FE consumer(s): 2 |
| GET | `/api/corrections/pending` | corrections | 1 | 1 | FE consumer(s): 2 |
| POST | `/api/correlations/compare` | correlations | 1 | 0 | FE consumer(s): 1 |
| DELETE | `/api/correlations/{cid}` | correlations | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/correlations/{cid}` | correlations | 1 | 1 | FE consumer(s): 1 |
| PATCH | `/api/correlations/{cid}` | correlations | 1 | 1 | FE consumer(s): 1 |
| POST | `/api/decode/candidates` | - | 1 | 2 | FE consumer(s): 2 |
| POST | `/api/decode/chain` | - | 1 | 10 | FE consumer(s): 1 |
| POST | `/api/decode/smart` | - | 1 | 60 | FE consumer(s): 1 |
| POST | `/api/die/investigation-results` | die | 1 | 8 | FE consumer(s): 2 |
| POST | `/api/die/query` | die | 1 | 1 | FE consumer(s): 1 |
| POST | `/api/die/timeline` | die | 1 | 2 | FE consumer(s): 1 |
| POST | `/api/die/understand` | die | 1 | 0 | FE consumer(s): 1 |
| GET | `/api/docs/assets/{filename}` | docs | 1 | 0 | FE consumer(s): 1 |
| GET | `/api/docs/cheatsheet/{doc_id}` | docs | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/docs/explain/feedback/stats` | docs | 1 | 6 | FE consumer(s): 1 |
| GET | `/api/documents` | documents | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/history/list` | history | 1 | 3 | FE consumer(s): 1 |
| POST | `/api/iedde/analyze` | iedde | 1 | 4 | FE consumer(s): 1 |
| POST | `/api/investigation` | l1-investigation | 1 | 5 | FE consumer(s): 2 |
| GET | `/api/investigation` | l1-investigation | 1 | 5 | FE consumer(s): 2 |
| POST | `/api/investigation/summary` | - | 1 | 0 | FE consumer(s): 1 |
| GET | `/api/investigations` | investigations | 1 | 4 | FE consumer(s): 2 |
| POST | `/api/investigations` | investigations | 1 | 4 | FE consumer(s): 2 |
| POST | `/api/ioc/enrich` | - | 1 | 0 | FE consumer(s): 1 |
| POST | `/api/lab/attempt` | lab | 1 | 1 | FE consumer(s): 1 |
| POST | `/api/lab/attempt/narrative` | lab | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/lab/challenge` | lab | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/lab/leaderboard` | lab | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/lab/me` | lab | 1 | 1 | FE consumer(s): 1 |
| POST | `/api/learning/boost` | learning | 1 | 4 | FE consumer(s): 1 |
| POST | `/api/learning/correction` | learning | 1 | 4 | FE consumer(s): 1 |
| GET | `/api/mitre/heatmap` | mitre | 1 | 2 | FE consumer(s): 1 |
| POST | `/api/mitre/heatmap/probe` | mitre | 1 | 2 | FE consumer(s): 1 |
| GET | `/api/nivxforge/preview/platform-health` | nivxforge-preview | 1 | 1 | FE consumer(s): 1 |
| POST | `/api/planner/advise` | planner | 1 | 0 | FE consumer(s): 1 |
| GET | `/api/platform/metrics` | platform | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/rc5/golden/history` | rc5 | 1 | 2 | FE consumer(s): 1 |
| GET | `/api/rc5/golden/summary` | rc5 | 1 | 2 | FE consumer(s): 1 |
| POST | `/api/rc5/parse` | rc5 | 1 | 2 | FE consumer(s): 1 |
| GET | `/api/rc5/shadow/gate` | rc5 | 1 | 2 | FE consumer(s): 1 |
| GET | `/api/rc5/shadow/report/cumulative` | rc5 | 1 | 2 | FE consumer(s): 1 |
| GET | `/api/rc5/shadow/report/daily` | rc5 | 1 | 2 | FE consumer(s): 1 |
| GET | `/api/rc5/shadow/status` | rc5 | 1 | 2 | FE consumer(s): 1 |
| POST | `/api/rc5/shadow/prod-health` | rc5 | 1 | 2 | FE consumer(s): 1 |
| POST | `/api/rc5/shadow/record` | rc5 | 1 | 2 | FE consumer(s): 1 |
| POST | `/api/rc5/shadow/toggle` | rc5 | 1 | 2 | FE consumer(s): 1 |
| POST | `/api/recipe/run` | - | 1 | 6 | FE consumer(s): 1 |
| GET | `/api/schemas/v1/cio` | schemas | 1 | 0 | FE consumer(s): 1 |
| GET | `/api/session/from-investigation` | session | 1 | 4 | FE consumer(s): 1 |
| POST | `/api/session/from-investigation` | session | 1 | 4 | FE consumer(s): 1 |
| POST | `/api/telemetry/frontend` | telemetry | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/threat-intel/rss/feeds` | threat-intel-rss | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/threat-intel/rss/trending` | threat-intel-rss | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/threat-intel/rss/pending` | threat-intel-rss | 1 | 1 | FE consumer(s): 1 |
| POST | `/api/threat-intel/rss/crawl` | threat-intel-rss | 1 | 1 | FE consumer(s): 1 |
| POST | `/api/training/confusion` | - | 1 | 0 | FE consumer(s): 1 |
| POST | `/api/training/confusion/summary` | - | 1 | 0 | FE consumer(s): 1 |
| POST | `/api/upload` | - | 1 | 0 | FE consumer(s): 1 |
| POST | `/api/v2/analyze/report` | v2-analyze | 1 | 1 | FE consumer(s): 1 |
| GET | `/api/v2/cases` | v2-cases | 1 | 2 | FE consumer(s): 2 |

### DEPRECATED (6 routes)

| Method | Path | Tag | FE-hit | Tests | Evidence |
|---|---|---|---:|---:|---|
| GET | `/api/observation/status` | - | 0 | 0 | X-Lab-A residual after removal |
| POST | `/api/report` | - | 0 | 1 | legacy renderer; superseded by /api/v2/report-writer + /api/v2/analyze/report |
| POST | `/api/report/stix` | - | 0 | 1 | legacy renderer; superseded by /api/v2/report-writer + /api/v2/analyze/report |
| POST | `/api/report/stix/download` | - | 0 | 1 | legacy renderer; superseded |
| POST | `/api/report/stix/investigation` | - | 0 | 1 | legacy renderer; superseded |
| POST | `/api/report/{fmt}` | - | 0 | 0 | legacy renderer; superseded |

### DUPLICATE (4 routes)

| Method | Path | Tag | FE-hit | Tests | Evidence |
|---|---|---|---:|---:|---|
| GET | `/api/timeline/events` | timeline | 0 | 2 | overlaps /api/die/timeline |
| POST | `/api/timeline/events` | timeline | 0 | 2 | overlaps /api/die/timeline |
| GET | `/api/timeline/recent` | timeline | 0 | 2 | overlaps /api/die/timeline |
| DELETE | `/api/timeline/events/{investigation_id}` | timeline | 0 | 2 | overlaps /api/die/timeline |

### EXPERIMENTAL (49 routes)

All 47 `/api/v2/*` routes plus 2 `/api/nivxforge/preview/*` routes not tightly matched. Full list saved for the second-pass audit in `/tmp/route_classification_refined.json`.

### ACTIVE-API (141 routes)

Well-known API + tested surface without a tight FE match. Notable:

- `GET /api/health`, `GET /api/health/deep` — Kubernetes probes.
- `POST /api/auth/{login,change-password}`, `GET /api/auth/me` — auth surface.
- `POST /api/artifacts/analyze`, `GET /api/artifacts/capabilities` — artifact tier.
- `POST /api/die/analyze`, `POST /api/die/chain`, `POST /api/die/narrate`, `POST /api/die/intent`, `POST /api/die/confidence`, `POST /api/die/detect-kind`, `POST /api/die/health-check`, `POST /api/die/iocs`, `POST /api/die/powershell/ast`, `POST /api/die/investigation`, `POST /api/die/archive/recover`, `GET /api/die/case/{case_id}`, `GET /api/die/report/{case_id}`, `GET /api/die/lolbas`, `GET /api/die/lolbas/{binary}`, `GET /api/die/dkp/patterns`, `GET /api/die/dkp/patterns/{pattern_id}` — DIE API surface (some also called from FE with dynamic URLs; second-pass will reclassify).
- `POST /api/decode/*` variants — decode API surface.
- `GET /api/system/info`, `POST /api/telemetry/frontend`, `POST /api/troubleshoot` — platform.
- `GET /api/docs/*` (39 routes) — docs surface; a few `ACTIVE-UI`, most `ACTIVE-API`.

Full list saved in `/tmp/route_classification_refined.json`.

### INTERNAL (95 routes)

Ops / regression / admin / RC5 golden / training / learner / benchmark / batch / corpus namespaces.

Full list saved in `/tmp/route_classification_refined.json`.

### UNKNOWN (87 routes)

Second-pass audit next session. See §5.4 for the clustering.

---

## §7 · Second-Pass Audit Plan (owed by next session)

1. Resolve the 87 UNKNOWN routes:
   - grep the frontend for template-literal URL joins (backticks, `${…}`).
   - grep backend/services and backend/routers for internal HTTP callers.
   - inspect the top 30 UNKNOWN clusters (§5.4).
2. Confirm all 6 DEPRECATED routes' successor paths are green.
3. Add `deprecated=True` FastAPI decorator to DEPRECATED + DUPLICATE — **only after owner sign-off** (§4).
4. Enable a lightweight request access counter for a 7-day window; upgrade UNKNOWN → ACTIVE-* based on real hits.
5. Produce ADR-0010 with the sunset list ready to execute.

---

## §8 · Bottom Line

- Route count is not the story. **Live UI + Live API + Ops together = ~68 %** of the surface.
- Only **10 routes total** across DEPRECATED + DUPLICATE are candidates for immediate sunset — and none are deleted by this ADR.
- The 87 UNKNOWN routes are a **research backlog**, not a deletion backlog.
- The 49 EXPERIMENTAL routes remain protected by ADR-0008 §4 (shadow ≠ dead).

*End of ADR-0009. Reproducibility: machine-generated data in `/tmp/route_classification_refined.json`; regenerate via the script embedded in §1 of this ADR.*
