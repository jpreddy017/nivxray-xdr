# NivXRay Load & Resource Audit — Post X-Lab Removal Baseline

**Date**: 2026-08-11  
**Trigger**: Owner directive after X-Lab observational-surface removal — "measure first, change nothing"  
**Mode**: **Read-only.** No code, config, dependency, DB, or file modified.  
**Guarantees verified after audit**: Workspace / Practice Lab / P0.2 / P0.3 / Sample1 — unchanged.

---

## Executive summary

| Dimension | Measured | Grade |
|---|---|---|
| Backend RSS (steady, idle) | **378 MB** | 🟢 Healthy |
| Backend peak under 10× concurrent SEP.csv | **+1 MB** vs baseline | 🟢 No leak |
| Backend VmPeak (transient, lifetime) | 3.9 GB virtual (378 MB physical) | 🟡 Large virtual footprint — expected for Python + pandas/pymupdf/litellm |
| Frontend (dev mode) | **1 236 MB** across 6 node procs | 🟡 Craco + ts-checker; production build would be far smaller |
| Frontend source | 3.7 MB | 🟢 Small |
| Frontend `node_modules` | 1.9 GB (1 110 packages) | 🟡 Standard React dev footprint |
| MongoDB `test_database` | dataSize 147 MB · storage 44 MB · 64 collections · 75 397 docs | 🟢 Healthy |
| Mongo active connections | 10 / 400 available | 🟢 Healthy |
| Redis | **not used** | 🟢 One less service |
| `/app` total | 2.2 GB (dominated by `frontend/node_modules`) | 🟢 |
| Investigation latency | 145–308 ms | 🟢 Fast |
| Investigation response size | 8.3–22.5 KB | 🟢 Well under 250 KB budget |
| Backend routes | **464 method-routes across 434 paths** | 🟡 High route count — see recommendations |
| Cold start `import server` | **3.06 s · 2 080 modules** | 🟡 Slow-ish import graph |
| Background async tasks at startup | 5 (LOLBAS refresh, nightly benchmark, confusion pre-warm, CTI RSS, corpus refresh) + hourly TI feed sync | 🟢 |

**Bottom line**: The system is comfortable. Backend physical memory is 378 MB and does not grow under concurrent load. The only meaningful weight sits in (1) the dev-mode frontend (~1.2 GB — will vanish in a production build), (2) `node_modules` (1.9 GB), and (3) the Python venv (1.1 GB). Nothing here calls for urgent optimisation.

---

## 1. Runtime memory

### 1.1 Process tree — actual NivXRay memory (not the pod host)

```
NivXRay backend (pid 21879 = uvicorn --reload parent)                                405.3 MB total
├── uvicorn reloader (parent)                                                          25.9 MB
├── multiprocessing.resource_tracker                                                   10.2 MB
└── uvicorn spawned worker (actual server)                                            369.1 MB  ← the important one

NivXRay frontend (pid 21883 = yarn/craco dev server)                               1 235.6 MB total
├── yarn start                                                                          73.5 MB
├── /bin/sh craco start                                                                  0.8 MB
├── node .bin/craco start                                                              40.4 MB
├── craco/scripts/start.js                                                            802.3 MB  ← webpack dev server
├── fork-ts-checker (worker A, --max-old-space-size=2048)                            245.4 MB
└── fork-ts-checker (worker B)                                                         73.2 MB
```

**Not part of NivXRay** (Emergent pod infrastructure, out of scope for optimisation):
- `plugins.tools.agent.server` uvicorn (port 8010): 446 MB — Emergent plugin agent
- `mongodb-mcp-server`: 105 MB — Emergent MCP bridge
- `mongod`: 198 MB — MongoDB (shared with the whole pod)

### 1.2 Peak-load test — 10 concurrent SEP.csv investigations

| Metric | Value |
|---|---|
| RSS before burst | 369 MB |
| Peak RSS during burst (sampled every 100 ms × 50) | 370 MB |
| RSS after all 10 responses settled | 370 MB |
| Δ from baseline | **+1 MB** |

**Verdict**: Workspace investigation has effectively **zero memory growth** under concurrent load — no leak, no unbounded caching. Ten concurrent requests all finished within the sampling window.

### 1.3 Backend virtual-memory ceiling

`/proc/22538/status`:
- VmPeak = **3.92 GB** (lifetime high-water for virtual address space)
- VmSize = 2.14 GB (current virtual)
- VmRSS  = 378 MB (current physical)
- VmData = 819 MB
- Threads = 28
- Open FDs = 50

Large `VmPeak` is a Python glibc artefact — heavy imports (pandas, numpy, pymupdf, litellm) briefly grow the address space, then release. **VmRSS is the number that matters for the pod's actual memory pressure.**

### 1.4 System-wide

```
Mem:   32 GB total · 19.5 GB used · 12.4 GB available · 0 swap
```

The pod is a shared cloud container; other NivXRay-adjacent processes (Emergent plugin agent, MCP bridge) consume a larger share than NivXRay itself. NivXRay's backend + frontend together = **~1.6 GB / 32 GB** = 5 % of pod RAM.

---

## 2. CPU

| Sample | Backend %CPU | Frontend %CPU |
|---|---:|---:|
| Idle | 0.0 % | 0.0 % |
| Startup (import server) | 3.06 s wall-clock (single-threaded) | ~13 s webpack initial compile |
| Investigation (cmdline) | briefly during 308 ms | 0 % |
| Investigation (SEP.csv 5 rows) | briefly during 187 ms | 0 % |
| 10× concurrent SEP.csv | not sampled per-CPU, but VmRSS stayed flat | 0 % |

Long-running background workers running under NivXRay:

- 3 `asyncio.create_task(...)` fired in `server.py::_startup()`:
  1. `lolbas_maybe_refresh(db)`
  2. `_nightly_benchmark_loop()`
  3. `_prewarm_confusion()`
- 3 schedulers armed in `server.py::_startup()`:
  4. `start_scheduler` — CTI RSS crawler
  5. Corpus refresh scheduler
  6. Hourly TI feed sync

None are CPU-hot. All idle at inspection time.

External cron: `webhook-crons` + `e2scrub_all` — pod-level, not NivXRay.

---

## 3. Storage

### 3.1 `/app` breakdown

```
2.0G   /app/frontend       ← 1.9 GB is node_modules; only 3.7 MB is source
146M   /app/backend        ← 25 MB tests, 122 MB backend/{routers,services,nivxforge,v2,…}
 63M   /app/evidence       ← 62 MB screenshots (RC-series demo captures — not runtime data)
 24M   /app/docs
5.7M   /app/memory
2.5M   /app/benchmarks
1.6M   /app/test_reports
```

### 3.2 Backend subdirectories

| Path | Size |
|---|---:|
| `backend/workspace_recovery` | 3.6 MB |
| `backend/routers` (54 routers) | 2.6 MB |
| `backend/nivxforge/investigation` | 1.9 MB |
| `backend/services/uaie` | 1.6 MB |
| `backend/v2/investigation` | 1.5 MB |
| `backend/services/die` | 1.3 MB |
| `backend/tests` (majority is `__pycache__` 11 MB + fixtures 3 MB) | 25 MB |
| `backend/canonical` (ADR-005 golden home) | 568 KB |

### 3.3 Python venv (top 15 site-packages)

```
134 MB  playwright             ← used by testing subagent, not the app
100 MB  googleapiclient
 79 MB  pandas                 ← used by csv_edr_analyzer
 63 MB  pymupdf                ← used by DOCX/PDF ingestion
 55 MB  litellm                ← EMERGENT_LLM_KEY bridge (needed)
 42 MB  numpy
 37 MB  google
 37 MB  <mypy compiled .so>
 33 MB  babel
 30 MB  botocore               ← boto3; used?
 29 MB  numpy.libs
 27 MB  mypy                   ← dev/CI only
 24 MB  stripe                 ← used?
 22 MB  zstandard
 17 MB  grpc
```

**Total venv: 1.1 GB.** Includes several dependencies whose necessity is not obvious from a quick scan (`googleapiclient`, `stripe`, `botocore`, `playwright`, `mypy`). All flagged as **recommendations, not actions**.

### 3.4 Log / cache / temp

```
297 MB  /root/.cache/pip
128 MB  /var/log
 66 MB  /var/log/supervisor
 54 MB  /root/.cache/node-gyp
2.5 MB  /tmp
193 __pycache__ folders in /app total (~28 MB cumulative)
```

`/var/log/supervisor` is 66 MB — worth a periodic rotation but nowhere near a problem.

### 3.5 MongoDB

```
DB: test_database
  dataSize:      147.01 MB
  storageSize:    43.93 MB   (WT compression)
  indexSize:      14.92 MB
  collections:    64
  indexes:       128
  objects:    75 397

Top-15 collections by dataSize:
  investigation_sessions           77.55 MB  storage=22.70 MB   327 docs
  v2_ai_jobs                       18.54 MB  storage= 3.92 MB   211 docs
  iocs                             17.72 MB  storage= 5.80 MB  64 480 docs
  investigations                   16.04 MB  storage= 4.16 MB  2 882 docs
  v2_decoded_payloads               3.21 MB  storage= 0.87 MB   161 docs
  workspace_cases                   3.01 MB  storage= 1.34 MB   257 docs
  investigation_ssot                2.26 MB  storage= 0.83 MB    35 docs
  regression_runs                   1.93 MB  storage= 0.27 MB   239 docs
  batch_runs                        0.98 MB
  v2_shadow_observations            0.92 MB
  benchmark_runs                    0.65 MB
  playbook_votes                    0.65 MB
  kb_entries                        0.62 MB   338 docs
  analyst_corrections               0.57 MB   887 docs
  investigation_events              0.33 MB   933 docs
```

Notable:
- `investigation_sessions` holds 327 docs at **237 KB avg per doc** — this is the "wire snapshot" store. Bounded and small.
- `iocs` has **64 480 docs at ~285 B avg** — well-indexed IOC cache.
- Total 64 collections is on the high side for one app; some may be residual from legacy engines (needs a **read-only inventory** before any drop — future task).

### 3.6 Mongo connections

```
current=10   available=399   totalCreated=418   active=3
```

Well-behaved connection pool.

### 3.7 Redis

- **Not used.** No `redis://` reference in `backend/.env` or `server.py`. No redis process. One less moving part.

---

## 4. Startup footprint

- **`import server`**: 3 061 ms wall-clock (single-threaded); 2 080 modules loaded.
- **Top Python namespaces by module count**:
  ```
  services       155     ← NivXRay
  v2             120     ← NivXRay
  docx            91     ← DOCX parsing
  numpy           84     ← via pandas
  routers         75     ← NivXRay (54 router files)
  reportlab       72     ← PDF report writer
  dns             58
  pymongo         56
  rich            55
  cryptography    50
  elftools        48     ← ELF parsing (used?)
  pypdf           48
  pydantic        43
  engine          41
  canonical       40     ← ADR-005 canonical
  ```
- **HTTP surface**: 434 paths / **464 method-routes** across 54 routers. Route-count leaders:
  ```
  /api/v2               55
  /api/docs             39
  /api/admin            37
  /api/investigation    21
  /api/threat-intel     20
  /api/correlations     20
  /api/rc5              19
  /api/die              19
  /api/decode           17
  /api/learner          16
  ```
- **Background workers/schedulers**: 6 armed at startup, all async — none CPU-hot.

---

## 5. Workspace investigation load

Measurement window: single request, backend worker isolated (pid 22538), RSS sampled immediately before and after.

| Input | Elapsed | Response size | Worker RSS Δ | MITRE | narrative? | keys |
|---|---:|---:|---:|---:|---|---:|
| `cmdline` (short PowerShell) | 308 ms | 10.5 KB | +0 MB | 0 | yes | 12 |
| `prose` (vendor narrative) | 152 ms | 11.2 KB | +0 MB | 1 | yes | 11 |
| `sep_csv` (5-row SEP) | 187 ms | 22.5 KB | +0 MB | 5 | yes | 12 |
| `empty` (`""`) | 145 ms | 8.3 KB | +0 MB | 0 | yes | 10 |

Every response is well under the P0.3 budget of 250 KB.

**10× concurrent SEP.csv burst** → peak worker RSS **370 MB** (Δ +1 MB from 369 MB baseline). No leak, no runaway allocation.

---

## 6. What X-Lab removal actually saved (measurable)

| Dimension | Measured saving |
|---|---:|
| Backend source | −20 KB (2 router files deleted) |
| Frontend source (src/) | −400 KB (`nivxforge/lab2/`, popout page, semantic inspector page) |
| API surface | **6 routes removed** (route count 470 → 464) |
| Frontend routes | 3 removed |
| DB collections dropped | 0 (X-Lab wasn't using any) |
| Mongo storage | 0 bytes |
| Backend RSS reduction (post-removal steady) | ≤ 10 MB (unmeasurable given the shared `nivxforge/investigation/pipeline` still loads) — **as the ADR-005 audit predicted** |
| Startup-time change | Statistically indistinguishable (still ~3 s) |
| Complexity | **6 endpoints gone, one architectural naming ambiguity resolved (A/B/C subsystems), one Lab2 renderer shell retired.** |

**The primary win from X-Lab removal was architectural clarity, not RAM. Numbers confirm the audit's forecast.**

---

## 7. Contracts still green (post-audit verification)

- `tests/canonical/api/` regression (P0.2 + P0.3): **47 passed / 4 skipped / 0 fail** — same as post-removal snapshot.
- External-URL Workspace SEP.csv smoke: `mitre=5`, all evidence chains populated, response 22.5 KB.
- External-URL Workspace prose smoke: `mitre=1`, all evidence chains populated, response 11.2 KB.
- Practice Lab `/api/lab/challenge` (admin token): 200 OK.
- Backend + frontend + Mongo supervisor: **RUNNING**.
- Sample1 case row: untouched during audit.

---

## 8. Top consumers, ranked

### 8.1 Top memory consumers

1. **Frontend dev server (webpack + ts-checker)** — 1 236 MB. **Would drop to <200 MB in a production build.** Dev-only.
2. **Backend worker** — 369 MB. Stable under load. Dominated by pandas / pymupdf / litellm imports.
3. **Emergent plugin agent** — 446 MB. Out of scope.

### 8.2 Top storage consumers (application, not deps)

1. `/app/frontend/node_modules` — 1.9 GB (1 110 packages).
2. `/root/.venv` — 1.1 GB (playwright + googleapiclient + pandas alone = 313 MB).
3. `/root/.cache/pip` — 297 MB.
4. `/var/log` — 128 MB.
5. `/app/evidence/screenshots` — 62 MB (RC-series demo captures, not runtime).
6. MongoDB dataSize — 147 MB (storage 44 MB compressed).

### 8.3 Top CPU consumers

Nothing hot at rest. Investigation bursts finish in <350 ms; the profiler shows no long-running compute.

---

## 9. Recommendations — ranked, NOT applied

### P0 (do only when we choose to)
- **None.** No urgent load bottleneck exists post-audit.

### P1 — high value, low risk (candidate future tasks)
- **Frontend production build path in the container** — replace dev-mode `craco start` with `craco build` + static-serve for pod screenshots/testing to reclaim ~1 GB RSS. Only relevant if the pod is memory-constrained for reasons other than NivXRay.
- **Prune 3 dependencies suspected unused** — verify usage of `googleapiclient` (100 MB), `stripe` (24 MB), `botocore/boto3` (30 MB). If not imported by any production route, drop them → ~154 MB smaller venv. **Verify with import graph before touching.**
- **Log rotation** — cap `/var/log/supervisor` and `/var/log` at 10 MB per file (currently unrotated).
- **`__pycache__` sweep** — 28 MB across 193 folders. Harmless but purge-able at build time.

### P2 — nice-to-have hygiene
- **Route inventory** — 464 method-routes across 54 routers is a lot. Some almost certainly belong to legacy paths superseded by the canonical bridge. A read-only ADR-005-style route-audit could identify further candidates. Not urgent.
- **Mongo collection audit** — 64 collections; a read-only pass could identify legacy shadow-observation / experiment collections safe to archive. Do NOT touch `investigation_ssot`, `workspace_cases`, `iocs`, `investigation_sessions` — these are hot Workspace-side.
- **Evidence-folder screenshots** (62 MB) can be moved to an artefacts bucket; they are demo captures, not runtime data.

### 9.1 Explicitly out-of-scope (do NOT touch)
- Shared `nivxforge/investigation/pipeline/**` (Workspace-critical).
- Any Workspace-related route/service — they are protected.
- Sample1, P0.2, P0.3 firewall, evidence chain, canonical bridge — protected.

---

## 10. Conclusion

- The system runs comfortably at **378 MB backend RSS + 147 MB Mongo + zero Redis**.
- X-Lab removal delivered exactly what the ADR-005 audit forecast: complexity reduction, minor source-size drop, negligible RAM change (because shared pipeline stays).
- Nothing here justifies a resource-driven refactor sprint.
- The Timeline MVP (owner's next feature) can be built without any load headroom concern.

**STOP. Awaiting owner direction to resume the Timeline MVP or pursue any of the P1/P2 recommendations.**
