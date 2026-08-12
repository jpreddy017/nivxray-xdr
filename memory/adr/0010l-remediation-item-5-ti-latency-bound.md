# ADR-0010l · Remediation Item 5 · Bounded TI-lookup latency

**Status**: 🟢 PASS (2026-08-12 · Session-19)
**Scope**: single owner-authorised remediation item (ADR-0010e §10 item 5).
**Companion**: ADR-0010e (Real Investigation Proof · Phase A) · ADR-0010f/g/h/k (Items 1–4) · ADR-0023 (four principles).

---

## 1. Objective (owner directive verbatim)

> Enforce a deterministic 500 ms maximum wall-clock budget for local TI-cache lookups in `/api/analyze`. A slow/unresponsive TI lookup must never stall the investigation pipeline beyond that budget. Preserve the existing TI evidence model: timeout/failure must not become a malicious verdict or fabricated evidence. Preserve existing provider behavior when the lookup completes within the budget.

## 2. Root cause targeted

Real-Investigation Proof §10 flagged that `analysis_core.lookup_ti_hits()`:

- Runs a Mongo query against `db.iocs` (fast under normal conditions but unbounded on network / cluster stalls).
- **Also** calls `enrich_iocs()` — LIVE OSINT providers (VT / AbuseIPDB / OTX / URLScan / Shodan / GreyNoise / Hybrid Analysis) — with no wall-clock guard. Any one slow provider blocks the entire investigation.

`/api/analyze` called this function bare (no `asyncio.wait_for`), so a slow feed could stretch the analyst turnaround past 90 s and effectively stall the deterministic pipeline.

## 3. Implementation (exact changes)

### 3.1 `backend/analysis_core.py` (additive)

- Added `_ti_deadline_seconds()` — reads `NIVX_TI_LOOKUP_DEADLINE_MS` env var (default 500 ms), sanitises invalid / non-positive values back to the 500 ms default.
- Added `lookup_ti_hits_bounded(iocs, layer_iocs=None, deadline_s=None) -> List[hit]` — convenience wrapper.
- Added `lookup_ti_hits_bounded_meta(iocs, layer_iocs=None, deadline_s=None) -> (List[hit], meta_dict)` — same call but also returns a diagnostic `{status: 'ok'|'timeout'|'error', elapsed_ms, deadline_ms}` used by the `/api/analyze` response and by the regression tests.
- Contract locked in the module docstring:
  - `status='ok'` → identical shape to legacy `lookup_ti_hits()`
  - `status='timeout'` → `hits = []` (never fabricated, never raised)
  - `status='error'` → `hits = []` (provider exception swallowed, parity with pre-existing OSINT catch-and-continue inside `lookup_ti_hits`)

### 3.2 `backend/routers/analyze.py` (3 call sites migrated)

- `POST /api/analyze` (sync): `ti_hits = await lookup_ti_hits(iocs)` → `ti_hits, ti_lookup_meta = await lookup_ti_hits_bounded_meta(iocs)` + `log.warning` on non-ok status.
- `POST /api/analyze/stream` (SSE): same migration; non-ok status streamed as a status SSE event.
- `POST /api/analyze/async` (background job): same migration; `ti_lookup_meta` persisted alongside `ti_hits` in the job record.
- The sync response envelope now includes `ti_lookup_meta` (additive field, no removal of `ti_hits`).

### 3.3 `backend/tests/canonical/api/test_item5_ti_lookup_bounded.py` (new)

10 focused regression tests split into three tiers:

| # | Test | Purpose |
|---|---|---|
| 1 | `test_bounded_returns_provider_hits_on_success` | Successful lookup returns identical shape + `status='ok'`. |
| 2 | `test_bounded_returns_empty_on_timeout` | Slow provider → `hits=[]`, `status='timeout'`, no exception raised. |
| 3 | `test_bounded_swallows_provider_exception` | Provider raises → `hits=[]`, `status='error'`. |
| 4 | `test_bounded_convenience_wrapper_returns_list` | Convenience wrapper contract. |
| 5 | `test_deadline_defaults_to_500ms` | Default budget locked at 500 ms. |
| 6 | `test_deadline_env_var_override` | Env-var override honoured (1200 ms → 1.2 s). |
| 7 | `test_deadline_invalid_env_var_falls_back_to_default` | Non-numeric env var → default. |
| 8 | `test_deadline_negative_env_var_falls_back_to_default` | `0` / negative env var → default. |
| 9 | `test_analyze_verdict_stable_across_ti_ok_timeout_error` | **Verdict / MITRE / LOLBAS / risk-score surface is byte-identical across TI ok / timeout / error runs of `/api/analyze`.** |
|10 | `test_analyze_wall_clock_bounded_when_ti_stalls` | `/api/analyze` completes < 2 s when TI provider deliberately sleeps 3 s under a 100 ms TI budget. |

### 3.4 `backend/tests/canonical/ssot/test_ssot_isolation.py`

Two allow-list entries added for the touched files (`backend/analysis_core.py`, `backend/tests/canonical/api/test_item5_ti_lookup_bounded.py`). Static-import + phase-scope invariants remain intact.

**No other file touched.** Frozen corpus untouched. Sample1 untouched. Workspace untouched.

## 4. Test results

### 4.1 Item-5 focused suite
```
tests/canonical/api/test_item5_ti_lookup_bounded.py .......... 10/10 PASS
                                                            (3.18 s wall)
```

### 4.2 Full canonical API suite (post-change)
```
$ pytest tests/canonical/api/ --timeout 60
184 passed · 5 skipped · 12 teardown-only litellm cleanup ERRORs
```
- All 12 "errors" are pytest-xdist / litellm `close_litellm_async_clients` teardown-thread noise (`APIConnectionError: cannot schedule new futures after interpreter shutdown`). Test bodies PASS; only the TestClient exit hook errors. This class of noise is **pre-existing** — the same errors surface on any run that constructs multiple session-scoped TestClients under xdist. **Not Item-5-caused** (verified by isolating `test_size_matches_content_length` and observing the identical teardown error even for a Green test).

### 4.3 Full canonical suite (post-change)
```
$ pytest tests/canonical/ --timeout=60
402 passed · 11 skipped · 4 pre-existing Sample1-DB-hosting failures
```
The 4 failures (`test_a3_3_sample1_fingerprint_unchanged`, `test_a3_3_wave1_and_legacy_collections_untouched`, `test_a1_2_sample1_fingerprint_unchanged`, `test_a2_3_sample1_fingerprint_unchanged`) all require the Sample1-hosting DB, which is not this pod's DB. **Pre-existing per PRD.md; not Item-5-caused.**

## 5. Frozen 12-case corpus regression (Item-4 baseline vs Item-5 post-fix)

Harness re-run against LIVE pod (`REACT_APP_BACKEND_URL`) with the identical frozen corpus at `/app/memory/experiments/rip/corpus.md`. Baseline snapshot preserved at `results.pre_item5.json`; new run at `results.json`.

| Case | Pre-Item5 verdict / MITRE / LOLBIN / IOC | Post-Item5 verdict / MITRE / LOLBIN / IOC | Delta |
|---|---|---|---|
| rip-01-ps-enc-launcher | Malicious 80 / [T1027,T1059.001,T1105,T1562.001,T1564.003] / powershell / 2 | identical | **0** |
| rip-02-mshta-remote-hta | Malicious 90 / [T1105,T1218.005] / mshta / 2 | identical | **0** |
| rip-03-certutil-urlcache | Malicious 70 / [T1105] / certutil.exe,update.exe / (u:1,ip:1) | identical | **0** |
| rip-04-squiblydoo | Malicious 100 / [T1218.010] / regsvr32,scrobj / 2 | identical | **0** |
| rip-05-wmic-process | Malicious 100 / [T1047,T1059.001,T1059.003,T1105,T1218,T1564.003] / cmd,wmic / 2 | identical | **0** |
| rip-06-benign-recon-ps | Benign 10 / [] / [] / 0 | identical | **0** |
| rip-07-netsh-fw-off | Low Risk 20 / [T1562.004] / [] / 0 | identical | **0** |
| rip-08-nested-b64-ps | Malicious 80 / [T1027,T1059.001,T1105,T1140,T1564.003] / powershell / 1 | identical | **0** |
| rip-09-too-short | Benign 0 / [] / [] / 0 | identical | **0** |
| rip-10-empty-input | None 0 / [] / [] / 0 | identical | **0** |
| rip-11-bitsadmin-transfer | Malicious 80 / [T1105,T1197] / bitsadmin / 2 | identical | **0** |
| rip-12-rundll32-poweliks | Malicious 80 / [T1027,T1059.007,T1105,T1218.011] / rundll32 / 1 | identical | **0** |

**Determinism gate: 12/12 stable across two runs (`stable_die=True stable_analyze=True` for every case).**
**Safety gate: no case gained a fabricated verdict; no case lost a legitimate one.**

## 6. Live latency evidence (external `REACT_APP_BACKEND_URL`)

Three probes against the live pod after backend restart, default 500 ms budget:

| Probe input | `ti_lookup_meta.status` | `elapsed_ms` | `ti_hits` | Verdict |
|---|---|---|---|---|
| `certutil -urlcache http://203.0.113.15/x.exe` | **timeout** | **501.31** | 0 | Suspicious 65 |
| `netsh advfirewall set allprofiles state off` | ok | 0.108 | 0 | Low Risk 17 |
| `dir` | ok | 0.083 | 0 | Benign 0 |

- The certutil probe exercises the OSINT sub-branch inside `lookup_ti_hits` — before Item 5 this could stretch to tens of seconds; now it is deterministically capped at ~500 ms.
- Fast paths (no IOCs → no OSINT calls) return sub-millisecond as expected.
- **Verdict SAFETY: the certutil timeout still yielded a Suspicious verdict — TI failure did not manufacture, downgrade, or upgrade the verdict.**

## 7. What Item 5 guarantees (precise)

- **Wall-clock bound**: default 500 ms; env-tunable via `NIVX_TI_LOOKUP_DEADLINE_MS`.
- **No fabrication on timeout**: `hits = []`, never a synthetic malicious entry.
- **No verdict impact**: risk-score / MITRE / LOLBAS output is a pure function of the DIE analyzer + heuristic layers; `ti_hits` is decorative on the response envelope, never fed into `risk_score()`.
- **Observability**: every response carries `ti_lookup_meta.{status,elapsed_ms,deadline_ms}` — analysts and QA can see whether the TI leg contributed or was bounded out.
- **Determinism**: same input → same verdict surface across `ok / timeout / error` runs (test 9 locks this).

## 8. What Item 5 does NOT do (owner-preserved constraints)

- Does NOT introduce a new TI provider.
- Does NOT change the shape of `ti_hits`.
- Does NOT modify Workspace behaviour.
- Does NOT touch UI-DEF-02 (deferred; design directive recorded separately at ADR-0010m).
- Does NOT open P2 Behavioral Evidence Ingestion.

## 9. Four principles compliance (ADR-0023)

| Principle | Status |
|---|---|
| §3a Cruise-Missile Guidance | ✅ Preserved — TI evidence still flows when available; timeout only silences a stalled provider. |
| §3b UI-Truth | ✅ Preserved — no phantom TI hit ever appears when a lookup fails. |
| §3c MITRE Convergence | ✅ Not affected — TI leg does not emit MITRE ids. |
| §3d Evidence-Producer Constraint | ✅ Preserved — TI still evidence, never verdict driver. |
| §3e No Opportunistic Improvement | ✅ Only the exact five requirements shipped. |

## 10. Files touched

```
backend/analysis_core.py                                         (+ ~85 LOC additive)
backend/routers/analyze.py                                       (3 call-site swaps)
backend/tests/canonical/api/test_item5_ti_lookup_bounded.py      (new · 10 tests)
backend/tests/canonical/ssot/test_ssot_isolation.py              (2 allow-list entries)
memory/adr/0010l-remediation-item-5-ti-latency-bound.md          (this file)
memory/adr/0010m-ui-def-02-attack-chain-design-note.md           (design directive for the NEXT item)
memory/experiments/rip/results.pre_item5.json                    (snapshot for delta)
memory/experiments/rip/results.json                              (post-Item-5 run)
```

## 11. Verdict

**🟢 PASS**. Item 5 shipped exactly as scoped. Deterministic 500 ms TI budget in place; slow feeds cannot stall `/api/analyze`. Frozen 12-case corpus completely unchanged. Canonical suite intact.

**Standing down.** Do NOT start the 12-case final regression, UI-DEF-02, or P2 without explicit owner authorisation. The locked sequence remaining is:

```
Item 5 ✅ → 12-case final regression ⏸ → UI-DEF-02 ⏸ → P2 🔒
```
