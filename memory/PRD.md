# NivXRay — Sprint Roadmap (v1.6.0 · Deterministic-First Pivot)

**Locked direction (from `Ideas_updated.docx` · Feb 2026)**: The deterministic
engine is the product. AI is an **opt-in analyst assistant**, never the
core decoder. Everything must work offline.

---

## Session 1 (DONE · this commit)

| # | Deliverable | File(s) |
|---|---|---|
| 1 | Global AI toggle — env default + admin override with `/api/ai/toggle` GET/POST | `routers/ai.py` |
| 2 | AI admission check gates every AI endpoint | `routers/ai.py::_ai_admission_check` |
| 3 | Credit guard: rate limit (10/h, 50/d), budget cap (500 credits/mo), SHA1 cache | `ai_credit_guard.py`, `.env` |
| 4 | Modular plugin skeleton | `/app/backend/decoders/`, `/normalizers/`, `/extractors/`, `/heuristics/` |
| 5 | First decoder plugin — `base64-decode` proving the contract | `decoders/base64.py` |
| 6 | Regression lock extended from 12 → 15 tests | `tests/test_regression_lock.py` |
| 7 | Env-tunable SLAs | `.env` — NIVX_AI_ENABLED, NIVX_AI_DEADLINE_S, … |

---

## Sprint plan (2 weeks)

### Priority 1 — Recursive Decode Engine (Session 2)
- Port existing decoders into `decoders/*.py` plugin files:
  base32, base58, base85, hex, xor, gzip, zlib, lzma, brotli,
  utf16, reverse, rot13, rot47, url, html, unicode, decimal, octal
- Refactor `smart_decoder.py` to iterate `decoders.all_plugins()` and pick
  by `detect()` confidence; never stop until no plugin above threshold.
- Add hard recursion cap (default 12 layers) + wall-time cap (5 s per input).

### Priority 2 — Decoder Coverage (Session 2/3)
- Add Base58, Base85, Brotli, LZMA (missing today).
- Auto-detect Gzip/Zlib members inside larger buffers.
- Nested archive extraction (ZIP/CAB/GZip).

### Priority 3 — PowerShell Reconstruction (Session 3)
- `[char]0x41` + `[char]65` + `[char]65,66,67 -join ''`
- `-f` operator format-string reconstruction
- `${env:X}` / `$env:X` expansion
- IEX cradle un-wrap (`(New-Object Net.WebClient).DownloadString()`)
- Reverse-array + Split/Join + Replace

### Priority 4 — CMD Reconstruction (Session 3)
- `^` in-string escape (already have basic strip-carets)
- `%VAR%` env expansion (recursive)
- `!VAR!` delayed expansion
- `&&`, `||`, `|` chain segmentation for per-stage analysis

### Priority 5 — IOC Extraction (Session 4)
- Move to `extractors/ioc.py`
- Add named pipes, mutex, service names, scheduled task names,
  API-call names (DLLs + exports), user-agent strings

### Priority 6 — MITRE Mapping (Session 4)
- Move to `extractors/mitre.py`
- Expand rule library from ~40 → 150 techniques
- Include ATT&CK sub-techniques
- Emit per-technique `confidence` + `reason` (as per Ideas doc)

### Deferred (post-sprint)
- Priority 7 — Threat scoring family heuristics (18-20 family files under `heuristics/`)
- Priority 8 — Knowledge base + Jaccard similarity ("94% similar to previous DarkGate")
- UI: Timeline view, collapsible cards, PDF export
- Performance: streaming decode, memory optimisation

---

## Non-negotiables

- **Do NOT remove existing features** — backward compatibility preserved.
- **Every decoder plugin ships with pytest unit tests.**
- **Every archetype ships with 2+ real-world samples.**
- **Regression lock (`test_regression_lock.py`) runs before every deploy.**
- **AI is opt-in. Deterministic works when AI is OFF.**

---

## Success criteria (end of sprint)

- ✅ 200+ archetypes (from 71)
- ✅ 18+ codec plugins in `decoders/`
- ✅ Full PS + CMD reconstruction
- ✅ 150+ MITRE techniques mapped
- ✅ AI-disabled mode produces analyst-ready reports (IOCs, MITRE, verdict, decode chain, LOLBAS)
- ✅ 100% regression pass on the multi-layer battery
- ✅ Modular architecture enables new decoders in <30 min

---

## API surface (added in Session 1)

- `GET  /api/ai/toggle` — current toggle state
- `POST /api/ai/toggle` — admin flips it (`{enabled: bool}`)
- `GET  /api/ai/budget` — monthly credit burn dashboard
- `POST /api/ai/auto-decode` — now respects admission check + credit guard
- `GET  /api/benchmark/multilayer` — battery report (12/12 pass)

---

## Backlog stays parked

- P0 Auto-Escalation Orchestrator SLAs (Q1-Q5 still open — user hasn't answered)
- P0 L4 NivX Crucible sandbox — deferred **indefinitely** per Ideas_updated.docx ("NO sandbox")
- P1 Qwen fine-tune activation — parked
- Learner auto-loop to L4 — blocked on L4 (which is now cancelled), redirect to L1 archetype auto-promotion
- Multi-tenant SaaS (P3)
- Per-feature snapshot rollback (P3)
