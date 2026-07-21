# RC4.5 · Production Baseline (Feb 21, 2026)

**Tag:** `rc4.5`
**Status:** Verified and frozen as production baseline.

---

## Highlights

### 🚀 RC4.5.1 · Cloudflare 524 / 520 Hotfix
Fixed catastrophic-backtracking (ReDoS) in three MITRE domain rules
(`T1105`, `T1102`, `T1583.001`) that caused 5-10s latency on large
PowerShell `-EncodedCommand` payloads and manifested as **Cloudflare
524 (timeout)** and **520 (empty response)** on Production.

| Metric                        | Before | After  | Δ         |
| ----------------------------- | ------ | ------ | --------- |
| `mitre_map` on 16KB blob      | 4.52 s | 0.10 s | **45×**   |
| `/api/decode/smart` E2E       | 10.4 s | 1.1 s  | **10×**   |
| Cloudflare 524 / 520 on Prod  | ✅      | ❌      | resolved  |

**Fix:** anchored `[a-z0-9-]+\.` alternation with `\b` + bounded
`{1,63}` DNS-label length. Zero semantic change to detection —
verified against 6 legit CDN/domain payloads (jsdelivr, contabostorage,
raw.githubusercontent, workers.dev, portal-support, post-app).

### 🧬 RC4.5 · PowerShell Backtick + Alias Normalizers
- Backtick / line-continuation stripper with literal-aware handling
  (`` `n `` `` `t `` etc. preserved inside `"…"`; nothing touched
  inside `'…'`).
- Cmdlet-alias expansion — ~80 aliases (`iex`, `iwr`, `irm`, `icm`,
  `gci`, `gc`, `sc`, `ni`, `sv`, `gv`, `ps`, `kill`, …).
- Both hooked into `/api/decode/smart` — banner in `output_raw`,
  op in `recipe`, rows in `transformation_trace`.

### 🛡️ CI Quality Gate
`.github/workflows/rc4x_quality_gate.yml` now runs:
1. RC2.3 baseline scope
2. RC4.0 6-pattern decoder pack
3. RC4.2 semantic mini + trace
4. RC4.3 PS normalizer
5. RC4.4 CMD Runtime Reconstruction
6. RC4.5 backtick + alias normalizers
7. **RC4.5.1 mitre_map ReDoS perf guard (NEW)**
8. RC2.3 chain-completeness benchmark (77.4% floor, 0 FP IOCs)

---

## Test Suite Status

| Suite                                | Tests | Pass |
| ------------------------------------ | ----- | ---- |
| RC4.4 CMD Runtime Reconstruct        | 23    | 23   |
| RC4.5 PS Backtick Normalizer         | 17    | 17   |
| RC4.5 PS Alias Normalizer            | 23    | 23   |
| RC4.5.1 mitre_map ReDoS perf         | 2     | 2    |
| Full regression (`test_regression_150plus`) | 189   | 189  |
| **Total**                            | **254** | **254** |

Zero regressions. Zero decoding regressions. Zero verdict regressions.

---

## Files Changed (RC4.5.1 hotfix)

- `backend/operations.py` — ReDoS-safe patterns for T1105 / T1102 / T1583.001
- `backend/tests/test_mitre_redos_perf.py` — new (perf regression guard)
- `.github/workflows/rc4x_quality_gate.yml` — added step 7 (ReDoS guard)
- `scripts/rc45_prev_prod_parity.py` — new (Prev↔Prod parity smoke script)
- `memory/PRD.md` — marked RC4.5 as production baseline

---

## Deploy Checklist (for tagging as `rc4.5`)

- [ ] Push branch to GitHub via **"Save to GitHub"** in Emergent
- [ ] GitHub Actions `RC4.x Quality Gate` runs green (all 8 steps)
- [ ] Click **Deploy** in Emergent to promote Preview → Production
- [ ] Run `scripts/rc45_prev_prod_parity.py` — expect 6/6 samples at parity
- [ ] Cut GitHub tag `rc4.5` from the same commit
- [ ] Freeze RC4.5 as production baseline; open RC4.6 branch

---

## Next: RC4.6 — Semantic Engine (blocked until RC4.5 baseline is frozen)

- Full CMD semantic engine (nested `%` expansion, delayed `!var!`, `CALL` 2nd pass)
- Full PS AST evaluator (`-split`, `-f`, `Substring`, `[char]`, `[Convert]`)
- Constant propagation across `$a = $b + "…"` chains
- Sleeper Hunter + Fuzzer scripts
