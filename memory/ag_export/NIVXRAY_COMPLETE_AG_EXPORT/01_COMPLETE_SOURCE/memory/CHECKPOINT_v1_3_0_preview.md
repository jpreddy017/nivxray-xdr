# CHECKPOINT · v1.3.0-preview (pre-Excel-analysis)

**Date:** February 2026
**Preview URL:** https://greeting-app-5782.preview.emergentagent.com
**Prod URL:** https://nivxray.nivxforge.com (still on v1.2.0)

## State snapshot

### ✅ What's on Preview right now (stable, tested)
- v1.2.0 code (all shipped to Prod on GitHub tag `v1.2.0`, Jul 18 2026)
- v1.3.0-preview additions:
  - **12 CTI sources absorbed** (Overlord/Gurucul + ShadowRecruit/Seqrite + LegacyHive + Finger/BleepingComputer + Wiz M&M GitHub Actions + Socket Jscrambler + Cypro Everest + InfoSec Mag ransomware + RedCanary Gamarue + Ars ESXi + TrendMicro Patriot Bait + BleepingComputer ClickLock macOS)
  - **192 MITRE heuristics** (v1.2.0 had 100 → +92)
  - **117 YARA-lite rules** (v1.2.0 had 40 → +77)
- **Batch pipeline bug fixes** (Feb-2026 · /app/backend/routers/batch_test.py):
  - LOLBAS field was empty on ALL batch rows because `_run_single` looked for `name`/`id` keys but `scan_lolbas()` returns `binary`. Fixed by falling back to `binary` first.
  - MITRE aggregation only used `mitre_map()` heuristics, ignoring the MITRE tags baked into LOLBAS registry entries. Now folded together — a certutil-only payload correctly surfaces `T1105, T1140, T1218` instead of just `T1105`.

### 📊 Test coverage
- 179/179 pass on Preview across v1.2.0 batch + Golden Vault + Real-World Battery
- Zero regressions after v1.3.0-preview additions

### 🎨 UI + endpoint additions still on Preview only
- Colour-coded STATUS bar (INFO/OK/RUNNING/WARN/ERROR)
- `TRADECRAFT DETECTED` chip banner
- Smart TI-HITS empty state
- `POST /api/emit/sysmon` endpoint
- Blind XOR archetype `BLIND_XOR_SINGLE_BYTE`
- AI-DECODE plaintext short-circuit

## How to roll back

### Option A · Roll back the whole Preview to a prior stable checkpoint
1. Open Emergent chat UI → click `Rollback` in the chat menu
2. Pick the commit immediately BEFORE this checkpoint (any commit ≤ v1.2.0-tag)
3. Free of cost, instant

### Option B · Roll back only the batch-pipeline changes
File touched:
- `/app/backend/routers/batch_test.py` — 2 changes around lines 205–225 (search for `Feb 2026 v1.3.0 · Fold LOLBAS-provided MITRE`)

Revert by restoring the previous shape:
```python
"mitre_ids": ",".join(sorted({m.get("id", "") for m in mitre if m.get("id")})),
"lolbins":   ",".join(sorted({(l.get("name") or l.get("id") or "").strip()
                              for l in lolbas
                              if (l.get("name") or l.get("id"))})),
```
That returns to the Major2/Major3 (buggy) behaviour.

### Option C · Roll back a Prod deploy
Prod is on `v1.2.0` tag. Rolling Prod requires:
1. Emergent → Deployments tab → find the current live deploy → click `Rollback to previous`
   (Prod hasn't received v1.3.0 changes yet, so this only applies once we redeploy.)

## Ground rules for the Excel-analysis session next
- ✏️ ALL new changes stay on Preview only until user says "ship to Prod"
- 🔒 Golden Vault regression tests must still pass after any change
- 📝 Every change gets a comment tag `Feb 2026 v1.3.0 · <reason>` for traceability
- 🚫 Do NOT overwrite `.env`, `requirements.txt`, `package.json` wholesale
- ⚡ If a change breaks the golden vault → auto-revert and ask user before proceeding

## Files that carry the v1.3.0-preview changes
- `/app/backend/operations.py` — 92 new MITRE + 77 new YARA rules
- `/app/backend/wrapper_archetypes.py` — BLIND_XOR archetype + hexfamily defensive
- `/app/backend/chain_analyzer.py` — TI enrichment on aggregate
- `/app/backend/routers/ai.py` — plaintext-guard `_is_already_plaintext()`
- `/app/backend/routers/sigma.py` + `/app/backend/sigma_generator.py` — Sysmon emitter
- `/app/backend/routers/batch_test.py` — LOLBAS + MITRE aggregation fix
- `/app/frontend/src/pages/WorkspacePage.jsx` — coloured STATUS bar
- `/app/frontend/src/components/ThreatAnalysis.jsx` — TRADECRAFT chip callout + smart TI-HITS empty state
- `/app/backend/tests/test_v1_2_0_batch.py` — 44 tests

## Backup ping-of-life
Backend health:  `curl -sf https://greeting-app-5782.preview.emergentagent.com/api/health`
Frontend health: browser hard-refresh → landing page renders
DB health:       `investigations` collection has ≥ 1233 docs for admin@nivxray.com (Preview)

**End of checkpoint document.**
