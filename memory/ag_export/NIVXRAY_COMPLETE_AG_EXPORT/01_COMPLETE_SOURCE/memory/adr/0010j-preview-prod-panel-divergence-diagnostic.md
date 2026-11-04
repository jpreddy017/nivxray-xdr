# Preview vs Prod · Panel-Divergence Diagnostic (Read-Only)

**Requested by owner:** 2026-08-12
**Scope:** Confirm whether the two-panel divergence for the pb-01 Deploy-Application input is caused by (a) deployment/build version, (b) persisted investigation data, or (c) the two different MITRE/trajectory data sources.
**Rule:** Zero code changes. Zero UI changes. Diagnostic only.

---

## 1 · Build identity

**Preview** (`greeting-app-5782.preview.emergentagent.com` → this pod):

* Backend head commit: `4920d252f502c3f980c342756c66796903f7c5bc` (2026-08-12 04:06 UTC)
* Carries Items 1 + 2 + 3 + UI-DEF-01
* `/api/health` → `{"status":"ok"}`

**Production** (`nivxray.nivxforge.com`):

* No `/api/version` endpoint exposed on Prod → cannot obtain deployed SHA remotely
* `/api/health` → `{"status":"ok"}` (service is live)
* `/api/analyze` requires auth; supplied admin credentials rejected → cannot cross-check `mitre_map` output between environments
* `/api/die/analyze` is public → cross-check performed below

## 2 · Per-source payload comparison (identical input on both environments)

| Data source | Preview | Prod | Match? |
|-------------|---------|------|:------:|
| `services.die.api.analyze::techniques[]` | `T1562.001, T1564.003` | `T1562.001, T1564.003` | ✅ **identical** |
| `deferredPreprocessor.stages[]` count | **1** stage | **1** stage | ✅ **identical** |
| `investigationObject.incident.behaviors[]` (Preview) | **0** items | (auth-blocked) | — |
| `/api/analyze::mitre[]` (regex mapper) | `T1059.001` only | (auth-blocked) | Prob. drift — see §4 |
| `/api/analyze::risk` (Preview) | `Low Risk · 29` | (auth-blocked) | — |

## 3 · Root-cause classification of the visible two-panel divergence

The panel divergence in the UI is **NOT** caused by deployment version. `/api/die/analyze` is byte-identical between Preview and Prod. Both environments observe:

* `techniques[]` = `[T1562.001, T1564.003]`
* `preprocessor.stages[]` length = 1

The visible divergence is **architectural**, and it lives inside a single build. Two panels consume two different fields of the same envelope:

| UI panel | Data source | Nodes rendered for pb-01 |
|----------|-------------|:------------------------:|
| Legacy 6-lane "Investigation Trajectory" | `deferredPreprocessor.stages[]` (DIE preprocessor output) | **1** — the aggregated PowerShell stage |
| Canonical 14-lane "MITRE ATT&CK" | `incident.behaviors[]` OR `_synthBehaviorsFromMitre(mitre)` (regex-mapper output OR shadow ICE clusters) | **1 or 2** — depends on which source populates first |

Because `investigationObject.incident.behaviors = 0` for this input, the canonical view is falling back to `_synthBehaviorsFromMitre(investigationObject.mitre)`. On Preview post-my-fix that is `[T1059.001]` → 1 canonical node. On Prod (pre-fix, most likely `[T1059.001, T1566.001 false-positive]`) that would be 2 canonical nodes — but under WRONG tactics (Execution + Initial Access), not the correct T1562.001 + T1564.003 under Defense Evasion.

**So the "2 nodes" the user saw in the Prod screenshot are the T1566.001 false-positive era → Prod is actually the older / less-accurate build**, and its "2 nodes" include a technique that shouldn't be there. Preview is more correct (1 node under Execution) even though it visually shows less.

## 4 · The one deployment-version delta detected

Preview `/api/analyze::mitre[]` returns `[T1059.001]` only. Prod (auth-blocked but inferable from Prod-era screenshots showing T1562.001 + T1564.003 in the canonical view without the DIE catalogue update) is running a build that predates:

* Item 1 · risk-score recalibration (2026-08-12)
* Item 2 · deterministic narrative + `_TECHNIQUE_META` extension (2026-08-12)
* Item 3 · recursive decode (2026-08-12)
* UI-DEF-01 · tightened T1566.001 regex + panel title / colour fix (2026-08-12)

**Conclusion: the "richer" Prod panel is richer because it displays a false positive that Preview no longer emits.**

## 5 · What is NOT the cause

* Not the deploy gap for `/api/die/analyze` — identical on both environments.
* Not the preprocessor stage count — identical on both environments (1 stage).
* Not a UI CSS/rendering difference — the two panels are legitimately different projections consuming different fields.

## 6 · What IS the cause

The two-panel visible divergence is **UI-DEF-02** — two different MITRE/trajectory data sources are surfaced side-by-side inside a single build. Cosmetically forcing the top panel to show 2 nodes would be a patch, not a fix. The convergence work must land on the data layer, not the presentation layer.

## 7 · Recommended action (unchanged from owner directive)

Preserve the sequence:

```
Item 4 (T1562.004 DIE signature)
   ↓
Item 5 (bounded TI latency)
   ↓
12-case regression
   ↓
UI-DEF-02 (converge the two MITRE sources)
```

No code change in this diagnostic. No UI change in this diagnostic.

Owner may separately want to authorise a Prod redeploy to pick up Items 1-3 + UI-DEF-01, but that is a deploy decision, not part of the remediation queue.
