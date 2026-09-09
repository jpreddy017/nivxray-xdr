# Paste-ready — GitHub Release "docs-2026-02-16"

Copy the two blocks below straight into the **New Release** dialog.

---

## Tag
```
docs-2026-02-16
```

## Title
```
NivXRay Docs Refresh · G1 Kill-Chain + URL-Sync + TI-HITS fix
```

## Description (paste into the release body)

```markdown
### 🚀 Highlights
- **G1 · Clean Kill-Chain Attack-Path Graph** — new PuppyGraph-style card *below* the existing (untouched) tactical Attack Graph. Semantic overlays: ⚡ Entry, 🎯 Choke, 👑 Crown Jewel. G1/G2 toggle for analyst preference.
- **TI-HITS matching fix (L0)** — URL→hostname fallback against 8,160-entry local Threat-Intel DB. No more silent misses on query-string-heavy URLs.
- **LOLBAS L1+L2+L3+L5** — 8 new 2025-era bins (`dotnet.exe`, `dnx.exe`, `Dxcap.exe`, `desktopimgdownldr.exe`, `stordiag.exe`, `msconfig.exe`, `PresentationHost.exe`, `Dfsvc.exe`), multi-stage kill-chain scoring, parent-child lineage detection, one-click **Sigma / KQL / SPL** rule export.
- **⭐ Training-Note URL-Sync feature** — paste any article URL (HTML **or PDF**), click SYNC, Claude Sonnet 4.5 condenses it into a directive that's prepended to every future AI investigation. First 4 references already captured live.
- **PDF · Side-by-side GRAPH + CHAIN figure** per payload — clean visual evidence in the auto-generated user guide.

### 🧪 Deployment stress test
- 20 huge single-stage command lines + 10 chained multi-stage payloads
- **30/30 · 100% decode pass rate** · 27/30 LOLBins · 26/30 MITRE · avg 2.4s/payload
- History integrity: every critical field (`input_preview`, `output_preview`, `iocs`, `mitre`, `chain`, `verdict_card`) present on every investigation

### 📋 What triggers on release
This tag fires `.github/workflows/docs-screenshots.yml`:
1. Preflight against prod backend (`NIVXRAY_BASE_URL`)
2. Playwright captures every YAML-registered payload/workflow screenshot
3. Regenerates all 12 export artefacts (PDF/HTML/DOCX × 4 audiences)
4. Attaches them to **this release** as assets
5. Auto-commits refreshed screenshots to `main`

Expected `nivxray-all-guide.pdf`: ≈ 6.8 MB with the new GRAPH+CHAIN pair figures embedded.

### 🐛 Fixed
- TI-HITS returning 0 for common query-string URL variance
- LOLBAS coverage gaps on 2025 .NET LOL binaries
- P2 backlog: side-by-side pair figure in per-payload PDF section
- Contrast issue on the floating training-note modal (typed text was too faint)

### 🩺 Feed hygiene note (informational — not blocking)
- `abuseipdb`: rate-limited (HTTP 429). Retry after 24h.
- `talos`: HTTP 403 due to upstream policy change. Consider dropping or migrating URL. Coverage overlap with CINS / Feodo means no analyst-facing impact.

### 📸 Documentation
Full changelog + backlog: `/app/memory/PRD.md`
Full workflow guide: `/app/GITHUB_RELEASE_CHECKLIST.md`
```

---

## After you publish

1. Actions tab → watch **Docs Screenshots** run go green (5-10 min).
2. Return to this release page → verify 12 assets attached.
3. Emergent chat → **Deploy** → Production. ~90s.
4. Sanity check on prod: `https://nivxray.nivxforge.com/docs` — sign in with admin, open any payload page → PDF should contain the new "GRAPH + CHAIN — visual evidence" figures.
