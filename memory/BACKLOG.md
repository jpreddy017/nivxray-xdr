# NivXRay — Backlog (post-v1.5.7)

_Captured 2026-02-28. Kept short and analyst-outcome-driven._

---

## UI cleanup (defer to next UI-focused release)

Trigger: whenever the next UI refactor happens. Not urgent.

- [ ] Delete `/app/frontend/src/pages/DashboardPage.jsx` (dormant since v1.5.7 — has a `TODO(next-ui-refactor): DELETE THIS FILE` marker at top)
- [ ] Remove any unused imports, CSS, assets, snapshots referring to `DashboardPage`
- [ ] Verify webpack tree-shaking doesn't include dormant Dashboard code in the production bundle (`yarn build && du -sh build/static/js/*`)
- [ ] Remove stale docs / screenshots mentioning the Dashboard tab from `/app/memory/` and README
- [ ] Consider tab-trim experiment (only after real-world usage data): promote BATCH and HEATMAP into ADMIN if the SOC log confirms they're rarely used in daily investigations

---

## v1.6.0 — Analyst Trust & Explainability (SME-prioritized)

Ship in this order. Each item ships only when the prior one is stable + regression-locked.

### 1. Semantic Command Understanding (P0 · highest priority)
- Explain plain-text command lines in analyst language
- Cleanly separate **facts** (observed tokens, decoded bytes) from **inferences** (behavioural conclusions)
- Zero AI hallucinations in the explanation layer — every claim must trace to a canonical Evidence object
- Ties into existing `/app/memory/V1_6_0_PLANNING.md` semantic-def-use design

### 2. Evidence-backed explanations (P0)
- Every verdict/behaviour/intent conclusion must cite the exact command-line tokens or decoded content that support it (line + col spans)
- UI: hover a conclusion → highlight the source evidence in the input/decoded panels
- Backend: add `evidence_refs: [{stream, offset, length, token}]` to every intent + verdict object

### 3. Confidence scoring (P1)
- Three tiers: **Observed** (direct evidence), **Likely** (chained inference from multiple observed facts), **Unknown** (no supporting evidence, do not fabricate)
- Never emit a claim without one of these three tags
- UI treatment: colour + icon per tier so analysts scan trust levels at a glance

### 4. Vendor / application recognition (P1)
- Identify applications only when there's **sufficient** evidence (executable name AND at least one confirming signal: signature match, known argument pattern, code-signing publisher, or path convention)
- Ban single-flag inferences (e.g. "haszoomim" ≠ Zoom)
- Add an ambiguous/unknown state — better to say "unknown application (only zoom-like flag observed)" than to guess

### 5. Analysis Performance metrics (P2)
- New "Analysis Performance" section in the investigation panel
- Show: total end-to-end time · per-stage timings (Input Understanding → CRE → RTE → Intent → Behavior → Verdict → Graph → Report)
- Highlight slow stages so analysts know when a delay is upstream (huge input) vs decoder-side
- Piggybacks on the v1.5.6 offload infrastructure — timings already exist in the executor, just need surfacing

---

## Real-world log (feed this while using NivXRay in the SOC)

`/app/memory/REAL_WORLD_LOG.md` — one line per case:
```
2026-03-XX · sample-class · verdict-correct? · what-missed · would-fix-priority
```
After ~10 real entries, prioritize v1.6.0 backlog against actual gaps.
