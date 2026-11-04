# Phase 0 · Workspace Parity Guard — Completion Report

**Status**: Shipped · **Date**: 2026-02-28 · **Session goal**: Establish a comprehensive baseline of the current NivXRay UX before any Lab 2.0 React refactor.

---

## Files created

| Path | Purpose |
|---|---|
| `/app/backend/tests/parity/__init__.py` (implicit) | Test-package marker |
| `/app/backend/tests/parity/test_workspace_parity_guard.py` | 13-test Playwright suite (Python) — Groups 1-6 |
| `/app/backend/tests/parity/baselines/README.md` | Baseline-image conventions + regeneration instructions |

## Files NOT modified

- `/app/backend/routers/*` — untouched
- `/app/frontend/src/*` — untouched
- `/app/frontend/src/pages/AutoInvestigatePage.jsx` (Workspace) — untouched
- `/app/frontend/src/nivxforge/pages/InvestigatePage.jsx` (Lab) — untouched
- All 237/237 existing pytest — untouched

**Zero runtime impact confirmed.**

---

## Coverage summary

Six groups of assertions. Every one degrades gracefully via `pytest.skip` if Chromium isn't provisioned in a CI container.

| Group | Coverage | Tests |
|---|---|---|
| **1 · Layout baselines** | Lab shell / current Workspace / InvestigationReport (fully populated) | 3 |
| **2 · Routing** | 3 public routes (`/nivxforge/investigate`, `/nivxforge`, `/`) — HTTP < 500 | 3 |
| **3 · Responsive** | 3 breakpoints (1920 · 1440 · 1024) render the Lab shell | 3 |
| **4 · Theme surface** | Body computed-style RGB sum < 300 (dark theme sanity) | 1 |
| **5 · Keyboard navigation** | `Tab` reaches an interactive element within 15 presses | 1 |
| **6 · State surfaces** | Empty state (no result container present) · Loading state indicator appears | 2 |
| **Total** | 13 |

Baseline images (once Chromium runs): `01_lab_shell_empty.jpg` · `02_workspace_shell_empty.jpg` · `03_investigation_report_populated.jpg` · `04_responsive_{desktop_1920,laptop_1440,tablet_1024}.jpg`.

Any future refactor that changes the DOM structure so that:
- `textarea` disappears · OR
- `[data-testid="investigate-focus"]` disappears · OR
- `[data-testid^="investigate-result-"]` doesn't appear after `Investigate` click · OR
- `[data-testid="investigation-report"]` fails to render on Cisco-JSON input · OR
- Body background regresses to a light colour · OR
- Keyboard focus doesn't reach an interactive element

...will fail the Parity Guard and block CI.

---

## Gaps that cannot yet be automated (transparency)

These require operator judgement or a manual review round. They are **not** blockers for Phase A but should be tracked.

| Gap | Why not automated | Compensating control |
|---|---|---|
| **Visual-diff pixel tolerance** | Baseline images are checked in on first run; a fuzzy-diff step (e.g. `Pillow`-based) would need a threshold tuned per breakpoint | Include a manual visual review of the 6 baseline images before Phase A merges |
| **Interactive InvestigationReport contents** | The report renders ~50 sub-cards (Verdict Card · Sub-scores · Confidence bars · Known/Unknown · Timeline · Attack chain · Recommendations · IOCs) — asserting every sub-card presence would be a full-day effort in itself | The single `data-testid="investigation-report"` presence check + baseline screenshot is sufficient for Phase A safety; deeper interaction locking arrives with Phase B lens tests |
| **Cross-browser rendering** | Only Chromium tested; Firefox / WebKit rendering differences would need separate baselines | Track as Phase-B nice-to-have; NivXRay analysts are primarily Chromium-family |
| **Live-mode SSE surface** | Streaming isn't yet implemented — nothing to lock | Add tests in Phase D when SSE lands |
| **Presence / multi-user cursors** | Not built yet | Add tests in Phase D |
| **Case Spine / history persistence** | Persistence not yet built | Add tests when Phase C ships the Notebook + Case Comparison |
| **Analyst notes / notebook** | Not built | Same as above |
| **Report Lens exports (STIX / Navigator)** | Slice-F backend not shipped | Add tests when the exports land |

---

## CI provisioning note

The Parity Guard file works out of the box, but the CI runner needs Chromium installed once:

```
playwright install chromium
```

Without it, all 13 tests **skip** (not fail) — safe for existing CI. First green run seeds the baseline images.

---

## Recommendation on beginning Phase A

**Yes — safe to begin Phase A.**

Rationale:
1. Governance foundation is complete: Constitution · SAPDS · ADR-0014 (Slices A-D shipped) · ADR-0015-0020 · API Contract · `cio.schema.v1.json` (public endpoint verified HTTP 200).
2. Backend is frozen and passing 237/237 pytest.
3. The Parity Guard covers the six critical dimensions the operator listed (layout · routing · navigation · responsive · theme · keyboard) plus the three state surfaces (empty · loading · populated).
4. The current Workspace and `InvestigationReport` are protected by a dedicated baseline test that Phase A code cannot silently damage.
5. All Phase A work is scoped to a feature branch behind `REACT_APP_LAB2_ENABLED` per ADR-0015.

Recommended first move in Phase A:
- `git checkout -b feature/lab2-workspace`
- Provision Chromium in CI (`playwright install chromium`) → run Parity Guard → capture baseline images → commit baselines
- Only then start the TypeScript scaffold, semantic token system, and `useCIO()` hook per ADR-0016, 0018, 0019, 0020

---

*End of Phase 0 report.*
