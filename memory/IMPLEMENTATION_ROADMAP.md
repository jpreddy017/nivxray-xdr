# NivXForge — Implementation Roadmap

_Status: **ACTIVE**. This is the only document that authorises engineering work.
Sibling to `/app/memory/PRODUCT_CHARTER.md` (permanent) and
`/app/memory/NORTH_STAR.md` (aspirational)._

_Established 2026-02-28._

---

## 1 · Entry gate — mandatory for every roadmap item

A feature is added to §3 only after ALL of the following are satisfied:

```
Observed Need
    ↓
Repeated Evidence     (≥ N similar real cases in REAL_WORLD_LOG.md)
    ↓
Architecture Decision Record (ADR)     (rationale + tradeoffs, checked into repo)
    ↓
Charter compatibility check            (no Rule 1-7 violation)
    ↓
Workspace Protection review            (compatibility contract satisfiable)
    ↓
Roadmap approval                       (this file)
    ↓
Implementation
    ↓
Validation                             (regression + benchmarks + workspace compat)
    ↓
Release
```

No shortcut. No exceptions. If it's not in the North Star it doesn't
even reach the gate.

---

## 2 · Current state

| Field                              | Value |
|-------------------------------------|-------|
| Real SOC cases reviewed (log)       | 1     |
| `Unknown` verdicts                  | 0     |
| Incorrect verdicts                  | 0     |
| `Incorrect Reasoning` cases         | 1 (Case 0001 — closed) |
| Top missing evidence                | — (single-case; not yet a signal) |
| Phase 1b justified?                 | **No** |
| Workspace protection status         | Enforced |
| Compatibility contract              | Not yet defined (no NivXForge code) |

Source of truth: `PRODUCT_CHARTER.md §4.5` scorecard.

---

## 3 · Scheduled features

### Phase 0 · Platform Foundation — **COMPLETE** (Feb-2026)

Foundational infrastructure only. Zero analytical features. Zero
Workspace modifications. Router dormant per Decision A1.

Delivered:

- `/app/backend/nivxforge/` — isolated package skeleton
- `config.py` — `FORGE_*` env prefix, `/nivxforge` route prefix, `forge_` Mongo prefix
- `router.py` — dormant FastAPI router (not mounted in `server.py`)
- `core/cio.py` — Canonical Investigation Object (append-only, provenance-required)
- `core/evidence.py` — Evidence Ledger (`Finding · Evidence · Engine · Confidence`; no-unsupported-conclusion enforced)
- `engines/base.py` — Engine `Protocol` (interface only, zero implementations)
- `observability/logging.py` — isolated `nivxforge.*` logger namespace
- `/app/frontend/src/nivxforge/` — reserved namespace, no UI
- `tests/` — foundational invariants:
  - `test_cio.py` — append-only, provenance, no overwrite
  - `test_evidence.py` — no unsupported conclusion, bounded confidence, frozen
  - `test_engine_interface.py` — Protocol conformance
  - `test_router_prefix.py` — every route under `/nivxforge`
  - `test_workspace_isolation.py` — static AST scan: zero Workspace imports
  - `test_workspace_compatibility.py` — router not registered, protected paths intact, no side-effect imports

Workspace files modified: **zero**.

### No further phases scheduled.

Everything else remains in the Candidate queue (§4) or in `NORTH_STAR.md`.

---

## 4 · Candidate queue (needs evidence, NOT yet scheduled)

Ordered by likely evidence-arrival, not ambition. Each candidate stays
here until the entry gate is satisfied.

| Candidate                          | Evidence source                                | Blockers            |
|------------------------------------|------------------------------------------------|---------------------|
| Verdict-Evidence Gating            | Gap #2 from Case 0001 · needs recurrence       | 1 case only         |
| Recipe Self-Reproducibility        | Case 0001 root cause · handler args persistence| Frontend guard covers today's harm |
| Evidence Ledger (server-side)      | Charter Rule 3 · adopt shape on next verdict pass | Awaiting verdict work |
| Semantic Vendor Recognition (Phase 1b) | Missing-Evidence tally (executable/signer)    | Awaiting 20-30 cases |
| Knowledge Graph                    | Multi-artifact correlation demand              | No demand signal yet |
| Consensus Engine                   | Ties verdict evidence to Gap #2 justification  | 1 case only         |
| Plugin Framework                   | Emerges when ≥ 3 engines share interface       | Not yet             |
| Event Bus                          | Emerges when engines outnumber direct calls    | Not yet             |
| Session Manager                    | Multi-turn investigations demand               | No demand signal yet |
| Performance Profiler UI            | Analyst timing complaints (none yet)           | No demand signal yet |

---

## 5 · Housekeeping (small, low-risk, always allowed)

Zero-risk items that don't need the full gate — must still pass Charter
and Workspace-protection review before merging:

- Documentation updates (PRD, CHANGELOG, ROADMAP itself)
- Test coverage for existing behavior
- Deletion of confirmed dead code (e.g. `DashboardPage.jsx`)
- Log tidying / observability improvements that don't change behavior

Nothing in §5 justifies opening a new engine or a new subsystem.

---

## 6 · Working rhythm

1. Analyst investigates a real case using NivXRay Workspace.
2. Case logged in `REAL_WORLD_LOG.md` under one of the four outcome
   buckets (`Correct` / `Missing Evidence` / `Incorrect Reasoning` /
   `Incorrect Verdict`).
3. Missing-Evidence tally in `PRODUCT_CHARTER.md §4.5` scorecard
   updates.
4. Corpus-quality review every 20-30 cases.
5. When scorecard says `Phase 1b justified? Yes`, the top
   Missing-Evidence row earns an ADR and enters §3 above.

That's the only path from user pain to code.

---

## 7 · Release cadence

- **NivXRay Workspace** — v1.6.x maintenance only. No feature releases
  until Validation Mode delivers evidence.
- **NivXForge** — no releases until §3 has at least one committed
  feature that has passed §1.

---

## 8 · Why this file is short

Because the discipline is:

> If we haven't earned the right to build it, we don't schedule it.

Length here grows only from operational evidence. Not from ideas.
