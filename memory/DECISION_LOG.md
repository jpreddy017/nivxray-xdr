# NivX · Decision Log

_One-page chronological index of every governance decision. Every row
links back to the authoritative document that carries the full
rationale. This log is read-only history — never edit past rows._

## How to use

- **Read:** newest at the top, oldest at the bottom.
- **Append:** add a row when an ADR is Accepted / Rejected / Superseded,
  when a Phase closes, or when a Charter / North Star clause changes.
- **Never rewrite:** if a decision is reversed, add a NEW row citing the
  ADR that supersedes the old one.

## Entries

| Date | Ref | Decision | Status | Source |
|---|---|---|---|---|
| 2026-02-28 | Governance | Add lightweight Decision Log to complement ADRs | Accepted | `DECISION_LOG.md` (this file) |
| 2026-02-28 | Phase 0 | NivXForge router remains **dormant** — not mounted in `server.py` | Accepted (Decision A1) | `PHASE0_COMPLETION.md §2` |
| 2026-02-28 | Phase 0 | Retain the two pre-plan scaffolding files (`__init__.py`, `config.py`) | Accepted (Decision B1) | `PHASE0_COMPLETION.md §2` |
| 2026-02-28 | Phase 0 | NivXForge Platform Foundation — isolated package, CIO, Evidence Ledger, Engine Protocol, tests | Accepted · CLOSED | `PHASE0_COMPLETION.md` |
| 2026-02-28 | Governance | Every phase after Phase 0 requires an ADR with 6 mandatory sections | Accepted | `IMPLEMENTATION_ROADMAP.md §1` + `adr/README.md` |
| 2026-02-28 | Governance | Adopt three-document governance triad (Charter · North Star · Roadmap) | Accepted | `PRODUCT_CHARTER.md` · `NORTH_STAR.md` · `IMPLEMENTATION_ROADMAP.md` |
| 2026-02-28 | Charter | Add Validation Mode (§4.5) — tri-state verdict, corpus quality review, scorecard, handoff instruction | Accepted | `PRODUCT_CHARTER.md §4.5` |
| 2026-02-28 | Charter | Every real case must resolve into exactly one of four outcome buckets | Accepted | `PRODUCT_CHARTER.md §4.5` (case review workflow) |
| 2026-02-28 | Hotfix | PS_ASCII_XOR_IEX output-selection fix in `selectCanonicalOutput.js` (Case 0001) | Accepted · Verified in preview | `PRD.md` · `REAL_WORLD_LOG.md` Case 0001 |
| 2026-02-28 | Deferred | Delete `DashboardPage.jsx` (Workspace housekeeping) | Deferred | Requires separate Workspace approval |
| 2026-02-28 | Deferred | `xor-brute` hard input-size cap (Workspace technical debt) | Deferred | Requires separate Workspace approval |
| 2026-02-28 | Deferred | Verdict-Evidence Gating (Gap #2 from Case 0001) | Deferred — evidence insufficient | Awaits repeated cases per Charter P-C |
| 2026-02-28 | Deferred | Recipe self-reproducibility (server-side hardening) | Deferred | Frontend guard covers current harm; awaits scale evidence |
| 2026-02-28 | Mode | Project transitions to **maintenance mode** — evidence-gated development only | Active | `IMPLEMENTATION_ROADMAP.md §7` |

## Standing operating rules (in force)

1. No implementation without evidence.
2. No Workspace modification without explicit approval.
3. No roadmap addition without an accepted ADR.
4. Compatibility + isolation tests are mandatory and remain green.
5. Evidence **quality** outweighs evidence **quantity**.
6. **Quarterly governance review** — every ~3 months, or after a
   meaningful accumulation of real cases, revisit:
   - Does recurring evidence justify drafting a new ADR?
   - Do existing ADRs still reflect current operational reality?
   - Does the North Star still describe the desired long-term direction?
   - Does the Product Charter need clarification (never expansion)?

   Findings from each review are appended as new rows in this log,
   citing the reviewed documents. Governance evolves through review,
   not accretion.

_See `PRODUCT_CHARTER.md`, `IMPLEMENTATION_ROADMAP.md`, and `adr/README.md`
for the authoritative definitions of each rule._
