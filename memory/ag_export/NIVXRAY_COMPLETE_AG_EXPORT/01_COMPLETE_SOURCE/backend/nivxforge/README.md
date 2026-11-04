# NivXForge

Enterprise-grade Autonomous Cyber Investigation Platform — sibling to
the NivXRay Workspace.

## Status · Phase 0 · Platform Foundation

This package is **architecturally isolated** from the Workspace and
**dormant at runtime**. It carries no analytical features.

- No router is mounted (Decision A1)
- No engine is implemented
- No UI is exposed
- No Workspace file is imported

## Governance

Three sibling documents govern every change to this package:

| File | Role |
|---|---|
| `/app/memory/PRODUCT_CHARTER.md` | Permanent engineering principles |
| `/app/memory/NORTH_STAR.md` | Aspirational architecture — vision only |
| `/app/memory/IMPLEMENTATION_ROADMAP.md` | Active work — the only file authorising code |

Do not add a decoder, engine, or user-facing capability to this tree
without an ADR and an entry in `IMPLEMENTATION_ROADMAP.md §3`. See the
entry gate in `IMPLEMENTATION_ROADMAP.md §1`.

## Layout

```
backend/nivxforge/
├── config.py           · FORGE_* env prefix, /nivxforge route prefix, forge_ collections
├── router.py           · dormant FastAPI router (not mounted)
├── core/
│   ├── cio.py          · Canonical Investigation Object (append-only)
│   └── evidence.py     · Evidence Ledger (Finding · Evidence · Engine · Confidence)
├── engines/
│   └── base.py         · Engine Protocol only — zero implementations
├── observability/
│   └── logging.py      · isolated `nivxforge.*` logger namespace
└── tests/              · foundational invariants (CIO, evidence, isolation, compat)
```

## Running the Phase 0 test suite

```
cd /app/backend && python3 -m pytest nivxforge/tests -v
```

All tests are structural and run in isolation from the Workspace suite.
