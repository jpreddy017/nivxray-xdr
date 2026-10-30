# NivXForge EDR — Complete Architecture Pack

**Compiled:** 2026-10-30 · **Mode of compilation:** read-only (no code, config, branch, database or deployment was changed)
**Platform revision inspected:** `/app` HEAD `5040c08cfd27e835c1ea9013c5d959ae9ea79c5c` (branch `fix/dt-v3-auth-contract-backend`)
**Repositories:** `jpreddy017/nivxray-xdr` (56 branches, 23 open PRs) · `jpreddy017/nivxforge-g3-reviewer-handoff` (frozen G3 candidate `d2f8b742`)

## Contents

| File | What it answers |
|---|---|
| `01_SYSTEM_ARCHITECTURE.md` | The whole system as it exists today: edge, frontends, backend runtime, data, agents, hosting |
| `02_FLOWCHARTS.md` | Every important flow as a diagram: enrollment, telemetry, canonicalisation, detection, trajectory, M1 install, build/deploy, governance gates |
| `03_BACKEND_SKELETON.md` | Backend tree, router inventory, startup/worker lifecycle, configuration contract, API surface |
| `04_FRONTEND_UIUX.md` | App shell, routes, screens, component inventory, design tokens, UX patterns, test-id conventions |
| `05_DATA_MODEL.md` | Collections, identity chain, relationships, ownership and index contract |
| `06_TOOLS_AND_ENGINES.md` | Tooling and engine architecture: sensors, installers, engines, CI, governance and verification tools |
| `07_TARGET_INDEPENDENT_EDR.md` | Target independent-EDR architecture and the copy-first migration map (design only, nothing authorized) |
| `08_EVIDENCE_AND_UNKNOWNS.md` | What is verified, what is inferred, what is unknown — the honesty ledger for everything above |

## How to read it

Diagrams are **Mermaid** inside fenced blocks. They render directly in GitHub, VS Code (Markdown Preview Mermaid), Obsidian, Typora and mermaid.live. No build step.

Every statement carries a confidence class:

- **SOURCE-VERIFIED** — parsed or read in this checkout at the revision above.
- **DEPLOY-VERIFIED** — observed live by an unauthenticated read of the running system.
- **REPO-VERIFIED** — read from the GitHub API.
- **INHERITED** — from an earlier assessment, not re-proved here.
- **UNKNOWN** — not observed; named rather than guessed.

Nothing in this pack is an implementation authorization. Per the binding isolation directive (`/app/memory/EDR_ISOLATION_DIRECTIVE.md`), separation work remains on **HOLD** until the open items in `08_EVIDENCE_AND_UNKNOWNS.md` are closed.
