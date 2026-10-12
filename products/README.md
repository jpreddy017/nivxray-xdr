# One repository, four product owners

Repository: `jpreddy017/nivxray-xdr`. Audited baseline: `release/xdr-rc2-validation` at `d9b3cd6c99580df407c5147c49b9b5753338bef7`, 2026-10-12.

This change organizes ownership and local verification without moving source files or changing runtime behavior. `manifest.json` is a representative source/dependency map, not a claim that every backend module has been classified.

| Product | Existing source | Build entry point | Existing Vercel project |
| --- | --- | --- | --- |
| NivX Machines | Website source not identified in audited baseline | Blocked; no substitute website created | Separate company project not identified in visible inventory |
| NivXMachines Workspace | `frontend/`; shared investigation backend | `frontend/package.json` | `nivxmachines-workspace` |
| NivXRay XDR | `apps/nivxray-xdr/src/xdr/`; shared console shell | Existing Vite package, scope `xdr` | `nivxray-xdr` engineering; `nivxray-xdr-production` |
| NivXForge EDR | `apps/nivxray-xdr/src/nivxforge/`, `agents/`, `backend/edr_plane/`, `backend/services/edr/` | Existing Vite package, scope `edr` | `nivxray-edr-production` (legacy project name retained) |

Vercel project names were verified through the connected inventory. Detailed project inspection returned 403: provider-side root directories, environment configuration and production branch mappings remain unverified. Source build scripts describe a shared XDR/EDR console root. No project was created, renamed, relinked or deployed.

## Ownership and dependencies

- Product page owners: XDR owns `src/xdr`; EDR owns `src/nivxforge` and existing agent source; Workspace owns `frontend`. Company ownership awaits identification of real source.
- Shared console owner: `App.jsx`, components, library utilities, `productScope.js` and Vite configuration. XDR/EDR are scoped builds of the existing shared application, not independently extracted packages. Shared changes require both checks.
- Platform security owner: existing authentication, RBAC, tenant registry and session context. These remain authoritative; frontend scope is not an authorization boundary.
- Backend composition owner: `backend/server.py` still mounts multiple product APIs. Independent backend releases are not established by this change. Shared investigation, collector and response services retain their current contracts and approval requirements.
- Evidence integration: preserve existing canonical evidence identifiers, schema exports and response states. Legacy contract documentation is not release approval; security HOLDs remain authoritative.

## Local commands

Run from the repository root with the existing dependencies installed:

```sh
python scripts/product_tasks.py all check
python -m unittest discover -s scripts/tests
python scripts/product_tasks.py xdr test
python scripts/product_tasks.py xdr build
python scripts/product_tasks.py edr test
python scripts/product_tasks.py edr build
python scripts/product_tasks.py workspace test
python scripts/product_tasks.py workspace build
```

Build outputs are isolated in `.build/products/{xdr,edr,workspace}` and ignored by Git. Proof builds use a disconnected local API origin; they are not production deployment artifacts. Existing deployment scripts, dependency versions and lockfiles are unchanged. Company build/test commands fail explicitly until its source is identified. `all` supports ownership checking only.

Workspace's test command runs its four existing dependency-free Node regression files. These include helper-level checks and do not establish authenticated UI acceptance. EDR's scoped Vitest command runs console boundaries and shared state tests, not Windows/Linux agent acceptance.

The new `product-boundaries.yml` adds read-only ownership and separate XDR, EDR and Workspace build/test jobs. It contains no deployment command or production-secret access. Existing backend and security workflows remain in place. GitHub execution of this new workflow is not yet verified.

## Preserved engineering milestones

| Branch | Verified commit |
| --- | --- |
| `release/xdr-rc2-validation` | `d9b3cd6c99580df407c5147c49b9b5753338bef7` |
| `engineering/xdr-dashboard-20261011` | `860dc2acaea8efcc25d2bd5747cacb4849f22638` |
| `feature/e3-edr-engines` | `258c8854c8b89e5203ba2c0e80f631fb3e700315` |
| `engineering/edr-windows-gate4-recovery` | `acf16e75f9ad55cee68456931af7090de7a5bdc0` |
| `engineering/edr-collector-tenant-isolation` | `11f88dc81826cdd5ca3bf98d09f58a0d75b398cc` |
| `engineering/edr-webhook-replay-protection` | `f156e1fac32dc6f94646ee4f65baa89958d175c8` |

These branches remain separate. RC2 agent files must not be assumed to contain every EDR milestone. No EDR security candidate or MITRE repair was integrated. PR #7 and release branches were not changed.

## Fresh validation and blockers

| Check | Result |
| --- | --- |
| XDR scoped frontend | 119 tests passed; build passed |
| EDR scoped console/shared boundary | 15 tests passed; build passed |
| Original combined-console test command | 119 tests passed |
| Workspace existing Node regressions | 25 tests passed |
| Product runner safety tests | 3 passed |
| Ownership map | Passed |
| Workspace full build | BLOCKED: dependencies not installed; `craco` unavailable |
| Company build | Intentionally blocked: source not identified |
| Authenticated browser acceptance | Not performed |
| Backend/agent integration | Not rerun; no backend or agent runtime source changes |

Workspace frozen installation stalled during dependency resolution and was stopped. Offline installation also failed; its existing lockfile lacks the requested `@xyflow/react` selector. No dependency repair or lockfile regeneration was performed. Workspace CI/build readiness therefore remains unresolved, not passing.

## Small next steps

1. Identify the company's authoritative website source and deployment ownership before adding a build target.
2. Resolve Workspace dependency/lockfile alignment in a focused change and run its full build and UI suite.
3. Obtain authorized Vercel project inspection to confirm existing deployment mappings; prepare proposed changes for approval before any relinking.
4. Keep shared-backend releases coordinated until service ownership and compatibility checks justify independent deployment. Test shared security and evidence contracts for every affected product.
5. Complete RC2 security and authenticated browser gates before any release. Migration, deployment relinking, merge and production promotion require owner approval.

No production database, DNS, secret, account, authentication authority or security HOLD was changed.

## PR #10 Workspace lockfile repair

GitHub Actions run `38205940818`, Workspace job `114669334393`, failed with `Your lockfile needs to be updated, but yarn was run with --frozen-lockfile`. Ownership, XDR and EDR jobs passed. Workspace tests and build were skipped in that run.

The existing Workspace manifest declared 17 direct dependency selectors absent from its lockfile: `@xyflow/react`, `dagre`, `konva`, `react-konva`, seven Storybook packages plus `storybook`, Node/React/React DOM types, `json-schema-to-typescript`, and TypeScript. Matching entries and their missing dependency closure were recovered from the repository's archived Workspace lockfile, then reconciled with Yarn 1.22.22. The existing manifest, resolution overrides, CI assertions, runtime source and deployment configuration are unchanged. This is not a wholesale restoration of the archived lockfile.

Fresh validation: Workspace installation passed; a clean dependency directory installed successfully with `--frozen-lockfile --non-interactive --offline` using the verified package cache. Its 25 existing Node helper tests and 14 Jest viewport tests passed. XDR's 119 tests/build, EDR's 15 console boundary tests/build and the three ownership-runner tests passed again. The earlier blocked build above describes the original organizational baseline.

The full Workspace build now reaches compilation but fails on existing `react-hooks/exhaustive-deps` warnings because `CI=true` treats warnings as errors. Affected existing files are `OutputView.jsx`, `StructuredEvidenceTab.jsx`, `investigation/FindRelatedDrawer.jsx`, `hooks/useIdlePersist.js`, and `v2/pages/{EvidenceCard,EvidenceGraphTab,InvestigationWorkspace}.jsx`. None were modified. No lint checks, warnings or assertions were disabled. This separate source-quality gate requires a focused repair before PR #10 can pass all checks or be merged. Authenticated browser acceptance and all existing release/security HOLDs remain unchanged.

## PR #10 Workspace Hook repair

The subsequent focused repair addresses all 13 Hook warnings in those seven files. Empty evidence references are memoized; the output cap is an explicit dependency; the related-case loader is stable per case. Idle persistence now compares committed top-level values and bulk-field names, retaining its debounce, size guards and unmount cleanup without a dynamic dependency array or lint suppression. Report-generation helpers remain ordinary functions.

Fresh local validation: strict Workspace build passed with `CI=true`; 25 Node helper regressions and all 22 Jest tests passed (14 existing viewport tests, six persistence regressions and two drawer interaction tests). XDR's 119 tests/build, EDR's 15 console boundary tests/build and three ownership tests passed. The CI workflow now also runs the Workspace Jest suite; no existing check was removed or weakened. Runtime routes, API contracts, authentication and tenant authority are unchanged. This supersedes the previous Hook build blocker; release and authenticated-browser gates remain separate.
