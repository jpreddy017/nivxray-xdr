# B8-SCOPE-1 · XDR selector release candidate

Isolated two-file release. Prepared and verified locally. **Not pushed, not merged, not deployed.**

## Approved base
`feature/rc2-alignment @ 6523ba1d` (2026-09-26 18:15:11Z) — the commit the live production
artifacts were promoted from (Vercel builds 18:19:37Z xdr / 18:20:24Z edr).

## Candidate
| | |
|---|---|
| branch | `release/xdr-b8-selector-candidate` |
| local commit | `c927f626d9564178b6e59ac9f7d9d94305b1be25` (local-only; see note) |
| tree | `b3e26825529022990dd6ca30b2474f18876108d8` |
| `AdminTenantGate.jsx` blob | `e49a2a49ef2094ad32700546ab4625c6b66dd9be` |
| `XdrScopeNavigator.jsx` blob | `62216e5c55b0511f403ee2b52e97af453fd2be5d` |
| patch | `docs/releases/B8_SCOPE_1_xdr_selector.patch` sha256 `dfc9b652bccfd402b2feaa65e85e9c8248d913b407938016a53d9a9622cce927` |

NOTE on the SHA: the commit SHA depends on author/committer timestamps, so re-running the
recipe produces a different commit SHA. The **tree** and the two **blob** SHAs above are the
invariants — verify those, not the commit.

## Delta — `git diff --name-only 6523ba1d..candidate`
```
apps/nivxray-xdr/src/xdr/admin/AdminTenantGate.jsx
apps/nivxray-xdr/src/xdr/components/XdrScopeNavigator.jsx
```
```
 apps/nivxray-xdr/src/xdr/admin/AdminTenantGate.jsx   | 14 +++++++++++---
 .../src/xdr/components/XdrScopeNavigator.jsx         | 20 +++++++++++++++++---
 2 files changed, 28 insertions(+), 6 deletions(-)
```
Both files are **byte-identical** to the reviewed/accepted versions in the Emergent workspace
(`3aeef2f2`). Nothing else: no backend, no PR #2 commits, no rc2-tip delta (138 commits /
303 files), no EDR pages, no enrollment change, no tenants/tokens.

## Build guard
`NIVX_PRODUCT_SCOPE=xdr bash scripts/vercel-build.sh` on the candidate tree:
2209 modules transformed, built in 6.28s, **XDR PRODUCTION BUILD GUARD · PASSED**
(`api_origin https://nivxray.nivxforge.com`, `product_scope "xdr"`, no unauthorised origin,
`/edr/*` cannot render). Artifact carries `authorized_tenants` in `XdrAdminPage-*.js` and
`XdrShell-*.js`. `node_modules` was reused from the workspace install: runtime dependencies
are identical at this commit, the only `package.json` delta between `6523ba1d` and the
workspace tip is the `vitest` devDependency plus its `test` scripts, which vite does not
bundle.

## Reproduce / publish (owner action — agent has no push credential)
`/root/.git-credentials` is stale (`Invalid username or token`) and `/.tok` is a JWT, not a
GitHub PAT, so the branch could not be created on GitHub.

```bash
git fetch origin feature/rc2-alignment
git checkout -b release/xdr-b8-selector-candidate 6523ba1d
git apply docs/releases/B8_SCOPE_1_xdr_selector.patch    # applies clean, zero fuzz
git add apps/nivxray-xdr/src/xdr/admin/AdminTenantGate.jsx \
        apps/nivxray-xdr/src/xdr/components/XdrScopeNavigator.jsx
git commit -m "B8-SCOPE-1: XDR tenant selectors read authority, not the incident corpus"
git diff --name-only 6523ba1d..HEAD      # must list exactly the two files
git push -u origin release/xdr-b8-selector-candidate
```

## Remaining gate before Production
Confirm in the Vercel dashboard for the **XDR** project only:
1. **Root Directory = `apps/nivxray-xdr`** — `vercel.json` and `scripts/vercel-build.sh` are
   only honoured at the project root. A build that bypasses the script points the console at
   the PREVIEW backend and drops `ProductScopeGuard`.
2. Build Command `bash scripts/vercel-build.sh`, Output `dist`, Install
   `yarn install --production=false`.
3. `NIVX_PRODUCT_SCOPE` unset or `xdr`; `XDR_PROD_API_ORIGIN` = `https://nivxray.nivxforge.com`
   (or unset — the script defaults to it).
4. Production branch / promotion mechanism: whether the project is Git-linked (and to which
   branch) or promoted by `vercel --prod` from a local checkout. Both live hosts serve
   `/build-info.json`, which only `vercel-build.sh` writes, so the correct script did run; the
   project→branch linkage is dashboard-only.
5. Do **not** touch the EDR project. It stays on its current artifact.

## Security debt found while preparing this
`.tok` (a JWT) is committed at the repository root on every branch inspected. A credential in
git history is a P0 hygiene defect independent of this release.
