# EDR-R4 — Source Reconciliation & Preservation

- **Date:** 2026-10-31
- **Branch created:** `reconciliation/edr-local-backend-2026-10-31`
- **Base:** frozen release head `73e2bfea8d09b269792db92360b902a6b75f7b76`
- **Head:** `33a876a15efa0baaf3291df0e3660fdc4fd4b317`
- **Result:** reviewable preserved candidate published. No local original altered, no release/main/preview ref moved, no deploy.

---

## 1 · Published commits

| # | Commit | Scope |
|---|---|---|
| 1 | `d749b99cbb30d283b4fb0553f85683fe07002df8` | **source** — 6 modules + 3 tests |
| 2 | `c9d234ed6c7ee14f4771d55f0546008fb50c8c61` | **review** — `server.py`, `transfer_bundle.py`, `edr_maintenance.py`. Explicitly NOT approval to deploy |
| 3 | `33a876a15efa0baaf3291df0e3660fdc4fd4b317` | **docs** — preview handoff, source-only |

`compare/73e2bfea8d09...reconciliation/edr-local-backend-2026-10-31` → **ahead 2 (now 3), behind 0**, 12 source files + 1 doc.

Refs confirmed unmoved after publication: `main 752a00ffefee`, `release/edr-trajectory-2026-10-31 73e2bfea8d09`, `validation/edr… f22b74aa9c67`, `validation/xdr… 7ed7c03bc5f5`, `validation/workspace… 98713f705c07`, `repair/… 73e2bfea8d09`.

The script refuses to run if the branch already exists, so no ref can be force-moved.

---

## 2 · Inventory of the differing paths

Local provenance is two commits, both 2026-10-29: `0fb1ea41` (*classify authentication evidence from the source's own class token*) and `f9fd38e5` (*one activity is one row — match the stores on their stated identity*).

| Path | release → local blob | Semantic difference | Importers | Recommendation |
|---|---|---|---|---|
| `edr_trajectory/contracts.py` | `2e81b5b6` → `9a355047` | Adds `AUTH_KINDS` to `KINDS`; adds `identity_keys` + `authentication` to the event contract; adds `reported()` mapping Windows `-` to explicit absence. **Contract extension — additive, but `EVENT_SCHEMA` stays `e3.dt.event.v1` with no version bump** | **33** | **RETAIN** |
| `edr_trajectory/identity.py` | `2fab92a4` → `d05c3e70` | `dedupe()` moves from a single `(tenant,event_id)` key to **ranked multi-key, tenant-scoped** grouping so one activity seen in two stores collapses to one row. Defect fix | 10 | **RETAIN** |
| `edr_trajectory/providers.py` | `26fce505` → `4872169f` | Classifies the source's own class token instead of collapsing authentication records into `OTHER`. Defect fix | 9 | **RETAIN** |
| `edr_trajectory/production_service.py` | `48a686d8` → `7c03c1b8` | Carries the authentication block through; `-` becomes `NOT_COLLECTED` rather than a value | 5 | **RETAIN** |
| `edr_trajectory/production_adapter.py` | `92ed75f2` → `deefef06` | `observed_us = min()` across merged representations — a merged activity orders by the instant its evidence first states | 17 | **RETAIN** |
| `edr_trajectory/v3_presentation.py` | `ad78354c` → `056391e6` | Renders authentication families + detail; never shows `-` as an account/address | 4 | **RETAIN** |
| `tests/edr_trajectory/test_sd_raw_reference.py` | `1c93272c` → `850b9a23` | Adapted to the new identity behaviour (+2/−2) | — | **RETAIN** |
| `tests/edr_trajectory/test_activity_identity.py` | **local-only** | 310 lines covering the dedupe rework | — | **RETAIN** |
| `tests/edr_trajectory/test_v3_authentication_contract.py` | **local-only** | 245 lines covering the auth contract | — | **RETAIN** |
| `server.py` | `31d5444c` → `5ca24cf9` | Three additive blocks (§3) | — | **ADAPT** — strip the temporary mounts before any publish |
| `transfer_bundle.py` | **local-only** | 52 lines, unreviewed in this release | — | **UNRESOLVED** — needs owner review |
| `routers/edr_maintenance.py` | **local-only** | 415 lines, **privileged tenant-wide reset** | — | **EXCLUDE from any production payload** |
| `tests/edr/test_b5_gap1_pre_canary_acceptance.py` | `d3b7c14a` → `3bc7b2df` | Windows sensor acceptance (`57043f29`), unrelated to this change set | — | **EXCLUDE** from this branch; local original preserved |
| `tests/reports/multilayer_battery.json` | `69d49e33` → `47a4c513` | Generated test-report artifact | — | **EXCLUDE**; local original preserved |

**Correction to my own prior inventory:** I had compared release→local only, which made **6 local-only files invisible**. They are now included above. I did not treat larger files as superior — every retain recommendation rests on the diff's stated semantics plus test evidence.

---

## 3 · `server.py` — the three concerns, explicitly

1. **`transfer_bundle` (`transfer_router`)** — local-only module, absent from release, unreviewed.
2. **`routers/edr_maintenance.py` (`edr_maintenance_router`) · PRIVILEGED** — tenant-wide development RESET; A0-03 recorded it touching 13 non-EDR collections. Gated behind `EDR_MAINTENANCE_TOKEN`, 404s when unset, but would enter the production image if the workspace were published as-is.
3. **Temporary `_arch` / `_pv` static mounts · TEMPORARY** — added by me for owner-requested downloads, inert unless `ARCH_DOCS_SHARE=1`. **Must be removed before any publish.**

The release branch contains none of these (`release hits: 0`, `local hits: 9`). Commit 2's message states plainly that preservation is **not** approval to deploy them.

---

## 4 · Secret scan before publication

All published source and the doc: **0 findings**, across 11 pattern classes (AWS keys, private-key blocks, GitHub PATs, Slack, JWT, Emergent/OpenAI keys, bearer literals, assigned secrets, Mongo URIs, URIs with inline credentials).

```
CLEAN  edr_trajectory/{contracts,identity,production_adapter,production_service,providers,v3_presentation}.py
CLEAN  tests/edr_trajectory/{test_sd_raw_reference,test_activity_identity,test_v3_authentication_contract}.py
CLEAN  tests/edr/test_b5_gap1_pre_canary_acceptance.py
CLEAN  docs/handoff/PREVIEW_ENVIRONMENTS.md
```

No file was withheld for secret reasons. Deliberately excluded from publication: `.git` history, `.tok`, `.env`, telemetry, archives, `memory/test_credentials.md`, unrelated dirty paths.

---

## 5 · Tests — candidate vs isolated baseline

Isolated baseline assembled by overlaying the **release** versions of the 6 modules and the 1 adapted test, and removing the 2 local-only tests.

| Run | Result |
|---|---|
| **Candidate** (`/app/backend`, local files) | **441 passed · 9 skipped · 0 failed** |
| **Baseline** (release versions) | **396 passed · 9 skipped · 1 collection error** |

- **Candidate regressions: NONE.** No test passing on baseline fails on the candidate, and the candidate has zero failures.
- The **+45** passing tests are the two local-only suites plus the adapted assertions.
- The 1 baseline error (`ModuleNotFoundError: mitre_mapping_diff` in `test_attack_catalog.py`) is an **artifact of my rsync exclusions**, not a code defect: the module lives in a directory I excluded from the isolated tree, and the same test collects cleanly against the candidate (**5 passed**). Classified as an unchanged-baseline harness artifact.

---

## 6 · Investigation: the `.tok` credential

**Identified without reading or disclosing the value.**

| Property | Finding |
|---|---|
| Type | **HS256 application JWT** — this platform's own access token, **not** a third-party vendor credential |
| Size | 163 bytes, single line — identical in shape to this backend's login tokens |
| Claims | `exp`, `iat`, `sub` only — **no `role` or `scope` claim** |
| Issued / expires | `2026-09-26T12:16:11Z` → `2026-09-27T12:16:11Z` |
| **Status** | **EXPIRED 33 days ago** |
| Expiry enforced? | **Yes, verified live** — presenting it returns **HTTP 401 `Invalid or expired token`** |
| Live copies on disk | **3**, byte-identical (`sha256 64f8ff12…`): `/app/.tok`, `/app/.worktrees/p0fix/.tok`, `/app/.worktrees/upg/.tok` |
| Consumers | **one** — `backend/tests/test_rc42_transformation_trace.py`, which reads and rewrites it as a cached login token |
| Gitignored? | **No** — not in `.gitignore`, which is why 22 historical commits captured it |

**Not rotated, not moved, not deleted, value never printed.**

**This materially downgrades blocker B-2.** The archive does not contain a live vendor secret; it contains an **expired, scope-less application JWT** that the running backend already rejects. Residual exposure is the `sub` identifier and the signing algorithm, permanently archived.

**Also newly surfaced:** `.tok` is live on disk **today** and **not gitignored**, so the test that rewrites it will re-commit a fresh, *valid* token into any repository that tracks it. That is a standing hazard independent of the archive, and worth fixing at source (gitignore it, or have the test cache outside the tree).

---

## 7 · Investigation: encrypted archive under a user-controlled key

**Viable, and it removes the immutable-plaintext problem entirely.**

| Requirement | Status |
|---|---|
| Tooling on-pod | `gpg 2.2.40` and `openssl` present (`age`, `7z` absent) |
| Disk headroom | 153 MB ciphertext needed; **791 MB free** — fits without a second plaintext copy |
| Key custody | Passphrase supplied by the owner, used in-memory, **never written to `/app`** and never stored by me |
| Storage outcome | Object storage holds **ciphertext only**; no plaintext credential is ever immutably stored |
| Delete constraint | Still `405 — no delete API`, but it no longer matters: an undeletable ciphertext blob is inert without the key |

This satisfies preservation **without** requiring rotation first. **Nothing has been encrypted or uploaded** — awaiting your instruction and a passphrase supplied through a secure channel, never chat.

---

## 8 · Packaging inventory

| Item | Measure |
|---|---|
| Declared dependencies | **218** packages in `requirements.txt` |
| Third-party modules actually imported by runtime code | **52** (excluding tests/docs) — e.g. fastapi, motor, pymongo, pydantic, litellm, cryptography, bcrypt, playwright, capstone, pefile, PIL, pdfplumber, py7zr |
| Current build context | **2.95 GB** |
| Realistic backend runtime payload | **≈30 MB** (`backend/` minus `docs` 76 MB, `tests` 16 MB, `reports`, `downloads`, `workspace_recovery`) |

**Supported workspace/build separation:** none beyond physical removal from `/app`. Platform evidence (verified extraction of run `81342093`) shows the context is the **whole working tree verbatim minus `node_modules` and `.git`**, with `.gitignore` **not** honoured and no `.dockerignore`/`.emergentignore` consulted. **No ignore rules were guessed or added.** The image `Dockerfile` COPY scope is platform-controlled and remains **BLOCKED**.

**`backend/.env` was not moved, not modified and not deleted** — the preview runtime depends on it. It remains unexcludable by any supported mechanism; that tension is unresolved and is not claimed as cleanup.

---

## 9 · Remaining blockers

| # | Blocker | Severity |
|---|---|---|
| B-3 | `backend/.env` must ship-exclude but cannot be deleted; no supported exclusion mechanism | HIGH |
| B-4 | `memory/test_credentials.md`, agent credential and ~170 MB raw host telemetry still enter the build context | HIGH |
| B-5 | `transfer_bundle` **UNRESOLVED**; `edr_maintenance_router` recommended **EXCLUDE** — both need an owner decision | HIGH |
| B-6 | `_arch` / `_pv` mounts still in `server.py`; must be removed pre-publish | MEDIUM |
| B-8 | Dockerfile COPY scope unknown | MEDIUM |
| B-9 | `/app` at 93 %, ~791 MB free | MEDIUM |
| B-10 | XDR/Workspace backend regression pass not yet executed against the candidate | MEDIUM |
| **NEW** | `.tok` is live on disk and **not gitignored**; a test rewrites it, so a valid token can be re-committed | HIGH |

**B-1 is resolved for reviewability** — the local work is now preserved and reviewable on GitHub. The release-content decision remains yours. **B-2 is downgraded** — the credential is expired and rejected, and encryption offers a clean path.

---

*Local originals preserved. No ref moved. No deploy. No credential rotated or disclosed.*
