# EDR-T1 — Unique Git History Preservation Report

**Reference:** T1 · **Date:** 2026-10-30 · **Mode:** additive preservation only · **Status:** COMPLETE — **PASS**
**Source repository:** `/app/rocket-p0/src/.git` (separate clone, HEAD `engineering/e3-stage2b-package`)
**Nothing was pushed.** `https://github.com/nivxforgeedr/nivxforge-edr` was **not contacted** in any form.

**Actions taken:** one bundle created, one read-only verification clone made and then removed, two small sidecar records written. No delete, clean, prune, reset, rebase or modification of any repository. No EDR/XDR/Workspace/NivX Machines change. No deployment, service restart, production database access, VM interaction or secret read.

---

## 1 · Source verification (pre-state)

| Check | Result |
|---|---|
| HEAD | `cd2b8b92d785bee2f88432d3202367bbd51508c0` (branch `engineering/e3-stage2b-package`) |
| Working tree | **clean** — `git status --porcelain` returned 0 lines |
| References | **27** — 23 `refs/heads`, 3 `refs/remotes`, 1 `refs/tags` |
| Objects | loose 787 (4.39 MiB) + in-pack 35,992 across 2 packs (140.45 MiB) |
| `git fsck --full` | **no corruption** — 0 errors, 0 missing objects; 9 informational lines, all "dangling" (§6) |
| Origin remote | `github → https://github.com/jpreddy017/nivxray-xdr.git` (fetch/push), untouched |

---

## 2 · Backup destination and free space

| Item | Value |
|---|---|
| Destination directory | `/var/backups/nivx-preservation/` |
| Volume | `overlay` mounted at `/` — **282 GB total, 237 GB available (16 % used)** |
| Why not `/app` | `/app` is **90 % full with ~1.1 GB free**; a 119 MB bundle plus verification clone would have risked exhausting it |
| Space after the operation | 237 GB still available — no measurable impact |

---

## 3 · Bundle created (one bundle, as authorized)

| Property | Value |
|---|---|
| Path | `/var/backups/nivx-preservation/ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle` |
| Size | **124,634,440 bytes (118.9 MiB)** |
| Command | `git bundle create <dest> --branches --tags --remotes` |
| Refs captured | **27 / 27** — every head, the tag, and all three remote-tracking refs |
| **SHA-256** | **`9ae11e502c9596ea603e21cabce8f9d22c812317a683e21f6168e7cee1d1e0a4`** |
| Checksum sidecar | `ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle.sha256` |
| Ref manifest sidecar | `ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.refs.txt` (27 lines) |

`--remotes` was included deliberately: `--all` alone would have silently dropped the three `refs/remotes/*` entries.

---

## 4 · Integrity verification

| Verification | Result |
|---|---|
| `git bundle verify` | **"The bundle records a complete history."** — no prerequisite commits required, so the bundle is self-contained and restorable without the source repository |
| Hash algorithm | sha1 (repository native) |
| `git bundle list-heads` | **27 refs**, matching the source ref set exactly |
| **Restore test** | bare-cloned the bundle to `/var/tmp/t1verify`: **23 heads + 1 tag materialised**, in-pack 31,387 objects (119.70 MiB), `git fsck` clean (only the benign `HEAD points to an unborn branch (master)` notice for a bare clone) |
| Verification clone | removed after the check; no residue |

Note on the clone count: a bare clone of a bundle does not materialise remote-tracking refs, so 24 refs appeared from 27. The three `refs/remotes/*` entries **are inside the bundle** (listed by `list-heads`) and are recoverable with `git fetch <bundle> 'refs/remotes/*:refs/remotes/*'`. Nothing was lost.

---

## 5 · Unique-commit verification

| Check | Result |
|---|---|
| Present as a bundle head | **yes** — `cd2b8b92d785bee2f88432d3202367bbd51508c0 refs/heads/engineering/e3-stage2b-package` |
| Resolvable in the restored clone | **yes** — `git cat-file -t` → `commit` |
| Commit identity | `2026-10-16 17:02:30 +0000` — *"Stage 2B.3 packaging: declared index, hash verification and posture proof"* |
| Still absent from `/app` git | yes — `git cat-file -t cd2b8b92` → *"Not a valid object name"* |
| Still absent upstream | yes — GitHub API `422`, while control SHA `35d47cc9…` returns `200` |

**The irreplaceable commit is now preserved in a verified, self-contained, checksummed artefact.**

### Preserved refs (27)

```
3db07b18… refs/heads/engineering/a1-security-harness
62a2c658… refs/heads/engineering/a3-security-gate
1dc4e358… refs/heads/engineering/e3-stabilization
cd2b8b92… refs/heads/engineering/e3-stage2b-package          ← unique commit / HEAD
eac0192b… refs/heads/engineering/edr-access-loop
e4031475… refs/heads/engineering/edr-access-permanent
d5bceb80… refs/heads/engineering/f1-v2-dependency
e2c96f2e… refs/heads/engineering/n1-audit-provenance
09a8c2e8… refs/heads/engineering/n1-ci-gate
1158afcc… refs/heads/engineering/n3-http500-investigation
38e294c6… refs/heads/engineering/n3a-telemetry-bson
1158afcc… refs/heads/engineering/n5-ci-gate
113ebfb8… refs/heads/engineering/n5-tenant-authority-tests
24139032… refs/heads/engineering/reenrol-placement-preserved
05b152ac… refs/heads/engineering/win-reenrol-recovery
05e8a413… refs/heads/publish/edr-access-loop
94e447d5… refs/heads/publish/edr-access-loop-frontend
94e447d5… refs/heads/publish/edr-denial-recoverable
63d7d104… refs/heads/publish/gate4-payload-context
d065fd67… refs/heads/publish/n3a-telemetry-bson
68e2f0a5… refs/heads/publish/reenrol-placement-preserved
63d7d104… refs/heads/publish/win-reenrol-recovery
b1240bba… refs/heads/sanitized/rocket-xdr-repair
ce8732ba… refs/remotes/github/engineering/stage1-staging-package
752a00ff… refs/remotes/github/main
d065fd67… refs/remotes/github/publish/n3a-telemetry-bson
06b56144… refs/tags/preserve-pre-alignment-2026-09-05
```

Two names previously unknown and now preserved: the `publish/*` family (7 branches) and `sanitized/rocket-xdr-repair`, plus the tag `preserve-pre-alignment-2026-09-05`.

---

## 6 · Unreachable objects requiring SEPARATE preservation

`git bundle` captures only reachable history. `fsck` found **9 dangling objects that are therefore NOT in the bundle**, confirmed absent from the restored clone:

| Object | Type | Identity |
|---|---|---|
| `6c1e1c4fe09d9cacf3a4f65ecd7cf9b04bd325f5` | commit | 2026-10-16 16:57 · *"WIP on engineering/e3-stage2b-package: 1efa6dc Stage 2B.2 …"* — stash-style WIP |
| `849a70d2f97a7bef142f98992f05fd425b03645d` | commit | 2026-10-18 16:02 · *"WIP on engineering/edr-access-permanent: eac0192b …"* — stash-style WIP |
| `2f940c8b2c6208209f61d56c5052693887f04e9f` | commit | 2026-10-18 13:47 · *"EDR access loop: a missing customer selection is not a page denial"* — an orphaned variant of `eac0192b`, which **is** preserved |
| 6 blobs | blob | `990ab60c…`, `9e497151…`, `0a56948a…`, `ce751789…`, `6bb17e12…`, `87ef2add…` |

**Why they were not captured:** attaching them to the bundle requires creating refs in the source repository, which this task forbids.

**Recommended separate step (needs its own authorization):** a plain `tar` of the whole `/app/rocket-p0/src/.git` directory to the same destination — a pure file copy that captures loose and unreachable objects verbatim, modifies nothing, and costs ~160 MB. Risk if skipped: low — one orphaned commit whose message is already represented by a preserved branch tip, plus two stash WIPs.

---

## 7 · Original unchanged — post-state proof

| Check | Pre | Post | Result |
|---|---|---|---|
| Ref list (object + name, 27 refs) | captured | captured | **`diff` identical — REFS UNCHANGED** |
| HEAD | `cd2b8b92d…` | `cd2b8b92d…` | unchanged |
| Working tree | 0 dirty paths | 0 dirty paths | unchanged |
| Loose objects / packs | 787 / 35,992 in-pack / 140.45 MiB | **identical** | unchanged |
| Garbage | 0 | 0 | unchanged, nothing pruned |
| `/app` repository | `backend` clean | `backend` clean (0 lines) | untouched |

No `gc`, `prune` or `repack` was triggered; object counts are byte-for-byte identical before and after.

---

## 8 · Storage usage summary

| Artefact | Size |
|---|---|
| Bundle | 118.9 MiB |
| Checksum sidecar | 113 bytes |
| Ref manifest sidecar | 2,237 bytes |
| Verification clone (temporary) | 119.7 MiB — **removed** |
| Destination volume after | 237 GB free of 282 GB (16 % used) |
| `/app` impact | **none** — nothing was written to `/app` |

---

## 9 · Remaining recovery risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | **Single-copy bundle.** The artefact lives on the same pod volume as the source; a pod loss destroys both | **HIGH** | copy off-pod — download via VS Code, or push the bundle's history to the new private repository once you authorize it |
| R2 | Unreachable objects (§6) still exist in exactly one place | LOW–MEDIUM | `tar` the `.git` directory in a separately authorized step |
| R3 | `rocket-p0/` **non-Git assets** are still unpreserved — `f1/` 208 MB, six gate working copies ≈ 94 MB each, and the `SECURE_EXPORT/` directories — classification of their uniqueness was outside T1 | MEDIUM | a scoped audit of `SECURE_EXPORT/` first; the working copies are probably derivable, but that is unproven |
| R4 | `/app` remains **90 % full (~1.1 GB free)** | MEDIUM | unrelated to T1, but it will obstruct any future build, test run or export from `/app` |
| R5 | The bundle preserves history, not a **tested build** | LOW | restore-to-build was verified only at the object/ref level (T2 in the P0-02A plan remains open) |
| R6 | P0-02A blockers unchanged — no production backup, unknown backend revision, unknown production DB identity, missing installer artefacts, no VM snapshot | **HIGH** | T6, T7 and the authorized production read; T1 does not alter them |

---

## 10 · Verdict

### **PASS — T1 complete**

The unique history is preserved in one verified, self-contained, checksummed bundle at `/var/backups/nivx-preservation/ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle` (SHA-256 `9ae11e50…e1d1e0a4`), covering **all 27 refs including the irreplaceable commit `cd2b8b92d…`**, proven restorable by an actual clone, with the source repository provably unchanged.

**Nothing was pushed to `https://github.com/nivxforgeedr/nivxforge-edr`.** The bundle is the safest possible input for that migration when you authorize it: it carries the complete history and its integrity is independently checkable by SHA-256 before anything is published.

**Immediate recommendation:** act on **R1** — the bundle currently exists in exactly one place, on the same volume as the source it protects. Stopping here as instructed.
