# A0_SOURCE_BASELINE_REPORT

Mode: READ-ONLY. No file in the repository was modified. Reports are written
outside the source tree (`/app/memory/A0/`) so `git status --porcelain` stays
empty and `prepare.py --verify-only` keeps passing.

## SOURCE STATUS: **VERIFIED** (with one scope limit, stated below)

## 1 · Repository and branches

Local repository: `/app/rocket-p0/src`. Declared repository identity
`jpreddy017/nivxray-xdr` (`deploy/stage1-staging/source.json`).

```
$ git branch -a
  engineering/e3-stabilization
* engineering/e3-stage2b-package
  sanitized/rocket-xdr-repair
$ git remote -v
(no output)
```

**No git remote is configured.** This is deliberate under the sanitized-import
policy, and it is also a limit on this audit: I can verify the local objects
completely, but **I cannot prove what GitHub currently contains.** Any claim
about the state of `origin` would be an assumption.

## 2 · Current head

| Item | Value |
|---|---|
| Branch | `engineering/e3-stage2b-package` |
| HEAD commit | `cd2b8b92d785bee2f88432d3202367bbd51508c0` |
| HEAD tree | `15a13aa6a5fe562895efaecabc11b4e434c8505f` |
| Pinned application commit | `593b3e9fdd6008b67e5cc353c29e413560778fda` |
| Pinned application tree | `54d6e4c28ac564af32f4e0dca59a90214cb0b1bc` |
| Working tree | clean — `git status --porcelain` returns 0 lines |
| Commits on branch | 12 |
| Object store | no `.git/objects/info/alternates`; `git fsck` clean |

Commit chain, oldest first: `b1240bb` (sanitized root) → `4c24410` (P1) →
`6c6c66f` (P2/P3) → `81f8649` (P4) → `e6d7efb` (P5) → `1dc4e35` (A-G final
acceptance) → `b30497f`, `a1e1be5` (Stage 2B.1) → `1516fe7`, `1efa6dc`
(Stage 2B.2) → `593b3e9`, `cd2b8b9` (Stage 2B.3).

## 3 · Is the repaired source available and authoritative?

**Yes.** The repaired work is present as the sanitized import plus six
engineering slices on top of it.

The original ChatGPT Work commit `3aebddc28514618dcf0bed805122cf4e133ee558` is
**not present and must not be expected**:

```
$ git cat-file -t 3aebddc28514618dcf0bed805122cf4e133ee558
fatal: git cat-file: could not get object info
```

This is by design, not a gap. `SECURE_EXPORT/SOURCE_DIFFERENCES.json` records
the policy as *"one new root commit only; no original commit/tree objects
imported"*. Work's clone was reference-coupled to another local repository and
its history carried a deleted credential scratch artefact, so an independently
importable sanitized snapshot was produced instead. The sanitized root is
`b1240bba` with tree `38a96a2f`.

### Sanitized export accounting (`SECURE_EXPORT/SOURCE_DIFFERENCES.json`)

| Metric | Count |
|---|---|
| Original files | 12,480 |
| Retained source files | 5,652 |
| Byte-identical retained files | 5,523 |
| Sanitized files | 129 |
| Removed artefacts | 6,828 |

Removals are classified in the manifest — generated runtime configuration
(`.emergent/cron/*`, `.emergent/emergent.yml`), collector runtime state
(`.state/outbox.db`), an embedded source/history export
(`NIVXRAY_XDR_SOURCE_EXPORT.html.gz`), customer/evidence uploads and
deployment artefacts. **None of the four repair families was removed**:
decoder, tenant/RBAC, response-security and validation-harness changes are all
present.

### Honest consequence

Because the original commit objects were never imported, a byte-for-byte
`git diff 3aebddc2 → b1240bba` **cannot be computed in this environment**. The
evidence available is the manifest plus `SECURE_EXPORT/verify_snapshot.py`.
Anyone needing a stronger guarantee must obtain the original clone separately.

## 4 · Transfer artefacts and digests

| Bundle | Size | SHA-256 |
|---|---|---|
| `nivxray-e3-final-acceptance.bundle` | — | `36515e1d9624f3ee5bf5182b0e57e8e3bee75f56ea4a4acf72de4b4d7580e757` |
| `nivxray-e3-stage2b-part1.bundle` | — | `58d52d5c3702a3473d3a5e2bdf023cb686abedfa419bea0d30b8b547f5e7a019` |
| `nivxray-e3-stage2b-part2.bundle` | 23,523,587 | `704d0561052ac9e2e8d770e326c417bab0269c28b6094f7f143297ff8cf799f0` |
| `nivxray-e3-stage2b-part3.bundle` | 23,532,611 | `98e4adba8ec497411e21b6fa3e9ad11aebcd5d5a2b915e592f2aa42c6747fdfa` |

Part 3 was re-verified from the bytes served over HTTPS: clone yields
`cd2b8b92` / `15a13aa6`, 12 commits, no alternates, `fsck` clean, acceptance
scripts `100755`, and `prepare.py --verify-only` prints "Pinned source
verified" inside the fresh clone.

## 5 · Discrepancies and gaps found

| Finding | Evidence | Severity |
|---|---|---|
| No git remote; GitHub state unknowable from here | `git remote -v` empty | scope limit |
| Original Work commit objects absent | `git cat-file -t 3aebddc2…` fails | by design, documented |
| 59 hardcoded `/app/...` literals in non-test backend code | `grep -rn '"/app/' backend \| grep -v /tests/ \| wc -l` → 59 | **real** — see A0_CURRENT_ARCHITECTURE §6 |
| 316 hardcoded `/app/...` literals in backend tests | same grep, tests only → 316 | audits the wrong tree outside a container |
| One empty SQLite file in ancestor commits | `apps/nivxray-xdr-response/data/executions.db`, 24,576 bytes, 0 rows, untracked since `b30497f8` | disclosed, benign |
| Repo `frontend/` is byte-identical to the pod's `/app/frontend` | `diff -rq` returns nothing | confirms Workspace app identity |

No uncommitted changes, no missing files relative to the manifest, and no
incomplete export were found.

## 6 · Repository implementation vs live deployment

Everything above describes **source code only**. This repository cannot prove
which services are running at `nivxray.nivxforge.com`, which environment
variables are set there, which image digests are deployed, or whether the
production database schema matches these collections. Those are **deployment
assumptions** until read from the running platform, which this task does not do
and is not authorised to do.
