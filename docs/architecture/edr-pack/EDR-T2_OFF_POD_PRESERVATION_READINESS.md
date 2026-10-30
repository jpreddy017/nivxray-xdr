# EDR-T2 — Off-Pod Preservation Readiness

**Reference:** T2 · **Date:** 2026-10-30 · **Mode:** bounded preservation only · **Status:** COMPLETE — **PASS, with one HIGH security finding**
**Scope:** protect the T1 bundle and the nine unreachable Git objects against loss of the Emergent pod.
**Nothing was pushed.** `github.com/nivxforgeedr/nivxforge-edr` was not contacted. No repository modified, no object deleted or pruned, no public upload, no database, production service or Windows VM touched. No secret value was printed, logged or stored.

---

## 1 · T1 bundle re-verification — **PASS**

```text
$ sha256sum -c ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle.sha256
ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle: OK

sha256  9ae11e502c9596ea603e21cabce8f9d22c812317a683e21f6168e7cee1d1e0a4   ← matches the T1 record
size    124,634,440 bytes (118.9 MiB)
```

---

## 2 · New archive — full `.git` directory

| Property | Value |
|---|---|
| Path | `/var/backups/nivx-preservation/ROCKET-P0-SRC_GIT_DIR_FULL_2026-10-30.tar.gz` |
| Source | `/app/rocket-p0/src/.git` (read-only tar, `--numeric-owner`) |
| Size | **153,416,720 bytes (146.3 MiB)** |
| Members | **1,247** |
| **SHA-256** | **`e16ba1e1b15ebac2ba5b5340d422729818e82ec257c4b1661090ed89c1b8debd`** |
| Checksum sidecar | `ROCKET-P0-SRC_GIT_DIR_FULL_2026-10-30.tar.gz.sha256` |
| Contents | complete `objects/` (loose + 2 packs), `refs/`, `packed-refs`, `HEAD`, `ORIG_HEAD`, `FETCH_HEAD`, `config`, `index`, `logs/` (reflogs), `hooks/`, `info/`, `branches/`, `worktrees/`, `description`, `COMMIT_EDITMSG` |

Why a tar rather than a second bundle: `git bundle` captures only **reachable** history, which is exactly why the nine dangling objects were missing from T1. A file-level archive captures them verbatim and additionally preserves reflogs and `ORIG_HEAD`, which no bundle can carry.

---

## 3 · Archive integrity verification — **PASS**

| Verification | Result |
|---|---|
| `gzip -t` | **OK** — no compression corruption |
| `tar -tzf` | 1,247 members listed without error |
| **Full extraction test** | extracted to `/var/tmp/t2verify`, then verified as a live repository |
| HEAD after restore | `cd2b8b92d785bee2f88432d3202367bbd51508c0` — identical to source |
| Refs after restore | **27 / 27** (23 heads, 3 remote-tracking, 1 tag) — bundle-only restore yields 24 because bare clones drop remote-tracking refs; the tar restores all 27 |
| `git fsck --full` on the restored copy | clean — 0 errors; the same 9 informational "dangling" lines as the source |
| **Nine unreachable objects resolvable in the restored copy** | **all 9 present**: `6c1e1c4f`=commit, `849a70d2`=commit, `2f940c8b`=commit, `990ab60c`/`9e497151`/`0a56948a`/`ce751789`/`6bb17e12`/`87ef2add`=blob |
| Verification copy | removed after the check |

**Pre-check confirming the need:** all nine objects were verified to be **loose** (`objects/6c/1e1c…`, `objects/84/9a70…`, …), which is why a file-level archive captures them.

---

## 4 · Credential and sensitive-material inspection (values never disclosed)

### 4.1 Method
History-wide path enumeration (`git rev-list --all --objects` → 8,405 distinct paths), filename pattern matching, then **count-only** regex scans of the candidate blobs and of all six dangling blobs. No blob content was written to any file or displayed.

### 4.2 Findings

| Check | Result |
|---|---|
| `.git/config` embedded-credential URLs (`https://user:token@…`) | **0** |
| `.git/config` GitHub token prefixes (`ghp_`, `github_pat_`, `gho_`, `ghs_`) | **0** |
| `.env` files anywhere in history | **none** — environment files were never committed |
| Private keys (`*.pem`, `*.key`, `id_rsa`, `*.pfx`, `*.p12`, `*.keystore`) | **none** |
| Cloud key patterns (`AKIA…`, `BEGIN … PRIVATE KEY`) in the six dangling blobs | **0 matches** |
| Secret-looking patterns in the three dangling commits' blobs | **0 matches** |
| Sensitive-sounding **source** paths (18) | all are legitimate product code or docs — `backend/routers/xdr_secrets.py`, `backend/security/secret_policy.py`, `backend/detection_content/xdr_credential_vault.py`, `apps/.../admin/SecretsBody.jsx`, their tests, and `docs/.../SECRETS_MANAGEMENT.md`. **Code about secrets, not secrets** |

### 4.3 🔴 HIGH — a credential-shaped blob **is** present in both archives

| Property | Finding (shape only) |
|---|---|
| Path | `.tok` at the repository root |
| Versions in history | **22 distinct blobs** |
| Size | 163 bytes each |
| Shape | single line, **no newline**, 160 alphanumeric characters, begins with `e` — consistent with an opaque bearer token / JWT-like credential |
| Known secret prefixes | none matched (not a GitHub PAT format) |
| Present at the clone's HEAD | **no** — removed from the tip, but **retained in history** |
| Reachability | reachable from the preserved refs, therefore present in **both** the T1 bundle **and** the tar archive |

**Consequences, stated plainly:**

1. **Both archives must be treated as secret-bearing.** They may not be placed on public storage, in a public repository, or in any shared location.
2. **This value should be rotated** regardless of this exercise — a token committed to history must be assumed exposed. Rotation is a separate authorized action; I did not perform it and did not read the value.
3. **This blocks a naive history migration.** Pushing `rocket-p0` history into `nivxforge-edr` would carry all 22 credential blobs into the new repository. If that history is ever migrated, it must be filtered first (`git filter-repo --invert-paths --path .tok`), which rewrites commit IDs — a decision requiring its own gate, and one that **must not** be applied to the original.
4. A `.tok` blob was independently observed at the root of the reviewer repository tree in A0-02. The same hygiene item appears in both repositories.

---

## 5 · Prepared artifacts and the exact download mechanism

### 5.1 Artifacts (all on the `/` overlay volume, outside `/app`)

| File | Size | SHA-256 |
|---|---|---|
| `ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle` | 124,634,440 B | `9ae11e502c9596ea603e21cabce8f9d22c812317a683e21f6168e7cee1d1e0a4` |
| `ROCKET-P0-SRC_GIT_DIR_FULL_2026-10-30.tar.gz` | 153,416,720 B | `e16ba1e1b15ebac2ba5b5340d422729818e82ec257c4b1661090ed89c1b8debd` |
| `…bundle.sha256` · `…tar.gz.sha256` · `…refs.txt` | 113 B · 142 B · 2,237 B | sidecars |

Location: `/var/backups/nivx-preservation/` — deliberately **not** `/app`, because `/app` is 90 % full and its contents are auto-committed to Git; 271 MB of binaries must not enter repository history.

### 5.2 Download mechanism — capability URL, retrieval-then-revoke

Because the artifacts live outside `/app`, the VS Code explorer cannot reach them. One additive, **flag-gated** static mount was added (`ARCH_DOCS_SHARE=1`, same mechanism as the existing documentation route) on an unguessable path segment:

```
Base:  https://greeting-app-5782.preview.emergentagent.com/api/_pv/ff603ec885f6068365d62548/

  ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle            124,634,440 B
  ROCKET-P0-SRC_GIT_DIR_FULL_2026-10-30.tar.gz              153,416,720 B
  ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle.sha256
  ROCKET-P0-SRC_GIT_DIR_FULL_2026-10-30.tar.gz.sha256
  ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.refs.txt
```

**End-to-end transfer proof:** the bundle was downloaded through this URL and re-hashed — 124,634,440 bytes, SHA-256 `9ae11e50…e1d1e0a4`, **byte-identical** to the source. The test copy was deleted.

**Verify after download, on your own machine:**

```bash
sha256sum -c ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle.sha256
sha256sum -c ROCKET-P0-SRC_GIT_DIR_FULL_2026-10-30.tar.gz.sha256
git clone --bare ROCKET-P0-SRC_UNIQUE_HISTORY_2026-10-30.bundle verify-clone   # expect 23 heads + 1 tag
tar -tzf ROCKET-P0-SRC_GIT_DIR_FULL_2026-10-30.tar.gz | wc -l                   # expect 1247
```

**Honest limitation:** this route is unauthenticated. The path segment is a 96-bit random capability, not an access control, and the payload is secret-bearing (§4.3). Treat it as a one-time retrieval: **download, verify the hashes, then tell me and I will remove the mount and the flag immediately.** It is preview-only — the flag is not set in production, and production deployment remains on HOLD.

**Recommended destination:** an encrypted volume on your own device, or private storage you control. Not a public repository, not a shared drive, not the new EDR repository until the `.tok` question is settled.

---

## 6 · Original unchanged — post-state proof

| Check | Result |
|---|---|
| Ref list (27 refs, object + name) | **`diff` identical to the T1 pre-state — REFS UNCHANGED** |
| HEAD | `cd2b8b92d785bee2f88432d3202367bbd51508c0` |
| Working tree | clean — 0 dirty paths |
| Objects | loose 787, in-pack 35,992, pack 140.45 MiB — **identical** |
| Garbage / pruned | 0 / none; no `gc`, `prune` or `repack` ran |
| `/app` repository | `backend` clean, untouched |
| XDR / Workspace / NivX Machines source | untouched; **no XDR or Workspace source was copied anywhere** |

---

## 7 · Storage position

| Item | Value |
|---|---|
| Destination volume (`/` overlay) | 282 GB total, **235 GB free (17 % used)** |
| Artifacts total | 271 MB (118.9 MiB + 146.3 MiB + sidecars) |
| `/app` impact | **none** — nothing written to `/app`; still ~1.1 GB free |
| Temporary verification copies | created and removed (extraction ≈ 160 MB, download test ≈ 119 MB) |

---

## 8 · Remaining preservation risks

| # | Risk | Severity | Status after T2 |
|---|---|---|---|
| R1 | **Artifacts still live only on this pod.** Both copies share one volume with the source | **HIGH — OPEN until you download** | mitigated the moment the two files are on an independent device; the download path is proven byte-exact |
| R2 | Unreachable objects unpreserved | **CLOSED** | all nine verified inside the tar and resolvable after restore |
| R3 | **`.tok` credential blobs (22 versions) inside both archives** | **HIGH — NEW** | rotate the value; filter before any history migration; keep archives private |
| R4 | `rocket-p0/` non-Git assets still unclassified — `f1/` 208 MB, six gate working copies ≈ 94 MB each, `SECURE_EXPORT/` directories | MEDIUM | out of T2 scope; `SECURE_EXPORT/` deserves a scoped audit first |
| R5 | Preservation ≠ tested build | LOW | object/ref integrity proven; restore-to-build (P0-02A test T2) still open |
| R6 | The capability URL is unauthenticated while it exists | MEDIUM | time-bounded by design — remove on your word |
| R7 | P0-02A blockers unchanged: no production backup, unknown backend revision, unknown production DB identity, missing installer artefacts, no VM snapshot | **HIGH** | untouched by T2 |

---

## 9 · Verdict

### **PASS — verified, securely transferable backup artifacts are ready**

Two independent, integrity-verified artifacts now exist outside `/app`: the reachable-history bundle (re-verified against its T1 hash) and a complete `.git` archive that additionally preserves **all nine unreachable objects**, the reflogs and `ORIG_HEAD`. Both were proven restorable — the tar by full extraction to a working repository with clean `fsck` and all 27 refs, the bundle by an end-to-end download that re-hashed byte-identically. The source repository is provably unchanged, nothing was pushed, and no XDR or Workspace source was copied.

**One finding changes the next step:** the archives contain 22 historical versions of a 163-byte, 160-character credential-shaped blob at `.tok`. Treat both files as secret-bearing, rotate that value, and do not migrate this history into `nivxforge-edr` until the blob is filtered out of the copy — never out of the original.

Stopping here as instructed. Tell me when the download is complete and I will remove the temporary route and its flag.
