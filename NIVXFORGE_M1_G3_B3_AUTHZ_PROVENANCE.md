# NIVXFORGE M1 — G3-B3 AUTHZ CORRECTION · SOURCE SNAPSHOT PROVENANCE

## What this is

A **sanitized, self-contained** export of the NivXForge M1 clean-installer
source at the current G3 candidate revision, produced because the candidate's
own Git history **cannot be exported** (see §4).

| Field | Value |
|---|---|
| Candidate commit | `388bb3d637a076f36d78fc9d1e218c878b082b9b` |
| Candidate tree | `df8eb48b5719b01c936c8dec3442aeba7763a59f` |
| Parent | `a4e544f45772a90686d478a19a7ce80201616506` (G3 integrated B1/B2/B3) |
| Earlier candidates | `601eaa46` (G3-01 AccessCheck), `4b3b6a2c` (G3 FAIL), `0fd09b3a` (G2) |
| Contains | the cumulative M1 implementation, including the B3 AuthzAccessCheck result correction |
| Branch | `engineering/m1-g3-integrated` |
| Authoritative worktree state | clean, `git status --porcelain` empty for both exported paths |

## 1 · What a snapshot can and cannot prove

**CANNOT.** This snapshot **cannot prove the Git commit identity**
`388bb3d6…`. A commit hash covers its complete tree and its whole parent
chain; neither is reproduced here, so no amount of verification against this
export establishes that commit `388bb3d6` exists or that it contains these
bytes. Accepting that linkage requires the authoritative repository.

**CAN.** Every exported source file is the **identical Git blob object** from
the candidate tree. A blob hash is content-addressed, so a matching blob hash
can only arise from byte-identical content. Two independent checks are
therefore available without the original repository:

1. **Per-file blob identity** — `git hash-object <path>` reproduces the blob
   SHA-1 recorded in `PROVENANCE_BLOBS.txt`, for all 18 source files.
   `PROVENANCE_BLOBS.txt` additionally carries an independent SHA-256 per
   file, so content can be checked without trusting SHA-1.
2. **Subtree identity** — the whole `agents/nivxforge-windows` directory
   hashes to the *same tree object* as in the candidate:

   | Path | Authoritative tree object at `388bb3d6` | Reproduced here |
   |---|---|---|
   | `agents/nivxforge-windows` | `db21f422561f14fb4dcec91b70925f2b5291c500` | **yes** |
   | `agents/nivxforge-windows/build` | `342244773daeff440bf421f2b97e427df516ae77` | **yes** (unchanged since G2) |
   | `agents` | — | no, deliberately partial |
   | `backend/tests/edr` | — | no, deliberately partial |

   `git rev-parse HEAD:agents/nivxforge-windows` in this snapshot must equal
   `db21f422…`. That is a Git-level proof that the entire M1 implementation
   directory — every file, name, mode and the directory structure — is
   byte-and-structure identical to the candidate.

   The two parent directories are **deliberately not** reproduced and their
   tree hashes will NOT match, which is expected and is not a discrepancy:
   upstream `agents/` also contains `_shared/` and `nivxforge-linux/`, and
   upstream `backend/tests/edr/` contains unrelated live-edge suites, six of
   them carrying hardcoded admin passwords (§4). Only the three M1-relevant
   files from that directory are exported, so its tree necessarily differs.
   Verification is per-file for those paths and per-tree for
   `agents/nivxforge-windows`.

## 2 · What changed in this revision

Two files differ from the parent candidate `a4e544f4`
(`3 files changed` upstream figure does not apply here; this revision is
`2 files changed, 453 insertions(+), 28 deletions(-)`):

| File | Change |
|---|---|
| `agents/nivxforge-windows/nivxforge_m1.py` | `ERROR_SUCCESS`; new pure `authz_access_verdict()`; `_authz_access_check()` reduced to descriptor lifetime plus the contract function; new `_authz_invoke()` carrying the native call with `Flags` declared as a `DWORD` |
| `backend/tests/edr/test_m1_clean_install.py` | 43 added regressions for the Authz reply contract, the native edge, per-principal combination, service-time validation and the `load_config` trace |

Everything else in the export is the cumulative M1 working set, unchanged, so
the reviewer sees the complete implementation rather than a patch: the
installer entrypoint `nivxforge_setup.py`, the sensor, journal, the enterprise
transaction engine and SCM worker (present so it can be confirmed that M1 does
**not** touch them), the local dependencies, the build scripts and the
operator wrapper.

## 3 · Running the suite from this snapshot

```
python3 -m pytest backend/tests/edr/test_m1_clean_install.py -q
```

The suite resolves the agent directory relatively
(`Path(__file__).resolve().parents[3] / "agents" / "nivxforge-windows"`), so
the two directories must keep the layout as exported. It needs `pytest` and —
for the directory `conftest.py` only — `requests`. It requires **no** backend
service, database, network or Windows host. Expected: **373 passed**.

These are portable tests of source logic. They prove nothing about real
Windows behaviour: no SCM, token, Authz, ACL, filesystem or LocalSystem call
is made. Note in particular that `wintypes.DWORD` is 8 bytes on 64-bit Linux
and 4 bytes on Windows, so the structure layouts exercised here are **not**
the Windows binary layouts.

## 4 · Sanitization statement

The candidate tree **could not be exported in full**, and the commit's own
history could not be bundled, because **the upstream tree contains live
credential material**. Exporting it would move secrets off the pod. The
following were audited and withheld. **No withheld value is printed anywhere
in this export, and none is reachable from it.**

| Withheld | Reason |
|---|---|
| `.tok` (repository root) | contains a bearer token (JWT) |
| `memory/evidence/17_production_smoke.txt` | production smoke evidence containing a JWT |
| `memory/P0_PREVIEW_VS_PRODUCTION_INCIDENTS_DIAGNOSIS.md` | contains a JWT |
| `backend/tests/edr/test_dt2_3_graph_read.py`, `test_iteration_82_activation.py`, `test_p0_a2_adversarial_live.py`, `test_p0_f6_response_ui_backend.py`, `test_p0c_durable_findings_live.py`, `test_wave0_api_smoke.py` | hardcoded live-edge admin passwords |
| `apps/nivxray-xdr/.env.development` | environment file |
| the remainder of the XDR monorepo | out of scope for M1 G3 |

The audit covering the candidate tree and all reachable history was performed
for the previous candidate and is unchanged by this revision, which touches
only the two files named in §2. **The 18 exported files were re-scanned with
the same patterns — `sk-…`, `ghp_…`, `github_pat_…`, `AKIA…`, `xox[baprs]-…`,
`AIza…`, `-----BEGIN … PRIVATE KEY-----`, `eyJhbGciOi…` — and are clean.**
They contain no token, password, key, certificate or environment value.

A full-history bundle is therefore deliberately **not** offered: that history
is not safe to export. An incremental bundle is also not offered, since the
prerequisite chain `388bb3d6 → a4e544f4 → 601eaa46 → 4b3b6a2c → 0fd09b3a → …`
reaches back through the whole repository and no prefix of it can be supplied
without the material above.

## 5 · Independent verification

See `VERIFY.sh`, which performs every check in a throwaway directory with no
access to the authoritative repository or its object database: repository
integrity, object completeness, subtree identity, per-file blob and SHA-256
identity, that the exported source parses, a credential scan, and the
portable regression suite.

## 6 · Boundary

This is a **G2 corrective implementation** awaiting independent G3 review. It
is not approved, not merged, not deployed and not signed. Nothing in this
export constitutes evidence of Windows-native (G4) acceptance.
