# NIVXFORGE M1 — G3 SOURCE SNAPSHOT · PROVENANCE

## What this is

A **sanitized, self-contained** export of the NivXForge M1 clean-installer
source at the G3 candidate revision, produced because the candidate's own Git
history **cannot be exported** (see §4).

| Field | Value |
|---|---|
| Candidate commit | `601eaa4625984b062be01848004744a5ba6d2603` |
| Candidate tree | `9d07cb6c4285a30142d915761ef5a9324840921b` |
| Parent | `4b3b6a2c7c7fc2f339bd2725c28d942f6693d575` |
| Grandparent (M1 G2) | `0fd09b3a1f9eacfab12e41ef7c6d971a98ecdcae` |
| M1 baseline | `bc8147be15af46e87a95612322e7d17f3859f587` |
| Branch | `engineering/m1-g3-corrective` |
| Authoritative worktree state | clean, `git status --porcelain` empty |

## 1 · What a snapshot can and cannot prove

**CANNOT.** This snapshot **cannot prove the Git commit identity**
`601eaa46…`. A commit hash covers its complete tree and its parent chain;
neither is reproduced here, so no amount of verification against this export
establishes that commit `601eaa46` exists or that it contains these bytes.
Accepting that linkage requires the authoritative repository.

**CAN.** Every exported file is the **identical Git blob object** from the
candidate tree. A blob hash is content-addressed, so a matching blob hash can
only arise from byte-identical content. Two independent checks are therefore
available without the original repository:

1. **Per-file blob identity** — `git hash-object <path>` reproduces the blob
   SHA-1 recorded in `PROVENANCE_BLOBS.txt`, for all 18 files.
2. **Subtree identity** — the whole `agents/nivxforge-windows` directory
   hashes to the *same tree object* as in the candidate:

   | Path | Authoritative tree object at `601eaa46` | Reproduced here |
   |---|---|---|
   | `agents/nivxforge-windows` | `51d6b3838b0b08c7a232d8cc3c31eb8b8eb5e4e8` | **yes** |
   | `agents/nivxforge-windows/build` | `342244773daeff440bf421f2b97e427df516ae77` | **yes** |
   | `agents` | `6acc186de1dbe6062fcdd5dae6b351f07e9acf92` | no — see below |
   | `backend/tests/edr` | (115 files upstream) | no — see below |

   `git rev-parse HEAD:agents/nivxforge-windows` in this snapshot must equal
   `51d6b383…`. That is a Git-level proof that the entire M1 implementation
   directory — every file, name, mode and the directory structure — is
   byte-and-structure identical to the candidate. It is the strongest
   statement available without the commit history.

   The two parent directories are **deliberately not** reproduced and their
   tree hashes will NOT match, which is expected and is not a discrepancy:
   upstream `agents/` also contains `_shared/` and `nivxforge-linux/`, and
   upstream `backend/tests/edr/` contains 115 files of which 112 are unrelated
   live-edge suites, six of them carrying hardcoded admin passwords (§4). Only
   the three M1-relevant files from that directory are exported, so its tree
   necessarily differs. Verification is therefore per-file for those paths and
   per-tree for `agents/nivxforge-windows`.

`PROVENANCE_BLOBS.txt` additionally carries an independent SHA-256 per file,
so content can be checked without trusting SHA-1.

## 2 · Contents — the full cumulative M1 working set

Not merely the last corrective patch. This is the complete M1 implementation
as of the candidate, with its installer entrypoint, local dependencies and
regression suite.

| File | Role |
|---|---|
| `agents/nivxforge-windows/nivxforge_m1.py` | the M1 clean-installer module: fresh-host probes, protected configuration, ownership, native service security, filesystem verdicts, payload provenance, process/image evidence, `WindowsHost` |
| `agents/nivxforge-windows/nivxforge_setup.py` | **installer entrypoint**: parser, `m1_dispatch`, `m1_payload_source`, enterprise paths unchanged |
| `agents/nivxforge-windows/nivxforge_sensor.py` | enrolment, identity publication, collection loop |
| `agents/nivxforge-windows/nivxforge_journal.py` | telemetry journal (required local dependency, unmodified) |
| `agents/nivxforge-windows/nivxforge_transaction.py` | enterprise transaction engine — present so the reviewer can confirm M1 does **not** touch it |
| `agents/nivxforge-windows/nivxforge_scm_worker.py` | enterprise SCM worker, likewise |
| `agents/nivxforge-windows/nivxforge_exclusions.py`, `nivxforge_delivery_counters.py`, `nivxforge_content_acquisition.py` | required local dependencies |
| `agents/nivxforge-windows/build/build_windows_installer.ps1` | packaging, hidden imports, payload manifest |
| `agents/nivxforge-windows/build/Invoke-TransactionAcceptance.ps1`, `build/run_transaction_tests.py` | build-side acceptance harness |
| `agents/nivxforge-windows/Install-NivXForgeSensor.ps1` | operator wrapper |
| `agents/nivxforge-windows/sysmon/*` | canary Sysmon config referenced by the sensor |
| `backend/tests/edr/test_m1_clean_install.py` | the complete M1 regression suite (275 tests) |
| `backend/tests/edr/conftest.py`, `__init__.py` | collection support for that path |

## 3 · Running the suite from this snapshot

```
python3 -m pytest backend/tests/edr/test_m1_clean_install.py -q
```

The suite resolves the agent directory relatively
(`Path(__file__).resolve().parents[3] / "agents" / "nivxforge-windows"`), so
the two directories must keep the layout as exported. It needs `pytest` and —
for the directory `conftest.py` only — `requests`. It requires **no** backend
service, database, network or Windows host. Expected: **275 passed**.

## 4 · Sanitization statement

The candidate tree `9d07cb6c` **could not be exported in full**, and the
commit's own history could not be bundled, because **the tree itself contains
live credential material**. Exporting it would move secrets off the pod. The
following were audited and withheld. **No withheld value is printed anywhere
in this export, and none is reachable from it.**

| Withheld | Reason |
|---|---|
| `.tok` (repository root) | contains a bearer token (JWT) |
| `memory/evidence/17_production_smoke.txt` | production smoke evidence containing a JWT |
| `memory/P0_PREVIEW_VS_PRODUCTION_INCIDENTS_DIAGNOSIS.md` | contains a JWT |
| `backend/tests/edr/test_dt2_3_graph_read.py`, `test_iteration_82_activation.py`, `test_p0_a2_adversarial_live.py`, `test_p0_f6_response_ui_backend.py`, `test_p0c_durable_findings_live.py`, `test_wave0_api_smoke.py` | hardcoded live-edge admin passwords |
| `apps/nivxray-xdr/.env.development` | environment file |
| ~12,355 further files | the remainder of the XDR monorepo, out of scope for M1 G3 |

Audit performed over **both** the candidate tree and all 2,476 commits of
reachable history, for: `.env*`, `*.pem`, `*.key`, `*.pfx`, `*.p12`, `*.jks`,
`*.keystore`, `id_rsa*`, and for value patterns `sk-…`, `ghp_…`,
`github_pat_…`, `AKIA…`, `xox[baprs]-…`, `AIza…`,
`-----BEGIN … PRIVATE KEY-----` and `eyJhbGciOi…`. Across history, exactly one
environment file was ever added (`apps/nivxray-xdr/.env.development`) and no
private key, certificate or keystore was ever committed.

**The 18 exported files were scanned with the same patterns and are clean.**
They contain no token, password, key, certificate or environment value. The
only credential-adjacent material is the *handling logic* under review —
`read_enrolment_secret`, identity publication, the enrolment attempt marker —
which contains no values.

A full-history bundle is therefore deliberately **not** offered: its history
is not safe to export. An incremental bundle is also not offered again, since
the prerequisite chain `601eaa46 → 4b3b6a2c → 0fd09b3a → bc8147be → …` reaches
back through all 2,476 commits, and no prefix of that chain can be supplied
without the credential material above.

## 5 · Independent verification

See `VERIFY.sh`, which performs every check in a throwaway directory with no
access to the authoritative repository or its object database.
