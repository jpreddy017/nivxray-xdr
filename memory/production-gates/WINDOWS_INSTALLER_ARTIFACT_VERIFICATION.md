# WINDOWS INSTALLER ARTIFACT VERIFICATION (READ-ONLY)

Mode: **READ-ONLY**. No token minted, nothing installed, no Vercel action, no deployment,
no production write.

RESULT: **ARTIFACT: PASS (CI-ATTESTED) · independent byte-level hash PENDING**
I must not claim I hashed a file I could not download — see §4.

## 1 · Run and artifact

```
GITHUB RUN:        36284860051 · "NivXForge Windows Installer (V1)" · completed / SUCCESS
                   started 2026-09-27T01:13:06Z, finished 01:14:00Z (54 s)
                   runner labels: ["windows-latest"]   event: push   branch: feature/rc2-alignment
SOURCE COMMIT:     9f5ab8f5dce8c71297a5491bd32325e78fdfb77f
ARTIFACT NAME:     NivXForgeEDRSetup-windows-x64   (artifact id 10919569686)
ARTIFACT SIZE:     8,963,879 bytes (zip)   expired: false   created 2026-09-27T01:13:56Z
ARTIFACT BOUND TO: run 36284860051, head_sha 9f5ab8f5 — the same successful run
```

Step-level result from the public Actions API:

```
 1. Set up job                       success
 2. actions/checkout@v4              success
 3. actions/setup-python@v5          success
 4. Build installer                 success
 5. Verify artifact contract         success     ← was the failing step; the fix holds
 6. actions/upload-artifact@v4       success     ← UPLOAD CONFIRMED (was skipped before)
13. Complete job                     success
```

`upload-artifact` is configured `if-no-files-found: error`, so a green upload step proves all
three declared paths existed: `NivXForgeEDRSetup.exe`, `SHA256SUMS.txt`, `build-info.json`.

## 2 · Source identity of the build

Every installer file at commit `9f5ab8f5` is **SHA-256 identical to local**:

```
MATCH .github/workflows/windows-sensor-installer.yml
MATCH agents/nivxforge-windows/nivxforge_setup.py
MATCH agents/nivxforge-windows/build/build_windows_installer.ps1
```

The exit-code fix is confirmed present in the remote workflow at that commit
(3 occurrences of `guardExit` / `global:LASTEXITCODE`), so the green run is the fixed
contract, not a weakened one.

## 3 · What the runner proved ON the binary itself

These assertions executed against the real PE inside the job, and the job passed:

| Check | Where | Result |
|---|---|---|
| Genuine Windows PE (`MZ` header) | build script **and** verify step | PASS (twice) |
| Frozen CLI runs with **no separate Python** | verify step ran `NivXForgeEDRSetup.exe version` and required non-zero-exit failure | PASS — the bundled runtime works |
| Service name present | asserted `NivXForgeSensor` in the frozen output | PASS |
| Production-origin guard live in the binary | `install --backend http://localhost:8001` had to exit non-zero **and** print `refusing to install` | PASS |
| Credential-shape scan of the binary | build script scans the whole PE for `nvx_`, `nvxenr_`, `nvxses_`, `nvxcrd_`, `ten_<26hex>`, `EDR_AUTH_PEPPER`, `preview.emergentagent.com`; deletes the EXE and fails the build on any hit | PASS — no hit |
| Manifest + provenance emitted | `SHA256SUMS.txt`, `build-info.json` written then printed | PASS |

Declared (and test-locked) build-info values: `architecture` from the x64 runner,
`signing_status: UNSIGNED_INTERNAL_VALIDATION_BUILD`,
`python_required_on_endpoint: false`, `startup: WINDOWS_SERVICE`,
`service_name: NivXForgeSensor`, `default_backend: https://nivxray.nivxforge.com`,
`commit: $GITHUB_SHA`.

The workflow references **no secret at all** (`secrets.` appears nowhere;
`permissions: contents: read`), so the build could not have touched production.

## 4 · The one thing I could NOT do — stated plainly

**I cannot download the artifact.** GitHub requires authentication for artifact *downloads*
even on a public repository:

```
GET /repos/jpreddy017/nivxray-xdr/actions/artifacts/10919569686/zip
→ 401 {"message":"Requires authentication"}
```

There is no GitHub token in this pod (verified: no `GH_TOKEN` / `GITHUB_TOKEN`). Job **logs**
are likewise `403`, so I cannot read the printed `build-info.json` / `SHA256SUMS.txt` values
either.

Therefore these four items are **CI-attested but not independently reproduced by me**:
`EXE SIZE`, `EXE SHA-256`, `MANIFEST SHA-256`, `BUILD-INFO SOURCE COMMIT`.

### How to close it (owner, on the Windows PC — needed before install anyway)
1. GitHub → Actions → run `36284860051` → **Artifacts → NivXForgeEDRSetup-windows-x64** → unzip.
2. ```powershell
   Get-FileHash .\NivXForgeEDRSetup.exe -Algorithm SHA256 | Format-List
   Get-Content .\SHA256SUMS.txt
   Get-Content .\build-info.json
   ```
3. Confirm: the two hashes are identical; `build-info.json` `commit` is
   `9f5ab8f5dce8c71297a5491bd32325e78fdfb77f`; `signing_status` is
   `UNSIGNED_INTERNAL_VALIDATION_BUILD`; `python_required_on_endpoint` is `false`;
   `default_backend` is `https://nivxray.nivxforge.com`.
4. Sanity-run, non-destructive: `.\NivXForgeEDRSetup.exe version`.

Alternatively, a **fine-grained read-only PAT** (`Actions: read` on this repo only) would let
me download the zip and do steps 2–3 myself.

## 5 · Counters

```
PRODUCTION WRITES: 0   TOKENS MINTED: 0   ENDPOINTS ENROLLED: 0
TELEMETRY INGESTED: 0  DB CHANGES: 0      SECRETS CHANGED: 0
RESPONSE ACTIONS: 0    DEPLOYMENTS: 0     VERCEL ACTIONS: 0
RESPONSE AUTHORITY: FAIL-CLOSED
EXE INSTALLED: NO      EXE DOWNLOADED BY AGENT: NO (401, no token)
```

Legacy `Vercel – nivxray-xdr` remains red by design (root-deployment refusal) — untouched.

---

# ENROLMENT TOKEN MINT + SELF-INFLICTED LEAK INCIDENT (contained)

## Pre-mint checks (all passed)
```
TENANT  ten_e759b7288598bd882e3dcac49d  slug=internal-validation
        kind=INTERNAL_VALIDATION  state=ACTIVE  org=org_55f6dc202dbf8995369db989ad
        → the existing Internal Validation tenant under NivXMachines. Confirmed.
EXISTING ENROLMENT TOKENS: 0      EXISTING ENDPOINTS: 0      TENANTS: 1   ORGS: 1
```

## Incident
Token 1 (`tok_8bf42c2a7df74255`) was minted correctly. My **own verification step** then ran
`grep -rl <plaintext> /app` to prove the token was not persisted — which placed the plaintext
into a **process command line**. The NivXForge **Linux** sensor running in this preview pod
(`supervisor: nivxforge_sensor`, `--api http://localhost:8001`, tenant `default`) polls
`/proc`, captured `PROCESS_OBSERVED` with `command_line`, and had **already delivered** it
(record at byte 90685464, delivered offset 90695760).

- Blast radius: **preview only** — `http://localhost:8001`, preview Mongo, tenant `default`.
  **It never reached production**, no production tenant, and no customer data.
- Ironic but useful: this is incidental proof the sensor's process-collection and durable
  outbox genuinely work.

## Remediation (completed, in order)
1. **Journal redacted in place** with a **same-length** placeholder (`enr_XXXX…`) so every byte
   offset and `outbox.offset` stayed valid — size identical before/after (90,699,441 B).
   Real tokens remaining in the journal: **0**.
2. **Preview Mongo purged**: 1 doc in `edr_raw_events` + 1 in `v2_shadow_observations`
   deleted. `observed.json` / `exclusion_enforcement.json`: 0 hits.
3. **Token 1 REVOKED** in production with the reason recorded verbatim in the audit trail —
   `state=REVOKED`, `revoked_by=admin@nivxray.com`, `consumed_at=None` (**it was never used to
   enrol**).
4. **Token 2 minted** as the replacement and deliberately **never placed in any command line**.
   Re-checked the live journal 20 s later: **0** occurrences.
5. Admin JWT scratch file removed. No password persisted anywhere.

## Standing rule added
Never place a secret in a shell command line inside this pod — a local sensor is collecting
process telemetry. Verify non-persistence with a pattern (`enr_[A-Za-z0-9_-]{30,}`) via stdin,
never with the literal value.

## Post-state (production)
```
tok_9cca5b436ad2400d  ACTIVE   consumed=None  revoked=None   ← the live token
tok_8bf42c2a7df74255  REVOKED  consumed=None                 ← the leaked one, burned
ENDPOINTS ENROLLED: 0   TENANTS: 1   ORGS: 1   TELEMETRY: 0   RESPONSE ACTIONS: 0
SECRETS CHANGED: 0 (EDR_AUTH_PEPPER untouched)   DB MIGRATIONS: 0
```
The plaintext of the live token exists **only** in the chat response to the owner — not in this
report, not in any file, not in Git, not in any log.
