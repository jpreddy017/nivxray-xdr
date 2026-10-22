# NIVXFORGE EDR — P0-2 WINDOWS INSTALLER OWNERSHIP DECISION
## READ-ONLY G0/G1 decision assessment · no implementation

Input of record: `NIVXFORGE_EDR_P0_1_WINDOWS_EXECUTION_PATHS.md`
(`099a6338bb9e1efd96fe9b3f11fc0f1130cf1a2fb6e9b1db8f4c9ff4e2c4d503`).
Trunk `f971c765` · M1 `388bb3d6` · frozen subtree `db21f422…` (untouched).
No CI, no deployment, no database change, no source edit, no endpoint action,
no migration, no task deletion, no service replacement.

---

## 1 · What Management → Downloads actually exposes, verified

Two independent distribution surfaces exist, and **each caps the downloadable
file set to its own declared list**:

| Surface | Route | Declared files | Gate |
|---|---|---|---|
| Onboarding packages | `GET /api/edr/onboarding/packages/{id}/file/{name}` | `windows-x64`: `Install-NivXForgeSensor.ps1`, `nivxforge_sensor.py` | `_artifact_path` 404s `ARTIFACT_NOT_IN_PACKAGE` for anything else (`edr_onboarding.py:136-139`) |
| Connector releases | `GET /api/edr/connector/releases/{id}/artifact/{name}` | `nvf-connector-windows-0.2.0-x64`: the above **+ `nivxforge_exclusions.py`** | `catalog.artifact_path` returns `None` for anything else (`catalog.py:257-264`) |

**Decisive availability finding — the advertised path is not installable as
published.** `Install-NivXForgeSensor.ps1` copies **four** `.py` siblings from
`$PSScriptRoot` under `$ErrorActionPreference = 'Stop'`:
`nivxforge_sensor.py`, `nivxforge_exclusions.py`,
`nivxforge_delivery_counters.py`, `nivxforge_content_acquisition.py`
(`PS1:145-151`). Onboarding can deliver **two** of them, the connector release
**three**. An operator who downloads exactly what the console offers gets an
installer that throws at the first missing `Copy-Item` and prints
*"INSTALL FAILED … nothing was enrolled or started by this attempt"*
(`PS1:198-201`). The missing modules are not a 404-by-accident: they are
absent from both declared inventories.

**Actual availability of each artifact:**

| Artifact | On disk | API state | Note |
|---|---|---|---|
| `Install-NivXForgeSensor.ps1` + `nivxforge_sensor.py` | present | `AVAILABLE` / `PUBLISHED`, `download_available: true` | the UI's download and "Deploy this version" buttons key **solely** off `download_available` (`EdrDownloadsPage.jsx:164,178`) |
| `nivxforge_exclusions.py`, `nivxforge_delivery_counters.py`, `nivxforge_content_acquisition.py` | present on disk | **not offered** by onboarding; only `exclusions` by the connector release | required by the PS1 at install time |
| `NivXForgeEDRSetup.exe` | **absent** — `agents/nivxforge-windows/dist/` does not exist in either revision | `INCOMPLETE` → `download_available: false` → route returns **409 `PACKAGE_NOT_AVAILABLE`** | `release_status: CI_BUILD_REQUIRED`, `signing_status: UNSIGNED_INTERNAL_VALIDATION_BUILD` |
| `windows-arm64`, `windows-x86` | no files declared | `NOT_BUILT` | no execution path to assess |
| M1 clean installer | ships **inside** the EXE (`m1-install` subcommand) | **no distribution surface at all** | not in `PACKAGES`, not in `RELEASES`; requires a pre-provisioned protected `--m1-config` root |

A second structural limit: `download_artifact` reads with
`open(path, encoding="utf-8")` and returns `PlainTextResponse`
(`edr_onboarding.py:242-250`). **A PE binary cannot be served by this route
even once it is built** — distributing the EXE needs a different transport, not
just a build.

Declared support posture, unchanged by this assessment:
`support_status: PREVIEW_NOT_FOR_PRODUCTION`, `signing_status: UNSIGNED`,
`requires: Python 3.11+ on the endpoint` (`catalog.py:59-95`).

---

## 2 · Mechanism comparison

| Dimension | **A · PS1 scheduled task** | **B · Trunk SCM installer** | **C · M1 clean installer** |
|---|---|---|---|
| **Installation security** | elevation checked; state dir ACL'd to SYSTEM+Administrators. **But the interpreter is resolved by `Get-Command python.exe` and that resolved path is baked into a SYSTEM `/RL HIGHEST` task** (`PS1:72-78, 181-183`) — if the first `python.exe` on PATH sits in a user-writable location, a user-writable binary executes as SYSTEM at every boot. No digest, no signature, no payload verification of the copied `.py` files | elevation, production-origin and explicit-tenant guards, `icacls /inheritance:r` on the state dir, service host staged from the installer's own embedded payload, `self_digest()` recorded. No per-file verification of the staged tree | everything in B **plus** create-only on a proven-pristine host where **UNKNOWN refuses as PRESENT**, attested payload (`m1_payload_check` → `copy_payload` → `verify_installed_binary`), directory ACLs verified by read-back, explicit service security descriptor verified by read-back, `AUTH_INSTALLER`/`AUTH_SERVICE` separation |
| **Enrolment** | calls the sensor CLI directly: **no attempt marker, two transport attempts, `IDENTITY_FILE.write_text` overwrites** on trunk. `-ReEnroll` **breaks outright on the M1 sensor** (no-overwrite publication refuses) | same sensor call, same two attempts, same overwrite; `install` adds RESUME (no token spent when already enrolled) and a rollback that spends no second token | marker opened **before** the request, `attempts=1`, `publish_identity` onto an absent destination with `fsync` + read-back, an `OPEN` marker **blocks** automatic re-enrolment, and `m1-reconcile-enrollment` resolves an unknown outcome under explicit operator confirmation |
| **Payload provenance** | **none.** Loose scripts plus whatever interpreter is found | installer-embedded onedir payload; `payload-manifest.json` consumed only on the M1 path | `payload-manifest.json` **mandatory** — an unpinned build is refused (`m1_payload_source`), members validated, installed image hash-verified before the service is registered |
| **Service ownership** | Task Scheduler, SYSTEM, `ONSTART`. No SCM identity, **no service security descriptor**, no failure actions, no start-type proof | real SCM service, LocalSystem, `start= auto`, failure actions `restart/60000 ×3`, `AUTO_START` verified from `sc qc` | SCM service created **DEMAND_START first**, SD applied and re-read, LocalSystem identity verified, started, **live running image proved** (`verify_running_image`), only then promoted to `AUTO_START` |
| **Telemetry continuity** | same sensor loop, same nine routes, same journal. **But the task action never passes `--state-dir`**, so the service-time state root is re-resolved from the environment; any divergence creates a *second* state directory that `Protect-StateDirectory` never ACL'd — i.e. a credential outside the protected path | `--state-dir` is authoritative and passed explicitly in the binPath, precisely because a LocalSystem service cannot be trusted to infer it | `--state-dir` must equal the approved configuration or the service refuses (`CONFIG_STATE_DIR_MISMATCH`) |
| **Uninstall** | `schtasks /End` + `/Delete /F`, then `Remove-Item $InstallDir -Recurse -Force`; `-Purge` removes the whole state dir. No ownership proof, no inventory, **deletes by path match**, and **never touches the SCM service** | `sc stop` + `sc delete` (neither waited nor verified) + `rmtree(ignore_errors=True)`; `--purge` destroys identity, journal, cursors and evidence. No ownership proof, failures silent, **never touches the task** | ownership-bound and fail-closed: `NOT_OWNED` refuses, PID identified **before** the stop, exit proven, `ERROR_SERVICE_DOES_NOT_EXIST` required or `PENDING_DELETION` reported honestly; identity, journal, cursors, queued evidence and audit **preserved**. No purge, by design |
| **Recovery** | Task Scheduler re-runs at boot only. No rollback, no restore, no settlement record | stop proven before mutation, `prior_state` captured, `_restore_service` on any `BaseException`, truthful `THIS ENDPOINT IS NOT COLLECTING`; cleanup helpers are the weak point (no PID, no exit proof, `ignore_errors=True`) | ownership record marks every resource `CREATE_INTENDED` → `CONFIRMED`/`OUTCOME_UNKNOWN`; `PRIOR_ATTEMPT_UNRESOLVED` refuses to adopt or delete anything automatically. (The M1 **lineage's** enterprise engine adds `recover-transaction` / `resolve-operation`, which are **outside M1's G3 approval**) |
| **Verification status** | no Windows gate of any kind; `-ReEnroll`/`-Uninstall` asserted nowhere | real-Windows CI gates **defined** (build, SCM lifecycle, re-enrol stop-race) but **run history UNKNOWN**; Gate 4 proves only a *failing* re-enrol | G3 PASS on reviewed source bytes; **G4 NOT RUN**; 636 portable tests measured across its three installer files — portable only, not Windows evidence |

---

## 3 · Decision table

| Mechanism | Current exposure | Actual availability | Security limitations | **Proposed status** | Existing-endpoint impact |
|---|---|---|---|---|---|
| **A · `Install-NivXForgeSensor.ps1`** (SYSTEM scheduled task) | **Advertised** as the `windows-x64` entrypoint in `PACKAGES` and as connector release `nvf-connector-windows-0.2.0-x64`; `download_available: true`; "Deploy this version" enabled | **Downloadable but NOT installable as published** — 3 of 4 required `.py` siblings are undownloadable from onboarding, 2 from the connector release | SYSTEM task executing a PATH-resolved interpreter; no payload provenance; no service SD; no `--state-dir`; overwriting enrolment with no marker; uninstall deletes by path match and ignores the SCM service; unsigned; requires endpoint Python | **DEPRECATED — existing endpoints only.** Not blocked: blocking would strand the fleet it installed | **None if withdrawn from new downloads.** Installed tasks keep running, keep their identity and keep delivering; §5 covers the detail |
| **B · trunk `nivxforge_setup.py`** (SCM service) | `windows-x64-exe` is listed but **409** (`CI_BUILD_REQUIRED`, `UNSIGNED_INTERNAL_VALIDATION_BUILD`) | **Not available**: no `dist/`, and the download route cannot serve a PE at all | cleanup/rollback without ownership or exit proof; `--purge` destroys evidence unconditionally; `--re-enrol` overwrites identity silently; unsigned; CI run history UNKNOWN | **INTERNAL VALIDATION ONLY** — the production *host* for the future standard, not yet a released artifact | None (nothing is installed from it today) |
| **C · M1 `nivxforge_m1.py`** (clean install) | **Not exposed anywhere** — no package, no release, no route | Ships inside an EXE that does not exist; needs a pre-provisioned protected `--m1-config` root | G4 **NOT RUN**; no native Windows evidence; no enterprise upgrade path (M1 is clean-install only); its own lineage has lost `--re-enrol` and `uninstall` | **FUTURE STANDARD — security contract of record; INTERNAL VALIDATION ONLY until G4 passes** | None today |
| **Enterprise transaction engine** (M1 lineage `install`/`recover-transaction`) | not exposed | not available | **outside M1 G3 approval**, unreviewed; its `install` refuses `--re-enrol` and its `uninstall` refuses entirely | **BLOCKED pending independent review** | None |

---

## 4 · Recommendation — exactly one

> **Adopt the M1 clean-install contract, delivered by the trunk SCM installer
> entrypoint, as the single official Windows mechanism for new endpoints —
> and advertise it only after G4 passes on real Windows and the artifact is
> signed.**

Three reasons, each evidenced rather than preferred:

1. **It is the only mechanism with provenance.** It is the only path that
   refuses an unpinned build, hash-verifies the installed image before
   registering a service, and proves the *live* process is that image. A is a
   SYSTEM task pointed at a PATH-resolved interpreter; that is a privilege
   boundary no amount of ACL work on the state directory repairs.
2. **It is the only mechanism that cannot silently destroy evidence or
   identity.** Ownership-bound uninstall with `NOT_OWNED` refusal versus two
   `rmtree(..., ignore_errors=True)` paths that delete by path match.
3. **Choosing it changes the exposure surface least.** B is the host
   entrypoint and already exists; C is already written, reviewed at G3 and
   frozen. A is the only mechanism that would have to be *built up* to the
   same contract, and it would have to acquire payload provenance, service
   ownership and an ownership model it has no structure for.

**What this recommendation explicitly does not do:** it does not advertise the
EXE. The EXE is unbuilt, unsigned and G4-unverified, the download route cannot
serve a PE, and the M1 path additionally requires a pre-provisioned
configuration root — so "official standard" here means *the mechanism work
converges on*, not *the thing the console offers tomorrow*. Until G4 passes and
signing exists, **the console's honest state for new Windows endpoints is "no
production-ready mechanism is published"**, and saying so is preferable to
continuing to advertise A.

---

## 5 · Impact of withdrawing the PowerShell connector from new downloads

| Concern | Assessment |
|---|---|
| Existing task installations | **Unaffected.** The task, the program files, `identity.json`, the journal and the cursors all live on the endpoint. Withdrawal changes a catalog listing, not an endpoint. No task is deleted, no service replaces it, nothing migrates |
| Telemetry continuity | **Unaffected.** The nine agent routes, session auth and the journal are shared by every mechanism; nothing tenant-, identity- or response-scoped changes |
| Credential lifecycle | **Unaffected.** Rotation and revocation are console-side (`rotate_credential`, `revoke_endpoint`) and are independent of how the sensor was installed |
| Re-installation / repair of an existing endpoint | **This is the real cost.** With A withdrawn and no replacement published, an operator who must repair a task installation has **no supported published path**. Mitigation: keep the artifacts downloadable for existing fleets (deprecated ≠ blocked) and complete the missing-file inventory *if* A remains downloadable at all |
| New Windows onboarding | Stops — and it is **already effectively stopped**: as published, the install cannot complete (§1). Withdrawal makes a true state visible rather than creating a new one |
| Fleet visibility | Endpoints installed by A are **not labelled** anywhere in the platform; see §6. Withdrawal should not precede the ability to count what was installed by it |
| Reversibility | Complete. The proposed change is data, not logic, and is one field |

**Preconditions before withdrawal (owner's call, not implied by this
assessment):** publish a repair instruction for existing task installations;
be able to count them (§6); and state the interim posture for new endpoints
explicitly rather than leaving an empty catalog to be read as an outage.

---

## 6 · Detecting scheduled-task versus SCM installations without touching the endpoint

**There is no telemetry field that answers this, and one cannot be added
cheaply.** `HeartbeatBody` is `model_config = ConfigDict(extra="forbid")` and
carries no mechanism field (`edr_enrollment.py:383-407`), so a sensor that
started reporting its own startup mechanism would be **422-rejected** by the
current backend. The enrolment body, `sensor_version` and `capabilities` are
identical across all three mechanisms.

Three non-invasive classifications, in order of fidelity:

| # | Method | What it proves | Limits |
|---|---|---|---|
| **D-1 · already-collected evidence (zero touch, console-side)** | The sensor collects the **System** channel (`CHANNELS = ("Security", "System", "Microsoft-Windows-Sysmon/Operational")`). An SCM installation emits **System 7045** (service installed, image `…\sensor\service\NivXForgeSensor.exe`, LocalSystem) and **7036** state transitions — already in the journal and already delivered | **Positive identification of SCM** from evidence the platform already holds | Task Scheduler events live in `Microsoft-Windows-TaskScheduler/Operational`, which is **not collected** — so A produces no System-channel signature |
| **D-2 · Sysmon corroboration (zero touch, console-side)** | Where Sysmon is present, EID 1 shows `python.exe` with `…\NivXForge\sensor\nivxforge_sensor.py run --api …` as a SYSTEM parent-of-boot process | Positive identification of **A** | Only on endpoints with Sysmon; otherwise the result is **UNKNOWN**, and UNKNOWN must be reported as UNKNOWN, never as "SCM" |
| **D-3 · operator-run read-only probes (no modification)** | `sc.exe query NivXForgeSensor` / `sc.exe qc NivXForgeSensor` → SCM present and its image path · `schtasks /Query /TN NivXForgeSensor /V /FO LIST` → task present, principal, action · file presence: `…\sensor\nivxforge_sensor.py` (A) vs `…\sensor\NivXForgeEDRSetup.exe` + `…\sensor\service\` (B) vs `m1-ownership.json` at the config root (C) vs `versions\` + `active.json` + `operations\` (enterprise engine) | Definitive, including the **both-installed** case | Requires an operator or an existing management channel; **not** a response action, and response actions remain out of scope |

Because the name is shared by all three mechanisms (`$TaskName` =
`SERVICE_NAME` = `_svc_name_` = `NivXForgeSensor`), a classifier must report
**four** outcomes — `SCM_ONLY`, `TASK_ONLY`, `BOTH`, `UNKNOWN` — and must never
collapse `UNKNOWN` into either positive.

---

## 7 · Smallest safe onboarding-catalog change (specified, **not implemented**)

`_describe()` spreads every package key except `directory`
(`edr_onboarding.py:179`), so a new data field reaches the API **with no route
or schema change**.

**Option A — smallest truthful change (data only, ~3 lines, no logic):** add to
`PACKAGES["windows-x64"]`:

```
"new_endpoint_eligible": False,
"eligibility_reason": "DEPRECATED for new endpoints: the scheduled-task
    mechanism is retained for the endpoints it already installed. Three
    required modules are not published by this package, so a fresh install
    cannot complete.",
```

Leaves `download_available` true, so existing fleets keep their artifacts.
**It does not stop a console operator by itself** — it only stops the API
from implying support.

**Option B — smallest *effective* change (A + one UI gate):** in
`EdrDownloadsPage.jsx:178` and the Add-Device flow, render "Deploy this
version" only when `new_endpoint_eligible !== false`, with the reason shown
in place of the button.

**Recommended: A + B together.** A alone is honest but ineffective; B alone
would be a UI claim without a backend authority.

**Explicitly out of this change:** deleting the package, flipping
`download_available`, touching `instructions.windows_script_invocation`,
changing `catalog.RELEASES`, altering `_artifact_path`'s allow-list, or
publishing the EXE. Each is a larger and separately reviewable decision.

---

## 8 · Owner decisions required

1. **Adopt the §4 recommendation** — M1 contract on the trunk SCM entrypoint as
   the single future standard? (Nothing proceeds without this.)
2. **Status of A** — confirm **DEPRECATED, existing endpoints only**, rather
   than *blocked* (blocking strands the installed fleet) or *supported*.
3. **Interim posture for new Windows endpoints** — publish "no
   production-ready mechanism" explicitly, or keep A listed with
   `new_endpoint_eligible: false` while the missing-module inventory is fixed?
   These are mutually exclusive and only one can be true in the console.
4. **The missing-module defect** — if A stays downloadable at all, is
   completing the published file set authorized as a separate bounded change,
   or does A remain download-only for endpoints that already have the files?
5. **Detection scope** — authorize D-1/D-2 (console-side, zero touch) as the
   fleet census, and confirm whether D-3's operator probes are in scope at all.
6. **G4 and signing as release gates** — confirm that *no* Windows artifact is
   advertised as production-ready until G4 passes on real Windows **and**
   signing exists **and** a binary-capable download transport exists (the
   current route cannot serve a PE).
7. **Enterprise transaction engine** — confirm it stays **BLOCKED** pending
   independent review, and that its `--re-enrol` and `uninstall` refusals are
   treated as defects to resolve rather than as the standard.

---

## 9 · Unchanged-state declaration

`git status --porcelain agents backend apps/nivxray-xdr/src .github docs` →
**0 entries**. No source edit, no commit, no merge, no CI run, no deployment,
no database read or write, no endpoint contacted, no installer executed, no
task or service touched, no credential value read or printed. The frozen M1
subtree `db21f422561f14fb4dcec91b70925f2b5291c500` is untouched, and no HOLD is
removed.

**Assessment ends here. No catalog change is implemented.**
