# NIVXFORGE EDR — P0-3 WINDOWS ONBOARDING SAFETY CORRECTION
## G1 bounded correction **design only** · read-only · not implemented

Authoritative input: `NIVXFORGE_EDR_P0_2_INSTALLER_OWNERSHIP_DECISION.md`
(`7ce67cd9193a58104c12896a97f57d6d48abf8a0d667ee0e711296adaa75cf3d`).
Trunk `f971c765` · frozen M1 subtree `db21f422…` (untouched).
No installer, M1, enrolment, telemetry, backend-security or CI change is
proposed. **Implementation requires independent review and explicit
authorization.**

---

## 1 · One finding that sets the shape of the correction

**Downloads and Add Device read two different backend authorities**, so a
single-file change cannot cover both:

| Console surface | API | Authority |
|---|---|---|
| Management → **Downloads** | `GET /api/edr/connector/releases` | `backend/edr_plane/connector/catalog.py::RELEASES` |
| **Add Device** | `GET /api/edr/onboarding/packages` | `backend/routers/edr_onboarding.py::PACKAGES` |

Both pass unknown keys straight through — `edr_onboarding.py:180`
(`**{k: v for k, v in package.items() if k != "directory"}`) and
`catalog.py:233` (`**{k: v for k, v in release.items() if k != "artifact"}`) —
so **a new eligibility field reaches both APIs with no route or schema
change**.

**And one logic change is unavoidable.** "Deploy this version" calls
`POST /api/edr/connector/deployments`, which **mints a real enrolment token**
(`edr_connector.py:184`). Its only gate is
`artifact_state != ARTIFACT_PUBLISHED` (`:159`), which the PowerShell release
passes. A UI-only correction would therefore be cosmetic and API-bypassable, so
the deploy refusal must live in the backend.

---

## 2 · Minimum change set

Five hunks. Three are data; one is a four-line refusal; two are UI gates.

| # | File | Change | Kind |
|---|---|---|---|
| **1** | `backend/routers/edr_onboarding.py` → `PACKAGES["windows-x64"]` (after `"release_status": "PREVIEW"`, `:80`) | add `"new_endpoint_eligible": False` and `"eligibility_reason": "<§3>"` | **data only** — surfaces via `:180`, no logic touched |
| **2** | `backend/edr_plane/connector/catalog.py` → release `nvf-connector-windows-0.2.0-x64` (`:59`) **and** `nvf-connector-windows-0.1.0-x64` (`:129`) | the same two keys | **data only** — surfaces via `:233` |
| **3** | `backend/routers/edr_connector.py::create_deployment`, immediately after the existing `ARTIFACT_PUBLISHED` check (`:159-165`) and **before** `mint_enrollment_token` (`:184`) | `if release.get("new_endpoint_eligible") is False: raise HTTPException(409, detail={"code": "NEW_ENDPOINT_NOT_ELIGIBLE", "reason": release["eligibility_reason"], "note": "existing installations are unaffected; this release is retained for the endpoints it already installed"})` | **logic, 4 lines** — `is False` so every release without the key is untouched |
| **4** | `apps/nivxray-xdr/src/nivxforge/pages/EdrDownloadsPage.jsx:178` | render "Deploy this version" only when `release.new_endpoint_eligible !== false`; otherwise show `eligibility_reason` in its place. **Leave the per-file download buttons at `:164` untouched** | UI gate |
| **5** | `apps/nivxray-xdr/src/nivxforge/pages/EdrAddDevicePage.jsx` | `:81` auto-select becomes `.find((p) => p.available && p.new_endpoint_eligible !== false)`; the download/enrol/install steps and the mint button (`:294`) additionally require `pkg.new_endpoint_eligible !== false`; render the §4 banner when **no** Windows package is eligible | UI gate |

**Deliberately not changed:** `download_available`, `available`,
`artifact_state`, `_artifact_path`/`artifact_path` allow-lists,
`download_artifact` / `download_release_artifact`,
`instructions.windows_script_invocation`, `silent_install`, the agent routes,
`PACKAGES["windows-x64-exe"]`, tenant scoping, or any file under
`agents/`.

---

## 3 · The reason string (one authority, used by both surfaces)

> `DEPRECATED for new endpoints. The scheduled-task mechanism is retained only
> for the endpoints it already installed. This package publishes 2 of the 4
> modules its installer copies, so a fresh installation cannot complete, and it
> is not repair-ready. No production-ready Windows installer is published yet:
> the service installer is unbuilt, unsigned and has not passed native Windows
> acceptance.`

Each clause is an §P0-1/P0-2 fact, not a judgement: the four `Copy-Item`
targets (`Install-NivXForgeSensor.ps1:145-151`) versus two declared files;
`dist/` absent in both revisions; `signing_status: UNSIGNED`; G4 **NOT RUN**.
For the connector release the count is **3 of 4** (`catalog.py:90-94`), so the
string is parameterised per surface and nothing is overstated.

---

## 4 · The truthful "nothing is published" message

Derived, **not a new backend field**: the banner appears when
`packages.filter(p => p.os === "WINDOWS" && p.new_endpoint_eligible !== false &&
p.available).length === 0`.

> **No production-ready Windows installer is currently published.** The
> PowerShell package below remains downloadable for computers that already use
> it; it is not offered for new installations. The service installer has not
> been built, signed or accepted on Windows.

An empty catalog read as an outage is the failure mode this avoids: the state
is stated, not implied.

---

## 5 · What each requirement maps to

| Requirement | Mechanism | Evidence it holds |
|---|---|---|
| `new_endpoint_eligible: false` with an accurate reason | hunks 1-2 | passthrough at `:180` / `:233` |
| No new-install/deploy action offered | hunks 3-5 | the backend refusal is the authority; the UI gates are presentation |
| Legacy download visibility retained, without a repair-ready claim | `download_available` untouched; the reason says **"not repair-ready"** | per-file buttons remain at `EdrDownloadsPage.jsx:164` |
| Truthful "nothing published" message | §4 | derived client-side, no schema growth |
| Existing telemetry, routes and controls preserved | nothing under `agents/`, no agent route, no auth, no tenancy touched | the nine `/api/edr/agent/*` routes and `edr_tenancy.py` are untouched |
| Other operating systems unaffected | `is False` guard + Windows-only data | `nvf-connector-linux-0.2.0-x64` gains no key, so hunk 3 cannot fire on it; `PACKAGES` holds **only** the four Windows ids (`windows-x64`, `windows-x64-exe`, `windows-arm64`, `windows-x86`) — Linux is not in that surface at all |

---

## 6 · Tests

**No existing assertion breaks.**
`test_edr_onboarding_v1.py:110-113` asserts
`win["available"] is True and win["state"] == "AVAILABLE"` — both are
deliberately preserved. `test_edr_route_tenant_authority.py:206-208` exercises
`POST /connector/deployments` with the **Linux** release, which hunk 3 cannot
refuse. `test_w1_windows_enrolment_instruction_contract.py` asserts instruction
*content*, which is unchanged.

**New (names and intent only — not written here):**

| # | Test | Asserts |
|---|---|---|
| T-1 | `test_p0_3_windows_package_is_not_eligible_for_new_endpoints` | `windows-x64` → `new_endpoint_eligible is False`, non-empty reason, **and still** `available is True`, `download_available is True` |
| T-2 | `test_p0_3_windows_release_is_not_eligible_for_new_endpoints` | the same for both `nvf-connector-windows-*-x64` releases |
| T-3 | `test_p0_3_deployment_is_refused_for_an_ineligible_release` | `POST /deployments` → **409 `NEW_ENDPOINT_NOT_ELIGIBLE`** |
| T-4 | `test_p0_3_a_refused_deployment_mints_no_token` | the `TOKENS` collection count is unchanged across T-3 — the refusal precedes `:184` |
| T-5 | `test_p0_3_other_operating_systems_are_unaffected` | the Linux release keeps `download_available: true`, carries **no** eligibility key, and `POST /deployments` against it still succeeds |
| T-6 | `test_p0_3_the_unbuilt_exe_is_still_unavailable` | `windows-x64-exe` → `INCOMPLETE`, `download_available: false`, download route **409** |
| T-7 | `test_p0_3_legacy_artifacts_remain_downloadable` | both PS1 artifact routes still return 200 with their `X-NivXForge-Sha256` |
| T-8 (UI) | `edr-release-deploy-*` absent and the reason rendered for the ineligible release; `edr-release-download-*` still present | Downloads |
| T-9 (UI) | Add Device auto-select lands on **no** package, the mint button is disabled, and the §4 banner renders | Add Device |

---

## 7 · Rollback

Revert five hunks; nothing else exists to undo. No schema, no migration, no
stored state, no endpoint contact, no CI, no artifact. The correction's only
*effect* on data is **preventing** a token from being minted, so a rollback
leaves no residue — unlike the current behaviour, which mints one.

---

## 8 · Acceptance criteria

1. T-1…T-9 green; the existing onboarding, tenant-authority and W-series tests
   green **unmodified**.
2. `GET /connector/releases` and `GET /onboarding/packages` return the new
   fields with the §3 reason; `download_available` is unchanged for every
   release and package.
3. `POST /connector/deployments` → 409 for the Windows PowerShell releases,
   unchanged for Linux, and the `TOKENS` count is identical before and after
   the refusal.
4. Both PowerShell artifact download routes still return 200.
5. `windows-x64-exe` still 409s; nothing advertises the EXE.
6. Downloads shows no deploy action for the ineligible release but still shows
   its files; Add Device shows the §4 banner and offers no install path.
7. `git diff --stat` touches **exactly** the three backend files and the two
   JSX pages — zero changes under `agents/`, `backend/edr_plane/enrollment/`,
   `backend/routers/edr.py`, `edr_response.py`, `edr_tenancy.py` or
   `.github/`.
8. No HOLD is removed; enterprise upgrade, re-enrolment and migration remain
   blocked.

---

## 9 · Residual risks

| Risk | Status |
|---|---|
| An operator who must **repair** an existing task installation still has no supported published path | **ACCEPTED and stated** — the reason string says "not repair-ready" rather than implying support. Resolving it is a separate authorized change |
| Existing task endpoints remain **uncounted** (no telemetry field identifies the mechanism; `HeartbeatBody` is `extra="forbid"`) | **OPEN** — the P0-2 §6 census (System 7045/7036, Sysmon EID 1) is a separate work item and is not a precondition for this correction |
| `release_status: "PREVIEW"` and `support_status: "PREVIEW_NOT_FOR_PRODUCTION"` now coexist with the new field | **ACCEPTED** — both remain truthful; consolidating the vocabulary is out of scope |
| The incomplete published file set is left incomplete | **DELIBERATE** — completing it would make a deprecated mechanism installable again, which contradicts the approved direction |

---

## 10 · Unchanged-state declaration

`git status --porcelain agents backend apps/nivxray-xdr/src .github docs` →
**0 entries**. No source edit, no commit, no merge, no CI run, no deployment,
no database read or write, no endpoint contacted, no installer executed, no
credential value read or printed. The frozen M1 subtree
`db21f422561f14fb4dcec91b70925f2b5291c500` is untouched and no HOLD is removed.

**Design ends here. Nothing is implemented. Independent review and explicit
authorization are required before any hunk is written.**
