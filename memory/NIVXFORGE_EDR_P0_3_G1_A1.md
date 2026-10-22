# NIVXFORGE EDR — P0-3 G1 **CORRECTION A1**
## Bounded, READ-ONLY design + evidence · not implemented

Corrects the three material findings in Codex's **P0-3 G1 FAIL** against
`NIVXFORGE_EDR_P0_3_ONBOARDING_SAFETY_CORRECTION.md`
(`5671f190ea298e836460eb949d1097f10aefc6ef511b775cb3a1260dbee24f79`).

Trunk baseline **`f971c765`** = `f971c7659de291d416cb1b7e1a57964af585f0d9`,
tree `506cf2d6046d5612e32f9674d12dd9e9c572b5c0`.
Frozen M1 subtree `db21f422…` untouched · every security HOLD preserved.
No implementation, commit, push, CI trigger, deployment, database write or
installer change.

---

## 0 · Three-finding closure matrix

| ID | Codex finding | Verdict | Corrected in |
|---|---|---|---|
| **C1** | The Add Device provisioning path was asserted, not traced; the proposed deployment refusal may not cover it | **CONFIRMED — a real bypass exists, and it is not the one the FAIL implied.** Add Device never calls `/connector/deployments`; it mints at a *generic* token route that has no package notion and must stay generic. The bypassable surface is the **published install instruction**, so the minimum guard belongs there — not in token policy | **§1** |
| **C2** | T-3/T-4 too weak to prove a refusal has no side effects | **ACCEPTED** — rewritten as T-3a/T-3b/T-4a-d with a spy at the real token boundary and four independent no-side-effect assertions | **§2** |
| **C3** | "exactly five files" contradicted by unnamed test files | **ACCEPTED** — production scope and test scope are now separate, and every test file is named | **§3** |
| — | Codex could not access `f971c765` | Addressed by a 15-file immutable extract with per-file blob verification | **§4** |

---

## 1 · C1 · The Add Device provisioning path, traced

### 1.1 The actual chain

```
EdrAddDevicePage.jsx:294  <button data-testid="edr-add-mint" disabled={!pkg?.available || …}>
  → mint()                                     EdrAddDevicePage.jsx
  → mintEnrollmentToken({label, ttlSeconds})   onboardingApi.js:46-51
  → POST /api/edr/enrollment/tokens            body: {"label": str|null, "ttl_seconds": int|null}
  → routers/edr_enrollment.py:95-108  mint_token(...)
       Depends(get_current_user)   ← authentication
       Depends(edr_tenant)         ← routers/edr_tenancy.py, the ONE canonical tenant authority
  → edr_plane/enrollment/store.py:109-143  mint_enrollment_token(...)
       inserts into TOKENS, audits TOKEN_CREATED, returns the plaintext once
```

### 1.2 Answers to the five questions

| Question | Verified answer |
|---|---|
| **Endpoint and body** | `POST /api/edr/enrollment/tokens`; `MintTokenBody` is `extra="forbid"` with exactly `label: Optional[str]` and `ttl_seconds: Optional[int] (60…86400)` (`edr_enrollment.py:88-93`) |
| **Authorization and eligibility checks** | Authentication via `get_current_user`; tenant authority via `edr_tenant`, registered `TENANT_SCOPED` at `edr_tenancy.py:90`. **There is no eligibility check of any kind — and no field on which one could act**: the body carries no `package_id`, `release_id`, OS or architecture |
| **Package-specific or generic?** | **Generic.** The minted token is mechanism-agnostic. `/api/edr/agent/enroll` consumes it from any connector — Windows PowerShell, Windows EXE or Linux. `create_deployment` is the *only* producer that later stamps `group_id`/`deployment_id`/`release_id` onto the token row (`edr_connector.py:196-200`); a token minted from Add Device carries none of them |
| **Can an ineligible Windows package bypass the proposed refusal?** | **Yes — because it never meets it.** `POST /connector/deployments` is not on this path at all. P0-3 hunk 3 therefore guards Downloads only. On the Add Device path the sole proposed control was a **client-side** `disabled` prop, and any authenticated tenant-scoped operator can skip the UI entirely: `GET /onboarding/packages` still publishes `silent_install` — the complete PowerShell invocation — for the ineligible package, and `POST /enrollment/tokens` still mints. **No backend control exists on that sequence** |
| **Generic token operations that must remain available** | `POST /enrollment/tokens` · `GET /enrollment/tokens` · `POST /enrollment/tokens/{id}/revoke` · `POST /enrollment/endpoints/{id}/rotate` · `POST /enrollment/endpoints/{id}/revoke` · `POST /connector/deployments` **for eligible releases** · the entire `/api/edr/agent/*` plane. Linux onboarding, lab enrolment and the repair of *existing* endpoints all depend on generic minting, so **the token route must not become package-aware** |

### 1.3 The minimum guard — and the boundary it respects

The platform cannot stop an operator running a script they already hold, and it
must not make generic minting package-aware. What it *can* stop is **teaching
the install**. The demonstrated bypass is an instruction-publication defect,
so the guard is one conditional in the package describer:

**Hunk 1a — `backend/routers/edr_onboarding.py::_describe` (`:154-199`)**

```
if package.get("new_endpoint_eligible") is False:
    out["silent_install"] = None
    out["install_instruction_withheld_reason"] = <the §3 reason>
```

Properties:

* **Backend-side**, so the UI cannot be bypassed: `GET /packages` stops
  emitting an executable instruction for an ineligible package.
* **`is False`**, so every package without the key is untouched — Linux is not
  in `PACKAGES` at all, and `windows-x64-exe`, `windows-arm64`, `windows-x86`
  are unaffected.
* **No new policy, no token change, no new route, no new dependency.** Token
  minting, TTL, revocation, rotation and tenancy are all untouched.
* **The UI fallback already exists**: `EdrAddDevicePage.jsx:52-57` prints
  `◇ INSTALL INSTRUCTION NOT PUBLISHED FOR THIS PACKAGE` when `silent_install`
  is falsy — so no additional UI work is required for this guard.

**One existing assertion must be re-targeted, and P0-3's "no existing
assertion breaks" claim is corrected accordingly.**
`test_edr_onboarding_v1.py:127-130` reads `win["silent_install"]` and asserts
`-AsSecureString` / `@args` and the absence of argv-secret forms. With the
guard, that value becomes `None` for `windows-x64`. The **contract does not
weaken — its subject moves**: the assertion is re-pointed at
`windows-x64-exe`, whose instruction remains published
(`edr_onboarding.py:109-112`), and the test additionally asserts that an
ineligible package publishes **no** instruction at all. By inspection,
`test_w1_windows_enrolment_instruction_contract.py:120-129` keeps passing: it
filters on `p.get("silent_install")` being truthy and still finds the EXE
package, so its non-empty assertion holds.

---

## 2 · C2 · Revised regression tests

Boundary conventions used by every test below:

* **Spy at the real generation boundary:**
  `monkeypatch.setattr(edr_connector.enrollment_store, "mint_enrollment_token", spy)`
  where `spy` records calls and raises if invoked. `edr_connector.py:35` imports
  the module (`from edr_plane.enrollment import store as enrollment_store`), so
  patching the attribute intercepts the **actual** call site at `:185`.
* **Isolated storage:** the repository's established idiom — a per-run
  `uuid4().hex[:8]`-suffixed tenant, organization and platform user created and
  torn down in a module fixture (`test_w1_…:56-77`) — with every count scoped by
  that `tenant_id`. `routers.edr_connector` binds `from deps import db as _db`
  at **import time** (`:32`), so a true separate database requires `DB_NAME` to
  be set before import; that stronger form is available but is **not** required,
  because tenant-scoped deltas plus the spy already make the assertions
  unambiguous.
* Collections asserted: `enrollment_store.TOKENS` and
  `edr_connector.DEPLOYMENTS` (`= "edr_connector_deployments"`, inserted at
  `:224`).

| ID | Test | Asserts |
|---|---|---|
| **T-3a** | `test_p0_3_deployment_refused_for_windows_0_2_0_release` | `POST /connector/deployments` with `nvf-connector-windows-0.2.0-x64` → **409**, `detail.code == "NEW_ENDPOINT_NOT_ELIGIBLE"`, reason non-empty |
| **T-3b** | `test_p0_3_deployment_refused_for_windows_0_1_0_release` | the same for `nvf-connector-windows-0.1.0-x64` — **both** ineligible ids, not one |
| **T-4a** | `test_p0_3_refusal_never_calls_the_token_generator` | the spy records **zero** calls across T-3a and T-3b |
| **T-4b** | `test_p0_3_refusal_persists_no_token` | `TOKENS.count_documents({"tenant_id": T})` is identical before and after, with the spy **removed** so the real generator would run if reached |
| **T-4c** | `test_p0_3_refusal_persists_no_deployment_record` | `DEPLOYMENTS.count_documents({"tenant_id": T})` identical before and after |
| **T-4d** | `test_p0_3_refusal_writes_no_token_audit_event` | no `TOKEN_CREATED` audit record appears for `T` (`store.py:135-138`) — closes the path where a token is audited but rolled back |
| **T-4e** | `test_p0_3_eligible_linux_deployment_still_succeeds` | `nvf-connector-linux-0.2.0-x64` → **200**, token count **+1**, deployment count **+1**, response carries the unchanged `artifact_identity` |
| **T-4f** | `test_p0_3_tenant_authorization_is_still_enforced` | the refusal does not precede authorization: no `X-Tenant-Id` → 401/403; a foreign tenant → refused by `edr_tenant`; an archived tenant → refused — **for both the refused and the successful release**, so the 409 can never mask an authorization bypass |
| **T-1** | `test_p0_3_windows_package_is_not_eligible_for_new_endpoints` | `windows-x64`: `new_endpoint_eligible is False`, reason non-empty, **and still** `available is True` and `download_available is True` |
| **T-1b** | `test_p0_3_ineligible_package_publishes_no_install_instruction` | `silent_install is None` **and** `install_instruction_withheld_reason` present — the §1.3 guard |
| **T-1c** | `test_p0_3_eligible_packages_still_publish_their_instruction` | `windows-x64-exe` still publishes a `silent_install` that satisfies the argv-secret contract (the re-targeted assertion) |
| **T-2** | `test_p0_3_windows_releases_are_not_eligible_for_new_endpoints` | both Windows release ids carry the field and reason |
| **T-5** | `test_p0_3_other_operating_systems_are_unaffected` | the Linux release has **no** eligibility key, `download_available is True`; `PACKAGES` contains only the four Windows ids |
| **T-6** | `test_p0_3_the_unbuilt_exe_is_still_unavailable` | `windows-x64-exe` → `INCOMPLETE`, `download_available False`, artifact route **409** |
| **T-7** | `test_p0_3_legacy_artifacts_remain_downloadable` | both PowerShell artifact routes return **200** with `X-NivXForge-Sha256` |
| **T-8** | UI · Downloads | `edr-release-deploy-*` absent for the ineligible release, reason rendered, `edr-release-download-*` still present |
| **T-9** | UI · Add Device | auto-select lands on no package, mint button disabled, `◇ INSTALL INSTRUCTION NOT PUBLISHED…` shown, §4 banner rendered |

---

## 3 · C3 · File scope, separated

### 3.1 Production files — **exactly six** (five from P0-3, plus the §1.3 guard, which lands in a file already in scope)

| # | File | Change | Kind |
|---|---|---|---|
| 1 | `backend/routers/edr_onboarding.py` | `PACKAGES["windows-x64"]` += `new_endpoint_eligible: False` + `eligibility_reason` (after `:80`) **and** the `_describe` instruction guard (§1.3) | data + 3-line guard |
| 2 | `backend/edr_plane/connector/catalog.py` | the same two keys on `nvf-connector-windows-0.2.0-x64` (`:59`) and `nvf-connector-windows-0.1.0-x64` (`:129`) | data only |
| 3 | `backend/routers/edr_connector.py` | 409 `NEW_ENDPOINT_NOT_ELIGIBLE` in `create_deployment`, after `:159-165` and **before** `:184` | 4 lines |
| 4 | `apps/nivxray-xdr/src/nivxforge/pages/EdrDownloadsPage.jsx` | gate the deploy action at `:178`; keep the download buttons at `:164` | UI gate |
| 5 | `apps/nivxray-xdr/src/nivxforge/pages/EdrAddDevicePage.jsx` | eligibility-aware auto-select (`:81`), gated steps and mint button (`:294`), "nothing published" banner | UI gate |

**No sixth module is authorized.** The count moved from five to five-plus-a-guard
*inside file 1*; nothing new enters production scope. Explicitly **not**
authorized: `edr_enrollment.py`, `enrollment/store.py`, `instructions.py`,
`edr_tenancy.py`, `edr.py`, `edr_response.py`, anything under `agents/`, and
every workflow.

### 3.2 Regression-test files — named, and **outside** the production count

| File | Status | Verifies |
|---|---|---|
| `backend/tests/edr/test_p0_3_onboarding_eligibility.py` | **NEW** | T-1, T-1b, T-1c, T-2, T-5, T-6, T-7 — catalog truth, the withheld instruction, legacy visibility, other-OS isolation |
| `backend/tests/edr/test_p0_3_deployment_refusal.py` | **NEW** | T-3a, T-3b, T-4a-f — the refusal, the spy, all four no-side-effect assertions, the eligible-Linux control and tenant authorization |
| `apps/nivxray-xdr/src/nivxforge/__tests__/edrDownloadsEligibility.test.jsx` | **NEW** | T-8 |
| `apps/nivxray-xdr/src/nivxforge/__tests__/edrAddDeviceEligibility.test.jsx` | **NEW** | T-9 |
| `backend/tests/test_edr_onboarding_v1.py` | **MODIFIED — one assertion re-targeted** | lines 127-130 move from `windows-x64` to `windows-x64-exe`; lines 110-113 (`available`/`AVAILABLE`) remain **unchanged** |
| `backend/tests/test_w1_windows_enrolment_instruction_contract.py` | **UNCHANGED** | verified by inspection: filters on truthy `silent_install`, still satisfied by the EXE package |
| `backend/tests/test_edr_route_tenant_authority.py` | **UNCHANGED** | its `POST /connector/deployments` case uses the **Linux** release (`:206-208`), which hunk 3 cannot refuse |

---

## 4 · Source-evidence package for independent review

Codex could not reach `f971c765`, so the review subject is published as an
immutable extract.

**Package:** `NIVXFORGE_EDR_P0_3_G1_A1_SOURCE.tar` (**uncompressed, deliberately**)
**Package SHA-256:** `209aa25058ed714b95a702843b61871e1127edd4fba6941b2abf1d01904408b1`
**Size:** 286,720 bytes · **15 files + `PROVENANCE.json`**
**Why uncompressed:** the hosting layer transparently decompresses a gzip
member, so a published `.tar.gz` digest would not match the bytes a reviewer
receives. The `.tar` was downloaded back and re-hashed: served bytes equal the
published digest exactly.
**Source commit:** `f971c7659de291d416cb1b7e1a57964af585f0d9`
**Source tree:** `506cf2d6046d5612e32f9674d12dd9e9c572b5c0`
**Extraction:** `git show f971c765:<repository_path>` — committed blobs,
byte-for-byte, no transformation.

| Package path | Repository path | SHA-256 (truncated) | Bytes |
|---|---|---|---|
| `production/edr_onboarding.py` | `backend/routers/edr_onboarding.py` | `ad23d07b09929fd1dd06d1c0a13bf7be…` | 28,580 |
| `production/edr_connector.py` | `backend/routers/edr_connector.py` | `fe64bb26c627f628c5f1c8c6b38d54e9…` | 12,332 |
| `production/catalog.py` | `backend/edr_plane/connector/catalog.py` | `d994890ae21929c6adc18af891760f0f…` | 12,489 |
| `production/EdrDownloadsPage.jsx` | `apps/nivxray-xdr/src/nivxforge/pages/EdrDownloadsPage.jsx` | `61d7d7b60fdc9b3a85f134b30f20a7c5…` | 20,166 |
| `production/EdrAddDevicePage.jsx` | `apps/nivxray-xdr/src/nivxforge/pages/EdrAddDevicePage.jsx` | `427725a3504f5c87e6423cff440e5f7e…` | 18,739 |
| `authority/store.py` | `backend/edr_plane/enrollment/store.py` | `73698aba979d9f99c23933345cddb489…` | 29,025 |
| `authority/edr_enrollment.py` | `backend/routers/edr_enrollment.py` | `abc37964b94c4cd8a40042b4f86f7d31…` | 33,237 |
| `authority/instructions.py` | `backend/edr_plane/enrollment/instructions.py` | `290edc766b392d977b76fe423f8fa9b8…` | 4,873 |
| `authority/edr_tenancy.py` | `backend/routers/edr_tenancy.py` | `f6cbf0d114a5610c4e4f62206f2b0fa6…` | 21,366 |
| `frontend_api/onboardingApi.js` | `apps/nivxray-xdr/src/nivxforge/onboardingApi.js` | `e603f5190854c2dbe77ae931b3ea6f31…` | 2,329 |
| `frontend_api/managementApi.js` | `apps/nivxray-xdr/src/nivxforge/managementApi.js` | `a4b08f76d079fea48ee1a7cfcac3f902…` | 6,019 |
| `existing_tests/test_edr_onboarding_v1.py` | `backend/tests/test_edr_onboarding_v1.py` | `378f1ecf4ab647cb3abf7f372b7913c6…` | 12,871 |
| `existing_tests/test_w1_windows_enrolment_instruction_contract.py` | `backend/tests/test_w1_…_contract.py` | `94d3b83da45fa87ae5656eacfb007718…` | 9,599 |
| `existing_tests/test_edr_route_tenant_authority.py` | `backend/tests/test_edr_route_tenant_authority.py` | `a4705d339d49c94da55896767c853793…` | 41,396 |
| `artifact/Install-NivXForgeSensor.ps1` | `agents/nivxforge-windows/Install-NivXForgeSensor.ps1` | `6b272dd39d329a814b45384faa4b52e0…` | 9,139 |

Full-length hashes and each file's **git blob id** are in `PROVENANCE.json`;
if repository access is later obtained, every row is checkable with
`git rev-parse f971c765:<repository_path>`.

### 4.1 Redactions and verification limits — disclosed

* **No redaction was applied.** Every file is the committed blob, so each is
  independently hash-verifiable. Nothing was rewritten, truncated or masked.
* **No** `.env`, credential store, key material, CI secret, JWT, API key or
  unrelated history is included. A secret-shape scan (the repository's own
  `nvx_`/`nvxenr_`/`nvxses_`/`nvxcrd_`/`ten_` patterns plus JWT, AWS-key and
  PEM private-key forms) returned exactly **one** match:
  `existing_tests/test_edr_route_tenant_authority.py:79`
  `TENANT_ARCHIVED = "ten_813aa…"`. It is a **tenant identifier fixture, not a
  credential**, and is retained unredacted so the file stays byte-verifiable.
* **Verification limit, stated plainly:** this package proves the content of
  **15 blobs at `f971c765`** and **nothing** about repository ancestry,
  history, signatures, authorship or any other path. **A sanitized extract can
  never substitute for repository access**, and no claim here should be read as
  doing so. The `agents/` file is included solely to let a reviewer count the
  four `Copy-Item` targets behind the "2 of 4 / 3 of 4" claim; the frozen M1
  subtree is not included and is not modified.

---

## 5 · Authorized G2 file scope (on approval only)

**Production:** the five files in §3.1 — nothing else.
**Tests:** the four new files in §3.2 plus one re-targeted assertion in
`test_edr_onboarding_v1.py`.
**Forbidden in G2:** installer sources, M1 source, enrolment/token policy,
telemetry, response, tenancy, CI, and any advertisement of the unbuilt EXE.
**Preconditions:** independent Codex re-review of this document **and** explicit
owner authorization.

---

## 6 · Unchanged-state declaration

`git status --porcelain agents backend apps/nivxray-xdr/src .github docs` →
**0 entries**. No source edit, commit, merge, push, CI run, deployment, database
read or write, endpoint contact, installer execution, or credential value read
or printed. The frozen M1 subtree `db21f422561f14fb4dcec91b70925f2b5291c500` is
untouched and **no HOLD is removed**.

**Stops at independent Codex re-review handoff.**
