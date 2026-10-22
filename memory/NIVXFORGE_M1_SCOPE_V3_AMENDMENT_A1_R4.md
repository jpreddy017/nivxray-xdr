# NIVXFORGE EDR — M1 SCOPE V3, AMENDMENT A1 (R4 ONLY)

Amends **only §R4** of `NIVXFORGE_M1_SCOPE_V3.md`
(`d10a3c04f9a187f313b7a11528fdd2fc0e51eb8b903adcf557e5cbdbc1653b70`).
**R1, R2, R3, R5 and R6 are accepted and unchanged**, as is Part II of V3 and
every B1–B6 requirement. Read-only design correction: no code, no commit, no
build, no Windows execution, no deployment. G2, enterprise upgrades, KUSHU,
production and rollout remain **HOLD**. Baseline unchanged: snapshot
`b13e1f3e70d9e2fa8fc8b76d773d0c7cf1cfca974dadc9b10d861c1c6bcde6ac`, candidate
`bc8147be15af46e87a95612322e7d17f3859f587`.

---

## Why R4 changed

`GetEffectiveRightsFromAcl` evaluates an ACL against a **single trustee SID**. It
does not compose a logon context, so ACEs granted to logon-session and
well-known group SIDs — `Authenticated Users (S-1-5-11)`, `INTERACTIVE
(S-1-5-4)`, `Everyone (S-1-1-0)`, `Users (S-1-5-32-545)` — are **not reflected**
when the trustee is an individual account. A service whose DACL grants
`SERVICE_START` to `Authenticated Users` would be reported as safe. It is
therefore **removed as an authoritative acceptance mechanism** and may appear
nowhere in the acceptance path.

## R4 (revised) — token-aware effective service-access verification

### Contract

1. **Apply, then read back** the service security descriptor before any start —
   `SetServiceObjectSecurity`, then `QueryServiceObjectSecurity` requesting
   **`OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
   DACL_SECURITY_INFORMATION`**. A DACL-only descriptor is rejected: `AccessCheck`
   requires owner and group and otherwise fails with
   `ERROR_INVALID_SECURITY_DESCR (1338)`. (Preserved from V3, extended.)

2. **Owner rights.** The owner must be `Administrators (S-1-5-32-544)` or
   `LocalSystem (S-1-5-18)`. Any other owner ⇒ **refuse**, because an owner
   retains implicit `READ_CONTROL` and `WRITE_DAC` and can rewrite the DACL
   irrespective of its contents. If an `OWNER RIGHTS (S-1-3-4)` ACE is present it
   is evaluated, never assumed to be restrictive.

3. **Generic-right resolution — both directions.**
   - Every ACE mask in the descriptor is passed through `MapGenericMask` with the
     **service** `GENERIC_MAPPING` before evaluation
     (`GenericRead = STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG |
     SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS`;
     `GenericWrite = STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG`;
     `GenericExecute = STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP |
     SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL`;
     `GenericAll = SERVICE_ALL_ACCESS`). `AccessCheck` does **not** map generic
     bits carried in ACE masks, so a `GENERIC_ALL` ACE is otherwise invisible.
   - The same mapping is supplied to the access evaluation for the
     desired-access side.
   - Any mask that cannot be fully resolved ⇒ **refuse**.

4. **Token-aware evaluation.** Effective access is decided by **`AccessCheck`
   against an impersonation token**, or by an **`AuthzAccessCheck` context that is
   explicitly and correctly populated with the applicable group SIDs**:
   - *Primary (native, authoritative):* a real logon token for a provisioned
     non-administrator account on the disposable VM — `LogonUser(…,
     LOGON32_LOGON_INTERACTIVE, …)` → `DuplicateTokenEx(…,
     SecurityImpersonation, TokenImpersonation, …)` → `AccessCheck`. A primary
     token is not accepted; `AccessCheck` requires an impersonation token.
   - *Equivalent:* `AuthzInitializeResourceManager` →
     `AuthzInitializeContextFromSid` → **`AuthzAddSidsToContext`** adding
     `S-1-5-11`, `S-1-5-4`, `S-1-1-0`, `S-1-5-32-545`, since
     `AuthzInitializeContextFromSid` does **not** synthesise logon-session SIDs.
     A context missing any required SID is incomplete ⇒ **refuse**.
   - The membership set actually used is recorded in the ownership record as
     evidence.

5. **Dangerous rights probed individually**, one evaluation per right, never as a
   single bulk `SERVICE_ALL_ACCESS` query (a bulk query can report denied while
   individual rights are granted):
   `SERVICE_CHANGE_CONFIG 0x0002`, `SERVICE_START 0x0010`, `SERVICE_STOP 0x0020`,
   `SERVICE_PAUSE_CONTINUE 0x0040`, `SERVICE_USER_DEFINED_CONTROL 0x0100`,
   `DELETE 0x10000`, `WRITE_DAC 0x40000`, `WRITE_OWNER 0x80000`. **Any one of
   these granted to a non-administrator context ⇒ refuse.** Read-class rights
   (`SERVICE_QUERY_CONFIG`, `SERVICE_QUERY_STATUS`, `SERVICE_INTERROGATE`,
   `SERVICE_ENUMERATE_DEPENDENTS`, `READ_CONTROL`) are permitted.

6. **Required grants** remain: `SERVICE_ALL_ACCESS` for `LocalSystem` and
   `Administrators`; DACL present and protected.

7. **Fail closed — never activate — when any of the following holds:** the token
   or Authz context cannot be built; a required group SID is absent from the
   context; the descriptor lacks owner or group; `AccessCheck` /
   `AuthzAccessCheck` returns an error; an ACE mask is unresolvable; a SID is
   unresolvable; the owner is unacceptable; or the evaluation cannot run on this
   host (including any non-Windows execution). The service remains
   **`CREATE_CONFIRMED`** and never reaches `ACTIVATION_VERIFIED`; the run exits
   non-zero naming the object, the right and the principal. Verification occurs
   **before** `sc start`, so an unsafe service is never started even once.

### Source-change boundary

`nivxforge_m1.py` only — the SD application, read-back, mapping and access
evaluation live in the M1 module. No change to `nivxforge_setup.py` beyond the
dispatch branches already permitted by R5, and none to the enterprise service
path, the sensor collection loop, the journal or the transaction engine.
`GetEffectiveRightsFromAcl` is **excluded by static assertion** from the M1 path.

### Regression and negative tests

**Negative — each must prevent activation (no `sc start` observed, state stays
`CREATE_CONFIRMED`, exit non-zero):**

| # | Injected ACE |
|---|---|
| N-R4-1 | `Authenticated Users` : `SERVICE_START` |
| N-R4-2 | `Authenticated Users` : `SERVICE_CHANGE_CONFIG` |
| N-R4-3 | `Authenticated Users` : `GENERIC_ALL` |
| N-R4-4 | `INTERACTIVE` : `SERVICE_START` |
| N-R4-5 | `INTERACTIVE` : `SERVICE_CHANGE_CONFIG` |
| N-R4-6 | `INTERACTIVE` : `GENERIC_ALL` |
| N-R4-7 | `Everyone` : `GENERIC_WRITE` (maps to `SERVICE_CHANGE_CONFIG`) |
| N-R4-8 | `Users` : `GENERIC_EXECUTE` (maps to `SERVICE_START/STOP/…`) |
| N-R4-9 | `Authenticated Users` : `WRITE_DAC` |
| N-R4-10 | owner set to a non-administrator principal, DACL otherwise correct |
| N-R4-11 | descriptor returned without owner/group (1338 path) |
| N-R4-12 | Authz context built without `S-1-5-11` / `S-1-5-4` (incomplete context) |
| N-R4-13 | `AccessCheck` forced to fail / unresolvable SID / unmappable mask |

**Positive:** SYSTEM + Administrators `SERVICE_ALL_ACCESS` only, owner
Administrators, protected DACL, read-class rights for `Users` ⇒ evaluation passes
and activation proceeds to `ACTIVATION_VERIFIED`.

**Meta-control (proves the mechanism change, not just the outcome):** an
evaluator implemented with `GetEffectiveRightsFromAcl` against an individual
account **must fail** N-R4-1 … N-R4-8 by reporting them safe. The suite asserts
that failure, which is the evidence that the ACL-walk mechanism was insufficient
and that the token-aware mechanism is what rejects those cases.

**Non-mocking rule:** no test may assert `safe = True/False` through a double
that assumes the access decision. Portable tests may drive descriptor
construction, mask mapping, SID-set composition and the refusal paths; the access
decision itself is only meaningful natively.

### Windows-native proof obligations (NOT RUN)

Real `SetServiceObjectSecurity` / `QueryServiceObjectSecurity` with owner, group
and DACL; real `MapGenericMask` with the service generic mapping; real
`LogonUser` + `DuplicateTokenEx(SecurityImpersonation)` + `AccessCheck` for a
provisioned non-administrator account, and the `AuthzAccessCheck` equivalent with
explicitly added group SIDs; per-right granted/denied results for all eight
dangerous rights; `ERROR_INVALID_SECURITY_DESCR (1338)` on an owner-less
descriptor; and confirmation that every negative case blocks startup on the
isolated VM. Exclusive administrative control of the disposable VM remains a
required operating condition; no protection is claimed against a malicious local
administrator.

---

## STATUS: **M1 G1 R4 CORRECTION READY FOR VERIFICATION**

R1, R2, R3, R5, R6 and Part II of V3 are unchanged. No contradiction remains in
R4; the only open items are the native obligations above, which are **NOT RUN**
and are not claimed. No implementation is authorised. The author of `bc8147be`
and of the G1 designs (this agent) is ineligible to verify this amendment.
