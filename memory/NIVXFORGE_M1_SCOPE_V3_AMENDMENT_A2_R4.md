# NIVXFORGE EDR — M1 SCOPE V3, AMENDMENT A2 (R4 ONLY, TWO DEFECTS)

Amends **only §R4**, superseding Amendment A1
(`332d6b65466d1efa60df541677e30b5c74250cd4017b9ea8361c495ef0a08fcb`).
**R1, R2, R3, R5, R6 and Part II of V3 remain accepted and are not reopened.**
Read-only design correction: no code, no build, no Windows execution, no
enrollment, no deployment. G2 and all security HOLDs unchanged. Baseline
unchanged: snapshot `b13e1f3e…`, candidate `bc8147be…`.

---

## Defect 1 — a single standard-user token proves too little

A passing `AccessCheck` for one provisioned test account says nothing about a
dangerous right granted to **a different individual account**, or to **a group
that account is not a member of**. Token evaluation samples one subject;
acceptance must cover the whole descriptor.

### Corrected acceptance contract — two mandatory, independent checks

**Check 1 — exhaustive ACE inspection (new, structural).** After applying and
reading back the descriptor (`OWNER | GROUP | DACL`, per A1), enumerate the DACL
with `GetSecurityDescriptorDacl` + `GetAce` and evaluate **every** access-allow
ACE:

1. Each ACE mask is resolved with `MapGenericMask` using the service
   `GENERIC_MAPPING` **before** comparison.
2. The **dangerous set** — `SERVICE_CHANGE_CONFIG 0x0002`, `SERVICE_START
   0x0010`, `SERVICE_STOP 0x0020`, `SERVICE_PAUSE_CONTINUE 0x0040`,
   `SERVICE_USER_DEFINED_CONTROL 0x0100`, `DELETE 0x10000`, `WRITE_DAC 0x40000`,
   `WRITE_OWNER 0x80000` — may be granted **only** to the explicitly approved
   trustees `LocalSystem (S-1-5-18)` and `Administrators (S-1-5-32-544)`,
   compared **by SID**, never by resolved name.
3. **Any dangerous right allowed to any other trustee ⇒ refuse**, whether the
   trustee is an individual account, a group, a nested group, a service SID or a
   virtual account, and whether it arrives as a specific or a generic right.
   Nested and indirect membership needs no enumeration here: the ACE is rejected
   on its trustee, so nesting cannot hide it.
4. Read-class rights (`SERVICE_QUERY_CONFIG`, `SERVICE_QUERY_STATUS`,
   `SERVICE_INTERROGATE`, `SERVICE_ENUMERATE_DEPENDENTS`, `READ_CONTROL`) remain
   permitted for any trustee.
5. **Refuse on anything not fully understood:** a NULL DACL (grants all access to
   everyone), an ACE type other than `ACCESS_ALLOWED_ACE_TYPE` /
   `ACCESS_DENIED_ACE_TYPE` (including callback and object ACE types), a mask
   that does not fully resolve, a malformed or truncated ACL, or a trustee SID
   that cannot be parsed.
6. **Deny ACEs are recorded but never used to justify a dangerous allow.** ACL
   canonical ordering is not guaranteed on a descriptor read back from the SCM,
   so a preceding deny is not accepted as neutralising a dangerous allow — the
   descriptor is refused and rewritten instead.

**Check 2 — token-aware verification (retained from A1, unchanged).**
`AccessCheck` against a `DuplicateTokenEx(…, SecurityImpersonation)` logon token
for a provisioned non-administrator account, or the equivalent
`AuthzAccessCheck` context populated via `AuthzAddSidsToContext` with
`S-1-5-11`, `S-1-5-4`, `S-1-1-0`, `S-1-5-32-545`. It catches composition effects
that ACE inspection alone does not model.

**Also retained unchanged from A1:** apply-then-read-back before any start; owner
must be `Administrators` or `LocalSystem`; required `SERVICE_ALL_ACCESS` for
SYSTEM and Administrators; DACL present and protected; dangerous rights probed
**individually**, never as a bulk `SERVICE_ALL_ACCESS` query; and fail-closed
activation — on any refusal the service stays `CREATE_CONFIRMED`, never reaches
`ACTIVATION_VERIFIED`, and is never started.

**Both checks must pass.** Either one failing, incomplete, or unevaluable ⇒
refuse. Unknown trustee, unresolved mapping or indeterminate evaluation result ⇒
refuse.

### Added negative cases (each must prevent activation)

| # | Injected ACE |
|---|---|
| N-R4-14 | an **unrelated individual user** (a provisioned account that is *not* the token account) : `SERVICE_START` |
| N-R4-15 | the same unrelated user : `GENERIC_ALL` |
| N-R4-16 | a **group the test account does not belong to** (e.g. a provisioned lab group, or `Backup Operators S-1-5-32-551`) : `SERVICE_CHANGE_CONFIG` |
| N-R4-17 | the same non-member group : `GENERIC_EXECUTE` (maps to `SERVICE_START/STOP/PAUSE_CONTINUE/USER_DEFINED_CONTROL`) |
| N-R4-18 | **indirect membership**: user → GroupA → GroupB, with the ACE on **GroupB** : `GENERIC_ALL` |
| N-R4-19 | indirect membership as above : `WRITE_DAC` |
| N-R4-20 | a **service/virtual account SID** (e.g. `NT SERVICE\…`) : `SERVICE_CHANGE_CONFIG` |
| N-R4-21 | **NULL DACL** on the service object |
| N-R4-22 | unknown/callback ACE type present |
| N-R4-23 | deny ACE preceding a dangerous allow for a non-approved trustee (must still refuse) |
| N-R4-24 | unparseable trustee SID / truncated ACL |

Retained from A1: N-R4-1 … N-R4-13 (`Authenticated Users` and `INTERACTIVE` ×
`SERVICE_START` / `SERVICE_CHANGE_CONFIG` / `GENERIC_ALL`, `Everyone:GENERIC_WRITE`,
`Users:GENERIC_EXECUTE`, `Authenticated Users:WRITE_DAC`, non-administrator owner,
owner-less descriptor (1338), incomplete Authz context, forced API failure).
Positive control unchanged: SYSTEM + Administrators `SERVICE_ALL_ACCESS` only,
owner Administrators, protected DACL, read-class rights for `Users` ⇒ activation
proceeds.

## Defect 2 — the meta-control was unsupported

**Withdrawn:** the assertion that a `GetEffectiveRightsFromAcl`-based evaluator
must report **all** of N-R4-1 … N-R4-8 as safe. That overstated the API's
limitation — `GetEffectiveRightsFromAcl` accepts a **group** trustee and
accumulates rights for the trustee queried, so for a grant to a group that is
actually the queried trustee it does report the right. The blanket claim is
retracted.

**Replacement acceptance criterion:** the replacement mechanism is accepted iff
**every unsafe case — N-R4-1 … N-R4-24 — is rejected and activation is
prevented.** Acceptance is measured on the replacement's own behaviour, not on
another API's failures.

**Retained, narrowly:** one demonstration of a *documented* limitation where it
genuinely applies — a single-trustee query evaluates only the trustee supplied,
so a dangerous right granted to an unrelated individual account (N-R4-14) or to a
group outside the queried trustee's membership (N-R4-16) is not reflected in that
query's result. This is recorded as a **documentation-backed observation on the
isolated VM**, not as an assumption, and it is not required to hold for grants to
principals the queried trustee is a member of. No acceptance decision depends on
it.

## Source-change boundary (unchanged)

`nivxforge_m1.py` only — descriptor application, read-back, ACE enumeration,
generic mapping and token-aware evaluation. No change to `nivxforge_setup.py`
beyond the dispatch branches already permitted by R5, and none to the enterprise
service path, the sensor collection loop, the journal or the transaction engine.
`GetEffectiveRightsFromAcl` remains excluded from the acceptance path by static
assertion; its only appearance is inside the limitation demonstration above.

## Windows-native proof obligations (NOT RUN)

Real DACL enumeration and ACE-type handling on an SCM-returned descriptor; real
`MapGenericMask`; real `AccessCheck` / `AuthzAccessCheck`; provisioning of an
unrelated account, a non-member group and a nested group on the disposable VM;
NULL-DACL and malformed-ACL behaviour; `ERROR_INVALID_SECURITY_DESCR (1338)`; and
confirmation that every negative case blocks startup. Exclusive administrative
control of the disposable VM remains a required operating condition; no
protection is claimed against a malicious local administrator.

---

## STATUS: **M1 G1 R4 AMENDMENT A2 READY FOR VERIFICATION**

Both defects corrected; no other scope section altered. Open items are the native
obligations above — **NOT RUN** and not claimed. No implementation is authorised.
The author of `bc8147be` and of these designs (this agent) is ineligible to
verify this amendment.
