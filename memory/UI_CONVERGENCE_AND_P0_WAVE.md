# NivXRay XDR · UI convergence + P0 security wave (2026-06)

Owner priority order in force: **P0 security/correctness → P1 core SOC
workflows → P2 secondary surfaces → P3 polish/icons**. Separate engineering
lanes (W2, T-RISK-3/4/5, Command Intelligence R4/R5, Defender DSM, L3
shutdown defect) are tracked independently and must not absorb P0/P1 effort.

## P0 — CLOSED 5/5

| Item | Verdict | Evidence |
|---|---|---|
| P0.1 · `test_xdr_api_keys.py` 7 failures | **STALE TESTS**, no backend defect. The suite sent the deprecated `allow_new_tenant` flag (tenancy is established only by `POST /api/xdr/tenants`), and the analyst-denial test used the admin's token so it proved nothing. | 9/9 pass |
| P0.2 · stale P0-SEC admin test | **STALE TEST.** It expected a tenant-less admin to get 200; the platform answers `TENANT_REQUIRED` (no default tenant). Test now registers a real tenant and names it; a new test pins the tenant-less refusal. Header identity NOT resurrected. | 22/22 pass |
| P0.3 · security regression gate | **NEW** `tests/test_p0_security_gate.py` — 6 outcomes × 6 planes (api keys, secrets, webhooks, audit, RBAC, collectors): unauth / tampered / expired / wrong-tenant / permission-short / authorized. | 51/51 pass |
| P0.4 · newly discovered defects pinned | audit permission-await + cross-tenant audit read both have dedicated regression tests in the gate. | pass |
| P0.5 · no fake green | Full backend regression executed; failures classified below rather than being called green from targeted runs. | see table |

### Security defects found and closed in this wave (all REAL, all pre-existing)

1. **`audit.read` / `audit.write` were never enforced.** `xdr_audit_log._lazy_require` was a *sync* dependency calling an *async* one, so the returned coroutine was never awaited and FastAPI took it as the dependency's value. Every audit route was permission-free for any authenticated caller.
2. **Cross-tenant audit read.** `xdr_audit_log._principal` resolved the tenant through the registry only — proving the tenant EXISTS, never that the caller was AUTHORIZED for it. Reproduced: a `platform_admin` of tenant B read 18 of tenant A's events, including other principals' identities.
3. **Cross-tenant API-key inventory** (caught by the new gate) and the same latent pattern in **collectors**. Both `_principal()` copies now delegate to `xdr_rbac.resolve_principal`, the single resolver that runs `authorize_requested_tenant()`.

Rule established: a router must not re-implement tenancy. Machine ingest
paths (`xdr_ingest`, `collector_authz`, `edr_enrollment`) deliberately keep
their own credential-bound resolution — there is no user session there — and
were left untouched.

## P0.5 · classification of the full backend regression

Run 1 completed in 1h22m: **11 404 passed · 493 failed · 271 errors · 264
skipped**. Run 2 was killed by its wall-clock budget at 79 % (no summary
line) — recorded here as INCOMPLETE rather than interpreted. Run 3 is
executing with a larger budget; `scripts/classify_backend_regression.py`
regenerates the classification from whichever log is current.

Classification of run 1 (by evidence, not opinion):

| Bucket | Files | Tests | Basis |
|---|---|---|---|
| `TEST_DEFECT_STALE_AUTH` | 86 | 276 | the file drives gated endpoints without ever calling `/api/auth/login`, and/or still asserts identity via `X-Principal-Id`. Broken by the P0-SEC hardening of 2026-09-09, i.e. **PRE-EXISTING**, long before this wave. |
| `ENVIRONMENT` | 10 | 178 | passes in ISOLATION, fails only inside the full run — shared-database contamination in `nivxray_ci_local`. |
| `NEEDS_REVIEW` | 60 | 310 | neither signature matched; must be read before anyone claims it is not a regression. |
| `NEW REGRESSION` | **0** | **0** | nothing yet attributable to this wave. |

**A real isolation defect was found and fixed while classifying**:
`tests/test_xdr_rbac.py` ran `delete_many({})` on `xdr_users`, `xdr_roles`,
`xdr_groups` and `xdr_assignments` — wiping *every* tenant's principals, not
its own. In a full run it destroyed the principals provisioned by
`test_p0_security_gate.py` and `test_xdr_rbac_enforcement.py`, which then
reported ~90 failures that did not exist in isolation. A test may only delete
what it created; all three now pass together (104 passed).

Suites repaired during classification (each **stale test**, no product
defect): `test_collector_api_key_auth` (33 pass), `test_xdr_lolbas` (20),
`test_xdr_response_evidence` (10), `test_xdr_dashboard` (20),
`test_xdr_api_keys` (9), `test_xdr_webhooks` (9), `test_xdr_secrets`,
`test_xdr_audit_log`, `test_p0sec_rbac_fail_closed` (22).

The remaining 86 stale-auth files are an evidenced backlog. They are NOT
counted as green.

## P1 — IN PROGRESS

* **P1.1 Nx foundation — COMPLETE.** Added `NxFilter` (active constraints are
  part of the primitive), `NxEntity`/`NxEntityList`, `NxProvenanceChain`,
  `NxTimeline`, `NxGraph` (deterministic layered layout, dashed edges for
  unobserved relationships), on top of the earlier `NxSection`, `NxToolbar`,
  `NxMetricStrip`, `NxDimensionStrip`, `NxBlockerGroup`, `NxKeyFact`,
  `NxTechnical`, `NxRaw`, `NxToken(List)`, `NxButton`, `NxState`.
* **P1.2 core analyst workflows — UNDER WAY.** Migrated: Detections
  (`NxFilter` + dense table, active-filter chips), Investigation Workspace
  (platform tab rail + artifacts table), Approvals (status vocabulary + an
  honest "engine not connected" section), Control Center, Investigations,
  Clients, Evidence Explorer, Automation Rules, Playbooks, Event Explorer,
  Admin generic list.

  Four defects found by DOM verification (iteration 120) and fixed — three
  shared ONE root cause worth remembering: **a page must not short-circuit to
  a bespoke empty block instead of rendering the platform table.** Doing so
  deletes the column contract exactly when the analyst most needs to see what
  was searched. The fourth: "Investigate" navigated to
  `/xdr/incidents/<caseId>`, but a case id is not an incident id, so cases
  without a same-id incident dead-ended on the deliberate
  "existence is never disclosed" page; it now opens
  `/xdr/investigations/<caseId>/_engine`.

  Still owed here: the owner's full tab set
  (Overview | Timeline | Entities | Detections | Response | Activity | Report)
  — deliberately NOT added as empty shells, because an empty tab claims a
  capability the platform does not have.

* **P1.2 original note.** Incidents → Investigation Workspace
  → Detections → Event Explorer → Hunting → Evidence → Entities/Graph →
  Response. Event Explorer and Evidence Explorer are migrated; the
  Investigation Workspace ten-tab experience is not started.
* **P1.3 operational/admin workflows** — Windows/Data Sources done; Collectors,
  Integrations, Detection Registry/Content, Users·Roles·Access Management,
  API Keys, Secrets, Webhooks outstanding. Access Management UI must mirror
  the backend authority contract exactly (now proven by the P0.3 gate).
* **P1.4 the 9 IN_PROGRESS routes** — control-center, incidents,
  investigations, events, hunting first.

## Foundation facts (for whoever picks this up)

* **`NxDataTable` resolves a header from `header ?? label`.** Before that fix
  every Windows table rendered an empty `<th>` row.
* **Status vocabulary has ONE authority**: `NxOpsState`. Backend tokens stay
  the truth (`data-nx-state`), the LABEL is ours, and an unmapped token
  renders visibly unmapped rather than being prettified.
* **Contrast is a gate, not taste**: `scripts/nx_contrast_audit.py` checks
  every text/surface and seam/surface pair in BOTH themes (0 failures).
  `nx_contrast_purge.py` (262 surface literals) and `nx_foreground_purge.py`
  (221 foreground literals) tokenised the hard-coded colours; 213 ambiguous
  literals were deliberately left and reported (P3).
* **Icons**: registry + provenance exists; every entry is `UNVERIFIED`, so the
  console shows a neutral NivX container with the product name. Never
  fabricate a vendor logo to finish a screen (P3).
* **Migration register** is generated from code:
  `python3 scripts/build_ui_migration_register.py`.

## Test commands that matter

```
python3 -m pytest tests/test_p0_security_gate.py -q -o addopts=""       # P0 gate
python3 -m pytest tests/test_xdr_rbac_enforcement.py -q -o addopts=""   # RBAC matrix
python3 scripts/nx_contrast_audit.py                                     # both themes
python3 scripts/build_ui_migration_register.py                           # register
cd apps/nivxray-xdr && yarn build                                        # compile gate
```

Note: pytest runs against `DB_NAME=nivxray_ci_local` (conftest), NOT the
preview database. A suite must therefore REGISTER the tenant it uses —
`tests/_verified_session.py` provides `admin_token`, `login`,
`provision_session_user`, `register_tenants`, `hdrs`.
