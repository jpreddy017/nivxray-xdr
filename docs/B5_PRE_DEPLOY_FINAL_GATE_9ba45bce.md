# PRE-DEPLOY FINAL GATE — COMMIT 9ba45bce

2026-09-29. Read-only investigation + local test confirmation. Nothing deployed,
nothing replayed, no Vercel change, no endpoint change, no E3.

## OUTPUT

```
DEPLOYMENT_CANDIDATE_SHA          = 9ba45bce9dc9599568266e43ee39dcde350bedac
RC4_PUSH_GATE                     = PASS
RC4_PR_GATE                       = PASS
RC5_SEMANTIC_GATE                 = PASS
RC5_GOLDEN_CORPUS                 = PASS
B5_FOCUSED_TESTS                  = PASS
EID5_RUNTIME_CODE                 = READY
EID5_BEHAVIOR_CHANGED_BY_CI_FIX   = NO
VERCEL_NIVXRAY_XDR_PROJECT        = the Vercel project whose Root Directory is the
                                    REPOSITORY ROOT (uses /vercel.json)
VERCEL_NIVXRAY_XDR_ENVIRONMENT    = LEGACY / MISCONFIGURED-ROOT (publishes nothing)
VERCEL_NIVXRAY_XDR_FAILURE_REASON = deliberate, hard-coded refusal:
                                    /vercel.json `buildCommand` =
                                    `bash scripts/refuse-root-deployment.sh`,
                                    which prints "DEPLOYMENT REFUSED · WRONG ROOT
                                    DIRECTORY ... Nothing was published" and
                                    `exit 1`. It is a safety guard firing as designed.
VERCEL_NIVXRAY_XDR_FAILURE        = NON_PRODUCTION_NON_BLOCKER
AUTHORITATIVE_PRODUCTION_PATH_IMPACT = NO
PROD_BACKEND_DEPLOYMENT           = NOT_STARTED

B5_PROD_DEPLOY_GATE = READY
```

## 1. EXACT COMMIT

`DEPLOYMENT_CANDIDATE_SHA = 9ba45bce9dc9599568266e43ee39dcde350bedac`
(branch `feature/rc2-alignment`, 2026-09-29T16:07:47Z, "Auto-generated changes" —
the platform's follow-up commit to `64c109fc`, my CI-fix step.)
Working tree at this SHA: **clean** (`git status --porcelain` empty).

Full diff `2f2586f4 → 9ba45bce` is **three files, zero product code**:

```
.emergent/emergent.yml                  |   2 +-
.github/workflows/rc4x_quality_gate.yml |   3 +-
docs/RC4X_QUALITY_GATE_FIX.md           | 153 +++++++++++++++
```

`git diff --name-only 2f2586f4 9ba45bce -- backend frontend apps agents` → **empty**.
No unintended product change after the B5-tested state.

Contained at `9ba45bce`:
- B5/EID5 implementation (ancestry of `2f2586f4`): `backend/edr_plane/windows_eventlog.py`
  line 83 `("sysmon", 5): ACTIVITY_PROCESS_TERMINATION`, line 680 `"exit_time": activity_time`.
- The RC4 CI live-suite exclusion: workflow line 174
  `--ignore=tests/edr/test_dt2_3_graph_read.py`.

## 2. WHAT "Vercel – nivxray-xdr" IS (read-only; nothing changed)

| Question | Evidence | Answer |
|---|---|---|
| Vercel project | the failing check builds from the repo ROOT, so Vercel selects `/vercel.json` — whose entire purpose is to refuse | the root-directory project |
| Environment | it cannot produce a servable artifact: the build exits 1 before any bundle is written | LEGACY / misconfigured-root; publishes nothing |
| Deployment target | none reached — "Nothing was published" is printed by the guard itself | none |
| Serves authoritative production traffic? | a failed Vercel deployment is never promoted, and this project has never produced a valid bundle | **NO** |
| Does `nivxray.nivxforge.com` depend on it? | that host is the **Emergent** deployment (`greeting-app-5782`, run `d85f3698`, cloudflare, target-6) proven in the production diagnose. The Vercel XDR bundle's own `build-info.json` records `api_origin: https://nivxray.nivxforge.com` — Vercel **consumes** that backend; the backend does not depend on Vercel | **NO** |
| Exact failure reason | `/vercel.json` → `"buildCommand": "bash scripts/refuse-root-deployment.sh"` → banner + `exit 1` | deliberate guard, not a regression |
| Caused by configuration rather than production code? | yes — the fix documented in the script itself is a project **setting**: `Settings → General → Root Directory = apps/nivxray-xdr`, plus `NIVX_PRODUCT_SCOPE` and `XDR_PROD_API_ORIGIN` | **configuration** |

Contrast with the PASSING check: the authoritative project uses Root Directory
`apps/nivxray-xdr`, hence `apps/nivxray-xdr/vercel.json` →
`bash scripts/vercel-build.sh` (product-scope validated, `verify-production-build.js`
enforced, host redirects for `xdr.nivxforge.com` / `edr.nivxforge.com`). The committed
artifact `.vercel/output/static/build-info.json` confirms it:
`product: nivxray-xdr`, `product_scope: xdr`, `api_origin: https://nivxray.nivxforge.com`,
`cross_product_origins: 0`.

Why the guard exists (from the script's own header): a root build would ship **no
`REACT_APP_PRODUCT_SCOPE`** (product boundary disappears — `xdr.nivxforge.com/edr/*`
would render EDR on the XDR host) and would bake the **preview** api origin into a
production bundle, with no `verify-production-build.js` to catch either. Failing loudly
was chosen deliberately over deleting the root config, because with no config Vercel
would fall back to framework auto-detection and build something unpredictable.

**So this red check is the guard working.** It is not a code regression, and it is not
on the authoritative production path. It does not touch the backend at all.

## 3. DOES IT BLOCK THE EID5 BACKEND DEPLOYMENT?

`VERCEL_NIVXRAY_XDR_FAILURE = NON_PRODUCTION_NON_BLOCKER`

Basis: (a) it publishes nothing by design, (b) the production backend and
`nivxray.nivxforge.com` are served by the Emergent deployment, not by Vercel,
(c) the authoritative XDR frontend project passed, (d) the failure is a project
Root-Directory setting, unrelated to any code in the deployment candidate.
Not classified on the word "Vercel".

## 4. FINAL B5 PRE-DEPLOY VALIDATION (at `9ba45bce`, clean tree)

| Proof | Evidence |
|---|---|
| Sysmon EID5 admission present | `windows_eventlog.py:83` `("sysmon", 5): ACTIVITY_PROCESS_TERMINATION` |
| EventID 5 → `process_exit` | `ACTIVITY_PROCESS_TERMINATION` branch, family `sysmon` |
| `UtcTime → exit_time` | `windows_eventlog.py:680` `"exit_time": activity_time` with provenance `":UtcTime (EventID 5)"`; `not_observed` explicitly lists `process.start_time` — the exit instant can never be read as a start |
| ProcessGuid authority present | `_process_identity(ProcessGuid, ProcessId, Image)`; `process_identity.py` `TERMINATION_KINDS` |
| canonical_event_id authority present | `canonical_bridge.py` (closure wave), C1/C5 suites |
| Focused B5 set | b5 termination + b2 process identity + c1 canonical event identity + c5 identifier end-to-end + phase0 windows canonical bridge → **96 passed** |
| Tenant isolation | cross-tenant + trajectory tenant isolation + observation identity + c2 evidence resolution + c3 delivery counters + p0 tenant authority fix1/fix2 → **135 passed** |

`EID5_BEHAVIOR_CHANGED_BY_CI_FIX = NO` — the CI fix touched only a workflow YAML.

## 5. DECISION

```
B5_PROD_DEPLOY_GATE = READY
```

Deployment candidate: **`9ba45bce9dc9599568266e43ee39dcde350bedac`**. Do **not** deploy
`2f2586f4` — it predates the CI correction.

Reminder of the agreed sequence after deploy: prove prod health → prove the EID5 runtime
contract is live → THEN owner-authorised controlled replay → genuine EID5 end-to-end →
B5 PASS → E3. Replica capacity stays a separate item.

STOP FOR OWNER REVIEW. NOT DEPLOYED.
