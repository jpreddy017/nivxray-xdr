# RC2.1a — Rollback Plan (pre-deploy)

**Effective:** 2026-07-19 (RC2.1a deployment window)
**Owner:** Operator / SOC lead
**Prior stable checkpoint (rollback target):** RC2.0 — deployed 2026-07-19T07:15Z, hash `feature/rc2` at the tip preceding the `families/` commit series.

---

## 1 · Backup Coverage

| Layer | Managed by | Snapshot Mechanism | Recovery Time |
|---|---|---|---|
| **Application code** | Emergent Platform | Immutable Deploy Checkpoints created on every Deploy click | < 1 min via platform Rollback |
| **Frontend build assets** | Emergent Platform | Bundled with each Deploy checkpoint | Same as above |
| **Backend Python code** | Emergent Platform | Bundled with each Deploy checkpoint | Same as above |
| **MongoDB (`workspace_cases`, `ai_response_cache`, `analyst_correction_ledger`)** | Managed MongoDB (Emergent) | Continuous point-in-time recovery (default) | ~ 5 min via provider |
| **Env vars (secrets/API keys)** | Emergent Platform | Immutable per-deploy | Restored automatically by Rollback |

**No user-uploaded artifacts** (RC2.1a doesn't introduce file-upload surfaces).

## 2 · Rollback Trigger Criteria

Immediately trigger rollback if **any** of the following fires during the 15-30 min post-deploy watch window:

1. `/api/` health endpoint returns non-200 for > 60 s
2. `POST /api/auth/login` returns 5xx (auth broken → no analyst access)
3. `GET /api/v2/plugins` returns < 12 plugins (registry corrupt)
4. `POST /api/v2/analyze` on the canonical Meterpreter payload doesn't reach `family-identified`
5. Any 5xx error rate spike > 2 % over any 5-min window
6. Backend supervisor logs show `RecursionError`, `OOMKilled`, or repeated `TimeoutError`
7. Frontend `/` returns 502/503 for > 60 s
8. Executive Summary card fails to render on the Analyst Workspace UI

## 3 · Rollback Procedure

### Path A — Platform Rollback (recommended, ~ 1 min)

1. Open the Emergent chat panel
2. Trigger the **"Rollback"** action
3. Select the checkpoint labelled **"RC2.0 · 2026-07-19T07:15Z"**
4. Confirm rollback
5. Wait ~60 s for the platform to restore code + env vars
6. Verify: `curl https://nivxray.nivxforge.com/api/` → `{"service":"NivXRay","status":"ok"}`
7. Verify: `GET /api/v2/plugins` → `count == 12`

### Path B — Emergency Backend-Only Revert (~5 min, if platform rollback unavailable)

1. On `feature/rc2`, revert the RC2.1a commit range with `git revert` (locally, then push)
2. Redeploy via Emergent
3. Same verification as Path A

## 4 · Post-Rollback Actions

1. Freeze RC2.1a deploys until root cause identified
2. Open incident ticket with RC2.1a diff bundle attached
3. Notify SOC team via preferred channel: "NivXRay production reverted to RC2.0 · investigating · RC2.1a will re-attempt after fix"
4. Re-run the full RC2.1a regression suite on the rolled-back preview environment before any re-deploy attempt

## 5 · Rollback Fire Drill (verified 2026-07-19, pre-deploy)

Confirmed the Emergent platform's Rollback control is available to the operator, and the previous RC2.0 checkpoint is visible in the checkpoint history. No dry-run rollback performed (that would take prod offline unnecessarily) — this is a signal check only.

---

**Sign-off before Deploy:** ☑
