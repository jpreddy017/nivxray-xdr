# G-41 · OWNER-EXECUTED PARSER PROOF (`report` mode) — read-only

The last unproven line of the G-41 gate is `ALL_CANDIDATES_PARSE`. Every count so far has been
either a database count or a **regex inference**; nothing has executed
`temporal_authority.to_epoch_us` over the real production candidates. This runbook closes that, and
only that.

**Why the owner runs it.** `POST /api/internal/admin/migrations/{operation}` is behind
`deps.require_admin` (`routers/edr_migration_control.py:50-55`). The deployer agent has no tool to
invoke an authenticated application endpoint and correctly refused to approximate the proof. The
agent never sees the token; the owner pastes back only the JSON response.

## What `mode=report` does and does not do

`observation_us_migration.op_backfill_observation_us(..., mode="report")` counts the candidates,
runs `to_epoch_us` on each one, and **returns before the write branch** — `written` is hard-coded to
`0` and no evidence document is opened for modification.

| | |
|---|---|
| evidence documents written | **0** |
| `e3_migration_row_ledger` rows | **0** — the ledger is only created inside the apply branch |
| indexes created | **0** |
| `e3_migration_runs` | **+1 audit record** — expected and unavoidable: the control plane records every invocation's lifecycle. An audit record is not an evidence mutation. |

## Step 1 · token (unchanged from `OWNER_JWT_REFRESH_PROCEDURE.md`)

Run Steps 0-2 of that procedure. `$tok` must be held in the session; do not print or paste it.
Rate limit: 5 failures / 300 s ⇒ 900 s lockout — type carefully, do not script retries.

## Step 2 · the proof (read-only)

```powershell
if (-not $tok) { Write-Host 'No token in session - run OWNER_JWT_REFRESH_PROCEDURE Step 1.'; return }

$A  = 'https://nivxray.nivxforge.com'
$op = 'backfill_canonical_observation_us'

try {
    $r = Invoke-RestMethod -Method Post `
            -Uri "$A/api/internal/admin/migrations/$op" `
            -Headers @{ Authorization = "Bearer $tok" } `
            -ContentType 'application/json' `
            -Body (@{ mode = 'report' } | ConvertTo-Json -Compress)
    $r | ConvertTo-Json -Depth 6
} catch {
    $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
    $det  = $null; try { $det  = $_.ErrorDetails.Message } catch {}
    "REPORT FAILED : HTTP $code :: $($det -replace '\s+',' ')"
}
```

`mode` is the **entire** caller-controlled surface (`MigrationRequest`, `extra: forbid`). No
collection, query, index or limit can be supplied by the caller, so this command cannot be
misdirected at another collection.

## Step 3 · what PASS looks like

```
expected_candidates   : 122477
observed_candidates   : 122477
contract_eligible     : 122477      <- executed to_epoch_us, not inferred
contract_unparseable  : 0
written               : 0           <- must be 0
would_write           : 122477
gates.expectation_declared     : true
gates.candidate_population_exact : true
gates.all_candidates_parse       : true
ok                    : true
```

Any other shape is a HOLD. In particular `ok: false` with
`candidate_population_exact: false` means the population moved and the exact-count gate refused —
which is the gate working, not a failure to work around. **The expectation is never edited to make
the gate pass.**

`mode=apply` is NOT authorized by this runbook. The same endpoint with `mode=apply` is the
122,477-row mutation; it requires a separate explicit owner decision.

## Already closed locally — the other two open items

Read from the deployed source in this workspace, so no production call was needed:

* **`TTL_OR_RETENTION_LOSS = NO`.** The only `insert_one` into `CANONICAL_COLLECTION` in runtime
  code is `detection_content/xdr_pipeline.py:421`; there is **no delete of any kind** against it
  anywhere in runtime code. The deletes that mention similar names belong to other namespaces —
  `e3_dt_seed_canonical_evidence` / `e3_dt_seed_shadow_observations`
  (`edr_trajectory/service.py:19-20`), the `e3_dt_*` overlay collections, and
  `tools/check_34f_pipeline_stamping.py`, an offline tool. Every TTL index in the codebase targets
  something else: `investigations` and `workspace_cases` (`privacy.py:132,153`), analyze jobs
  (`routers/analyze.py:315`), history (`routers/history.py:183`), `investigation_events`
  (`timeline/__init__.py:30`). No TTL index exists on the canonical collection
  (deployer-confirmed), and the collection is not capped.
* **`NEW_UNSTAMPED_WRITER_PATH = NO`.** `xdr_pipeline.py:415-421` is `stamp()` → `assert_stamped()`
  → the single `insert_one`, in that order, so no document can enter the store unstamped. The only
  other canonical write is `xdr_pipeline.py:569`, a narrow `$set` of
  `provenance.timestamps.rule_evaluated_at` / `verdict_at` on an already-stamped document — it
  cannot remove `observation_us` or create a candidate. The fail-closed branch would leave
  `observation_us` ABSENT with state `UNPLACEABLE_UNPARSEABLE_OBSERVATION_TIME`, which WOULD create
  a new candidate; the deployer measured **0** such rows and **0** unstamped rows without a valid
  string `event_time`, so the population is closed in practice as well as by design.

Status: runbook supplied, nothing executed by the agent. APPLY not authorized.
