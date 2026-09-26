# W2-0 EVIDENCE — REGRESSION FOUNDATION (owner review)

2026-09-18. Scope executed: **W2-0 only** — dedupe fixture repair, contract
freeze, executable regression harness. **W2-1 not started.** No production
write, no endpoint execution, no W1 replay or modification, no UDOF, no
deployment. Preview/local only.

## 1 · Fixture repair — the regression gate is armed again

| | before | after |
|---|---|---|
| `tests/test_p0_ingest_idempotency.py` + `tests/test_p0_dedupe_hardening.py` | **7 passed / 25 errors** | **32 passed / 0 errors** |

Root cause confirmed, not guessed: both module fixtures called
`POST /api/xdr/collectors` for an ad-hoc tenant id that was never registered,
so the enforced registry answered `403 TENANT_NOT_FOUND` —
*"tenancy is established only by POST /api/xdr/tenants; collector creation,
API-key creation, endpoint enrolment, telemetry and incident creation never
create a tenant"*. **The registry was right; the tests had drifted.**

Fix (minimal, and it respects the authority it was violating): a module-scoped
autouse fixture registers the tenants through the **registry service**
(`services.tenant_registry.create_organization` / `create_tenant`), using the
registry's own `tenant_id=` adoption parameter so the modules' tenant constants
stay stable and **no assertion elsewhere in either file changed**. Teardown
removes the org and tenants. No product code was touched, no check was
weakened, no test was skipped or deleted.

## 2 · Contracts frozen
`memory/W2_CONTRACTS_FROZEN.md` — C-1 acquisition · **C-3 two checkpoints**
(acquisition position advances only when the event is durably recoverable in
the local outbox; accounting position advances only on authoritative server
accounting; survivability owned by the outbox, never by Windows circular-log
retention) · C-2 identity · **C-4 Telemetry Integrity Events** with
`HEALTHY · EVIDENCE INCOMPLETE` as a required state · C-5 backpressure states
and counters with `dropped = 0` **measured, not assumed** · C-6 time ·
C-7 server-owned versioned profiles (no customer-facing raw YAML) ·
C-8 security · C-9 gates · C-10 UI data honesty with the BUILD list ·
C-11 sequence.

## 3 · Executable regression harness
`scripts/w2_regression_harness.py` — one command, one report, exit code is the
verdict. `--only <gate>`, `--fast`, `--timeout`. Writes
`/app/test_reports/w2_regression_latest.json` plus a timestamped copy.

```
W2 REGRESSION HARNESS · 2026-09-18T12:58:16Z
  PASS  dedupe_contract               0.7s   defends W1-E2, W2-D   (34/34 checks)
  PASS  ingest_idempotency          163.1s   defends W2-D, W2-F
  PASS  dedupe_hardening            161.4s   defends W2-D, W2-F
  PASS  collector_plane_auth          2.7s   defends W2-A, W2-G    (112 passed)
  PASS  tenant_registry_authority     5.2s   defends W2-A          (30 passed)

VERDICT PASS (5/5)
```
Totals: **208 checks green** (32 dedupe + 112 collector-plane auth + 30 tenancy
authority + 34 contract-probe assertions). Each gate declares which W2
acceptance gate it defends, so a future failure names the contract it broke.

## 4 · Honest limits of this evidence
* Preview database only. Nothing here asserts anything about production.
* The harness covers the gates that exist **today** (identity/idempotency,
  collector-plane auth, tenancy authority). `W2-C`, `C2`, `E2`, `F2`, `F3`, `G`,
  `H`, `I` cannot be armed until the W2-1 acquisition engine exists — they are
  declared in `C-9`, not silently assumed.
* `parser_ok` / `normalized_ok` remain collector-**asserted** defaults; making
  them measured is W2-1 work (residual #4), and the harness will gain a gate
  for it then.
* The two repaired suites take ~160 s each because they drive the real ASGI app
  and the real store. That is deliberate: they are integration evidence, not
  unit mocks. Use `--fast` for the contract-only loop during development.

## 5 · Requested decision
Accept W2-0 and authorise **W2-1** (native Windows acquisition engine: strict
subscriptions, per-channel bookmark XML, durable outbox + backpressure, gap
detection, **Sysmon regression first, then PowerShell as the first genuinely
new channel** — Security deferred to W2-2 per owner direction so that a failure
in the engine is unambiguous).
