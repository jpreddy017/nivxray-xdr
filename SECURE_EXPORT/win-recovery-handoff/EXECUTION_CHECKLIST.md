# EXECUTION CHECKLIST · Windows sensor recovery · one endpoint, one token

Companion to `RECOVERY_PROCEDURE.md`. That document explains *why*; this one
is the running order. **Nothing here has been executed.**

> ## !!! DO NOT EXECUTE — B4 REOPENED 2026-10-19 !!!
>
> The platform's own mint function, applied to tenant
> `ten_e759b7288598bd882e3dcac49d` and ProcessorId `BFEBFBFF000806C1`,
> yields **`ep_814199c05cfa49595311`** — NOT `ep_1989031c8c1d0085812f`.
> No case, whitespace, hostname or kind variant reproduces the recorded id,
> and the mint function has not changed since 2026-09-06, three weeks before
> this endpoint enrolled. The recorded identity was therefore almost
> certainly minted from `machine_guid` or `device_iid`, i.e. `processor_id`
> was absent at original enrolment.
>
> Running PHASE C today would send `processor_id`, the platform would prefer
> it (hw > guid), and a **NEW** endpoint would be minted: the token spent,
> the fleet split to 3, and the 1.99 GB backlog delivered into an identity
> holding none of the 157,226 events.
>
> **Step A2 below is the gate that catches this, and it currently FAILS.**
> Resolve B4 first — see `B4_REOPENED.md`.

Hard rules for the whole run: never `uninstall --purge`; never delete or
truncate `outbox.jsonl`, `outbox.offset` or the journal; never put the token
on a command line; never point `--backend` at the frontend host; never rename
or switch `DB_NAME`.

---

## FROZEN BASELINE — every acceptance check below compares against these

| Fact | Value |
|---|---|
| endpoint_id | `ep_1989031c8c1d0085812f` |
| tenant_id | `ten_e759b7288598bd882e3dcac49d` |
| ProcessorId | `BFEBFBFF000806C1` |
| event_count | **157,226** |
| last_telemetry_at | 2026-10-01T02:22:52Z |
| states | enrollment / credential / sensor = REVOKED / REVOKED / REVOKED |
| group / policy | `grp_default_windows` / `pol_default_detect_only` |
| credentials for this endpoint | 1, REVOKED |
| fleet | `edr_endpoints` **2** · `edr_agent_credentials` **2** · `edr_enrollment_tokens` **0** · `edr_agent_sessions` 0 |
| store | `edr_raw_events` 1,877,149 · `edr_processing_queue` 1,718,750 · `edr_rejected_telemetry` **25,992** |
| installer | 0.3.0-windows, built from `63d7d104`, Gate 4 PASS on run 39144147851 |
| local queue | ~1.99 GB · backup `C:\NivXForge-Recovery-Backup` VERIFIED |

Record the laptop-side numbers from step A4 before step C. Everything after
is compared to them, not to memory.

---

## PHASE A · read-only, on the laptop, immediately before enrolment

**A1 · ProcessorId** (elevated PowerShell)
```powershell
(Get-CimInstance Win32_Processor).ProcessorId
```
Expect `BFEBFBFF000806C1`. **STOP** on empty output or any other value.

**A2 · Recompute the identity the platform will mint**
```powershell
$t = "ten_e759b7288598bd882e3dcac49d"
$p = (Get-CimInstance Win32_Processor).ProcessorId
$b = [Text.Encoding]::UTF8.GetBytes("$t`u{1F}hw`u{1F}$p")
$h = [BitConverter]::ToString(
       [Security.Cryptography.SHA256]::Create().ComputeHash($b)
     ).Replace("-","").ToLower()
"ep_" + $h.Substring(0,20)
```
Expect **exactly** `ep_1989031c8c1d0085812f`.
**STOP on any difference.** This is the only guard before the token is spent:
a fallback to `machine_guid` mints a *different* endpoint and the 1.99 GB
backlog delivers into a brand-new computer while the original goes silent.

**A3 · Artifact provenance**
```powershell
Get-FileHash .\NivXForgeEDRSetup.exe -Algorithm SHA256
.\NivXForgeEDRSetup.exe version
```
Expect `build_commit` `63d7d104…`, `build_run_id` = 39144147851, and the hash
equal to that run's `artifact_sha256`. **STOP** on `UNOFFICIAL_BUILD` or any
hash mismatch.

**A4 · Current state — write these numbers down**
```powershell
Get-Service NivXForgeSensor
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe status
Get-ChildItem C:\ProgramData\NivXForge\sensor | Select-Object Name,Length,LastWriteTime
Get-ChildItem C:\NivXForge-Recovery-Backup
```
Expect `endpoint_id` `ep_1989031c8c1d0085812f`, `tenant_id`
`ten_e759b7288598bd882e3dcac49d`, `enrolled: true`, a journal that is not
`JOURNAL_CORRUPT`, and `identity.json` / `outbox.jsonl` / `outbox.offset`
present in **both** directories. Record `queue_depth` and
`legacy_outbox_remaining` as **Q0** and the `outbox.offset` value as **O0**.
**STOP** if the backup is missing or the journal reports corrupt.

## PHASE B · the token (console, owner)

**B1** Mint **exactly one** enrolment token (Management → Enrolment). Record
the `token_id` only. Never paste the secret into a shell, file, ticket or
chat.

**B2** Confirm `edr_enrollment_tokens` now shows exactly **1 unspent** token
for the tenant and no others.

**STOP** if more than one token exists — a spare token is a second
enrolment waiting to happen.

## PHASE C · the one command that changes anything

**C1** From an elevated PowerShell in the directory holding the verified
artifact:
```powershell
$t = Read-Host -AsSecureString "enrolment token"
[Runtime.InteropServices.Marshal]::PtrToStringBSTR(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($t)
) | .\NivXForgeEDRSetup.exe install `
      --backend https://nivxray.nivxforge.com `
      --tenant ten_e759b7288598bd882e3dcac49d `
      --re-enrol --token-stdin --interval 30
```
`--re-enrol` is required (without it the installer RESUMES and spends no
token). `--token-stdin` is the only accepted input — there is no `--token`
flag and the installer re-checks its own `argv` before enrolling.

**C2 · Expected output, in order**
```
=== 1 . STAGE ===            build identity + artifact SHA256
=== 2 . PROTECTED STATE ===  state dir ACL
=== 3 . ENROLMENT ===        enrolled endpoint_id=ep_1989031c8c1d0085812f
=== 4 . WINDOWS SERVICE ===  NivXForgeSensor (LocalSystem, automatic, running)
=== 5 . IDENTITY ===         status JSON
```
**The printed `endpoint_id` must equal `ep_1989031c8c1d0085812f`.**
If it does not — **STOP immediately**, go to ROLLBACK R4. A second endpoint
now exists and every delivered event from this point lands on the wrong one.

If the run ends in `=== ROLLBACK ===`, read PHASE F before retrying.

## PHASE D · local acceptance (first 5 minutes)

**D1 · Identity and service**
```powershell
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe status
Get-Service NivXForgeSensor
```
Expect: same `endpoint_id` and `tenant_id`, `enrolled: true`,
`credential_present: true`, journal healthy, service **Running**.

**D2 · State preserved, not recreated**
```powershell
Get-ChildItem C:\ProgramData\NivXForge\sensor | Select-Object Name,Length,LastWriteTime
Get-Content C:\ProgramData\NivXForge\sensor\outbox.offset
```
`outbox.jsonl` must be the same file, same or larger size, **not** newly
created. The offset must be ≥ **O0**. **STOP** if `outbox.jsonl` has shrunk
or its timestamp indicates recreation.

**D3 · Delivery is progressing** — repeat after ~10 and ~30 minutes:
```powershell
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe status
```
`legacy_outbox_remaining` must be **below Q0 and falling**. Drain is bounded
by wall clock per cycle, so expect a steady decline, not a cliff. A value
that never moves across three samples is a **STOP** → R5.

## PHASE E · platform acceptance (your console session, read-only)

All of these are authenticated GETs against
`https://nivxray.nivxforge.com` with your console bearer token. They read;
they change nothing.

| # | Request | Expected |
|---|---|---|
| E1 | `/api/edr/enrollment/endpoints` | **exactly 2** endpoints for the tenant. A third = duplicate identity → R4 |
| E2 | `/api/edr/onboarding/computers/ep_1989031c8c1d0085812f` | `enrollment_state` ENROLLED, `credential_state` ACTIVE, `sensor_state` healed off REVOKED, `tenant_id` unchanged |
| E3 | same record, `event_count` | **≥ 157,226** and increasing on re-reads as acknowledged telemetry arrives. A value near zero = delivery record reset → **STOP**, report |
| E4 | same record, `group_id` / `policy_id` | `grp_default_windows` / `pol_default_detect_only`, unchanged |
| E5 | same record, `last_telemetry_at` / `last_heartbeat_at` | both newer than 2026-10-01T02:22:52Z |
| E6 | same record, `outbox_queue_depth` | tracking the laptop's falling queue (sensor-reported) |
| E7 | `/api/edr/enrollment/tokens` | the one token from B1 marked spent, `used_by_endpoint_id` = `ep_1989031c8c1d0085812f`; no unspent token left |
| E8 | `/api/edr/enrollment/rejections` | **no new rejections** after C1. New entries mean the sensor is being refused — read the code, not the symptom |

## PHASE F · store-level checks (counts only, read-only)

No API exposes raw collection counts, so these need a **read-only deployer
query**. Ask for **counts only and the named fields only — no documents, no
credential values**:

| # | Ask for | Expected |
|---|---|---|
| F1 | `edr_agent_credentials` total, and the count + `status` values for `ep_1989031c8c1d0085812f` | total **2 → 3**; for this endpoint **2**: the old one still `REVOKED`, exactly one `ACTIVE` |
| F2 | `edr_endpoints` total | **2**, unchanged |
| F3 | `edr_rejected_telemetry` total | **25,992** + 0. Any growth → authentication or credential problem, **STOP** → R6 |
| F4 | `edr_raw_events` total, sampled twice ~15 min apart | rising while the backlog drains; the increase should track D3's decline |
| F5 | distinct `endpoint_ref` values in `edr_raw_events` written **after** C1 | exactly one, and it must be `ep_1989031c8c1d0085812f`. A second value = telemetry attributed to a duplicate identity → R4 |
| F6 | `edr_processing_queue` total, sampled twice ~15 min apart | growing with F4, then reconciling. The queue is idempotent on `(tenant_id, raw_id)`, so a **replayed** event must not create a second entry — if the queue grows materially faster than `edr_raw_events`, suspect duplicate ingestion and **STOP** → R7 |

**Pre-existing observation, not caused by this recovery:**
`edr_processing_queue` already holds 1,718,750 entries against 1,877,149 raw
events. Whether that is healthy retention or a reconciliation backlog is
**unverified**. The drain will add ~157k+ events to it. Worth answering
before or shortly after the recovery; it is not a reason to delay.

## ROLLBACK / STOP CONDITIONS

| id | Trigger | State at that moment | Action |
|---|---|---|---|
| R1 | A1/A2 mismatch or empty ProcessorId | nothing touched, no token spent | **Do not enrol.** Report the computed value |
| R2 | A3 artifact mismatch / `UNOFFICIAL_BUILD` | nothing touched | Obtain the artifact from run 39144147851 and re-verify |
| R3 | C1 fails **before** `3 . ENROLMENT` | no token spent, no identity written, `ROLLBACK` restored the prior service state | Fix the cause, re-run C1. Nothing lost |
| R3b | C1 fails **at** enrolment (bad/expired/spent token) | token may be spent; `identity.json` untouched (written only after a successful response); service restored | Mint a **new** token, re-run C1. Never re-present a token |
| R3c | C1 fails **after** enrolment | new credential issued and stored; service restored by rollback | Re-run **without** `--re-enrol` — it RESUMES on the new identity and spends no token |
| R4 | Printed or stored `endpoint_id` ≠ baseline, or E1 shows 3 endpoints, or F5 shows a second `endpoint_ref` | a duplicate identity exists and is receiving evidence | `sc.exe stop NivXForgeSensor`, restore `identity.json` from `C:\NivXForge-Recovery-Backup`, report. **Do not purge, do not delete the queue.** The duplicate endpoint must be retired platform-side, not locally |
| R5 | D3 shows no drain across three samples | enrolled, service up, delivery stalled | `status` + service log first. Do **not** re-enrol — the credential is valid; this is a delivery problem |
| R6 | F3 rejections growing | sensor authenticated but refused | Stop the service to end the refusal loop, report with the rejection codes. Do not mint another token |
| R7 | F6 queue growing materially faster than F4 | possible duplicate ingestion | Stop the service, report both sample pairs. Idempotency is on `(tenant_id, raw_id)`; a breach is a platform defect, not an operator action |
| R8 | Service will not start after C1 | image staged, service create/start failed | `status` first. The state directory is untouched; re-run C1 **without** `--re-enrol` |

**Success is all of:** A1-A4 matched · one token spent · printed
`endpoint_id` = baseline · D1-D3 green with a falling queue · E1-E8 green ·
F1-F5 green. Anything else is a STOP, and a STOP is cheaper than a split
identity.
