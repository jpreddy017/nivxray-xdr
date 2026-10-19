# NivXForge EDR · Windows Sensor Recovery · DESKTOP endpoint

**Status: HOLD.** Do not run section 3 until the two gates in section 0 are
answered. Everything below is read-only until section 3 step 5.

The purpose of this document is to restore telemetry **without** minting a
second endpoint, erasing the delivery record, or discarding the local queue.

---

## 0 · Gates that must be answered BEFORE anything is run

| # | Gate | Why it blocks |
|---|------|---------------|
| G1 | The workflow run that produced your `0.3.0-windows` artifact from commit `63d7d104` reported **`GATE 4 RE-ENROL ROLLBACK: PASS`** | That gate is the only proof that *this* build stops the service, proves it stopped, proves the image released, and restores a previously-running service on failure. Run #23 (`39141512250`) FAILED it on `c845ff0b`; `63d7d104` is the repair. An artifact whose Gate 4 did not run is an untested installer. |
| G2 | The group and policy reset is accepted, or the backend fix is deployed first | `store.enroll` on the live backend CLEARS `group_id`, `policy_id` and their provenance, and the enrolment route then places the computer in the **DEFAULT** group and policy. Identity, history and queue are safe; the administrator's placement is not. Fix prepared, NOT deployed (§5). |

If G2 is accepted as-is, add the remediation step in §4.4.

---

## 1 · What the live backend will do (verified, §5 for evidence)

* `endpoint_id` is minted **server-side** as
  `sha256(tenant_id ␟ "hw" ␟ processor_id)[:20]`, precedence
  **hardware id > machine guid > device_iid > hostname**. The agent cannot
  name its own identity. Same processor id + same tenant = same endpoint.
* The spent token is burned first; the fresh credential is `ACTIVE`; the old
  credential stays `REVOKED`; `enrollment_state` returns to `ENROLLED` and
  `sensor_state` is healed off `REVOKED`.
* `event_count`, `last_telemetry_at`, `last_heartbeat_at`,
  `report_interval_seconds`, `cadence_basis`, `lifecycle_reported` and
  `outbox_queue_depth` are **insert-only** — a re-enrolment cannot reset them.
* The enrol response carries `delivery_history_preserved: true` when the
  endpoint already had telemetry. That field is your single best immediate
  confirmation.

## 2 · Read-only pre-checks, in this order

**2.1 · The artifact is the one you think it is** (any machine):

```powershell
Get-FileHash .\NivXForgeEDRSetup.exe -Algorithm SHA256
.\NivXForgeEDRSetup.exe version
```

`build_commit` must be `63d7d104…`, `build_run_id` must be the run that
answered **G1**, and `build_commit` must **not** be `UNOFFICIAL_BUILD`.
The hash must equal `artifact_sha256` in that run's `build-info.json`.

**2.2 · The identity the platform will mint has not changed** (on the laptop,
elevated, read-only):

```powershell
(Get-CimInstance Win32_Processor).ProcessorId
```

Empty output is a **STOP**. This is the one failure mode that silently
creates a second endpoint: the sensor enrols on `machine_guid` instead, the
platform mints a *different* `endpoint_id`, and the 1.99 GB queue delivers
into a brand-new computer while the original keeps its history and goes
silent. Nothing detects this before the token is spent.

Recompute the identity from that value and compare it to the recorded
endpoint id — same arithmetic the platform uses, no secret involved:

```powershell
$t = "<tenant_id>"; $p = (Get-CimInstance Win32_Processor).ProcessorId
$b = [Text.Encoding]::UTF8.GetBytes("$t`u{1F}hw`u{1F}$p")
$h = [BitConverter]::ToString(
       [Security.Cryptography.SHA256]::Create().ComputeHash($b)
     ).Replace("-","").ToLower()
"ep_" + $h.Substring(0,20)
```

It must equal the original endpoint id **exactly**. If it does not, stop and
report — do not enrol.

**2.3 · Current local state**

```powershell
Get-Service NivXForgeSensor
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe status
```

Record `endpoint_id`, `tenant_id`, `queue_depth` and
`legacy_outbox_remaining`. These are the numbers §4 compares against.

**2.4 · The state directory is intact and backed up**

```powershell
Get-ChildItem C:\ProgramData\NivXForge\sensor |
  Select-Object Name,Length,LastWriteTime
Get-ChildItem C:\NivXForge-Recovery-Backup
```

`identity.json`, `outbox.jsonl`, `outbox.offset` (and the journal) must be
present in both. The installer never deletes this directory — only
`uninstall --purge` does, and **`--purge` must never be used here**.

## 3 · The recovery itself

**3.1** Issue ONE fresh single-use enrolment token in the console
(Management → Enrolment). Do not paste it into a shell, a file, a ticket or a
chat window.

**3.2** From an elevated PowerShell on the laptop, in the directory holding
the verified artifact:

```powershell
$t = Read-Host -AsSecureString "enrolment token"
[Runtime.InteropServices.Marshal]::PtrToStringBSTR(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($t)
) | .\NivXForgeEDRSetup.exe install `
      --backend https://nivxray.nivxforge.com `
      --tenant <tenant_id> `
      --re-enrol --token-stdin --interval 30
```

Why this exact shape:

* `--token-stdin` is the **only** accepted input. The installer has no
  `--token` flag, refuses any argv value that looks like a secret, and
  re-checks its own `argv` at runtime before enrolling.
* `--re-enrol` is required: without it the installer RESUMES on the existing
  `identity.json` and consumes no token.
* `--backend` stays the **API** host. Never the frontend hostname.
* Nothing in `C:\ProgramData\NivXForge\sensor` is removed; the queue, the
  offset and the journal are left exactly where they are.

**3.3** Expected output, in order: `1 . STAGE` (build identity + artifact
SHA256), `2 . PROTECTED STATE`, `3 . ENROLMENT`
(`enrolled endpoint_id=…`), `4 . WINDOWS SERVICE`, `5 . IDENTITY`.

The printed `endpoint_id` **must** equal the original. If it does not, stop
immediately and go to §6 — a second endpoint now exists.

## 4 · Post-recovery verification

**4.1 · Locally**

```powershell
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe status
Get-Service NivXForgeSensor
```

Expect: `enrolled: true`, the **original** `endpoint_id`,
`credential_present: true`, `journal` healthy, and `queue_depth` /
`legacy_outbox_remaining` still ≈ the §2.3 numbers — the backlog is delivered
over many cycles, bounded by wall clock each cycle, so it falls gradually.
The file is never rewritten or deleted.

**4.2 · In the console** (Management → Computers): one row for this computer,
not two. `event_count` must start at **the recorded historical count** and
grow — a count that restarts near zero means the delivery record was reset
and you should stop and report.

**4.3 · Credentials**: the previous credential remains `REVOKED`, the new one
is `ACTIVE`, and the enrolment token shows as spent.

**4.4 · If G2 was accepted as-is**: re-assign the computer to its correct
group and policy in the console, and confirm the policy actually applied.
Until the §5 fix is deployed, every future re-enrolment repeats this.

## 5 · The backend fix (prepared, NOT deployed)

`publish/reenrol-placement-preserved` · commit
`faa8046b761f47c31b535254505e9ca9e1733df2` on PR #18's head `63d7d104`.

Placement and policy provenance join the delivery record in the insert-only
partition, and the two placement helpers return the **effective** placement
instead of the intended one. 6 targeted tests; two of them fail against the
current tree, which is how the defect was confirmed. No deployment performed.

## 6 · Failure and rollback

| Symptom | What already happened | Action |
|---|---|---|
| Install failed before `3 . ENROLMENT` | No token spent, no identity written. `ROLLBACK` restored the previous service state | Re-run after fixing the cause. Nothing was lost |
| Enrolment refused (bad/expired/spent token) | Token may be spent; `identity.json` untouched (written only after a successful response); service restored | Issue a new token, re-run §3. Never pass a token twice |
| Install failed AFTER enrolment | New credential issued and stored; service restored by rollback | Re-run **without** `--re-enrol` — it RESUMES on the new identity and consumes no token |
| Printed `endpoint_id` differs | A second endpoint exists; the queue will deliver into it | Stop the service, restore `identity.json` from `C:\NivXForge-Recovery-Backup`, report. Do **not** purge, do **not** delete the queue |
| Service will not start | Image staged, service create/start failed | `status` first. The state directory is untouched; re-run §3 without `--re-enrol` |

Hard rules: never `uninstall --purge`, never delete or truncate
`outbox.jsonl` / `outbox.offset` / the journal, never point `--backend` at
the frontend host, never put the token on a command line.
