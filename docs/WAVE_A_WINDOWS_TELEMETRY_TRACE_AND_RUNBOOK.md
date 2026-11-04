# WAVE A · WINDOWS PROCESS TELEMETRY — TRACE RESULT + OWNER RUNBOOK

Owner rule: *do not assume the low count is caused by Sysmon config until
proven.* This traces Sysmon config → subscription → sensor → ingest →
canonical evidence and reports only what is measured.

Corpus: `ten_f1a5479243e901cf159e230fa0` / `DESKTOP-A9HGFJJ`,
2026-09-22 15:43–16:46 UTC, 3,299 canonical rows.

---

## 1 · WHAT WAS MEASURED

| stage | finding | proven? |
|---|---|---|
| collector subscription | **NO event-ID filter exists.** `filters` is empty in all four `CollectionProfile`s (validation, recommended-security, forensic, domain-controller). The whole Sysmon Operational channel is subscribed. | **YES** |
| collector → ingest | Sysmon deliveries: **0 blocked**. Security deliveries: **24 BLOCKED**, System: 1, unattributed: 1. | **YES** |
| ingest refusal reason | `mismatch_reason: SOURCE_FORMAT_MISMATCH`, `content_recognized_as: []`, declared `windows_security` → `windows-security-evd`. The declaration is not overridden and no other DSM is tried. | **YES** |
| is the DSM the defect? | **NO.** A well-formed Security 4688 inside the collector's own `{channel, xml}` envelope passes both `WindowsSecurityDSM.recognizes_format()` and `.supports()`. Verified against the bare-XML and no-channel-key shapes too. | **YES** |
| WHY those 24 records were unrecognisable | **UNKNOWN — and it was UNKNOWABLE BY DESIGN.** See §2. | not proven |
| Sysmon Event ID 1 count | 16 in the window (14 in the 15h hour, 2 in the 16h hour). Nothing was dropped by the collector filter or refused at ingest, so the loss — if any — is upstream of the collector. | count proven; **cause NOT proven** |

### Source event ids actually collected
`Sysmon:13`×2335 · `Sysmon:12`×766 · `Sysmon:11`×107 · `Sysmon:3`×70 ·
**`Sysmon:1`×16** · `Sysmon:22`×1 · `Security:4672`×2 · `Security:4624`×2.
**`Security:4688` — absent.**

---

## 2 · THE ACTUAL P0 DEFECT FOUND (fixed)

The ingest refusal ledger could not explain itself.

`routers/xdr_ingest.py` wrote

```python
"payload_excerpt": str(raw.get("line") or raw.get("message") or "")[:300]
```

The Windows Event Log collector sends `payload_keys: ["channel", "xml"]`.
Neither `line` nor `message` exists, so **every Windows refusal recorded
an empty excerpt** — including the 24 Security refusals that hid the
absence of 4688.

Measured blast radius: **55 `SOURCE_FORMAT_MISMATCH` blocks across 4
tenants, 0 with an excerpt.** Excerpts existed only for
`DECLARATION_REQUIRED` / `SOURCE_NOT_AUTHORIZED` (14 of 171).

**FIX.** `_excerpt_evidence()` walks a declared, ordered list of
content-bearing keys (`line, message, xml, raw, body, event, _raw, text,
payload, data`), and records:

* `payload_excerpt` — bounded to 300 chars,
* `payload_excerpt_source` — WHICH key it came from, so an excerpt can
  never be read as coming from a field it did not,
* `payload_excerpt_len` / `payload_excerpt_truncated`,
* `payload_excerpt_absent_reason` — when no declared key carried text,
  the keys that DID have a value are listed. An empty payload and an
  unread payload are now different facts.

Consequence: this class of refusal is diagnosable on its next
occurrence. **I am not claiming the 24 records were empty** — that
evidence was never captured and is gone.

---

## 3 · OWNER RUNBOOK — nothing here is run automatically

### Purpose
1. Capture a DIAGNOSABLE Security-channel refusal (the fix above only
   takes effect for NEW deliveries).
2. Establish whether 4688 is absent because of Windows audit policy.
3. Establish whether 16 process-creations/hour reflects the endpoint's
   Sysmon configuration.

### Files changed (server side, already applied, no endpoint impact)
* `backend/routers/xdr_ingest.py` — `_excerpt_evidence()`, `_CONTENT_KEYS`
* `backend/routers/xdr_ingest_routing.py` — refusal read model exposes
  the four new excerpt fields

Restart required: backend only (already done). No sensor change is
required for the fix itself, and **no configuration has been changed on
any endpoint.**

### Step 1 — capture the endpoint's CURRENT state (read-only, PRE)
```powershell
# Sysmon config actually in force — THIS is the unproven variable
Get-Process Sysmon*,Sysmon64* -ErrorAction SilentlyContinue
& "$env:SystemRoot\Sysmon64.exe" -c            # dumps the active config
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
  Select-Object LogName,IsEnabled,MaximumSizeInBytes,RecordCount

# how many Event ID 1 records does the CHANNEL itself hold for the window?
(Get-WinEvent -FilterHashtable @{
   LogName='Microsoft-Windows-Sysmon/Operational'; ID=1;
   StartTime='2026-09-22 15:43'; EndTime='2026-09-22 16:46'}).Count

# audit policy — 4688 cannot exist without this
auditpol /get /subcategory:"Process Creation"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled
```
Report the numbers back. **If the channel itself holds ~16 Event ID 1
records for that window, nothing was lost and the endpoint genuinely
created few processes — do not change anything.**

### Step 2 — only if Step 1 shows the channel held MORE than 16
Then telemetry was lost between channel and canonical evidence, and I
will trace the collector bookmark/acquisition ledger before any config
change is proposed. **Do not change the Sysmon config at this point.**

### Step 3 — enable 4688 (optional, your decision)
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```
Why: 4688 is an INDEPENDENT process-creation source from Sysmon 1 and
must not be collapsed into it. The second registry value adds the
command line to 4688, without which 4688 adds little for content rules.

Expected telemetry: `Security:4688` rows appear in
`xdr_canonical_evidence` with `process.command_line` populated.

Restart/reload: none. Audit policy is effective immediately for new
processes.

**Rollback:**
```powershell
auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f
```

Risk: 4688 is higher-volume than Sysmon 1. Enable it on this one
acceptance endpoint only, and watch the ingest volume.

### PRE acceptance numbers (recorded)
`process_create` = 16 · `Security:4688` = 0 · Security refusals = 24 ·
refusals with a usable excerpt = 0 · canonical rows = 3,299 ·
evaluation-ledger entries = 3,299 · detections = 0.

### Expected POST acceptance criteria
1. Any NEW Security refusal carries a non-empty `payload_excerpt` **or**
   an explicit `payload_excerpt_absent_reason`. *(This is the real
   acceptance test of the fix.)*
2. If Step 3 is applied: `Security:4688` > 0 with
   `process.command_line` populated, and 4688 rows are NOT merged with
   Sysmon 1 rows.
3. `process_create` count rises to at least the channel count measured
   in Step 1.
4. Re-run `POST /api/edr/endpoints/{id}/detection-replay?apply=true` and
   the coverage matrix; `PARTIAL` rules gated on uncollected fields
   should move only if the field is genuinely now collected.

**Do not deploy to production. Do not modify historical evidence.**

---

## 4 · RETRACTIONS (measurement corrected me)

| earlier claim | status |
|---|---|
| "Cisco on that machine would also show no detections" | **WITHDRAWN.** Not establishable. Correct form: *NivXForge's currently collected evidence and currently implemented detection content produced no detections for this corpus.* |
| "0 file SHA-256 in the corpus" | **WRONG.** All 16 `process_create` rows carry `process.hashes.md5` AND `.sha256` with `field_provenance` citing `sysmon:EventData.Hashes`. |
| "16 of 3,299 carry a command line ⇒ fields are being dropped" | **WRONG.** 16 is the `process_create` COUNT; 16/16 carry a command line. Registry/file/network events have no command line of their own, correctly. |
| "a dialect mismatch kills a rule" | **WITHDRAWN.** No rule compares `event_type` against `process_creation`; it appears only as a function name and as Sigma-style `telemetry_requirements` labels. |
| "the corpus bypassed detection" | **REFINED.** It reached canonical evidence via the XDR ingest plane; what was missing was the evaluation RECORD. |
| "9 rules are dead on canonical evidence" | **WRONG — my own measurement artefact.** Those rules ship canonical-shaped fixtures and my canonicaliser was overwriting them. After fixing the generator: 0 dead rules. |

The one gap the matrix found that WAS real: `DET-CR-002` (T1003.003)
gated on the literal string `ntds.dit` and could not fire on its own
positive fixture, because `ntdsutil "ac i ntds" "ifm" "create full
<dir>"` never names the file. Fixed, with a regression.
