# W1 · PHASE 2 — WINDOWS FORWARDING PATH (design + owner review)

Phase 1 result accepted: **real Windows host + Sysmon + required local
telemetry + SHA256 = PROVEN.** The remaining blocker is now precisely
**transport/onboarding into NivXRay XDR**.

Phase 2 delivers the forwarder and proves its **contract** against the live
ingest route. It does **not** touch the laptop beyond one read-only dry run,
requires **no secret**, creates **no collector or key on the owner's behalf**,
and does not widen `_COLLECTED_PRODUCTS`.

---

## 1 · WHY A SMALL POWERSHELL FORWARDER IS THE SMALLEST HONEST PATH

What actually exists in this codebase:

| Option | Status in this repo | Verdict |
| --- | --- | --- |
| `POST /api/xdr/ingest/telemetry` — HTTPS, JSON, `X-XDR-API-Key` + `X-Tenant-Id`, D15 declared-source routing, exactly-once idempotency | **IMPLEMENTED** and already the boundary N1/N2.1/X1/DCR-1 were proven over | **use it** |
| collector `protocol: "wef"` | registered **SCAFFOLD** — "Windows Event Forwarding subscription not implemented" | would be a lie to claim |
| a Windows agent / collector binary | **does not exist** (`apps/nivxray-xdr-collector` has syslog/webhook/rest/cef/leef only) | not inventing one |
| collector `protocol: "rest"` | **IMPLEMENTED**, transport `https` | **this is the honest protocol value** |

So the forwarder is a host-side reader of the Sysmon channel that POSTs the
envelope the route already accepts. It is transport only: NivXRay re-parses
`raw` itself, exactly as the ingest contract states.

**Script:** `scripts/windows/NivXRay-SysmonForwarder.ps1`

Authority chain it preserves, unchanged:

```
Windows Sysmon
  → forwarder (transport only, no authority)
  → X-XDR-API-Key            scoped ingest key, read from a local ACL'd file
  → X-Tenant-Id              must equal every envelope tenant AND the
                             collector's tenant on the server (403 otherwise)
  → collector_id             server-side identity, one collector per batch
  → declared_source: microsoft-sysmon   must be in the collector's
                             server-side authorized_sources (D15 fails closed)
  → Sysmon DSM → canonical evidence → provenance
```

Design decisions, each for a reason:

* **only the 7 DSM-supported event ids are read** (1, 3, 11, 12, 13, 14, 22).
  Anything else would be refused at the DSM boundary, so it is never sent.
* **EventData is forwarded verbatim** — no field renamed, defaulted, derived
  or dropped. The forwarder never decides meaning.
* **exactly-once**: `source_event_id = <Computer>|<EventRecordID>` plus a
  durable bookmark (`C:\ProgramData\NivXRay\state\sysmon-bookmark.json`). The
  bookmark advances only after the server has accounted for that chunk.
* **no silent loss**: anything the server refuses is appended to
  `state\refused.jsonl` with the server's own stated reason; if a backlog ever
  exceeds the fetch window the skipped record range is written to
  `state\gap.jsonl` and logged as a WARNING. A gap is reported, never hidden.
* **forward fetch**: the query pushes `EventRecordID > bookmark` into XPath and
  takes the **oldest first**, so a backlog is drained in order rather than the
  newest window being skimmed.
* **security**: HTTPS enforced (a non-`https://` base URL is rejected),
  TLS 1.2+, **no certificate-validation bypass anywhere**, and the script
  **refuses to read the key file if `Everyone` / `Users` / `Authenticated
  Users` can read it**. The key is never logged, echoed or written by the
  script, and never appears in an error message.
* `connector_id = nivx-sysmon-forwarder/1.0@<HOSTNAME>` so provenance names
  the transport instance instead of `unmapped`.

---

## 2 · CONTRACT ALREADY PROVEN SERVER-SIDE (no laptop involved)

`scripts/p0_w1_forwarder_contract_check.py` — **PASS, 21/21** against the live
preview route, using the **byte-for-byte envelope shape the PowerShell script
emits** (scratch collector, synthetic Sysmon records — this proves the
CONTRACT, not the source):

* the envelope is accepted (`accepted=3`, `routing_blocked=0`), every record
  `REASONED`, and the collector reached `CONNECTED` **on evidence**
  (`received/parsed/normalized: 3/3/3`);
* `collection_method: "windows_eventlog_pull"` is accepted verbatim;
* canonical evidence carries `ProcessGuid` + `ParentProcessGuid`
  (`SOURCE_PROCESS_IDENTITY`), `OriginalFileName = Cmd.Exe` **separate from**
  `process.name = cmd.exe`, `parent_executable_path`, `parent_command_line`,
  SHA256 **and** MD5, `registry.target_object` / `value_data`, DNS query +
  answer;
* provenance names the collector, the transport instance and
  `dsm_id = microsoft-sysmon`; Sysmon's `UtcTime` is the activity-time basis;
* a replayed record is a `DUPLICATE` and creates **no** second canonical row;
* refusals behave: `declared_source` outside the authorized set →
  `routing_blocked=1`; tenant-header mismatch → **403**; no key → **403**; an
  unsupported Sysmon event id → `BLOCKED`, never canonicalized.

---

## 3 · TELEMETRY VOLUME — RECORDED, NOT FILTERED

The owner's measured 15-minute window:

```
EID 12: 22 728 | EID 13: 2 041 | EID 11: 24 | EID 3: 36 | EID 1: 14 | EID 22: 8
≈ 24 851 records / 15 min  ≈  1 657 / min  ≈  99 000 / hour
```

Forwarder defaults are sized for that: `MaxEvents = 5000` per cycle,
`BatchSize = 200` per POST, 60-second polling ⇒ ~5 000 records/min capacity,
about **3× headroom**. Roughly 25 POSTs per minute at ~80 KB each.

**No filtering is being added during W1**, per your instruction. Two honest
consequences to plan for, not to paper over:

1. a sustained run at this rate writes ~100 000 canonical rows/hour into the
   preview database. The acceptance run should therefore be a **bounded
   window** (15–30 minutes is ample to prove every leg);
2. `EID 12` (registry key create/delete) is ~91 % of the volume and no store
   rule reads it today — `win_persistence_registry_run_key` reads **EID 13**
   (`SetValue`). That is a **telemetry-volume/tuning item for after
   acceptance**, recorded here and nowhere silently applied.

---

## 4 · PHASE 2 OWNER ACTIONS — review + one read-only dry run

Nothing here needs a key, a collector, a tenant id or network access, and the
bookmark is not created or moved.

### 4.1 Copy the script to the laptop

Put `NivXRay-SysmonForwarder.ps1` in `C:\NivX\forwarder\`. (It is in the repo
at `scripts/windows/NivXRay-SysmonForwarder.ps1` — copy by whatever means you
normally use; do not download it from an untrusted mirror.)

### 4.2 Read it, then check its posture without running it

```powershell
# PowerShell 5.1, Administrator
Get-Content C:\NivX\forwarder\NivXRay-SysmonForwarder.ps1 |
  Select-String -Pattern 'Invoke-RestMethod|SecurityProtocol|https|ServerCertificate|ExecutionPolicy'
```

**Expected:** exactly one `Invoke-RestMethod`, one `SecurityProtocol` line
setting TLS 1.2+, an `https://` guard — and **no** certificate-validation
callback of any kind. If you see anything that disables certificate checking,
stop and tell me.

### 4.3 Dry run — renders what WOULD be sent, sends nothing

```powershell
Set-Location C:\NivX\forwarder
powershell.exe -ExecutionPolicy Bypass -File .\NivXRay-SysmonForwarder.ps1 -DryRun
```

**Expected:** a line stating how many records are pending, then
`DRY RUN — 5 envelope(s) written to C:\ProgramData\NivXRay\state\dryrun-<ts>.json`,
followed by a table with one row per envelope:

```
source_event_id  declared_source     event_id provider                  utc_time  fields has_guid has_parent_cmd has_orig_name hash_algos
<HOST>|<recid>   microsoft-sysmon           1 Microsoft-Windows-Sysmon  ...           ~24 True     True           True          MD5+SHA256
```

For at least one EID 1 row: `has_guid`, `has_parent_cmd`, `has_orig_name` all
`True` and `hash_algos` containing `SHA256`. The tenant/collector fields will
read `<TENANT>` / `<COLLECTOR>` — that is correct, they are assigned in
Phase 3.

### 4.4 Return for review

1. the output of 4.2;
2. the full dry-run console output from 4.3;
3. **one** envelope from the dry-run JSON, redacted as you see fit (replace
   user names, host name and file paths with `REDACTED` if you prefer) — I
   only need the **key names** and the field presence, e.g.
   ```powershell
   (Get-Content C:\ProgramData\NivXRay\state\dryrun-*.json -Raw |
     ConvertFrom-Json)[0].raw.PSObject.Properties.Name
   ```

Do **not** create the config file, mint a key, or enrol a collector yet — that
is Phase 3, and I will give you the ACL command for the key file there.

---

## 5 · WHAT PHASE 3 WILL DO (for context only, do not run it yet)

1. you choose preview vs production and the tenant id;
2. **you** create the collector (`protocol: rest`,
   `authorized_sources: ["microsoft-sysmon"]`) and mint **one** ingest key
   with `collectors.enroll` + `collectors.read`;
3. the key is pasted **only** into
   `C:\ProgramData\NivXRay\config\ingest.key` on the laptop, with an ACL
   restricted to `SYSTEM` + `Administrators` (exact command supplied then);
   the script refuses to read it otherwise;
4. `forwarder.json` gets `ApiBaseUrl`, `TenantId`, `CollectorId`,
   `SourceLabel` — no secret in that file;
5. a single bounded run delivers genuine Sysmon records; then Phases 5–8
   verify the receipt, canonical evidence and provenance from **your** host.

`_COLLECTED_PRODUCTS` stays `{"linux"}` until genuine Sysmon evidence from
this host has been received and validated (Phase 9).

**STOP — Phase 2 is owner review. W1 remains NOT CLOSED.**
