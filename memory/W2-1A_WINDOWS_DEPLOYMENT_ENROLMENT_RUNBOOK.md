# W2-1A · WINDOWS COLLECTOR DEPLOYMENT & ENROLMENT RUNBOOK

Status: **READY FOR A REAL WINDOWS ENDPOINT.** Nothing in this runbook has been
executed on Windows yet — that is the gate, and it needs a machine the owner
controls.

Architecture being deployed (accepted 2026-06):

```
Windows Event Log (local subscription)
  → durable local queue (SQLite outbox)
  → authenticated OUTBOUND delivery (HTTPS)
  → NivXRay XDR tenant-authorized persistence
```

No inbound connection to the endpoint is ever required. Cloud-side remote
WMI/RPC polling is **not** the architecture: the decisive reasons are
operational and security-model — inbound RPC/DCOM reachability, privileged
credential storage, firewall complexity, endpoint availability and scaling —
not an inability to checkpoint (it *can* be checkpointed; it still should not
be the primary path). WEF/WEC remains a **later supported ingestion topology**,
not a replacement for the native collector.

---

## 1 · PREREQUISITES

| Requirement | Value | Why |
|---|---|---|
| Windows version | Server 2016/2019/2022/2025, or Windows 10/11 | `EvtSubscribe` + bookmark APIs |
| Architecture | x64 | matches the Python/pywin32 build |
| Runtime | Python 3.11 x64 (the collector is Python today) | same runtime as the rest of the collector plane |
| Native binding | `pywin32` (`pip install pywin32`) — then `python Scripts/pywin32_postinstall.py -install` | provides `win32evtlog` |
| Service identity | **LocalSystem** for the validation run | reading `Security` requires it (or membership of *Event Log Readers* **plus** the `SeSecurityPrivilege`-equivalent grant). A least-privilege service account is a follow-up once the flow is proven |
| Minimum log rights | *Event Log Readers* for non-Security channels; `Security` additionally needs LocalSystem or an explicit channel ACL | |
| Sysmon | Installed with a config (SwiftOnSecurity / Olaf Hartong baseline) | Sysmon is the highest-value channel and the only one with canonical analysis support today |
| Network | **Outbound 443 only** to the NivXRay ingest host | no inbound rules, no port-forwarding |
| TLS | System trust store; the ingest host's certificate must validate. Certificate validation is **never** disabled | |
| Proxy | `HTTPS_PROXY` honoured by the delivery client; authenticated proxies need the credential in the service environment, not in a config file in the repo | |
| Disk | **≥ 2 GB free** at `XDR_STATE_DIR` for the durable queue + bookmarks | a full disk must degrade honestly, not lose events silently |
| CPU / memory | ~1 vCPU, 150–300 MB RSS at a `windows-recommended-security` profile | measure during validation; do not publish a figure we have not measured |
| Clock | Time synchronised (w32tm) | activity vs observation vs ingest clocks are compared downstream |

---

## 2 · ENROLMENT CHAIN

```
Tenant → Collector identity → Device identity → Credential → Collection profile → Server acknowledgement
```

| Step | What it establishes | Where it comes from |
|---|---|---|
| 1 · Tenant | which customer owns this telemetry | `NIVX_TENANT_ID`; the core compares it against the `X-Tenant-Id` header **and** every envelope's `tenant_id` — a mismatch is refused |
| 2 · Collector identity | which collector process is speaking | `NIVX_COLLECTOR_ID`; anchors acquisition state and the outbox |
| 3 · Device identity | which *host* produced the event | taken from the event's own `<Computer>` as `origin_computer`, kept **separate** from `collector_host`. Never inferred from the collector |
| 4 · Credential | proves the collector may deliver | `NIVX_INGEST_TOKEN` + `NIVX_INGEST_AUTH_MODE` (`api_key` → `X-XDR-API-Key`, or `bearer`) |
| 5 · Collection profile | what to read | `windows-validation` first (see §4) |
| 6 · Server acknowledgement | the core confirms the chain | `POST /api/xdr/ingest-preflight` — one synthetic envelope proving auth + tenant + routing before any real telemetry moves |

**Secret handling — mandatory**
- The ingest credential is issued **per collector**, never a reusable
  tenant-wide secret pasted into an install command line (a command line is
  visible in `Get-CimInstance Win32_Process` and in transcript logs).
- Store it in the **service environment** (or Windows Credential Manager /
  DPAPI for the hardened follow-up), not in a file in source control.
- **Never logged.** No enrolment secret appears in collector logs, in this
  runbook's output, in chat, or in the repository.
- Rotation: issue a new collector credential, restart the service, revoke the
  old one. Acquisition position is unaffected — the bookmark is independent of
  the credential.

---

## 3 · INSTALL (exact commands — not yet executed)

```powershell
# 1 · runtime + native binding
py -3.11 -m pip install --upgrade pip
py -3.11 -m pip install pywin32 fastapi uvicorn httpx pydantic
py -3.11 C:\Python311\Scripts\pywin32_postinstall.py -install

# 2 · lay down the collector and its durable state directory
New-Item -ItemType Directory -Force C:\Program Files\NivXRay\collector
New-Item -ItemType Directory -Force C:\ProgramData\NivXRay\state
# copy the nivxray-xdr-collector tree into the collector directory

# 3 · service environment (NEVER on the command line)
[Environment]::SetEnvironmentVariable('NIVX_TENANT_ID','<tenant-id>','Machine')
[Environment]::SetEnvironmentVariable('NIVX_COLLECTOR_ID','<collector-id>','Machine')
[Environment]::SetEnvironmentVariable('NIVX_INGEST_URL','https://<host>/api/xdr/ingest/telemetry','Machine')
[Environment]::SetEnvironmentVariable('NIVX_INGEST_AUTH_MODE','api_key','Machine')
[Environment]::SetEnvironmentVariable('XDR_STATE_DIR','C:\ProgramData\NivXRay\state','Machine')
# the credential, set interactively so it never lands in a script or history:
$t = Read-Host -AsSecureString 'NIVX_INGEST_TOKEN'
[Environment]::SetEnvironmentVariable('NIVX_INGEST_TOKEN',
  [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($t)),'Machine')

# 4 · acknowledgement BEFORE any real telemetry
py -3.11 -c "import httpx,os;print(httpx.post(os.environ['NIVX_INGEST_URL'].replace('/ingest/telemetry','/ingest-preflight'),headers={'X-XDR-API-Key':os.environ['NIVX_INGEST_TOKEN'],'X-Tenant-Id':os.environ['NIVX_TENANT_ID']},timeout=20).text)"

# 5 · run as a Windows service (LocalSystem, auto-start, restart on failure)
sc.exe create NivXRayCollector binPath= "\"C:\Python311\python.exe\" \"C:\Program Files\NivXRay\collector\main.py\"" start= auto obj= LocalSystem DisplayName= "NivXRay XDR Collector"
sc.exe failure NivXRayCollector reset= 86400 actions= restart/5000/restart/15000/restart/60000
sc.exe description NivXRayCollector "Local Windows Event Log acquisition with durable outbound delivery"
sc.exe start NivXRayCollector
```

> `sc.exe create` with a bare `python.exe` is the **validation** form. Production
> packaging (a proper service wrapper handling SCM stop/shutdown signals, or a
> compiled service) is tracked as **B-SVC-1** and must not be skipped before
> 24×7 use.

---

## 4 · FIRST PROFILE — DELIBERATELY NARROW

`windows-validation` = **Sysmon + Security + PowerShell Operational**.
Not every channel the reader supports: process/network/registry/file evidence
from Sysmon, authentication and security auditing from Security, script
execution from PowerShell.

Then expand in this order: **Defender → Task Scheduler → WMI Activity →
AppLocker → System → Application**.

Shipped profiles (all validate clean, asserted in tests):

| Profile id | Channels |
|---|---|
| `windows-validation` | Sysmon · Security · PowerShell Operational |
| `windows-recommended-security` | + Defender · Task Scheduler · WMI Activity |
| `windows-forensic` | + System · Application · AppLocker · Code Integrity · RDP (×2) · WinRM · DNS Client · Windows Firewall · SMB client |
| `windows-domain-controller` | recommended + Directory Service · DNS Server audit |

A channel that is absent or unreadable on the host is reported per channel
(`CHANNEL_NOT_FOUND`, `READER_UNAVAILABLE`, …) and **never fails the whole
collector** — asserted by
`test_unavailable_channel_does_not_fail_the_whole_collector`.

Collection is profile → channel → filtering → **raw preservation** → DSM →
canonical evidence → detection. The collector is **not** built around a
hard-coded Event ID list; detection content is where 4624/4625/4688/4698/
4720/4728/4732/4768/4769/4776/1102 belong.

---

## 5 · THE TWO STATES (never merged)

| Fact | Question | Today |
|---|---|---|
| **Collection support** | can NivXRay acquire this channel reliably? | 21 channels architected; invariants proven off-endpoint |
| **Analysis support** | can NivXRay parse, normalize and reason over it? | **Sysmon only** |

So this is a **valid** reported state and the code emits exactly it:

```
Security   Collection: RECEIVING
           Normalization: NOT YET SUPPORTED
           Detection coverage: NOT AVAILABLE
```

It must never be rolled up as `Security — HEALTHY` because XML reached the
server. Asserted by
`test_collection_support_does_not_imply_analysis_support`.

---

## 6 · SERVICE-BEHAVIOUR MATRIX (to execute on the endpoint)

| # | Behaviour | Expected | Status |
|---|---|---|---|
| S1 | Automatic startup | starts at boot without a console session | PENDING |
| S2 | Restart after failure | SCM restarts per `sc failure` | PENDING |
| S3 | Graceful shutdown | in-flight batch finishes or stays queued; **no position advance without durability** | PENDING |
| S4 | Bookmark persistence | restart resumes from the bookmark, **never** resets to "now" | PENDING (proven off-endpoint) |
| S5 | Outbox persistence | queued events survive restart | PENDING (proven off-endpoint) |
| S6 | Upgrade | binaries replaced; state dir untouched; position continues | PENDING |
| S7 | Uninstall | service removed; state dir removal is an explicit operator choice | PENDING |
| S8 | Config update | profile change is versioned and recorded per channel | PENDING |
| S9 | Log rotation | collector logs bounded; **no secrets** in any log | PENDING |
| S10 | Proxy | delivery honours `HTTPS_PROXY` | PENDING |
| S11 | Certificate validation | a bad certificate fails delivery **closed** | PENDING |
| S12 | Disk exhaustion | queue refuses and **accounts** the drop; never silent loss | PENDING |
| S13 | Network outage | events queue durably and replay on restore | PENDING |
| S14 | Server outage | retry/backoff; no position advance | PENDING |

---

## 7 · REAL-ENDPOINT ACCEPTANCE MATRIX (the W2 gate)

Generate known benign validation activity (e.g. `whoami`, a scheduled-task
create/delete, a signed-in RDP session, a benign PowerShell one-liner) and
prove, with server-side citation:

| # | Proof | How it is cited |
|---|---|---|
| 1 | **Acquisition** — Windows generated it, the subscriber observed that exact event | `EventRecordID` + raw XML match |
| 2 | **Durability** — persisted locally **before** the position advanced | outbox row exists while `bookmark_xml` is still the previous one |
| 3 | **Delivery** — authenticated outbound only | ingest receipt |
| 4 | **Tenant** — attributed to exactly the authorized tenant | server-side `tenant_id` equals the enrolled tenant; a mismatch is refused |
| 5 | **Persistence** — raw Windows XML server-side with provenance | raw row id in the receipt |
| 6 | **Identity + dedupe** — `channel + origin_computer + EventRecordID` preserved; replay creates no second event | `duplicates` counter increments, no new raw row |
| 7 | **Time** — activity / observation / ingestion remain distinguishable | `activity_occurred_at` + `activity_time_source` + `sensor_observed_at` + server ingest time all present and different |
| 8 | **Restart** — bookmark continuation | no gap, no replay storm |
| 9 | **Network outage** — durable replay without silent loss | received = generated |
| 10 | **Duplicate delivery** — idempotency | as #6 |
| 11 | **Canonicalization** — raw → parsed → normalized → canonical (Sysmon today) | canonical evidence id |
| 12 | **Detection** — at least one deterministic detection from a newly supported channel once its DSM lands | detection id citing the evidence |

**Connection status gate.** Only after the server can **cite the received
event** may the UI say `RECEIVING`/`CONNECTED`.
`INSTALLED ≠ CONFIGURED ≠ CONNECTED ≠ RECEIVING ≠ HEALTHY`. Installation is not
connection proof; enrolment is not telemetry proof; **HTTP 200 alone is not
end-to-end evidence proof**.

---

## 8 · WHAT THE OWNER MUST PROVIDE

1. A Windows host (Server 2016+ or Win10/11 x64) — domain-joined or standalone.
2. Administrator access on it, and outbound 443 to the preview ingest host.
3. Sysmon installed with a baseline config (or say so and we validate
   Security + PowerShell first).
4. Confirmation of whether it is a **Domain Controller** (changes the profile).

Then §3 is executed verbatim, §6 and §7 are filled in with real results, and
only the rows that pass are marked `DONE`.
