# G1 · Windows endpoint proof — STEP 1 of 2 (read-only pre-flight)

**Nothing in this step changes your machine.** No install, no channel
enabling, no Sysmon, no NivX component started, no registry write.

The runbook that actually deploys the NivXForge EDR collector is **written
after** you return the pre-flight JSON, because it must be generated for the
edition/build/channel reality of your host rather than assuming Windows
Server.

---

## 1 · Get the reviewed code onto the Windows host

Use **Save to Github** in this chat, then on the Windows endpoint:

```powershell
git clone <your-repo-url> C:\nivx
cd C:\nivx\scripts\windows\g1
```

(`git pull` in the same folder is how any approved fix reaches the host
later. No ZIP, no uncontrolled copy.)

## 2 · Run the read-only pre-flight

Elevated PowerShell is preferred — the `Security` channel is only readable by
an administrator, and the script must be able to state that truthfully. It
also runs unelevated and will say so.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-NivXRayG1Preflight.ps1
```

It prints one JSON document and writes the same content to
`nivxray-g1-preflight.json` next to the script.

## 3 · Send the JSON back

Paste the JSON (or the file contents) into the NivXRay engineering thread.
The credential variable `NIVX_INGEST_TOKEN` is **never printed** — only
whether one is set.

---

## What the pre-flight reports

| Section | Contents |
|---|---|
| `host` | hostname, OS caption/version/build, architecture, install date, last boot, **CLIENT vs SERVER vs DOMAIN_CONTROLLER**, domain/workgroup state, CPU/RAM |
| `shell` | PowerShell version + edition, execution policy, current user, **elevation state** |
| `prerequisites` | python / py / pip / git presence + versions, **pywin32 importability** (the only Windows-specific dependency of the acquisition path: `win32evtlog` · `EvtSubscribe`/`EvtCreateBookmark`), .NET release |
| `sysmon` | INSTALLED / NOT_INSTALLED, services, driver, binary version. **Sysmon is never installed by this script** |
| `channels` | for each of the 23 channels the existing adapter declares: presence, enabled, log mode, max size, current size, record count, oldest record number, last write time, file path, and a **one-record read probe** proving this account can actually read it |
| `summary` | counts + the explicit truth note |
| `collector_environment` | whether the NivX collector variables are already set on this host (token presence only) |
| `network` | TCP reachability of the ingest host, only if an ingest URL is already set |

### Truth states it will use

* `NOT_PRESENT` — the channel does not exist on this host.
* `PRESENT_NO_RECORDS` — it exists and has recorded nothing (**not** "no
  activity occurred").
* `READ_DENIED` — this account could not read it, with the Windows error
  (**not** "empty").
* Sysmon absent → its channel reports `NOT_PRESENT` and will be carried
  through the proof as `NOT_OBSERVED`, never as healthy and never silently
  installed.

---

## What happens after you return the JSON (STEP 2, not yet written)

1. Server-side onboarding, generated for your host: a dedicated G1 proof
   tenant via the tenancy control plane, an enrolled collector whose
   `authorized_sources` cover exactly the channels your host can actually
   read, and one scoped ingest credential (revoked at the end of G1).
2. A pre-seeded `connectors.json` for `${XDR_STATE_DIR}` carrying the
   authoritative `collector_id` — the collector service rehydrates and
   auto-starts it, so **no HUMAN control-plane route is called on the Windows
   host** and no authorization classification is weakened.
3. The exact command sequence for: venv + dependencies (+ `pywin32`), start,
   observe, controlled restart, kill-between-durable-write-and-delivery,
   Event Log clear/rollover, and the read-only SQLite queries that evidence
   bookmarks, outbox and dead-letter.
4. The server-side verification: raw evidence, canonical evidence with
   `canonical_evidence_id`, three-clock distinctness, Event Explorer, and the
   honest `REFERENCED`/`GAP` classification for the unparsed channel.

## Fixes already applied in preparation (code, reviewed)

`framework/windows_eventlog.py` — two deployment-path defects found during
pre-flight, approved by the owner as B1+B2:

* **B1** the connector now accepts the `identity` argument the collector
  service passes to every connector (`main.py` rehydrate and
  `routes/connectors.py` create). Previously it raised `TypeError`, which boot
  swallowed, so the Windows connector silently never started.
* **B2** `collector_id` now comes from the connector configuration, with
  `NIVX_COLLECTOR_ID` as the explicit fallback, and **fails closed** when
  neither is declared. It is never generated, because it anchors both the
  envelope identity the ingest boundary matches and the bookmark scope
  `(tenant, collector_id, channel)` that acquisition resumes from.

Tests: `tests/test_windows_eventlog_deployment_identity.py` (6) +
`tests/test_windows_eventlog_acquisition.py` (27) → **33 passed**.
These are Linux tests: they prove the deployment contract, **not** the
endpoint proof. The endpoint proof is STEP 2 on your host.
