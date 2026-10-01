# PRODUCTION COLLECTOR ENROLMENT — nivx-prod-1 (2026-06)

Status: **BLOCKED on one credential the agent cannot obtain.** Everything that
does not need it is built, tested and listed below. Nothing was created in
production. No telemetry sent. No seeding, no rule tuning, no other product
touched.

## 0 · THE BLOCKER — production control-plane authentication

Creating the collector and minting the ingest key both require an
**admin JWT for production**:

```
POST https://nivxray.nivxforge.com/api/xdr/collectors     ← collectors.create
POST https://nivxray.nivxforge.com/api/xdr/api-keys       ← api_keys.create
```

The production admin password was rotated by the owner and, per
`memory/test_credentials.md`, is deliberately unknown to this workspace.
So there are exactly two ways forward:

| Option | What it needs | Notes |
|---|---|---|
| **A · owner supplies a short-lived admin JWT** (recommended) | one `access_token`, minutes-long | This is the path `test_credentials.md` already sanctions: "supply a short-lived JWT. **Never a password.**" The agent then creates the collector + key over the API with explicit tenant confirmation. |
| B · owner mints it in the production XDR UI | **NOT POSSIBLE TODAY** | The production XDR SPA was built `2026-09-09T21:16:47Z`; the `confirm_tenant_id` UI landed in commit `e9978291` at `21:42:48Z`. The live UI would POST without `confirm_tenant_id` and the hardened endpoint would reject it. Fixing this means a **Vercel XDR frontend redeploy** — a separate approval, and explicitly out of the current scope. |

This is a real consequence of the hardening we just shipped, surfaced now
rather than discovered mid-enrolment.

## 1 · What will be created (once unblocked) — exact values

| Item | Value |
|---|---|
| Tenant | `nivx-prod-1` (dedicated; isolated from the live login tenant) |
| Collector name | `nivx-prod-1-linux-auditd` |
| Collector protocol | `syslog` (`IMPLEMENTED` in `PROTOCOL_REGISTRY`) |
| Initial state | `ADOPTED` — only real received/parsed/normalized counters can move it to `CONNECTED`; the admin API is forbidden from forging that |
| API key name | `nivx-prod-1-auditd-ingest` |
| **Granted scopes** | **`collectors.enroll`** (required to POST telemetry) + **`collectors.read`** (read-only; lets the host preflight confirm the collector without a write). Nothing else. No `collectors.create`, no `collectors.delete`, no `api_keys.*`, no `alerts.*`, no wildcard. |
| Issuance guard | `confirm_tenant_id: nivx-prod-1`, `allow_new_tenant: true` (first credential for a genuinely new tenant) |
| Expiry | `expires_at` set to 30 days — owner may choose a shorter window |
| Secret handling | plaintext is returned **once** by the API and will be delivered to the owner out-of-band. **It will never be printed in chat, committed, or written to any file in this repo.** |

**Exact production ingest endpoint**
```
POST https://nivxray.nivxforge.com/api/xdr/ingest/telemetry
Headers: X-XDR-API-Key: nvx_<48 hex>
         X-Tenant-Id: nivx-prod-1
         Content-Type: application/json
Body:    {"envelopes":[ … ]}
```

## 2 · Host-side shipper — built and TESTED

`scripts/nivxray_auditd_forwarder.py` — standard library only, no `pip install`
on the monitored host. It is a **shipper, not a second ingestion
implementation**: no parsing, no normalization, no detection, no verdict. It
posts verbatim auditd lines to the one authoritative endpoint using the
existing envelope contract; every decision stays in the core.

Modes: `--preflight` (auth + collector identity, sends nothing) ·
`--dry-run` (builds real envelopes, prints, sends nothing, offset not
advanced) · `--once` (one batch) · `--follow`.

Validated against **preview** in a throwaway tenant (`fwd-tool-test-*`,
collector and key both deleted afterwards):
- `--preflight` → `[1/2] HTTP 400 {"detail":"empty batch"}` (proves auth,
  tenant, scope and the rate limiter all passed **before** the handler, with
  zero telemetry written) then `[2/2] HTTP 200 name='fwd-tool-test-auditd'
  protocol=syslog state=ADOPTED events_received=0` → **PREFLIGHT PASS**.
- `--dry-run` correctly selected the `type=SYSCALL` and `type=EXECVE` lines,
  **filtered out** `type=USER_LOGIN`, preserved the message byte-for-byte, and
  derived `source_event_id: auditd:1757451111.123:456` from the audit serial.
- **A real bug was caught here and fixed before it could reach the owner's
  host**: iterating the log with `for line in f` enables read-ahead buffering,
  so `f.tell()` raised `OSError: telling position disabled by next() call` —
  and that offset is exactly what prevents re-sending lines. Now uses
  `readline()`.
- SYSCALL and EXECVE share one audit serial. Verified safe: the platform's
  `event_identity()` mixes a `payload_digest` of `raw` into the dedupe key
  (`services/ingest_idempotency.py:139-156`), so the two records are distinct
  deliveries while a byte-identical retry is still recognised as a duplicate.

## 3 · Supported Linux distributions for this proof

| Distribution | auditd install | Notes |
|---|---|---|
| Debian 11 / 12 | `apt-get install -y auditd` | verified package name |
| Ubuntu 20.04 / 22.04 / 24.04 | `apt-get install -y auditd` | |
| RHEL / Rocky / Alma 8 / 9, CentOS Stream | `dnf install -y audit` | usually preinstalled |
| Fedora 38+ | `dnf install -y audit` | |
| Amazon Linux 2 / 2023 | `dnf install -y audit` (`yum` on AL2) | |
| SLES 15 / openSUSE Leap | `zypper install -y audit` | |

**Not suitable**: Alpine (musl; auditd is not a standard package), unprivileged
containers, and WSL — the kernel audit netlink socket is unavailable, so
auditd cannot collect. It must be a real host or a full VM.

## 4 · Prerequisites on the Linux host
1. `root` / `sudo`.
2. A real kernel with audit support (see above) — not a container, not WSL.
3. `python3` **3.8 or newer** (stdlib only; nothing to install).
4. Outbound **HTTPS/443** to `nivxray.nivxforge.com`.
5. `auditd` installed and running, plus an `execve` rule (step 2 of §5).
6. A writable state directory: `/var/lib/nivxray/`.
7. The API key delivered out-of-band and exported into the environment — never
   pasted into a shell history file or a repo.

## 5 · Host sequence (do NOT start until the owner approves)

**THE EXACT FIRST COMMAND — read-only, changes nothing:**
```bash
uname -srm; python3 -V; \
(systemctl is-active auditd 2>/dev/null || echo "auditd: NOT INSTALLED"); \
curl -s -o /dev/null -w 'nivxray api: %{http_code}\n' https://nivxray.nivxforge.com/api/health
```
Expected: a kernel/arch line, `Python 3.8+`, `active` or `NOT INSTALLED`, and
`nivxray api: 200`. Send that output back; it decides the install command.

Then, in order (each one is a separate confirmation):
```bash
# 2 · install auditd + load an execve rule
sudo apt-get install -y auditd                     # or the distro command above
echo '-a always,exit -F arch=b64 -S execve -k nivxray_exec' \
  | sudo tee /etc/audit/rules.d/nivxray-exec.rules
sudo augenrules --load && sudo auditctl -l         # expect the nivxray_exec rule

# 3 · install the shipper
sudo install -m 0755 nivxray_auditd_forwarder.py /usr/local/bin/
sudo install -d -m 0750 /var/lib/nivxray

# 4 · preflight — sends NO telemetry
export NIVX_INGEST_URL=https://nivxray.nivxforge.com/api/xdr/ingest/telemetry
export NIVX_TENANT_ID=nivx-prod-1
export NIVX_COLLECTOR_ID=<col_… issued in step 1>
export NIVX_XDR_API_KEY=<delivered out-of-band>
sudo -E /usr/local/bin/nivxray_auditd_forwarder.py --preflight

# 5 · first real telemetry (only after PREFLIGHT PASS)
sudo -E /usr/local/bin/nivxray_auditd_forwarder.py --once
```

## 6 · Verification (platform side, after step 5)
1. Collector transitions `ADOPTED → CONNECTED` with
   `state_reason: "telemetry received/parsed/normalized: N/N/N"` — set only by
   `xdr_ingest`, never by the admin API.
2. Receipt reports `reasoned > 0` and `observations_created > 0`, or names the
   honest blocker (`NO_DSM`, `BLOCKED`, `NOT_ATTEMPTED`).
3. Evidence chain readable end to end: `xdr_canonical_events` → canonical
   evidence (`dsm: linux-auditd`, `parser: linux-auditd-parser`) → IUE →
   detection → VEEE → incident, with full provenance.
4. An incident appears **only** if VEEE genuinely crosses
   `INCIDENT_MIN_SCORE`. A zero-incident result with real events flowing is a
   PASS, not a failure — and no rule will be tuned to change that.
5. Tenant isolation: the incident is visible under `nivx-prod-1` and absent
   from the live login tenant's queue.
6. Replay: re-running `--once` on the same lines must report `duplicates > 0`
   and create no second incident.

## 7 · Uninstall / rollback

Host (fully reversible, ~30 seconds):
```bash
sudo rm -f /usr/local/bin/nivxray_auditd_forwarder.py
sudo rm -rf /var/lib/nivxray
sudo rm -f /etc/audit/rules.d/nivxray-exec.rules
sudo augenrules --load          # or: sudo auditctl -D
# optional, only if auditd was installed for this proof:
sudo apt-get remove -y auditd
```

Platform (owner-authorised, agent-executable with a JWT):
- `POST /api/xdr/api-keys/{id}/revoke` → the credential stops verifying
  immediately (revocation is checked at every request).
- `POST /api/xdr/collectors/{id}/disable` → state `DISABLED`; further ingest is
  refused.
- Optional: `DELETE /api/xdr/collectors/{id}`.
- Data: everything written lives under tenant `nivx-prod-1` only. It can be
  reviewed or removed without touching any other tenant. **No production
  backend rollback is required** — this change set is additive.

## 8 · Owner action
Provide a **short-lived production admin JWT** (not a password). The agent will
then create the tenant context, the `syslog` collector and the minimum-scope
key, deliver the secret out-of-band, and stop before any host action.
