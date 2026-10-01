# Microsoft 365 real-source onboarding — owner procedure

Status today: **EXTERNAL_ACCESS_BLOCKED.** NivX has the acquisition
connector, the authoritative DSM, canonical evidence, provenance and a
detection that cites real Microsoft fields. What it does not have is
permission to talk to your Microsoft tenant.

**No secret, token, certificate or password may ever be pasted into chat, a
report, a test fixture, a log line or source control.** Every value below is
set once, server-side, by you.

---

## 1 · Register the application (Microsoft Entra admin centre)

1. Entra admin centre → **Identity → Applications → App registrations →
   New registration**.
2. Name it something operationally obvious, e.g. `NivXRay XDR — M365 Audit
   Collector`.
3. Supported account types: **single tenant** (accounts in this
   organizational directory only).
4. No redirect URI — this is an unattended, app-only collector.
5. From the app **Overview**, copy two values for later:
   * **Directory (tenant) ID** → NivX `M365_TENANT_ID`
   * **Application (client) ID** → NivX `M365_CLIENT_ID`

## 2 · Grant the API permission

1. App → **API permissions → Add a permission → APIs my organization uses**
   → **Office 365 Management APIs**.
2. Choose **Application permissions** (NOT delegated — delegated
   permissions require a signed-in user and cannot do unattended
   collection).
3. Select **`ActivityFeed.Read`**. Nothing else.
   * `ActivityFeed.ReadDlp` is deliberately **not** requested: `DLP.All` is
     outside Phase 1 scope.
   * `ServiceHealth.Read` and `ActivityReports.Read` are not needed.
4. Click **Grant admin consent for <tenant>**. A Global Administrator (or
   Privileged Role Administrator) must do this. Confirm the permission row
   shows **Granted for <tenant>**.

Without step 4 the preflight reports `PERMISSION_OR_CONSENT_FAILED`, even
though authentication succeeds.

## 3 · Create the credential

**Option A — client secret (implemented today)**
App → **Certificates & secrets → Client secrets → New client secret**.
Copy the **Value** once (Microsoft shows it only at creation) and put it
straight into the collector environment as `M365_CLIENT_SECRET`. Record its
expiry in your own calendar — Microsoft will not warn NivX.

**Option B — certificate (preferred for production, NOT yet implemented)**
NivX recognises certificate credentials and reports
`CERTIFICATE_AUTH_NOT_IMPLEMENTED` rather than pretending the flow exists.
Do not configure this expecting collection to work; it is on the roadmap as
the production-preferred mode.

## 4 · Microsoft-side audit prerequisite

Unified audit logging must be **on** in the tenant, or the feed is
legitimately empty and NivX will report `RETRIEVED_NO_CONTENT` rather than
inventing activity:

* Microsoft Purview portal → **Audit** → if prompted, **Start recording
  user and admin activity**.
* Exchange mailbox auditing is on by default for most licences; mailbox
  (`ExchangeItem`) records only appear where it is enabled.
* Newly enabled audit logging is not retroactive — records begin from the
  moment it is switched on.

## 5 · NivX side — one collector, one declaration

Create a collector in the owning NivX tenant, authorized for **exactly** the
Microsoft source:

```
POST /api/xdr/collectors           (admin JWT, header X-Tenant-Id: <tenant>)
{ "name": "m365-audit-collector",
  "protocol": "rest",
  "authorized_sources": ["m365-unified-audit"] }
```

Mint an ingest key scoped for enrolment:

```
POST /api/xdr/api-keys
{ "name": "m365-audit-collector-key",
  "confirm_tenant_id": "<tenant>",
  "scopes": ["collectors.enroll", "collectors.read"] }
```

The key value is shown once. It goes into the collector environment, nowhere
else.

## 6 · Collector environment (server-side only)

| Variable | Value |
| --- | --- |
| `M365_TENANT_ID` | Directory (tenant) ID from step 1 |
| `M365_CLIENT_ID` | Application (client) ID from step 1 |
| `M365_CLIENT_SECRET` | secret value from step 3 |
| `M365_CONTENT_TYPES` | optional; default `Audit.Exchange,Audit.AzureActiveDirectory,Audit.General` |
| `M365_PUBLISHER_ID` | optional; defaults to the tenant GUID |
| `M365_LOOKBACK_MINUTES` | optional; first-run window, default 60 |
| `NIVX_INGEST_URL` | `<preview-or-prod-base>/api/xdr/ingest/telemetry` |
| `NIVX_INGEST_TOKEN` | the collector API key from step 5 |
| `NIVX_INGEST_AUTH_MODE` | leave unset (`api_key`); `bearer` only if the value is a user JWT |
| `NIVX_COLLECTOR_ID` | the collector id from step 5 |
| `NIVX_TENANT_ID` | the NivX tenant that owns that collector |
| `XDR_STATE_DIR` | a persistent directory — durable acquisition state and the outbox live here |

`XDR_STATE_DIR` must survive restarts. Without it, collection state is
in-memory only and a restart falls back to the configured lookback instead
of resuming the exact committed window.

## 7 · Run the reproducible acceptance

```
python3 /app/scripts/m365_preflight.py
```

It prints exactly one final state and never echoes a secret:

| State | Meaning |
| --- | --- |
| `CONFIGURATION_INCOMPLETE` | a required variable is unset |
| `CONFIGURATION_VALID` | settings present (printed before the live checks) |
| `SOURCE_REACHABILITY_FAILED` | Microsoft endpoints unreachable |
| `AUTHENTICATION_FAILED` | Microsoft rejected the credential (its own error code is shown) |
| `PERMISSION_OR_CONSENT_FAILED` | authenticated but not authorized — revisit step 2 |
| `SUBSCRIPTION_FAILED` | subscription could not be established |
| `RETRIEVED_NO_CONTENT` | authorized, but the tenant returned nothing — revisit step 4; **not a proof** |
| `RETRIEVED_BUT_NOT_ACCEPTED` | genuine Microsoft telemetry obtained, NivX did not accept it — **not a proof** |
| `REAL_SOURCE_PROVEN` | records retrieved from Microsoft **and** accepted into the authoritative evidence path |

OAuth success alone never yields `REAL_SOURCE_PROVEN`.

## 8 · What you should see once it is proven

* Accepted deliveries on the routing surface
  (`/xdr/admin/ingest-routing`) with declared source `m365-unified-audit`
  and DSM `m365-unified-audit`.
* Canonical evidence carrying Microsoft's `Operation`, `Workload`,
  `RecordType`, `ResultStatus`, the acting principal, client IP where
  recorded, and the activity instant from `CreationTime` — with
  `contentCreated` kept separately as blob availability.
* DET-PS-004 firing only on inbox rules whose recorded parameters forward,
  redirect, blind-copy or delete mail.

## 9 · Known limits to expect on day one

1. **Certificate authentication is not implemented** (step 3, option B).
2. **Device identity does not exist in this source** — Management Activity
   records carry no device id, so endpoint correlation must come from
   NivXForge EDR.
3. **A permanently rejected record holds its content blob, and therefore
   its collection window, open** and is reported as
   `BLOCKED_BY_DEAD_LETTER_RECORDS`. There is deliberately no automatic
   release policy yet.
4. **DLP and Microsoft Graph activity are not collected.**
5. Rotate the client secret before its expiry; NivX reports
   `AUTHENTICATION_FAILED` with Microsoft's error code when it lapses.
