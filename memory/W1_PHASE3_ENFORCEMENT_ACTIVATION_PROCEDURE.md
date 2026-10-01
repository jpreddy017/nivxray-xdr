# TENANT REGISTRY ENFORCEMENT ACTIVATION — PROCEDURE + ACCEPTANCE (owner-executed)

Production: `https://nivxray.nivxforge.com` · publish 100 / build `e2d8f54`
Authoritative tenancy (bootstrap CLOSED):
`org_55f6dc202dbf8995369db989ad` NivXMachines · VENDOR · ACTIVE
`ten_e759b7288598bd882e3dcac49d` Internal Validation · INTERNAL_VALIDATION ·
ACTIVE · products XDR + EDR · collectors 0 · api_keys 0 · enforcing false

**Nothing activated by the agent. No collector, no key, no telemetry.**

## 1 · MECHANISM (platform-confirmed)

`NIVX_TENANT_REGISTRY_ENFORCE` is a backend environment variable, currently
**not defined at all** (the code defaults it to `false`).

- Location: **Deployments → the deployed app → deployment side panel →
  Secrets → Edit → add `NIVX_TENANT_REGISTRY_ENFORCE = true` → Save.**
- **Saving alone does NOT take effect.** A **redeploy is required** for the new
  value to reach the running container.
- Zero downtime: rolling update, new container starts with the new secret and
  traffic switches when healthy. Typically 2-5 minutes.
- Code note: `services.tenant_registry.enforcing()` reads `os.environ` **per
  call** and caches nothing, so once the container has the variable the switch
  is immediate and auditable per request. The redeploy is a platform
  requirement, not an application one.
- Secrets are **not versioned and are not part of a deployment rollback**: a
  rollback restores the container image and runs it with whatever secrets are
  currently configured. Therefore treat the flag and the build as two
  independent levers and never change both in one operation.

## 2 · MANDATORY PRE-FLIGHT BEFORE ACTIVATING (owner-side, read-only)

Enforcement refuses any tenant that is not registered. Anything already living
in production under an unregistered tenant string (for example the literal
`default`) will fail closed the moment the flag is on. Production shows 0
collectors and 0 API keys, but the **EDR plane must be checked separately**:

```powershell
$Api = 'https://nivxray.nivxforge.com'
foreach ($t in @('default', 'ten_e759b7288598bd882e3dcac49d')) {
  $h = @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = $t }
  $ep = (Invoke-RestMethod -Uri "$Api/api/edr/enrollment/endpoints" -Headers $h).endpoints
  $tk = (Invoke-RestMethod -Uri "$Api/api/edr/enrollment/tokens"    -Headers $h).tokens
  $co = (Invoke-RestMethod -Uri "$Api/api/xdr/collectors"           -Headers $h).data.count
  $ky = (Invoke-RestMethod -Uri "$Api/api/xdr/api-keys"             -Headers $h).data.count
  "{0}: edr_endpoints={1} edr_tokens={2} collectors={3} api_keys={4}" -f `
      $t, @($ep).Count, @($tk).Count, $co, $ky
}
```
- All zeros for `default` → safe to activate.
- **Any non-zero under `default`** → STOP and report. Those objects must first
  be adopted (`kind: LEGACY_ADOPTED`, id preserved, never renamed) or
  deliberately abandoned. Do not activate over live objects.

Also expected after activation, and accepted in advance:
- the Vite investigation page hardcodes `tenant_id=default`
  (`XdrInvestigationWorkspacePage.jsx:179`) and the Workspace security-state
  tab passes a `tenantId` (`SecurityStateTab.jsx:48-54`). With enforcement on,
  a call naming `default` gets **403 TENANT_NOT_FOUND**. The Security State tab
  therefore fails closed until those callers name `ten_e759…`. Everything else
  in the UI is unaffected. UI change NOT authorized and NOT performed.
- **B7 (accepted):** any tenant-scoped control-plane call without
  `X-Tenant-Id` returns `403 TENANT_REQUIRED`. There is no default tenant.

## 3 · OWNER ACTION (exact)

1. Record the current publish/build (`100 / e2d8f54`) as the rollback
   reference, and note that the flag is currently **absent**.
2. Run the §2 pre-flight. Proceed only if `default` shows all zeros.
3. Secrets → add `NIVX_TENANT_REGISTRY_ENFORCE = true` → Save.
4. Redeploy (this is what makes it effective). No code change, no other secret
   touched, `EDR_AUTH_PEPPER` untouched.
5. Run §4 acceptance. If any line fails → §5 rollback.

## 4 · POST-ACTIVATION ACCEPTANCE

Unauthenticated (must be unchanged — enforcement only ever adds strictness):
```powershell
$A='https://nivxray.nivxforge.com'
(Invoke-WebRequest "$A/api/"       -UseBasicParsing).StatusCode          # 200
(Invoke-WebRequest "$A/api/health" -UseBasicParsing).StatusCode          # 200
# each of these must throw 403/401 - a 200 is a FAILURE
try { Invoke-RestMethod "$A/api/xdr/organizations" } catch { $_.Exception.Response.StatusCode.value__ }   # 403
try { Invoke-RestMethod "$A/api/v2/security-state/streaming/status?tenant_id=default" } catch { $_.Exception.Response.StatusCode.value__ }  # 403
try { Invoke-RestMethod -Method Post "$A/api/xdr/ingest/telemetry" -ContentType 'application/json' -Body '{"envelopes":[]}' } catch { $_.Exception.Response.StatusCode.value__ }  # 403
try { Invoke-RestMethod -Method Post "$A/api/xdr/ingest/telemetry" -ContentType 'application/json' -Headers @{'X-XDR-API-Key'=('nvx_'+('0'*48)); 'X-Tenant-Id'='probe'} -Body '{"envelopes":[]}' } catch { $_.Exception.Response.StatusCode.value__ }  # 401
```

Authenticated (owner session, `$tok` never printed):
```powershell
$H  = @{ Authorization = "Bearer $tok" }
$T  = 'ten_e759b7288598bd882e3dcac49d'
$HT = @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = $T }

# A · registry reports enforcement ON and still exactly one tenant
$r = (Invoke-RestMethod -Uri "$A/api/xdr/tenants" -Headers $H).data
"enforcing   : $($r.enforcing)"        # expect True
"tenant_count: $($r.count)"            # expect 1

# B · the authoritative tenant resolves ACTIVE
$t = (Invoke-RestMethod -Uri "$A/api/xdr/tenants/$T" -Headers $H).data
"state       : $($t.state)"            # ACTIVE
"org         : $($t.organization_id)"  # org_55f6dc202dbf8995369db989ad
"products    : $($t.products -join ',')"  # XDR,EDR

# C · valid admin + exact tenant SUCCEEDS on tenant-scoped reads
(Invoke-RestMethod -Uri "$A/api/xdr/collectors" -Headers $HT).data.count            # 0, no error
(Invoke-RestMethod -Uri "$A/api/xdr/api-keys"   -Headers $HT).data.count            # 0, no error
(Invoke-RestMethod -Uri "$A/api/xdr/collectors/sources/catalog" -Headers $HT).data.sources.'microsoft-sysmon'   # present

# D · unknown tenant FAILS CLOSED
try { Invoke-RestMethod -Uri "$A/api/xdr/collectors" -Headers @{Authorization="Bearer $tok";'X-Tenant-Id'='ten_does_not_exist'} }
catch { $_.ErrorDetails.Message }      # expect TENANT_NOT_FOUND, HTTP 403

# E · missing tenant on a tenant-scoped operation -> TENANT_REQUIRED  (B7)
try { Invoke-RestMethod -Uri "$A/api/xdr/collectors" -Headers $H }
catch { $_.ErrorDetails.Message }      # expect TENANT_REQUIRED, HTTP 403

# F · B6 · security-state honours the authority, refuses an unregistered tenant
(Invoke-RestMethod -Uri "$A/api/v2/security-state/streaming/status?tenant_id=$T" -Headers $H).tenant_id   # $T
try { Invoke-RestMethod -Uri "$A/api/v2/security-state/streaming/status?tenant_id=default" -Headers $H }
catch { $_.ErrorDetails.Message }      # expect TENANT_NOT_FOUND

# G · B4 · a data-plane write still cannot create tenancy
try { Invoke-RestMethod -Method Post -Uri "$A/api/xdr/collectors" `
        -Headers @{Authorization="Bearer $tok";'X-Tenant-Id'='ten_typo_not_registered'} `
        -ContentType 'application/json' `
        -Body '{"name":"b4-probe","protocol":"rest","authorized_sources":["microsoft-sysmon"]}' }
catch { $_.ErrorDetails.Message }      # expect TENANT_NOT_FOUND
(Invoke-RestMethod -Uri "$A/api/xdr/tenants" -Headers $H).data.count   # still 1

# H · B5 · EDR admin plane consumes the same authority
(Invoke-RestMethod -Uri "$A/api/edr/enrollment/endpoints" -Headers $HT) | Out-Null   # succeeds, no "default"
try { Invoke-RestMethod -Uri "$A/api/edr/enrollment/endpoints" -Headers $H }
catch { $_.ErrorDetails.Message }      # expect TENANT_REQUIRED

# I · B3 · audit actor is the verified principal, not a claimed header
(Invoke-RestMethod -Uri "$A/api/xdr/audit-log?limit=5&tenant=$T" `
   -Headers @{Authorization="Bearer $tok";'X-Tenant-Id'=$T;'X-Principal-Id'='attacker@evil.test'}).data.entries |
  Select-Object action, principal_id, principal_kind
# no row may show principal_id = attacker@evil.test
```

PASS requires: A True/1 · B ACTIVE + correct org + XDR,EDR · C all succeed ·
D TENANT_NOT_FOUND · E TENANT_REQUIRED · F own tenant 200 and `default`
refused · G refused with tenant count still 1 · H scoped succeeds, unscoped
TENANT_REQUIRED · I no spoofed actor.

## 5 · ROLLBACK TO ENFORCEMENT OFF

Secrets → set `NIVX_TENANT_REGISTRY_ENFORCE = false` (or delete the key) →
Save → **Redeploy**. Same zero-downtime rolling update, 2-5 minutes. Behaviour
returns to the observational path already accepted on publish 100; the
organization and tenant remain (they are data, not enforcement) and nothing is
destroyed. Note: a *build* rollback alone would NOT clear the flag, because
secrets are not versioned — the flag must be changed explicitly.

## 6 · AFTER ENFORCEMENT PASSES

W1 Phase 3.1 under `ten_e759b7288598bd882e3dcac49d` (separate approval): one
collector (`protocol=rest`, `authorized_sources=["microsoft-sysmon"]`), one
`collectors.enroll` key with short expiry and **no** `allow_new_tenant`,
DESKTOP-A9HGFJJ configuration with `BatchSize=5`, then exactly 5 genuine
Sysmon events traced by `source_event_id`.
