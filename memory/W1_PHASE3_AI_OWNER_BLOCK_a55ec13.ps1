# AUTHENTICATED A-I SUBSET - PRODUCTION publish 100 / build a55ec13
# READ-ONLY. Every request below is a GET. Nothing is created, changed or deleted.
# Every URI was verified to exist with a GET method in the LIVE production OpenAPI.
# Prereq: $tok from memory/OWNER_JWT_REFRESH_PROCEDURE.md Step 1 (24h lifetime).
# Paste the printed output back to the agent. NEVER paste $tok.

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$A = 'https://nivxray.nivxforge.com'
$T = 'ten_e759b7288598bd882e3dcac49d'
$X = 'ten_doesnotexist000000000000'
if (-not $tok) { 'NO TOKEN - run OWNER_JWT_REFRESH_PROCEDURE Step 1 first.'; return }

function G($label, $uri, $tenant, $extra) {
  $h = @{ Authorization = "Bearer $tok" }
  if ($tenant) { $h['X-Tenant-Id'] = $tenant }
  if ($extra)  { $extra.GetEnumerator() | ForEach-Object { $h[$_.Key] = $_.Value } }
  try {
    $r = Invoke-WebRequest -Method Get -Uri $uri -Headers $h -UseBasicParsing
    $c = ($r.Content -replace '\s+',' ')
    "$label : HTTP $($r.StatusCode) :: $($c.Substring(0,[Math]::Min(320,$c.Length)))"
  } catch {
    $sc = $null; try { $sc = $_.Exception.Response.StatusCode.value__ } catch {}
    $d  = $null; try { $d  = $_.ErrorDetails.Message } catch {}
    "$label : HTTP $sc :: $($d -replace '\s+',' ')"
  }
}

"BUILD UNDER TEST : publish 100 / a55ec13"
'=== SESSION ==='
G 'me                       ' "$A/api/auth/me" $null $null

'=== A · REGISTRY AUTHORITY + ENFORCEMENT ==='
# expect: count = 1 and enforcing = true
G 'A tenants list           ' "$A/api/xdr/tenants" $T $null
# expect: exactly one org, the authoritative one
G 'A organizations list     ' "$A/api/xdr/organizations" $T $null

'=== B · TENANT IS ACTIVE UNDER THE AUTHORITATIVE ORG ==='
# expect: state ACTIVE, organization_id = org_55f6dc202dbf8995369db989ad, products XDR + EDR
G 'B tenant detail          ' "$A/api/xdr/tenants/$T" $T $null
# expect: TENANT_NOT_FOUND (no default resurrection in the registry)
G 'B default tenant detail  ' "$A/api/xdr/tenants/default" $T $null

'=== C · EXPLICIT-SCOPE READS · COUNTS MUST BE 0 ==='
G 'C collectors             ' "$A/api/xdr/collectors" $T $null              # expect 0
G 'C api keys               ' "$A/api/xdr/api-keys" $T $null                # expect 0
G 'C sources catalog        ' "$A/api/xdr/collectors/sources/catalog" $T $null
G 'C enrollment tokens      ' "$A/api/edr/enrollment/tokens" $T $null       # expect 0
G 'C enrolled endpoints     ' "$A/api/edr/enrollment/endpoints" $T $null    # expect 0

'=== F · SECURITY-STATE TENANT AUTHORITY ==='
G 'F authoritative          ' "$A/api/v2/security-state/streaming/status?tenant_id=$T" $T $null   # expect 200
G 'F default MUST refuse    ' "$A/api/v2/security-state/streaming/status?tenant_id=default" $T $null # expect TENANT_NOT_FOUND

'=== H · GATE H · EDR EXPLICIT TENANT ==='
G 'H endpoints scoped       ' "$A/api/edr/endpoints" $T $null               # expect 200
G 'H endpoints UNSCOPED     ' "$A/api/edr/endpoints" $null $null            # expect 403 TENANT_REQUIRED
G 'H endpoints unknown      ' "$A/api/edr/endpoints" $X $null               # expect 403 TENANT_NOT_FOUND
G 'H endpoints default      ' "$A/api/edr/endpoints" 'default' $null        # expect 403 TENANT_NOT_FOUND
G 'H enrollment UNSCOPED    ' "$A/api/edr/enrollment/endpoints" $null $null # expect 403 TENANT_REQUIRED
G 'H isolation scoped       ' "$A/api/edr/response/isolation-policy" $T $null
G 'H isolation UNSCOPED     ' "$A/api/edr/response/isolation-policy" $null $null # expect 403 TENANT_REQUIRED

'=== I · PRINCIPAL SPOOF MUST NOT ATTRIBUTE ==='
G 'I spoofed principal read ' "$A/api/edr/endpoints" $T @{ 'X-Principal-Id' = 'attacker@evil.test'; 'X-Principal-Email' = 'attacker@evil.test' }
# expect: no row attributed to attacker@evil.test (this tenant has 0 actions anyway)
G 'I response actions       ' "$A/api/edr/response/actions" $T $null

'=== CONSOLE EXPLICIT-TENANT CONTRACT ==='
# expect: all_tenants=false, tenant_ids=[ten_e759...], explicit_tenant matching,
#         basis = EXPLICIT_REQUEST_TENANT
G 'edr context explicit     ' "$A/api/edr/context?tenant=$T" $T $null

'DONE - read-only. No object created. Collector Auth P0 still open. W1 still held.'
