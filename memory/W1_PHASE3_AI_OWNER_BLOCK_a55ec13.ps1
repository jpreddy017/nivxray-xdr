# AUTHENTICATED A-I SUBSET - PRODUCTION publish 100 / build a55ec13
# READ-ONLY. GET requests only. Nothing is created, changed or deleted.
# Prereq: $tok from memory/OWNER_JWT_REFRESH_PROCEDURE.md Step 1 (24h lifetime).
# Paste the printed output back to the agent. Never paste $tok.

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$A = 'https://nivxray.nivxforge.com'
$T = 'ten_e759b7288598bd882e3dcac49d'
$O = 'org_55f6dc202dbf8995369db989ad'
if (-not $tok) { 'NO TOKEN - run OWNER_JWT_REFRESH_PROCEDURE Step 1 first.'; return }

function G($label, $uri, $tenant, $extra) {
  $h = @{ Authorization = "Bearer $tok" }
  if ($tenant) { $h['X-Tenant-Id'] = $tenant }
  if ($extra)  { $extra.GetEnumerator() | ForEach-Object { $h[$_.Key] = $_.Value } }
  try {
    $r = Invoke-WebRequest -Method Get -Uri $uri -Headers $h -UseBasicParsing
    "$label : HTTP $($r.StatusCode) :: $((($r.Content) -replace '\s+',' ').Substring(0,[Math]::Min(300,$r.Content.Length)))"
  } catch {
    $c = $null; try { $c = $_.Exception.Response.StatusCode.value__ } catch {}
    $d = $null; try { $d = $_.ErrorDetails.Message } catch {}
    "$label : HTTP $c :: $($d -replace '\s+',' ')"
  }
}

'=== A/B/C REGISTRY AUTHORITY + ENFORCEMENT + COUNTS ==='
G 'A tenants(list)          ' "$A/api/xdr/tenants" $T $null      # expect count=1, enforcing=true
G 'B tenant(detail)         ' "$A/api/xdr/tenants/$T" $T $null   # ACTIVE, org matches, XDR+EDR
G 'B org state              ' "$A/api/xdr/organizations/$O/state" $T $null
G 'C tenant state           ' "$A/api/xdr/tenants/$T/state" $T $null
G 'C collectors             ' "$A/api/xdr/collectors" $T $null   # expect 0
G 'C api keys               ' "$A/api/xdr/collectors/api-keys" $T $null  # expect 0 (404 ok if route differs)
G 'C sources catalog        ' "$A/api/xdr/collectors/sources/catalog" $T $null

'=== F SECURITY-STATE TENANT AUTHORITY ==='
G 'F authoritative          ' "$A/api/v2/security-state/streaming/status?tenant_id=$T" $T $null   # 200
G 'F default (must refuse)  ' "$A/api/v2/security-state/streaming/status?tenant_id=default" $T $null  # TENANT_NOT_FOUND

'=== H GATE H - EDR EXPLICIT TENANT ==='
G 'H endpoints scoped       ' "$A/api/edr/endpoints" $T $null               # 200
G 'H endpoints UNSCOPED     ' "$A/api/edr/endpoints" $null $null            # 403 TENANT_REQUIRED
G 'H enrollment scoped      ' "$A/api/edr/enrollment/endpoints" $T $null    # 200, 0 endpoints
G 'H enrollment UNSCOPED    ' "$A/api/edr/enrollment/endpoints" $null $null # 403 TENANT_REQUIRED
G 'H isolation scoped       ' "$A/api/edr/response/isolation-policy" $T $null
G 'H isolation UNSCOPED     ' "$A/api/edr/response/isolation-policy" $null $null
G 'H unknown tenant         ' "$A/api/edr/endpoints" 'ten_doesnotexist000000000000' $null  # TENANT_NOT_FOUND

'=== I PRINCIPAL SPOOF MUST NOT ATTRIBUTE ==='
G 'I spoofed principal read ' "$A/api/edr/endpoints" $T @{ 'X-Principal-Id' = 'attacker@evil.test' }
G 'I audit rows             ' "$A/api/edr/response/audit?limit=5" $T $null  # expect 0 rows attributed to attacker@evil.test

'=== CONSOLE EXPLICIT-TENANT CONTRACT ==='
G 'edr context explicit     ' "$A/api/edr/context?tenant=$T" $T $null
# expect all_tenants=false, tenant_ids=[ten_e759...], basis=EXPLICIT_REQUEST_TENANT

'DONE - read-only. No object created. W1 still held.'
