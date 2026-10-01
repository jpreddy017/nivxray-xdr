# OWNER JWT REFRESH — PRODUCTION AUTH PROCEDURE (owner-executed, read-only)

Derived from the deployed authentication implementation. No user created, no
credential reset, no RBAC change, no configuration change, no production data
touched. The agent does not execute any of this and never sees the token.

## Deployed auth contract (from the running build)

`backend/routers/auth.py` · confirmed present in the production OpenAPI as
`POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/change-password`.

- `POST /api/auth/login` · body `LoginIn` = `{"email": "...", "password": "..."}`
  (`schemas.LoginIn`; `email` is validated as an email address).
- Response `TokenOut` = `{"access_token": "<JWT>", "token_type": "bearer",
  "email": "..."}`.
- The JWT is `HS256` over `{"sub": <email>, "iat", "exp"}`
  (`deps.create_token:273`). **Lifetime = `JWT_EXPIRE_HOURS`, default 24 h**
  (`deps.py:72`, shortened from 7 days by audit SEC-002). Expiry produces
  exactly the `401 {"detail":"Invalid or expired token"}` you saw.
- Presented as `Authorization: Bearer <access_token>`.
- There is **no refresh-token endpoint**. Re-authentication via
  `POST /api/auth/login` is the only supported path.

### Failure modes to expect
| status | meaning | action |
|---|---|---|
| 401 `Invalid credentials` | wrong email or password | retry carefully — see rate limit |
| 429 `rate_limited` + `Retry-After` | `LOGIN_LIMITER` tripped | wait; do not retry in a loop |
| 428 `password_change_required` | the account has `must_change_password` | **STOP and report** — do not rotate the password as part of a read-only acceptance run |
| 200 | token issued | proceed |

**Rate limit (`security/rate_limit.py:71-73`)** — keyed by
`(lowercased email, client IP)`: **5 failures** inside a **300 s** window ⇒
**900 s lockout**. A successful login clears the counter. So a handful of typos
can lock the owner account out of login for 15 minutes. Type the password into
the secure prompt carefully; do not script retries.

## Step 0 · clear the placeholder

```powershell
Remove-Variable tok -ErrorAction SilentlyContinue
```

## Step 1 · authenticate and capture the token (nothing printed)

Interactive prompts. The password is entered into a `SecureString`, converted
to plaintext only in process memory for the single HTTPS request, then zeroed.
The JWT is assigned to `$tok` and never written to the console.

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$A     = 'https://nivxray.nivxforge.com'
$email = Read-Host 'Owner email'
$sec   = Read-Host 'Owner password' -AsSecureString

$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $body  = @{ email = $email; password = $plain } | ConvertTo-Json -Compress
    try {
        $login = Invoke-RestMethod -Method Post -Uri "$A/api/auth/login" `
                    -ContentType 'application/json' -Body $body
        $tok = $login.access_token
        "LOGIN        : HTTP 200"
        "ACCOUNT      : $($login.email)"
        "TOKEN_TYPE   : $($login.token_type)"
        "TOKEN_LENGTH : $($tok.Length)   (value not displayed)"
    } catch {
        $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        $det  = $null; try { $det  = $_.ErrorDetails.Message } catch {}
        "LOGIN FAILED : HTTP $code :: $($det -replace '\s+',' ')"
        if ($code -eq 429) { "RATE LIMITED - wait for Retry-After before retrying." }
        if ($code -eq 428) { "PASSWORD CHANGE REQUIRED - STOP and report. Do not rotate here." }
    }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Variable plain, body, sec, bstr -ErrorAction SilentlyContinue
}
```

`TOKEN_LENGTH` is printed instead of the token so you can confirm a value was
assigned without exposing it. A plain 401 here means the credential is wrong —
**not** that the account or endpoint is broken.

## Step 2 · verify the session (non-secret identity only)

`GET /api/auth/me` returns the full user document minus `password`
(`routers/auth.py:64`). The block below selects only the fields needed to
confirm the session and its authority, and deliberately does not dump the whole
object.

```powershell
if (-not $tok) { Write-Host 'No token in session - Step 1 did not succeed.'; return }

try {
    $me = Invoke-RestMethod -Method Get -Uri "$A/api/auth/me" `
             -Headers @{ Authorization = "Bearer $tok" }
    "AUTH         : HTTP 200"
    "EMAIL        : $($me.email)"
    "ROLE         : $($me.role)"
    "TENANT_ID    : $($me.tenant_id)"
    "TENANT_IDS   : $(@($me.tenant_ids) -join ',')"
    "PW_CHANGE_REQ: $([bool]$me.must_change_password)"
} catch {
    $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
    $det  = $null; try { $det  = $_.ErrorDetails.Message } catch {}
    "AUTH FAILED  : HTTP $code :: $($det -replace '\s+',' ')"
}
```

Expected: `HTTP 200`, the owner email, and a **cross-tenant role** — that is
what made gates A–C and G succeed earlier. `PW_CHANGE_REQ: False` is required;
`True` cannot reach this route at all (it returns 428).

Note on `TENANT_ID` / `TENANT_IDS`: if both are empty, that is the §4a /
R5 finding showing itself — `resolve_tenant_scope` would fall back to the
literal `"default"` for a non-cross-tenant user. For a cross-tenant role the
fallback is not reached. Either way, **record the values; change nothing.**

## Step 3 · then Gate F

With `$tok` refreshed, run the corrected Gate F probe from
`/app/memory/W1_PHASE3_EDR_TENANT_CONVERGENCE_PLAN.md` §5
(`/api/v2/security-state/streaming/status?tenant_id=...`). The agent does not
execute it.

## Hygiene

The token lives only in the PowerShell session variable and expires in 24 h.
To drop it early: `Remove-Variable tok -ErrorAction SilentlyContinue`.
Do not persist it to a file, an environment variable, or chat.

Status: procedure supplied. Nothing executed. No implementation, no republish.
Gates F and I still pending. W1 Phase 3 remains paused.
