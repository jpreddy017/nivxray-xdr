# G1 · reviewed-code manifest (content identity, not commit identity)

Emergent's **Save to Github** does not guarantee preservation of local commit
SHAs, so a commit SHA is not a reliable anchor for "the Windows host is
running the reviewed code". These SHA-256 content hashes are.

Local branch `feature/rc2-alignment`, local HEAD
`d8d8154f10f12d22549a02be24fb12bd3871314d` (2026-09-22T04:00:47Z), working
tree clean for every path below.

| SHA-256 | Path |
|---|---|
| `3D43E6235BBBEB631EAC11B96AF10C5AF14B6227C93ABDBCD88F966CAD9C4AF7` | `scripts/windows/g1/Get-NivXRayG1Preflight.ps1` |
| `055A28E5FA8EBDBAA25ABE97E33B2C776E347CEC20DD536D4479942132EF598C` | `scripts/windows/g1/README_G1_STEP1_PREFLIGHT.md` |
| `CA697B61827BC61653C1A698607D0E463C2956AF913E2B7B6159C9356F1F798B` | `apps/nivxray-xdr-collector/framework/windows_eventlog.py` |
| `EE54AB0E2F41E6E74E8163DABE058222DE56DB394A46E14B077B4D8A7C42DE4F` | `apps/nivxray-xdr-collector/framework/windows_bookmarks.py` |
| `B5ED4F5524A89C53D9CBF2BA8E6852C15C09C94AABC2F3EB4C199EBEAA4AB280` | `apps/nivxray-xdr-collector/framework/collector_identity.py` |
| `DD7577B7712066E1F0EC087D6F8BCCFEDBFB60CF4C47190CA14F1C5FD3E6BBDD` | `apps/nivxray-xdr-collector/framework/runtime.py` |
| `2E764F049893CCD7DD94DE485C8E0BE254CE00B64274E008FB3F93610C30F147` | `apps/nivxray-xdr-collector/framework/scheduler.py` |
| `985EF41B94E978925B0716A61C008A8230AD307BB1C4426CE3CDEDE6B8C34250` | `apps/nivxray-xdr-collector/framework/outbox.py` |
| `A4A308FA8A6DDDE2DDB4A4901E8DF9745B1A634CDFE2A2D88257B276B08A8F6B` | `apps/nivxray-xdr-collector/main.py` |
| `7917C53D96BCC9F4117D76FA8F028A0F35B6B2ECD2E375760C8340755F68CB20` | `apps/nivxray-xdr-collector/routes/connectors.py` |

## Verify on the Windows host (read-only)

```powershell
cd C:\nivx
$expected = @{
 'scripts\windows\g1\Get-NivXRayG1Preflight.ps1'                        = '3D43E6235BBBEB631EAC11B96AF10C5AF14B6227C93ABDBCD88F966CAD9C4AF7'
 'apps\nivxray-xdr-collector\framework\windows_eventlog.py'             = 'CA697B61827BC61653C1A698607D0E463C2956AF913E2B7B6159C9356F1F798B'
 'apps\nivxray-xdr-collector\framework\windows_bookmarks.py'            = 'EE54AB0E2F41E6E74E8163DABE058222DE56DB394A46E14B077B4D8A7C42DE4F'
 'apps\nivxray-xdr-collector\framework\collector_identity.py'           = 'B5ED4F5524A89C53D9CBF2BA8E6852C15C09C94AABC2F3EB4C199EBEAA4AB280'
 'apps\nivxray-xdr-collector\framework\runtime.py'                      = 'DD7577B7712066E1F0EC087D6F8BCCFEDBFB60CF4C47190CA14F1C5FD3E6BBDD'
 'apps\nivxray-xdr-collector\framework\scheduler.py'                    = '2E764F049893CCD7DD94DE485C8E0BE254CE00B64274E008FB3F93610C30F147'
 'apps\nivxray-xdr-collector\framework\outbox.py'                       = '985EF41B94E978925B0716A61C008A8230AD307BB1C4426CE3CDEDE6B8C34250'
 'apps\nivxray-xdr-collector\main.py'                                   = 'A4A308FA8A6DDDE2DDB4A4901E8DF9745B1A634CDFE2A2D88257B276B08A8F6B'
 'apps\nivxray-xdr-collector\routes\connectors.py'                      = '7917C53D96BCC9F4117D76FA8F028A0F35B6B2ECD2E375760C8340755F68CB20'
}
$bad = 0
foreach ($k in $expected.Keys) {
  if (-not (Test-Path $k)) { Write-Host "MISSING   $k" -ForegroundColor Red; $bad++; continue }
  $h = (Get-FileHash $k -Algorithm SHA256).Hash
  if ($h -eq $expected[$k]) { Write-Host "OK        $k" -ForegroundColor Green }
  else { Write-Host "MISMATCH  $k`n  expected $($expected[$k])`n  actual   $h" -ForegroundColor Red; $bad++ }
}
if ($bad -gt 0) { Write-Host "`nSTOP: the host is NOT running the reviewed G1 code ($bad file(s))." -ForegroundColor Red }
else { Write-Host "`nReviewed G1 code confirmed byte-for-byte." -ForegroundColor Green }
```

**If anything prints MISMATCH or MISSING, stop before acquisition.** A proof
taken on unreviewed code is not a proof.

Note on line endings: if Git normalises `.py`/`.ps1` to CRLF on checkout the
hashes will differ legitimately. If that happens, run
`git config --global core.autocrlf false`, re-clone, and re-verify — do not
proceed on a mismatch you have not explained.
