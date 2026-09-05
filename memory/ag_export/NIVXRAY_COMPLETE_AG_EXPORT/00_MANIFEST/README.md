# NivXRay Complete Export — Master Manifest & Verification Guide

**Directory Path**: `00_MANIFEST/`  
**Generated**: 2026-09-05 11:14:23  

---

## Files in this Directory:

1. [`NIVXRAY_COMPLETE_AG_EXPORT_MANIFEST.json`](./NIVXRAY_COMPLETE_AG_EXPORT_MANIFEST.json) — Master JSON database cataloging all 4,675 source files, sizes, SHA-256 hashes, lines of code, categories, classifications, and status.
2. [`NIVXRAY_COMPLETE_AG_EXPORT_REPORT.md`](./NIVXRAY_COMPLETE_AG_EXPORT_REPORT.md) — Comprehensive technical report and retrospective detailing metrics, components, audits, and exclusions.
3. [`SHA256SUMS.txt`](./SHA256SUMS.txt) — Standard GNU coreutils sha256sum verification file.

## Verifying Integrity:

On Linux / macOS:
```bash
sha256sum -c 00_MANIFEST/SHA256SUMS.txt
```

On Windows PowerShell:
```powershell
Get-Content 00_MANIFEST\SHA256SUMS.txt | ForEach-Object {
    $hash, $file = $_ -split '\s+', 2
    if ((Get-FileHash -Algorithm SHA256 $file).Hash.ToLower() -eq $hash.ToLower()) {
        Write-Host "OK: $file" -ForegroundColor Green
    } else {
        Write-Host "FAILED: $file" -ForegroundColor Red
    }
}
```
