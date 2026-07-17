# NivXRay · CHANGELOG

## v1.1.0 — 2026-07-17 · Case4/5 Archetypes + Critical Bug Fixes

**GitHub Release:** https://github.com/jana017/NivXRAY_NivXForge/releases/tag/v1.1.0
**Deployed to:** https://nivxray.nivxforge.com

### 🐛 Bug fixes (5)
- **Command Analyzer blank page** — `useEffect` was missing from the react import in `CommandAnalyzerPage.jsx`, causing `/analyze` to render a blank black screen on prod. One-line fix.
- **SAVE CASE `[object Object]`** — `verdict` field now accepts both string and dict (Pydantic `Optional[Any]`). Frontend catch handler stringifies Pydantic 422 error arrays properly.
- **History "X ago" 5-hour skew** — `relTime()` appends `Z` to timestamps missing tz suffix, forcing UTC parse. Fixes IST users seeing "5h ago" for just-saved cases.
- **Cloudflare masking on SYNC** — `/api/admin/training-notes/sync-url` returns `200 OK` with `{ok:false, error, hint}` envelope. Real errors (LLM budget, bot-block, etc.) reach the browser instead of Cloudflare's generic HTML.
- **Cloudflare bot-block bypass on SYNC** — Browser-like User-Agent + Accept-* + Sec-Fetch-* headers so Cloudflare-fronted CTI sites (Red Canary, Group-IB) serve the real article body.

### 🎯 New detection archetypes (from real-world Case4 + Case5)
- **`SyncAppvPublishingServer.vbs`** LOLBAS entry → MITRE **T1216** (Microsoft-signed AppV VBS script proxy execution).
- **`wscript.exe` / `cscript.exe`** LOLBAS entries → MITRE T1059.005.
- **Trusted CDN / object-storage abuse** heuristic → **T1105** + **T1102** (Trusted-Domain C2 Fronting) for jsdelivr, raw.githubusercontent, contabostorage, aliyun OSS, cdn.discordapp, statically.io, b-cdn.net, pages.dev, workers.dev.
- **WinHTTP COM stager** (`New-Object -ComObject WinHttp.WinHttpRequest.5.1`) → T1059.001 + T1105.
- **Bohannon wildcard cmdlet obfuscation** (`(gcm *stM*)`, `(gal i*x)`) → T1027 + T1059.001.

### 🧪 Real-world testing infrastructure
- New **40-payload real-world battery** (`tests/real_world_battery.py` + `test_real_world_battery.py`):
  Emotet caret, QakBot reverse-string, Cobalt Strike -enc, Meterpreter b64+XOR,
  certutil, MSHTA, BITSAdmin, Squiblydoo, Empire gzip, VBS Chr, Node zlib,
  Bash /dev/tcp, wmic, PSExec, wiper family, cmstp UAC bypass, and more.
- **121/121** battery tests green on live preview backend.
- **145/145** full suite green (battery + Golden Vault + CJK + Defense Evasion + Sigma).

### 🎯 New MITRE heuristics
- VBS `Chr()&Chr()` concat → T1059.005 + T1027
- Node.js `Buffer.from + zlib.gunzip` → T1059.007 + T1027 + T1140
- HTML-entity encoded PowerShell (`&#N;` chains) → T1027 + T1140
- Perl `-MMIME::Base64 -e eval(decode_base64(...))` → T1059.006 + T1027.010
- `bcdedit recoveryenabled No` → T1490
- `$encryptionKey = FromBase64String(...)` PS TaskScheduler-Crypto-Loader → T1053.005 + T1027

### 🛡️ Deobfuscator quality
- ROT-N / Atbash false-positive guard on filesystem-path-heavy inputs (was mis-mapping `C:\temp\*.exe` to `R:\itbe\*.tmt`).

### ✅ Cases handled in this sprint
- **Case2** — multi-stage PowerShell -enc with `$encryptionKey` loader
- **Case4** — SyncAppvPublishingServer.vbs proxy with `(gcm *stM*)` wildcard obfuscation + jsdelivr CDN abuse + WinHTTP COM stager
- **Case5** — 7-stage PowerShell downloader from Contabo object storage

All 3 cases now surface **5/5 target MITRE techniques**.

---

## v1.0.0 — 2026-02-16 · NivXRay Docs Refresh
See `/app/RELEASE_NOTES_2026-02-16.md`
