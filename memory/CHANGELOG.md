# NivXRay · CHANGELOG

## v1.2.0 — 2026-07-18 · Preview batch · Tradecraft-signature release

**Status:** Batched on Preview · staged for prod release after 7-day soak
**Preview URL:** https://greeting-app-5782.preview.emergentagent.com

### 🐛 P0 Bug fixes (5)
- **IOC URL extractor stops on shell metacharacters** — URLs now cleanly stop at `|`, `&`, `;`, `` ` `` and trailing `.),]}`. Fixes the ClickFix regression where `https://tommy-aa.lol/f|for` was extracted as a single broken URL, defeating downstream TI lookups. (`operations.py::extract_iocs`)
- **`/api/decode/chain` now enriches with local Threat Intel** — Multi-line pastes (Case4/5) previously showed 0 TI-HITS because `lookup_ti_hits(...)` was only called in the single-decode path. Chain aggregate now exposes `ti_hits` field. (`chain_analyzer.py::analyze_chain`)
- **`hexfamily-detect` no longer raises on unrecoverable payloads** — Previously threw `ValueError` on 4-layer nested cases; now returns text unchanged so the archetype dispatcher's `out != current` gate skips it cleanly. (`wrapper_archetypes.py::_handle_hexfamily`)
- **`SyncAppvPublishingServer.vbs` test coverage** added to `test_v1_2_0_batch.py`.

### 🎯 New Tradecraft Signatures (from real-world screenshots + Wikipedia XOR intel)
- **`LOLBAS_Curl_Rename`** + **`LOLBAS_Signed_Bin_Rename`** (YARA) + **T1036.003** (MITRE) — detects `copy c:\windows\system32\curl.exe TNheBOJElq.exe` and analogous rename tradecraft for certutil, bitsadmin, powershell, wmic, regsvr32, rundll32, mshta, msiexec, hh, cmstp, installutil, xwizard, wscript, cscript, forfiles, syncappvpublishingserver.
- **`Msiexec_Remote_Silent_Install`** (YARA) + **T1218.007** — `msiexec /i <URL_or_MSI> /qn` silent installs from remote URL / Temp / bare filename.
- **`OneNote_Phishing_Chain`** + **`OneNote_Extracted_Payload_Path`** (YARA) + **T1566.001** / **T1204.002** — detects ONENOTE.EXE spawning mshta/wscript/cscript/cmd/hh/curl/rundll32/powershell child procs, and the canonical `\OneNote\16.0\Exported\{GUID}\NT\N\<file>.hta` extraction path.
- **`Temp_Directory_Staging`** (YARA) + **T1074.001** — `cmd /c cd /d %TEMP%` / `%LOCALAPPDATA%\Temp` / `%APPDATA%` staging-directory pivot.
- **`Suspicious_TLD_Domain`** (YARA) + **T1583.001** — flags `.lol`, `.top`, `.click`, `.zip`, `.mov`, `.xyz`, `.monster`, `.rest`, `.sbs`, `.cfd`, `.life`, `.quest` heavily abused by ClickFix / phishing operators.
- **`Free_Hosting_Delivery`** (YARA) + **T1567.002** / **T1105** — `transfer.sh`, `anonfiles.com`, `filebin.net`, `gofile.io`, `catbox.moe`, `file.io`, `tempfiles.ninja`, `sendgb.com`, `dropmefiles.com`.
- **`Wildcard_Path_Resolution`** (YARA) + **T1027** — Bohannon-style `c*d.e?e` → `cmd.exe`, `c*u*r*l.e?e` → `curl.exe`, `p*ell.exe` → `powershell.exe`.
- **`XOR_Cipher_Indicator`** (YARA) + **T1027.013** — visible `-bxor 0x<key>` / `-bxor '<key-string>'` markers.

### 🧬 New Wrapper Archetype
- **`BLIND_XOR_SINGLE_BYTE`** — brute-force all 256 XOR keys on hex/base64 ciphertext, scores each candidate by printable-ratio + magic-byte hits (MZ, PK, %PDF, ELF, PNG, GIF, JPEG) + English keyword bonus + space/lowercase distribution. Fires only when a key beats baseline by ≥0.20 with score ≥0.90. `terminal: True` so the recursive wrapper doesn't re-enter.

### 📤 New Detection Emitter
- **`POST /api/emit/sysmon`** — deterministic Sysmon Event 1 (ProcessCreate) rule emitter. Returns: (a) `<Rule>` XML fragment for `<ProcessCreate onmatch="include">`; (b) Event Viewer XPath query; (c) PowerShell `Get-WinEvent` hunt one-liner. Complements the existing Sigma emitter.

### 🎨 UI polish
- **Colour-coded STATUS bar** — INFO (accent teal), OK (green), RUNNING (amber), WARN (yellow), ERROR (red) with matching label + dot.
- **`TRADECRAFT DETECTED` callout** — named-tradecraft chips (LOLBAS RENAME, MSIEXEC /qn, ONENOTE PHISHING, STAGING, SUSPICIOUS TLD, FREE HOSTING, WILDCARD BINARY, XOR CIPHER) surface at the TOP of the ThreatAnalysis panel so analysts don't have to hunt in the RULES tab.
- **Smarter TI-HITS empty state** — instead of misleading "No matches", shows contextual message when: T1102/T1105 legit-CDN abuse detected → explains why NO hit is expected + how to detect; T1583.001 suspicious TLD → prompts VT / urlscan submission; IOCs present but no feed hit → prompts feed sync.

### 🧪 Testing
- **New `tests/test_v1_2_0_batch.py`** — 24 tests covering all P0 fixes + P1 signatures + composite screenshot-#1 payload smoke test. All 24 pass.
- **Full sweep**: 209/210 test pass on Preview (1 pre-existing failure in `test_archetype_bash_b64_gunzip`, unrelated to v1.2.0).

### 📁 Files touched
- `backend/operations.py` — IOC URL regex hardened; 12 new MITRE heuristics + 10 new YARA-lite rules.
- `backend/wrapper_archetypes.py` — hexfamily defensive; BLIND_XOR_SINGLE_BYTE archetype added.
- `backend/chain_analyzer.py` — TI enrichment on aggregate.
- `backend/sigma_generator.py` — `emit_sysmon()` function.
- `backend/routers/sigma.py` — `/api/emit/sysmon` endpoint.
- `frontend/src/pages/WorkspacePage.jsx` — coloured STATUS bar.
- `frontend/src/components/ThreatAnalysis.jsx` — TRADECRAFT callout + smart TI-HITS empty state.
- `backend/tests/test_v1_2_0_batch.py` — new regression suite.

---

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
