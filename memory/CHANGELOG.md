# NivXRay · CHANGELOG

## v1.3.0-preview (batch 2) — 2026-07-18 · Heatmap + Corpus Validator + macOS Decoder + Analyst Gap Fixes

**Status:** Preview batch · staged for next prod release

### 🗺️ NEW: MITRE ATT&CK Detection Heatmap (`/heatmap`)
- Visual coverage matrix — 231 heuristics · 102 unique techniques · 13 tactics in kill-chain order
- Top-covered techniques strip, sparse-coverage warning (candidates for new signatures)
- **Payload probe** — paste any command, cells light up in real-time
- Filter box for T-ID / technique name

**New endpoints:**
- `GET  /api/mitre/heatmap`
- `GET  /api/mitre/heatmap/tactic/{name}`
- `POST /api/mitre/heatmap/probe`

### 🧪 NEW: Corpus Validator (`POST /api/corpus/validate`)
- Accepts CSV / JSON / JSONL / XLSX
- Returns per-row **gap report**: expected MITRE vs got MITRE, missing/extras, coverage %
- Prefix-match logic (T1059 covers T1059.001)
- `by_status` summary: pass / gap / no_expectations / empty_mitre_no_expectations
- Downloadable starter template at `GET /api/corpus/validate/example`

### 🍎 NEW: macOS `osascript` decoder archetype
- Handles AppleScript `do shell script "…"` variants
- Handles JXA (`osascript -l JavaScript -e …`)
- Extracts embedded `echo <b64> | base64 -d | sh` chains → recovers plaintext
- Emits T1059.002 · T1140 · T1204.002 · T1105 · T1543.001

### 🎯 Fragment-mode heuristic improvements (from analyst "Now" batch feedback)
- Extended `cmd /c` fragment allow-list: now includes `rundll32|tasklist|comsvcs|wmic|net use|schtasks|vssadmin|for /f`
- Extended `.dll,Export` pattern: accepts ordinal-form exports (e.g., `comsvcs.dll, #+000024` → T1218.011)
- **New**: `comsvcs.dll ordinal MiniDump` → T1003.001 (LSASS credential dumping)

### 🐛 Verdict noise fix (v1.2.0 → v1.3.0-preview)
- Tiny (<20 char) no-signal payloads (`[`, `],`, `"-Embedding",`) no longer flagged **Suspicious**
- Downgrade rule: `len<20 AND no MITRE AND no LOLBAS AND no IOCs AND no shellcode → Unknown`
- Fixes false-flag Suspicious verdicts on JSON parser debris in analyst pastes

### 🧪 Tests
- `tests/test_v1_3_endpoints.py` — 14 new tests (heatmap / corpus / osascript)
- `tests/test_fragment_mitre_mapping.py` — 18 fragment tests (up from 16), all green
- Full v1.3.0 test set: **49/49 pass**

### 📊 Analyst validation
- Re-ran user "Now" batch (11 rows, LSASS-dump tradecraft) — all 5 target fixes landed:
  - `[`, `],`, `"-Embedding",` → downgraded to Unknown ✅
  - `/Q /c for /f ... rundll32` → now 5 MITRE (was 4, added T1059.003) ✅
  - `comsvcs.dll, #+000024 ...` → now 2 MITRE (was 1, added T1218.011) ✅

---

## v1.3.0-preview (batch 1) — 2026-07-18 · Fragment MITRE + Batch Recent Runs UI

**Status:** Preview batch · staged for EOD prod release

### 🎨 UI additions
- **Recent Runs panel** in Batch tab (`BatchTestPage.jsx`) — was hidden despite backend `/api/batch/history` existing. Now visible via `HISTORY` toggle button. Shows When / Name / Mode / Total / Mal / Susp / Unk / Err + LOAD / rename / delete actions. Currently loads 30 most-recent runs.
- New `.nvx-btn.xs` size class for compact action buttons inside tables.

### 🎯 Fragment-mode MITRE mapping (Issue 2 · P0)
Argument-only command fragments (no LOLBin host present) now surface MITRE tags. Fixes the 9/11 empty-MITRE fragments from the analyst-uploaded Excel corpus.

New heuristics in `operations.py`:
- Bare `-EncodedCommand <b64>` → **T1059.001** + **T1027.010** (long payload)
- Bare `-Command "IEX(...)"` → **T1059.001**
- Bare `/c` or `/k` chain → **T1059.003**
- Bare `-urlcache -f https://…` → **T1105**
- Bare `-decode staged.b64 payload.exe` → **T1140**
- Bare `/transfer <job> <url> <path>` → **T1197**
- Bare `<path>.dll,Export` → **T1218.011**
- Bare `add HKCU\…\Run` → **T1547.001**
- Bare `/create /tn <name> /tr <cmd>` → **T1053.005**
- Bare `process call create <lolbin>` → **T1047**
- Bare `delete shadows /all /quiet` → **T1490**
- Bare `-NoP -W Hidden -EP Bypass` → **T1059.001**
- Standalone base64 blob ≥200 chars → **T1027**
- Bare `javascript:/vbscript:` URI → **T1218.005**

### 🧪 Test coverage
- `tests/test_fragment_mitre_mapping.py` — 16 new tests (all green)
- Fixed pre-existing `test_archetype_bash_b64_gunzip` (chained archetype now correctly asserted via `chain_ids[0]`)

### ✅ Regression status
- Fragment tests: **16/16 pass**
- Wrapper archetypes: **17/17 pass**
- Full suite: **352 passed** (9 pre-existing `test_training_corpus` failures unchanged, non-blocking)

---

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
- **New `tests/test_v1_2_0_batch.py`** — 44 tests covering all P0 fixes + P1 signatures + macOS tradecraft + Cloud/Identity abuse + Plaintext-guard + composite screenshot-#1 payload smoke test. All 44 pass.
- **Full sweep**: 218/218 pass across v1.2.0 + Golden Vault + Real-World Battery + Chain + TI + IOC + Sigma. Zero regressions.

### 🍎 macOS Archetype Family (NEW)
- **AppleScript / osascript** — `T1059.002` execution + `T1056.002` fake-credential-prompt dialog (Amos/MacStealer tradecraft).
- **LaunchAgent / LaunchDaemon persistence** — `T1543.001` via `~/Library/LaunchAgents/*.plist` + `launchctl load`.
- **Keychain dump** — `security find-generic-password / dump-keychain / unlock-keychain` → `T1555.001`.
- **Gatekeeper bypass** — `xattr -d com.apple.quarantine` + `spctl --master-disable` → `T1553.001`.
- **Sudo piped password** — `echo "pwd" | sudo -S` → `T1548.003`.
- **TCC reset** — `tccutil reset SystemPolicyAllFiles` → `T1562`.
- **Browser profile access** — Chrome/Brave/Edge/Safari/Firefox macOS paths → `T1555.003`.
- **dscl account discovery** — `dscl . -read/-list /Users/` → `T1087.001`.
- **defaults autostart** — `defaults write LSUIElement/ApplePersistenceIgnoreState` → `T1547.015`.

### ☁ Cloud & Identity Abuse (NEW)
- **OAuth device-code phishing** — `microsoft.com/devicelogin?otc=…` → `T1566.002` + `T1621` MFA fatigue.
- **Illicit-consent grant** — over-scoped Mail/Files/Directory/Chat permissions → `T1550.001` + `T1528`.
- **Microsoft Teams webhook C2** — `*.webhook.office.com/webhookb2/…` → `T1102` GIFshell-class.
- **Microsoft Graph API exfil** — `graph.microsoft.com/v1.0/me/messages|drive|chats` → `T1567`.
- **AAD/Entra PRT abuse** — `x-ms-refreshtokencredential`, `aadinternals`, `aadconnect` → `T1550.001`.
- **AWS credential leaks** — `AKIA[0-9A-Z]{16}` + secret-key patterns → `T1552.001`.
- **Cloud CLI cred manipulation** — `gcloud iam service-accounts keys create`, `az ad sp credential reset`, `kubectl create token` → `T1098.001`.

### 🛡 AI Decode Plaintext Guard (NEW)
- **Bug fixed:** For plaintext commandlines (like `cmd /c copy c:\windows\system32\curl.exe X.exe`), AI DECODE was echoing input to output because no encoding to strip. Analysts read this as "AI reversed my input".
- **Fix:** `_is_already_plaintext()` detector at top of `/ai/auto-decode`. When input is ≥95% printable ASCII with real command/keyword markers AND no base64/hex/gzip/url-encoding markers, endpoint returns `stopped_gracefully=True` with a clear guidance message: "Input already appears to be plaintext — no decoding needed. Use ANALYZE + OSINT for MITRE + IOC + verdict."
- Verified against 4 real plaintext cases pulled from live Preview history + 4 encoded-payload rejections.

### 📁 Files touched
- `backend/operations.py` — 22 new MITRE heuristics (macOS + Cloud) + 15 new YARA-lite rules.
- `backend/wrapper_archetypes.py` — hexfamily defensive; BLIND_XOR_SINGLE_BYTE archetype added.
- `backend/chain_analyzer.py` — TI enrichment on aggregate.
- `backend/sigma_generator.py` — `emit_sysmon()` function.
- `backend/routers/sigma.py` — `/api/emit/sysmon` endpoint.
- `backend/routers/ai.py` — `_is_already_plaintext()` + plaintext short-circuit in `/ai/auto-decode`.
- `frontend/src/pages/WorkspacePage.jsx` — coloured STATUS bar.
- `frontend/src/components/ThreatAnalysis.jsx` — TRADECRAFT callout + smart TI-HITS empty state.
- `backend/tests/test_v1_2_0_batch.py` — new 44-test regression suite.

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
