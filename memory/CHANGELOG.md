# NivXRay Changelog

Chronological record of significant releases (newest first).


---

## RC3.1.1 — Production Hotfix Batch · 2026-02-21

**Status:** ✅ Ready to redeploy · CI gate green (203/203 pytest)
**Tag recommended:** `v1.0.0-RC3.1.1`
**Trigger:** Field-test findings from PROD (case saved as "Do not download this directly on your machine" + Screen1/Screen2)

### 🐛 5 production bugs fixed

- **PROD-BUG-1 (P0) · Verdict / confidence tri-state unified.**
  Frontend `ThreatAnalysis.jsx` now prefers `analysis.verdict_card` (canonical source of truth) over the legacy `analysis.risk` object. Backend `ops.py:decode_smart` resolves the Investigation Summary confidence from `verdict_card.risk_score` (never from the deterministic engine's decode-score, which returns 0 for plain base64→PE decodes). All three UI surfaces — Threat Analysis rail, Analysis Verdict card, embedded Investigation Summary — now render the same verdict + confidence.
- **PROD-BUG-4 (P0) · OUTPUT panel falls back to trace preview when input==output.**
  `WorkspacePage.jsx:setOutput()` now checks whether the raw backend output byte-matches the input; if so and a terminal-layer preview is available, that preview is displayed instead. Fixes the canonical `base64 → PE` case where the OUTPUT panel was showing the base64 input string.
- **PROD-BUG-6 (P1) · PE-executable-payload tradecraft surfaces.**
  New `_post_decode_pe_check()` in the orchestrator: hooks into the primary decode loop to capture PE fingerprints (MZ + PE\\0\\0) at every successful layer BEFORE downstream transforms mangle them. Also scans the raw input as base64. Surfaces `pe-executable-payload (high)` tradecraft + T1204.002 + T1105 MITRE hints. Verified: base64-wrapped PE → `verdict=malicious · risk=100 · tradecraft=[pe-executable-payload(high)] · MITRE T1027,T1055.012,T1105,T1204.002`.
- **PROD-BUG-2 (P1) · LOLBAS false-positives on garbled binary tail eliminated.**
  `_post_decode_lolbas_scan()` now gates behind a printable-ratio floor of 0.60 on the scanned surface. Binary-only tails (raw PE bodies, shellcode residue) no longer match `Control.exe` / `Remote.exe` etc. Clean plaintext inputs are still scanned even when the decoded tail is binary.
- **PROD-BUG-3 (P1) · Investigation continues on corrupt terminal.**
  Same PE-check surface now also runs on ALL intermediate layer outputs via `ctx._pe_hits[]` — if the terminal layer is a garbled xor-brute mangle but an earlier layer produced a valid PE, the tradecraft flag + MITRE still surface. Same principle applied to LOLBAS gate.

### 🧪 Regression coverage — `tests/test_rc311_prod_hotfix.py`

- 6 new regression tests (203/203 gate)
- Every bug locked via either direct behavioural assertion (BUG-6, BUG-2) or source-diff regression lock (BUG-1, BUG-4) so a refactor cannot silently reintroduce the issue.

### 📊 CI-gate deltas (RC3.4 → RC3.1.1)

| Metric                     | RC3.4 | RC3.1.1 |
|----------------------------|-------|---------|
| Pytest passing (gate)      | 197   | **203** |
| Plugin golden fixtures     | 75    | 75 (held) |
| Family detectors           | 14    | 14 (held) |
| Chain completeness         | 96.8% | 96.8% (held) |
| Verdict precision          | 29/31 | 29/31 (held) |
| Avg latency                | 240ms | 240ms (held) |

### 🚀 Deploy path

Redeploy required to push RC3.1.1 into prod. All backend + frontend changes are staged on preview and CI-verified.



---

## RC3.4 — Family Expansion (FormBook + NjRAT + Emotet) + IR-Export Flywheel · 2026-02-21

**Status:** ✅ Ready to ship
**Tag recommended:** `v1.0.0-RC3.4`
**Tests:** 197/197 CI gate pytest · 75 plugin-golden fixtures across 36 plugins · **14 family detectors**

### 🦠 D.3 · FormBook / XLoader
- `decoders/families/formbook.py` — 9 signatures, 8 MITRE (T1055.012 Process Hollowing, T1056.004 Credential API Hooking, T1027.007 Dynamic API Resolution).
- YARA seed `MAL_FormBook_XLoader` · ART pointer T1055.012.
- E2E verified: `verdict=malicious · risk=79 · family=FormBook(1.00) · 8 MITRE`.

### 🦠 D.4 · NjRAT / Bladabindi
- `decoders/families/njrat.py` — 8 signatures anchored on the canonical `|'|'|` config splitter, 7 MITRE (T1562.004 firewall bypass, T1547.001 Run-key, T1059.005 VBS).
- YARA seed `MAL_NjRAT_Bladabindi` · ART pointer T1219.
- E2E verified: `verdict=malicious · risk=83 · family=njRAT(1.00) · 8 MITRE`.

### 🦠 D.5 · Emotet / Heodo
- `decoders/families/emotet.py` — 10 signatures, 10 MITRE (T1204.002 Malicious File, T1573.001 Symmetric Crypto C2, T1562.001 Defender bypass, XL4 macros, `@`-delimited fallback URL list).
- YARA seed `MAL_Emotet_Loader` · ART pointer T1204.002.
- E2E verified: `verdict=malicious · risk=83 · family=Emotet(1.00) · 11 MITRE`.

### 🌀 IR-Export → Golden-Fixture flywheel

- New `tools/ir_export_to_fixture.py` converter — takes any IR Handoff JSON export from a saved analyst case and locks it as a permanent regression in `tests/fixtures/plugin_regression/prod-cases.jsonl`.
- Runner extension: `prod-cases.jsonl` is a reserved end-to-end bucket. Every entry runs through the full Orchestrator and asserts verdict floor, risk-score floor, chain-layer count floor, MITRE / LOLBAS / family drift-free.
- Field-hardened flywheel: **every real-world case becomes permanent CI protection** with a single command:
  ```
  python tools/ir_export_to_fixture.py Screen1.json Screen2.json "Do not download this directly on your machine".json
  ```

### 📊 CI-gate deltas (RC3.3 → RC3.4)

| Metric                     | RC3.3 | RC3.4 |
|----------------------------|-------|-------|
| Pytest passing (gate)      | 185   | **197** |
| Plugin golden fixtures     | 63    | **75**  |
| Family detectors           | 11    | **14 (+ FormBook, NjRAT, Emotet)** |
| Chain completeness         | 96.8% | 96.8% (held) |
| Verdict precision          | 29/31 | 29/31 (held) |
| Avg latency                | 241ms | 240ms |



---

## RC3.3 — Malware-Family Expansion (D.2 RedLine) · 2026-02-21

**Status:** ✅ Ready to ship (extends RC3.2 baseline)
**Tag recommended:** `v1.0.0-RC3.3`
**Tests:** 185/185 CI gate pytest (+4 · RedLine golden fixtures) · 63 plugin-golden fixtures across 33 plugins · 11 family detectors

### 🦠 RC3.3 · RedLine Stealer family detector (D.2)

- New `decoders/families/redline.py` — 10 weighted signatures covering the RedLine panel namespace, `IRemoteEndpoint` SOAP contract, `ScanBrowsers/ScanWallets/ScanTelegram/ScanDiscord/ScanSteam/ScanFTP/ScanFiles` feature enum, `V20-V23` version banner, Rijndael/3DES helpers, and IP-check services (`api.ip.sb`, `iplogger.org`).
- **8 canonical MITRE mappings:** T1555.003 (Web-browser creds), T1005 (Local data collection), T1113 (Screen capture), T1082 (System info discovery), T1071.001 (Web-protocol C2), T1573.001 (Symmetric-crypto C2), T1547.001 (Startup persistence), T1041 (C2 exfiltration).
- Auto-generated YARA seed `MAL_RedLine_Stealer` + Atomic Red Team pointer T1555.003.
- End-to-end verified: RedLine V23 config → `verdict=malicious · risk=83 · family=RedLine(1.00) · 9 MITRE techniques`.
- 4 golden regression fixtures locking panel namespace, ScanRules feature flags, V23 version banner, and strings-dump correlation.

### 📊 CI-gate deltas (RC3.2 → RC3.3)

| Metric                     | RC3.2 | RC3.3 |
|----------------------------|-------|-------|
| Pytest passing (gate)      | 181   | **185** |
| Plugin golden fixtures     | 59    | **63**  |
| Family detectors           | 10    | **11 (+ RedLine)** |
| Chain completeness         | 96.8% | 96.8% (held) |
| Verdict precision          | 29/31 | 29/31 (held) |
| Avg latency                | 241ms | 241ms (held) |

### 🐛 Deferred to RC3.1.1 hotfix (production findings only)

- **PROD-BUG-1** verdict tri-state UI inconsistency (Malicious 70% vs Threat Analysis rail Benign 13/100 on same case)
- **PROD-BUG-4** OUTPUT panel showing INPUT bytes instead of decoded terminal-layer payload
- **PROD-BUG-6** post-decode extractor skipping `pe-executable-payload` tradecraft when terminal layer is a valid PE
- **PROD-BUG-2** LOLBAS false-positives on garbled binary tail
- **PROD-BUG-3** IOC extractor should re-run on previous printable layer when terminal is corrupt

### 🟢 Next up

- **RC3.4** — D.3 FormBook · D.4 NjRAT · D.5 Emotet (same RedLine/XWorm template)
- **RC3.1.1** — batch-ship all 5 production hotfixes with saved-case regression from field-test



---

## RC3.2 — Deterministic Coverage Sprint · 2026-02-21

**Status:** ✅ Ready to ship (Preview verified · CI gate green)
**Tag recommended:** `v1.0.0-RC3.2`
**Tests:** 181/181 CI gate pytest · 59 plugin-golden fixtures across 32 plugins · verdict precision 29/31 (held) · chain 96.8 % (held)

### 🏗️ RC3.2a · Golden Fixture Framework

- New `tests/fixtures/plugin_regression/<plugin_id>.jsonl` per-plugin corpus with density-gated schema (`case_id`, `input`, `detect_min_confidence`, `expected_output_contains`, `expected_mitre`, `expected_tradecraft`, `expected_lolbas_binaries`, `expected_family`, `expected_family_min_confidence`).
- New `tests/test_plugin_golden_fixtures.py` parametrised runner + discoverability lock (`test_every_registered_plugin_has_fixture_file`) — the moment a new decoder registers without a paired JSONL, CI fails.
- **59 golden fixture cases** shipped across `base64-decode`, `base32-decode`, `hex-decode`, `url-decode`, `rot13-decode`, `rot47-decode`, `utf16-decode`, `gzip-decompress`, `zlib-deflate-decompress`, `brotli-decompress`, `lzma-decompress`, `zstd-decompress`, `ascii85-decode`, `base58-decode`, `base91-decode`, `html-unicode-escape`, `decimal-charcode-decode`, `octal-charcode-decode`, `reverse-string`, `caesar-decode`, `jwt-decode`, `data-uri-extract`, `ps-hex-escape`, `nibble-swap`, `custom-hex-slash`, `xor-brute`, `extract-wrapper`, `ps-reconstruct`, `js-reconstruct`, `vbs-reconstruct`, `cmd-reconstruct`, `family-xworm`.

### 🦠 RC3.2b · XWorm reference family detector

- New `decoders/families/xworm.py` — 12 weighted signatures covering XClient class, `XWormMutex_` prefix, feature enums (`XPlugin` / `XChat` / `XKeyLog` / `XHVNC`), wire tags (`pong` / `save_Plugin` / `offline_Get`), `USB_Spread` module, `XWorm V<n>` banner.
- 7 canonical MITRE mappings: T1219 (Remote Access), T1055 (Process Injection), T1547.001 (Startup persistence), T1091 (Removable Media replication), T1573.001 (AES C2), T1056.001 (Keylogging), T1113 (Screen Capture).
- Auto-generated YARA rule stub `MAL_XWorm_Client` + Atomic Red Team pointer T1219.
- End-to-end verification: single-line XWorm V5.6 config XML → `verdict=malicious · risk=79 · family=XWorm(1.00) · 7 MITRE techniques`.

### 🔐 RC3.2c · Enriched `crypto-key-required` tradecraft + expanded shape detection

- `TradecraftFlag.metadata` gains a structured schema: `algorithm`, `mode`, `key_len_bits`, `iv_len_bits`, `nonce_required`, `encoding`, `ciphertext_len`, `keys_found`, `ivs_found`, `confidence`, `candidates`. Analysts (and downstream crypto extractors) can now consume the flag without re-parsing the evidence text.
- `crypto_hints.detect_encryption_shape()` extended to surface `AES-GCM`, `AES-CTR`, `ChaCha20`, `DES/3DES` alongside `AES-CBC/ECB` and `RC4`.
- 6 new regression tests locking the schema and the ChaCha20 / AES-CTR / AES-GCM stream detection.

### 📊 CI-gate deltas (`tests/rc30_baseline/lock.json` → RC3.2)

| Metric                     | RC3.1 | RC3.2 |
|----------------------------|-------|-------|
| Pytest passing (gate)      | 116   | **181** |
| Plugin golden fixtures     | 0     | **59**  |
| Family detectors           | 9     | **10 (+ XWorm)** |
| Chain completeness         | 96.8% | 96.8% (held) |
| Verdict precision          | 29/31 | 29/31 (held) |
| Avg latency                | 500ms | 500ms (held) |
| False-positive IOCs        | 0     | 0 (held) |

### 🐛 Deferred to RC3.1.1 hotfix (production findings only — no CI regression)

- **PROD-BUG-1** Verdict / confidence tri-state inconsistency (Threat Analysis rail vs Verdict card vs Investigation Summary).
- **PROD-BUG-2** LOLBAS false-positives (`Control.exe` / `Remote.exe`) from post-decode scanner on garbled binary tail.
- **PROD-BUG-3** Chain terminates on corrupt final layer — IOC extractor should re-run on the PREVIOUS printable layer.



---

## RC3.1 — Verdict precision + IR Handoff Export · 2026-02-21

**Status:** ✅ Ready to ship (Preview verified end-to-end)
**Tag recommended:** `v1.0.0-RC3.1`
**Tests:** 116/116 CI gate green · 9 new regression tests · verdict precision 15/31 → 29/31 (**93.5%**)

### 🐛 P1 hot-fixes (closes RC3.0 backlog)

- **Terminal-layer `BROKEN` badge → `RECOVERED`.** The trace panel now
  downgrades the terminal layer to ✓ `RECOVERED` whenever the OVERALL
  investigation surfaced valid IOCs / MITRE / LOLBAS / family / verdict.
  Analysts no longer see a misleading red badge when the pipeline actually
  succeeded (`DecodingTracePanel.jsx`, `WorkspacePage.jsx`).
- **Cloudflare origin-parse fix on `/analyze/status/{job_id}`.**
  `routers/analyze.py` now sanitises NUL / C0 control chars, caps every
  string field at 128 KB, and shrinks the entire response to ≤ 512 KB
  before returning via `JSONResponse` with explicit `Content-Length` — no
  more chunked-transfer fallback on Whale-payload polls.

### 🎯 P0 · Verdict precision — 15/31 → 29/31 (48 % → 93.5 %)

- New tiered LOLBAS scoring (`_HIGH_LOLBAS` vs `_BENIGN_LOLBAS`).
- Hard-signal gating stops isolated obfuscation from scoring — `_classify`
  now leaves pure `IEX` / `-f` / `-replace` samples at UNKNOWN, and pushes
  canonical `certutil / mshta / regsvr32 + URL` combos into MALICIOUS.
- Post-decode global LOLBAS re-scan (`_post_decode_lolbas_scan`) merges
  wrapper-decoder blindspots (certutil, regsvr32, bitsadmin, wmic, hh, …).
- `encoding-chain` bonus for canonical staging (`base64+utf16+gzip+URL`)
  distinguishes malicious Empire / Meterpreter loaders from PS-only
  obfuscation, which stays at SUSPICIOUS.
- Tradecraft severity re-weighted (medium 15 → 25, cap 30 → 25) so pure
  reconstruction obfuscation without downstream signal returns UNKNOWN.

### ✨ P1 · New capability

- **HTML entity + JS `\uXXXX` Unicode-escape decoder**
  (`decoders/html_unicode_escape.py`). Recognises `&#65;`, `&#x41;`,
  `\u0041`, `\u{1F600}` and `\x41` escape streams; density-gated so sparse
  noise inside a binary payload never triggers a phantom decode.
- **IR Handoff Export UI** — analyst-ready download strip under the Verdict
  header (MD / PDF / JSON / STIX 2.1). Re-runs the deterministic engine
  server-side so the file always matches the on-screen findings.

### 🧪 Regression coverage

- `tests/test_html_unicode_escape.py` — 4 golden regression tests
- `tests/test_rc31_p1_hotfixes.py` — 5 tests locking sanitiser + downgrade
- `tests/test_regression_lock.py::test_lock11_*` — renamed SALVAGED → RECOVERED

### 📊 CI-gate deltas (`tests/rc30_baseline/lock.json` → RC3.1)

| Metric                  | RC3.0 | RC3.1 |
|-------------------------|-------|-------|
| Chain completeness      | 96.7 % | **96.7 %** (held) |
| Verdict precision       | 15/31 | **29/31 (93.5 %)** |
| Pytest passing (gate)   | 107   | **116** |
| Avg latency             | 500 ms | 500 ms (unchanged) |
| False-positive IOCs     | 0     | 0 (held) |


---

## RC2.2 — Decoder Expansion + Universal File Ingest · 2026-07-20

**Status:** ✅ Ready to ship (Preview verified, awaiting Save-to-GitHub + Deploy)
**Tag recommended:** `v1.0.0-RC2.2`
**Tests:** 194/194 engine green (63 new · zero regressions)
**Release notes:** `/app/memory/RELEASE_NOTES_v1.0.0-RC2.2.md`

### Added — 7 new decoder plugins

- `utf16-decode` — UTF-16LE/BE detection + decode (unblocks all `powershell -EncodedCommand` payloads)
- `ps-reconstruct` — `[char]NN`, `[char[]](nums)-join`, string-concat, backtick strip
- `data-uri-extract` — RFC 2397 `data:*;base64,` + percent-encoded body unwrap
- `ioc-extractor` — post-decode intelligence plugin (URLs / IPs / domains / emails / hashes / BTC / paths)
- `base58-decode` — Bitcoin / Solana / IPFS wallet alphabet
- `jwt-decode` — JWT header + payload → pretty JSON (marked terminal)
- `reverse-string` — string-reverse obfuscation recovery

### Added — Universal file ingest for Batch Analyst

- `POST /api/batch/test/mine/preview` — dry-run extraction (returns candidates
  without executing them, for analyst review)
- `POST /api/batch/test/mine` — full mine-and-run: extracts commandlines from
  any supported document and runs each through the deterministic pipeline
- Frontend: new **"MINE FROM ANY FILE"** button on the Batch Analyst page,
  results table now shows a `Source` column with `<kind> · <origin>`
- New modules `backend/file_extractors.py` (extractor dispatch) and
  `backend/commandline_miner.py` (regex-based candidate mining)
- Supported: .docx, .pdf, .xlsx, .pptx, .html, .htm, .eml, .rtf, .json,
  .jsonl, .yaml, .csv, .tsv, .zip, .tar, .tgz, .gz, .txt, .log, .md, .ini,
  .cfg, .conf, .ps1, .psm1, .bat, .cmd, .sh, .py, .js, .vbs, .hta, .wsf,
  .reg, .rb, .pl, .php, .xml
- Archives recursed up to 25 members, 25 MB per file, 8 MB per member
- Rows carry `source_kind` and `source_origin` for full traceability

### Changed

- `extract_wrapper._normalize()` — strips PowerShell backticks (mirror of the CMD `^` fix)
- `base64-decode` — defers to `base58-decode` for wallet-shaped payloads
- `base91-decode` — rejects whitespace-separated structured text (JSON, prose)
- `xor-brute` — skips high-printable structured text + short binary blobs (<32 B)
- `fingerprint_util._COMMON_EN` — added JSON claim names + short web tokens

### Dependencies added
- `beautifulsoup4 == 4.15.0`
- `lxml == 6.1.1`
- `striprtf == 0.0.32`

### Fixed

- `powershell -enc <UTF-16LE Base64>` now decodes end-to-end to a clean URL + IOC
- `p`ow`ers`h`ell -e <B64>` backtick-obfuscated wrappers now recognised
- `data:text/html;base64,…` now unwrapped and further decoded
- JWT tokens no longer mangled by downstream `xor-brute`
- Base58 wallet addresses no longer misclassified as Base64 → `xor-brute` garbage

---


## RC2.1a — Malware Family Intelligence · 2026-07-19

**Status:** ✅ **SHIPPED TO PRODUCTION** — https://nivxray.nivxforge.com
**Deploy timestamp:** 2026-07-19T09:04Z
**Tag recommended:** `v1.0.0-RC2.1a`
**Tests:** 124/124 (46 new · zero regressions)
**Post-deploy watch:** 30/30 iters · 29 OK · 1 transient CF-520 (recovered ≤ 6 s)
**Production authenticated smoke:** ✅ Meterpreter + AsyncRAT + all 4 export formats
**Full evidence:** `/app/memory/DEPLOYMENT_EVIDENCE.md` §12
**Release notes:** `/app/memory/RELEASE_NOTES_v1.0.0-RC2.1a.md`

### Added

- **9 first-class family plugins** in `backend/decoders/families/`:
  - `meterpreter.py` — Meterpreter / MSFvenom stager (calibration 1.10)
  - `asyncrat.py` — AsyncRAT (calibration 0.85)
  - `lumma.py` — Lumma Stealer (calibration 0.90)
  - `darkgate.py` — DarkGate Loader (calibration 0.90)
  - `remcos.py` — Remcos RAT (calibration 0.90)
  - `agenttesla.py` — AgentTesla / OriginLogger (calibration 0.85)
  - `quasarrat.py` — QuasarRAT / xRAT (calibration 0.90)
  - `cobalt_strike.py` — Cobalt Strike Beacon (calibration 1.00)
  - `snake_keylogger.py` — Snake / 404 Keylogger (calibration 0.90)

- **`FamilyPlugin` base class** (`_base.py`) with weighted-signature scoring,
  auto-generated YARA rule stubs, per-family MITRE mapping, Atomic-Red-Team
  hints, and structured `EvidenceItem` emissions.

- **Post-decode intelligence pass** in `orchestrator.py`:
  - Runs every `intelligence`-category plugin over the **raw input**, the
    **final payload**, and every **trace layer's preview**.
  - Deduplicates on 512-char prefix; one hit per plugin.
  - Excluded from the normal candidate loop to prevent premature termination.

- **Terminal-state promotion**: if the intelligence pass surfaces a family at
  ≥ 80 % confidence, the report terminal is promoted to `family-identified`
  even when the main decode loop had already ended in `complete` or
  `no-candidate`.

- **Model extensions** (`models.py`):
  - `EvidenceItem` (type / pattern / location / weight)
  - `FamilyHint.evidence_items` / `.mitre_techniques` / `.yara_suggestion` /
    `.atomic_red_hint`
  - Same fields on `FamilyMatch` so exports carry the enriched data through
    to the JSON / MD / TXT / PDF reports.

- **Aggregator propagation**: `_aggregate_findings` now lifts
  `yara_suggestion`, `evidence_items`, `atomic_red_hint`, and per-family
  MITRE techniques from the winning `FamilyHint` into `findings.family`.

- **Registry auto-discovery** now walks one level deeper into
  sub-packages (`decoders/families/`).

### Verified

- Plugin count: **21** on API (`GET /api/v2/plugins`) — 12 base + 9 family.
- Meterpreter E2E: `family-identified` · verdict `malicious` · risk `100` ·
  family `Meterpreter/MSFvenom stager (100%)` · YARA `APT_Meterpreter_MSFvenom_Stager` ·
  chain `[extract-wrapper, base64-decode, xor-brute, family-meterpreter]` ·
  elapsed `~90 ms`.
- AsyncRAT E2E: `family-identified` · verdict `malicious` · risk `87` ·
  family `AsyncRAT (100%)` · YARA `MAL_AsyncRAT_Client` · 7 signatures matched.
- All 9 family plugins pass positive-vector + english-negative regression.

### Files Touched

- **New**: `backend/decoders/families/{__init__,_base,meterpreter,asyncrat,`
  `lumma,darkgate,remcos,agenttesla,quasarrat,cobalt_strike,snake_keylogger}.py`
- **New**: `backend/tests/test_family_plugins.py` (46 tests)
- **Modified**: `backend/engine/models.py`, `backend/engine/orchestrator.py`,
  `backend/engine/registry.py`, `backend/tests/test_engine_phase_b_batch4.py`
  (updated chain assertion to accept the new intelligence-pass step).

### Deferred to Later Phases

- YARA / MITRE-Navigator / IOC-CSV UI rendering → **RC2.1c**
- STIX 2.1 bundle export → **RC2.1b** (next up)
- Golden-corpus calibration of confidence thresholds → RC2.5

---

## RC2.0 — PDF Export & Rebrand · 2026-07-19

Shipped to production https://nivxray.nivxforge.com. Details in
`/app/memory/DEPLOYMENT_EVIDENCE.md`.

Key deliverables: PDF export via `reportlab`, "NivXRay v1.0 · MCIP" branding,
`Analyst Workspace / Regression Battery / Investigator` navigation. 122 tests
green pre-ship.

---

## RC1 — Deterministic Plugin Engine Baseline

12-plugin orchestrator, deterministic decoder chain, findings aggregator,
budget & loop guards, 113 tests green. Locked as `RC1_READINESS.md`.
