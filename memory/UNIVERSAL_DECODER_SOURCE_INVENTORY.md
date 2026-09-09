# UNIVERSAL_DECODER_SOURCE_INVENTORY.md

**P0-1B · Phase 1 · Read-only source inventory · owner-locked 2026-09-02.**

Scope contract: `/app/memory/P0_1B_SCOPE.md`.
Companion documents: `UNIVERSAL_DECODER_COVERAGE_MATRIX.md`,
`UNIVERSAL_DECODER_LICENSE_MATRIX.md`.

This document inventories every command-language, codec,
compression, crypto, and semantic-reconstruction capability
NivXRay already owns AND every credible open-source source
identified for harvest. **NO code, tests, or runtime bridges have
been added — this is a read-only catalogue.**

---

## 1 · Two capability planes (never conflate)

The engine must distinguish these two planes explicitly:

### Plane A — Generic decoding
Reversing a well-defined transform: Base64, GZIP, XOR, AES, RC4,
UTF-16LE, hex, URL-encoding, ROT13, ZIP, deflate, zlib, brotli,
LZMA, zstd, etc.

Property: input → transform → output is *deterministic and
context-free*. If the transform is known, output is recoverable.

### Plane B — Command-language semantic deobfuscation
Reconstructing what a command interpreter (CMD / PowerShell / Bash)
would execute given a syntactically obfuscated command line.
Includes: caret stripping in CMD, `%VAR%` / `!VAR!` expansion,
`SET` reassembly, `CALL` unwrapping, `FOR /F` reconstruction,
PATH-based executable resolution, wildcard-executable resolution
(`c*d.e?e → cmd.exe`), PowerShell string concatenation and
character-array assembly, format-string function-name assembly,
Bash quoting / ANSI-C escapes / command substitution.

Property: reconstruction requires *language semantics + a knowledge
base of legitimate binaries / cmdlets / builtins*.  It is NOT a
pure transform.

> **Design consequence:** the tommy-aa.lol sample is *predominantly
> Plane B*, not Plane A. Every P0-1B design decision must be
> checked against this distinction. Adding more codecs will NOT
> close a Plane B gap.

---

## 2 · NivXRay-native inventory

### 2.1 · Plane A · Generic decoding (services/uaie/plugins + services/die/preprocessor/recursive_decoder.py)

| # | Capability | Module / Function | Notes |
|---|---|---|---|
| A01 | Base64 (bare) | `uaie/plugins/base64_bare` · `_decode_bare_base64` | min_len 120 default |
| A02 | Base64 (PowerShell FromBase64String) | `uaie/plugins/base64_frombase64string` · `_decode_frombase64string` | detects idiom |
| A03 | Base64 repair (HTML entities) | `uaie/plugins/repair_base64_strip_html_entities` | |
| A04 | Base64 repair (surgical padding) | `uaie/plugins/repair_base64_surgical` | |
| A05 | Base64 validator | `uaie/plugins/validator_base64_text` | |
| A06 | UTF-16LE realignment | `_utf16le_realign` | best-effort realign for stripped BOM |
| A07 | Gzip inflate | `uaie/plugins/gzip_inflate` · `_decode_gzip_bytes` | |
| A08 | Gzip validator | `uaie/plugins/validator_gzip_bytes` | |
| A09 | Zlib inflate | `uaie/plugins/zlib_inflate` · `_decode_zlib_bytes` | |
| A10 | AES-CBC | `uaie/plugins/crypto_aes_cbc` | key/iv from context |
| A11 | RC4 (fixed key) | `uaie/plugins/crypto_rc4` · `uaie/plugins/op_rc4_inline_decrypt` | |
| A12 | XOR brute (single-byte) | `uaie/plugins/xor_brute` | |
| A13 | Byte-array XOR loop | `uaie/plugins/transformer_byte_array_xor_loop` · `_decode_byte_array_xor_loop` | detects `-bxor` pattern |
| A14 | Inline XOR key (PS) | `uaie/plugins/op_ps_xor_inline_key` | |
| A15 | Crypto shape detector | `uaie/plugins/crypto_shape_detector` | classifies unknown blob |
| A16 | Shellcode analyzer | `uaie/plugins/shellcode_analyzer` | statistical |
| A17 | Shellcode ASCII string scan | `uaie/plugins/shellcode_string_scan` · `_shellcode_ascii_strings` | IOC-only |
| A18 | Shellcode validator | `uaie/plugins/validator_shellcode_bytes` | |
| A19 | PE detector | `uaie/plugins/validator_pe_bytes` | MZ / PE signature |
| A20 | PE extractor | `uaie/plugins/pe_extractor` | |
| A21 | PE analyzer (static) | `uaie/plugins/pe_analyzer` · `uaie/plugins/pe_dotnet_recognizer` | pefile-backed |
| A22 | Magic-byte retype | `uaie/plugins/analyzer_magic_byte_retyper` | |
| A23 | Binary configuration extract | `uaie/plugins/extractor_binary_configuration` · `promoter_configuration_iocs` | |
| A24 | CS Beacon config parse | `uaie/plugins/cs_beacon_config_parser` | Cobalt Strike |
| A25 | Family universal recognizer | `uaie/plugins/family_universal_recognizer` | family classifier |
| A26 | Recursive multi-layer peel | `services/die/preprocessor/recursive_decoder.peel_recursively` | orchestrator (currently ~5 stage decoders wired) |
| A27 | Recursive orchestrator (`services/die/recursive_decode.py`) | high-level API | |
| A28 | Decoder-bridge → canonicalizer | `services/decoder_bridge/__init__.py` | P0-0 plumbing (2026-09-02) |

**MISSING in Plane A** (identified during Phase 1):
Base16 explicit · Base32 (RFC-4648 test corpus exists but no decoder plugin) · Base36 · Base58 · Base85 · brotli · LZMA · XZ · zstd · deflate (raw, non-zlib) · URL-encoding decoder (regex-based extraction only; not a stage) · HTML/XML entity decode (only for base64 repair, not general) · Unicode escape reversal (`\u00XX`) · hex-string reversal · octal ASCII · decimal ASCII (test fixture exists) · DES/3DES/Blowfish · Caesar/ROT (test corpus exists, no plugin) · repeating-key XOR (transformer plugin handles static byte-array, but no general repeating-key search).

### 2.2 · Plane B · Command-language semantic (services/die/*_ast.py + canonicalizer)

| # | Capability | Module / Function | State |
|---|---|---|---|
| B01 | CMD tokenisation | `services/canonicalizer/__init__.py` · `shlex.split(posix=False)` | **partial** — no caret handling |
| B02 | CMD launcher peel | canonicalizer `_LAUNCHER_RULES` | cmd/start/powershell/pwsh/mshta/rundll32/regsvr32/wscript/cscript/bash/sh |
| B03 | Windows env-var normalisation (LEADING TOKEN ONLY) | `_expand_windows_envvars` | `%COMSPEC%`, `%SystemRoot%\system32\cmd.exe`, `%WINDIR%\system32\cmd.exe` |
| B04 | PowerShell `-EncodedCommand` peel | canonicalizer + `_decode_ps_encoded_command` | Base64 + UTF-16LE, `-enc` / `-e` / `-EncodedCommand` |
| B05 | PowerShell AST (structural) | `services/die/powershell_ast.py` · `parse_powershell` | cmdlets · LOLBIN detection · obfuscation score |
| B06 | PS alias normalizer | `uaie/plugins/ps_alias_normalizer` | iex→Invoke-Expression, etc. |
| B07 | PS backtick normalizer | `uaie/plugins/ps_backtick_normalizer` | strips backtick escapes |
| B08 | PS hex escape | `uaie/plugins/ps_hex_escape` | |
| B09 | PS reconstruct | `uaie/plugins/ps_reconstruct` | |
| B10 | PS normalize (op) | `uaie/plugins/op_ps_normalize` | |
| B11 | PS reverse string | `uaie/plugins/op_ps_reverse_string` | |
| B12 | PS reverse regex swap | `uaie/plugins/op_ps_reverse_regex_swap` | |
| B13 | PS hex-CSV inline | `uaie/plugins/op_ps_hex_csv_inline` | |
| B14 | PS semantic mini | `uaie/plugins/op_ps_semantic_mini` | limited semantic pass |
| B15 | PS EncodedCommand multi-layer | `uaie/plugins/op_ps_encodedcommand_multilayer` | |
| B16 | CMD AST (structural) | `services/die/cmd_ast.py` · `parse_cmd` | **FLAGS ONLY — no reconstruction.** Detects delayed-expansion / caret / wmic-exec / netsh-fw-disable; lists variables but does NOT resolve them. |
| B17 | Bash AST | `services/die/bash_ast.py` · `parse_bash` | structural |
| B18 | VBScript AST | `services/die/vbscript_ast.py` | |
| B19 | JavaScript AST | `services/die/javascript_ast.py` | |
| B20 | Python AST | `services/die/python_ast.py` | |
| B21 | LOLBAS registry | `services/die/lolbas.py` · `lolbas_lookup()` | knowledge base of Windows LOLBins |
| B22 | Family recognizer (preprocessor) | `services/die/preprocessor/family_recognizer.py` | |
| B23 | Command normalizer | `services/die/preprocessor/command_normalizer.py` | |
| B24 | Input normalizer | `services/die/preprocessor/input_normalizer.py` | |
| B25 | Artifact extractor | `services/die/preprocessor/artifact_extractor.py` | |
| B26 | Artifact router | `services/die/preprocessor/artifact_router.py` | |
| B27 | Process relations | `services/die/preprocessor/process_relations.py` | |
| B28 | Stage builder | `services/die/preprocessor/stage_builder.py` | |
| B29 | Decode telemetry | `services/die/preprocessor/decode_telemetry.py` | traceability of stages |
| B30 | IOC semantic extractor | `services/die/ioc_semantic.py` · `extract_iocs` | shared |
| B31 | Chain module | `services/die/chain.py` | |
| B32 | Archive recovery (ZIP/etc.) | `services/die/archive_recovery.py` | static |
| B33 | Recursive child pipeline | `services/recursive_child_pipeline.py` | |
| B34 | Bash echo b64 pipe decoder | `tests/test_bash_echo_b64_pipe_decoder.py` (test-only) | |
| B35 | PS env reassembly decoder | `tests/test_ps_env_reassembly_decoder.py` (test-only) | |
| B36 | DKP engine | `services/die/dkp/engine.py` · `services/die/dkp/seed_patterns.py` | |
| B37 | Behavior explainer / analyst narrative / intent | `services/die/behavior_explainer.py` · `analyst_narrative.py` · `intent.py` | evidence-derived only |

**MISSING in Plane B** (identified during Phase 1 — these are the
gaps that would close tommy-aa.lol and similar samples):

- CMD caret stripping ANYWHERE (only detected as `flags.caret_obfuscation`, never removed)
- CMD `!VAR!` delayed-expansion resolution (detected as flag, not resolved)
- CMD `%VAR%` static resolution when preceded by `SET VAR=…` (variables listed, not resolved)
- CMD `SET a=power&SET b=shell&%a%%b%` reassembly
- CMD substring / search-replace expansion (`%V:~2,3%`, `%V:x=y%`)
- CMD `CALL` expansion
- CMD `FOR /F "usebackq" %%i in ('cmd') DO %%i …` semantic reconstruction
- CMD wildcard-executable resolution (`c*d.e?e → cmd.exe` via LOLBAS/PATH search)
- CMD PATH-based executable resolution
- CMD `START` argument peel (partial — `_peel_one_launcher.start_wrapper` exists but does not handle the tommy-aa.lol chain)
- PowerShell format-string function-name assembly (`'{1}{0}' -f 'ex','i'`)
- PowerShell character-array function-name assembly (`$e=[char]105+[char]101+[char]120`)
- PowerShell variable indirection (`$a='iex'; &$a $x`)
- PowerShell stdin-piped (`echo … | powershell -c -`)
- Bash ANSI-C quoting (`$'\x48\x54\x54\x50'`)
- Bash hex / octal escape resolution
- Bash `$(cmd)` and backtick command substitution reconstruction

### 2.3 · NivXRay corpora already present

| Track | Location | Count | Purpose |
|---|---|---:|---|
| P0-1 immutable 76-scenario corpus | `backend/tests/corpus/scenarios.py` | 76 | Owner-locked ground truth |
| Fixtures corpus (48 categories) | `backend/tests/fixtures/corpus_*` | 523 files | Category coverage |
| Trust corpus (PowerShell scenarios) | `backend/tests/trust_corpus/` | 18 (16 T-labelled + 2 PS gzip stagers) | Behavior chains |
| Golden corpus samples | `backend/tests/golden_corpus/samples/` | 5 files (PS/PE/docm chain) | End-to-end investigations |
| RC5 unit powershell corpus | `backend/tests/rc5/unit/powershell/test_corpus.py` | (in-test) | |
| RC5 golden corpus expansion | `backend/tests/rc5/unit/golden_corpus/` | (in-test) | |
| Canonical stage1 goldens | `backend/tests/canonical/stage1_goldens/goldens/` | 7 JSON | Canonical projection |
| NVKC command_line | `backend/nvkc/corpus/command_line/` | 9 YAML | Seeded validation corpus |
| NVKC benign_enterprise | `backend/nvkc/corpus/benign_enterprise/` | 1 seed | Benign FP guard |
| Locale corpus sweep | `tests/test_locale_corpus_sweep.py` | (in-test) | |
| Adversarial regression | `tests/test_adversarial_regression.py` | (in-test) | |
| Phase-2 batch regression | `tests/test_corpus_phase2_regression.py` / `..._batch2_...` | (in-test) | |
| Real-world stress suite | `tests/real_world_stress_suite.py` | (in-test) | |
| RC2 P0.15c5 vendor corpus | `tests/test_p015c5_vendor_corpus_v1.py` | (in-test) | Vendor telemetry |
| RC2 R23 regression corpus | `tests/test_r23_regression_corpus.py` | (in-test) | |
| Corpus v1 parity sweep | `tests/test_corpus_v1_parity_sweep.py` | (in-test) | |
| Decoder-realworld validation | `tests/decoder_realworld_validation.py` | (in-test) | |
| Command reconstruction engine | `tests/test_command_reconstruction_engine.py` | (in-test) | Existing PS reconstruction claims |

**Fixtures corpus category summary (48 groups × 5 samples each):**
`aes_cbc_analyst · asyncrat_stager · base32_rfc4648 · base64_utf16le ·
batch_var_slicing · caret_escaping_cmd · char_arrays · clickfix ·
decimal_ascii · deflate_base64 · double_base64 · env_var_expansion ·
format_operator · gzip_base64 · hex_bytes · hta_javascript ·
iso_lnk_wrapper · join_split · js_eval_atob · lnk_launcher ·
lolbas_bitsadmin · lolbas_certutil · lolbas_installutil · lolbas_msbuild ·
lolbas_mshta · lolbas_msiexec · lolbas_reg_run · lolbas_regsvr32 ·
lolbas_rundll32 · lolbas_schtasks · lolbas_wmic · lumma_stealer ·
multi_stage_b64_gz_xor · octal_ascii · office_macro · onenote_embed ·
rc4_analyst · reflection_assembly_load · reverse_strings · rot13 ·
shellcode_virtualalloc · string_concat_iex · triple_base64 ·
unicode_escapes · url_encoding · vbscript_execute ·
xor_ascii_decimal_iex · xor_base64 · zip_password_paste`

> **Important**: the *fixture files exist* for many categories; the
> *runtime decoders* for many of them do NOT (e.g. `base32_rfc4648`,
> `octal_ascii`, `decimal_ascii`, `rot13`, `url_encoding`,
> `unicode_escapes`). This is the exact "test corpus present · runtime
> missing" pattern that P0-1B must close.

---

## 3 · External sources (harvest targets — READ-ONLY reference)

### 3.1 · CyberChef (GCHQ)
- **Repo:** https://github.com/gchq/CyberChef
- **License:** Apache 2.0 (Crown Copyright).
- **Language:** JavaScript.
- **Version:** v11.2.0 (June 2026).
- **Operation count:** ~401 operations across categories.
- **Categories:**
  - Data format (58)
  - Encryption / Encoding (50)
  - Compression (12)
  - Extractors (15)
  - Language (6)
  - Utils (regex + misc)
  - Public key · Hashing · Networking · MAC · Multimedia · Forensics
- **Plane classification:** predominantly Plane A (codec + crypto +
  format). A few Plane-B-adjacent operations (`Parse UNIX file
  permissions`, `Parse User Agent`).
- **Usable for XDR:** ~90-95% of operations are static-safe transforms.
  Fetch/Networking operations are DYNAMIC — MUST BE REJECTED at
  classification.
- **Harvest strategy:** knowledge + test vectors + operation semantics.
  Clean-room reimplementation only (see LICENSE_MATRIX).
- **Test vectors:** each operation ships with unit tests → convert to
  XDR-native static regression tests.

### 3.2 · Invoke-Obfuscation (Daniel Bohannon)
- **Repo:** https://github.com/danielbohannon/Invoke-Obfuscation
- **License:** Apache 2.0.
- **Language:** PowerShell.
- **Released:** September 2016 (DerbyCon 6.0).
- **Purpose:** OFFENSIVE — generates obfuscated PowerShell. INVERSE
  role for our engine: every obfuscation technique it emits is a
  reconstruction case we must handle.
- **Technique families:**
  - **Token** — Reserved / Command / Argument / Member / Type /
    Variable / Whitespace / Comment tokenisation abuse
  - **String** — Concatenate / Reorder split-join / Ticks / Format
    string / Reverse
  - **Encoding** — ASCII / Hex / Octal / Binary / SecureString /
    BXOR / Special chars
  - **Compress** — via `IO.Compression.DeflateStream`
  - **Launcher** — `powershell` / `cmd` / `wmic` / `rundll32` /
    `mshta` / `clip++` / `var++` / `stdin++`
- **Plane classification:** Plane B (PowerShell semantic).
- **Harvest strategy:** technique catalogue → build inverse rule for
  each. Behavioural knowledge, not code.

### 3.3 · Invoke-DOSfuscation (Daniel Bohannon)
- **Repo:** https://github.com/danielbohannon/Invoke-DOSfuscation
- **License:** Apache 2.0.
- **Language:** PowerShell (generates CMD).
- **Released:** March 2018.
- **Purpose:** OFFENSIVE — generates obfuscated cmd.exe commands.
  INVERSE role for our engine.
- **Technique families:**
  - Payload concatenation
  - Payload reversal
  - FIN caret + double-quote insertion
  - Environment-variable substring
  - Environment-variable search-replace
  - FOR-loop encoding
  - Stdin-piping (`^| cmd`)
- **Test harness:** `Invoke-DOSfuscationTestHarness.psm1` +
  `Invoke-DosTestHarness` / `Get-DosDetectionMatch` for thousands of
  generated samples.
- **Plane classification:** Plane B (CMD semantic — direct target).
- **Harvest strategy:** technique catalogue + test-harness generator
  patterns → build corpus of thousands of statically-annotated
  CMD samples.

### 3.4 · PowerDecode (Malandrone)
- **Repo:** https://github.com/Malandrone/PowerDecode
- **License:** **GPL-3.0 (INCOMPATIBLE with XDR-owned engine).**
- **Language:** PowerShell.
- **Capabilities:** deobfuscation + DYNAMIC ANALYSIS (HTTP response
  checking, VirusTotal API, LiteDB backing, cmdlet overriding).
- **Static parts usable:** Base64 / GZIP / deflate handling · regex-based
  layer removal · variable extraction · shellcode injection detection.
- **Dynamic parts REJECTED:** HTTP response checking · VirusTotal ·
  cmdlet overriding requires sandbox.
- **Plane classification:** mixed A + B; only A + static B parts
  useful.
- **Harvest strategy:** **CANNOT COPY CODE (GPL).** Extract
  behavioural knowledge + published research + test vectors only;
  clean-room reimplement. Optional even for knowledge if
  Apache-2.0 alternative exists.

### 3.5 · PSDecode (R3MRUM)
- **Repo:** https://github.com/R3MRUM/PSDecode
- **License:** **UNSPECIFIED** — must treat as "all rights reserved"
  until confirmed. Do NOT harvest code. Documentation may be
  studied.
- **Language:** PowerShell.
- **Capabilities:** method-override interceptor (`Invoke-Expression`,
  `IEX`, `Invoke-Command`) · `-dump` flag for Base64 executable
  extraction · string-replace resolution · `-timeout` argument.
  **REQUIRES SANDBOX** — unhandled functions execute.
- **Plane classification:** Plane B (PowerShell dynamic-interception).
- **Harvest strategy:** technique catalogue only (documentation).
  DYNAMIC interception model is REJECTED for XDR (must be static).

### 3.6 · CMD-DeObfuscator (bobbystacksmash)
- **Repo:** https://github.com/bobbystacksmash/CMD-DeObfuscator
- **License:** BSD 3-Clause.
- **Language:** Node.js.
- **Capabilities:** command string parser · variable expansion ·
  obfuscation-character filter. Two modes: `delayed_expansion`
  (`/V:ON` / `SETLOCAL EnableDelayedExpansion`) and `expand_inline`.
- **Plane classification:** Plane B (CMD semantic — DIRECT).
- **Harvest strategy:** BSD-compat — behavioural knowledge, test
  vectors, and algorithm shape can be studied. Clean-room
  reimplementation preferred; if code is directly re-used the BSD
  3-clause notice must be preserved verbatim in an XDR-owned
  ATTRIBUTION.md.

### 3.7 · batch_deobfuscator (DissectMalware · with forks)
- **Repo:** https://github.com/DissectMalware/batch_deobfuscator
- **Forks:** `TargetPackage/batch_deobfuscator` (expanded), `gdesmar/batch_deobfuscator`
- **License:** MIT.
- **Language:** Python.
- **Capabilities:** string-substitution deobfuscation · escape-character
  handling. Fork `TargetPackage` adds command exit codes,
  mathematical operations, verbose output.
- **Plane classification:** Plane B (CMD semantic — DIRECT).
- **Harvest strategy:** MIT-compat — knowledge + test vectors +
  algorithm reference. Direct code re-use permissible if MIT notice
  is preserved.

### 3.8 · BatchAlchemy
- **Repo:** https://github.com/BatchAlchemy/batchalchemy
- **License:** BSD 3-Clause.
- **Language:** Python + Tree-sitter grammar.
- **Released:** 2024.
- **Capabilities:** extensible framework · Tree-sitter AST for batch
  files · analyses both known and emerging obfuscation patterns.
- **Plane classification:** Plane B (CMD semantic — AST-driven).
- **Harvest strategy:** BSD-compat. Tree-sitter grammar is the
  interesting bit — study it for our CMD AST reimplementation.
  Do not import Tree-sitter as a runtime dependency (adds a heavy
  native binding).

---

## 4 · Additional credible sources discovered during Phase 1

- **CyberChef fork tree** (e.g. `mattnotmax/cyberchef-recipes`) — recipe
  library for specific real-world obfuscation chains. Apache-2.0.
- **LOLBAS Project** (`https://lolbas-project.github.io/`) — JSON
  registry of Windows living-off-the-land binaries. **Public
  domain / CC BY-SA-4.0**. Already partially mirrored in
  `services/die/lolbas.py`. Enhance to cover ATT&CK tag per binary.
- **LOOBins Project** (`https://loobins.io/`) — macOS analogue. MIT.
  Relevant when Mach-O support is opened.
- **GTFOBins** (`https://gtfobins.github.io/`) — Unix analogue.
  Public domain / CC BY-NC-SA-4.0. Relevant for Bash semantic
  reconstruction.
- **Wietze/HijackLibs** — DLL hijack registry. Not directly relevant
  to command semantics but useful for future PE-side extension.
- **MITRE ATT&CK STIX** (already integrated in
  `backend/mitre_catalogue/`) — used for tagging semantic
  reconstruction outputs.
- **Cyber-Chef-Python-API** (mattnotmax) — Python wrapper. Apache-2.0.
  **DO NOT bridge**; potential test-vector generator only.

---

## 5 · A → G validation model — inventory alignment

The owner-locked A→G validation model is now populated:

| Track | Source | Count / status | Location |
|---|---|---|---|
| **A** existing decoder corpus | 48-category fixtures corpus | 523 files | `backend/tests/fixtures/corpus_*` |
| **B** existing command corpus | Trust corpus (T01-T15) + additional | 18 | `backend/tests/trust_corpus/` |
| **B** existing command corpus | NVKC command_line seed | 9 | `backend/nvkc/corpus/command_line/` |
| **B** existing command corpus | Golden corpus samples | 5 | `backend/tests/golden_corpus/samples/` |
| **C** P0-1 76-scenario corpus | Owner-locked immutable | 76 | `backend/tests/corpus/scenarios.py` |
| **D** historical regressions | Adversarial + Phase 2 batch + R23 + realworld | mixed | `tests/test_adversarial_regression.py`, etc. |
| **E** harvested external corpus | Invoke-DOSfuscation test harness | TBD (thousands generatable) | not yet imported |
| **E** harvested external corpus | Invoke-Obfuscation technique tree | TBD | not yet imported |
| **E** harvested external corpus | CyberChef operation vectors | ~401 op-vectors | not yet imported |
| **E** harvested external corpus | CMD-DeObfuscator test fixtures | TBD | not yet imported |
| **E** harvested external corpus | batch_deobfuscator fixtures | TBD | not yet imported |
| **F** new semantic corpus | TBD Phase 2 | 0 | not yet authored |
| **G** tommy-aa.lol mandatory regression | Owner-supplied 2026-09-02 | 1 | added to P0-1 corpus as `obf-02` (partial) — full sample belongs to F/G |

**Track F is empty by design** — the new semantic corpus is a
deliverable of Phase 2, not Phase 1.

---

## 6 · Benign / malformed / adversarial corpora status

| Bucket | Present | Location | Gap |
|---|---|---|---|
| Benign enterprise | Partial (P0-1 20 · NVKC 1) | `tests/corpus/scenarios.py` · `nvkc/corpus/benign_enterprise/` | Need broadly-varied real-world benign (SCCM, Intune, Defender scans, Exchange, Azure, dev/build). Scope contract mandates. |
| Malformed | Implicit (some fixtures) | scattered | Need explicit malformed-Base64, malformed-Unicode, truncated-gzip, broken-caret-escape, incomplete-`FOR`, malformed-PS |
| Adversarial | Present | `tests/test_adversarial_regression.py` | Coverage details in the file — not audited during Phase 1 |

**Phase-2 requirement:** Every category above becomes a first-class
bucket with a stated FP/FN gate.

---

## 7 · Summary of Phase 1 findings

1. **NivXRay is Plane-A-heavy, Plane-B-light.** ~40 codec/crypto
   plugins vs. ~5 truly-semantic command-language modules
   (PowerShell AST is the strongest; CMD AST is flag-only; Bash AST
   is structural).
2. **Fixture corpora exceed runtime coverage.** 48 fixture
   categories, but only ~20 have a matching runtime decoder. This
   is the largest "capability listed, not delivered" gap.
3. **The tommy-aa.lol sample is Plane B**, not Plane A. Building
   more codecs will not close it. The 5 missing CMD semantic
   capabilities (caret · `%VAR%` · `!VAR!` · wildcard-exec · `FOR /F`)
   are the critical shortfall.
4. **External sources are dominated by Apache-2.0 / MIT / BSD-3.**
   Only PowerDecode (GPL-3.0) is incompatible with runtime import.
   PSDecode license is UNSPECIFIED and must be treated as
   restricted.
5. **A→G validation model is populatable today.** Tracks A/B/C/D
   already exist inside the repo. Track E requires a Phase-1.5
   harvest step (test-vectors only). Tracks F/G are Phase-2 work.
6. **The 401 CyberChef operations vs. ~28 NivXRay generic
   decoders** is the numerical gap. The important gap is
   qualitative: NivXRay lacks the *classifier that decides which
   codec to attempt* for a given input, which CyberChef solves via
   its "Magic" operation.

**Next document:** `UNIVERSAL_DECODER_COVERAGE_MATRIX.md` — makes
these gaps explicit, per capability × per source, with XDR-target
column.

**Explicit hold:** Phase 2 not started. No engine code written.
