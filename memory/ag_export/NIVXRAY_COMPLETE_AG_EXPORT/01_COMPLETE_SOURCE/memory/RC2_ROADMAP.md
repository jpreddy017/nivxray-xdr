# NivXRay · Release Candidate 2 (RC2) — Roadmap

**Status:** Planning · No implementation until owner approval
**Base:** RC1 (deployed) · `feature/plugin-decoder-engine`
**Target branch:** `feature/rc2` (to be created on approval)
**Guiding constraint:** RC1 codebase is deployed. Zero regressions to legacy engine, legacy endpoints, and legacy frontend routes. All RC2 work lands on a new feature branch and merges to `main` only after full regression + real-payload validation.

---

## 0 · Recap of RC1 (do-not-touch)

| Locked artifact | Contract |
|---|---|
| `engine/*` primitives | Frozen ABI — additive changes only |
| 12 registered plugins | No regressions on Meterpreter chain (`extract-wrapper → base64 → xor-brute → family-identified`, 82 ms) |
| 7 design-principle regression locks | Must remain green on every commit |
| `NIVX_ENGINE=legacy` default | Legacy pipeline continues to serve `/api/analyze`, `/api/decode/smart` |
| `/analyst` route + `/api/v2/*` | Existing surface; RC2 extends only, never removes |

**Every RC2 PR must run the RC1 test bundle first and demonstrate 113/113 green before adding new tests.**

---

## 1 · RC2 Priority Order (per owner mandate — **updated 2026-07-19 post-RC2.0 sign-off**)

**RC2.0 shipped to production ✅** (https://nivxray.nivxforge.com · 2026-07-19). Remaining scope expanded by owner to elevate NivXRay from decoder into a true enterprise MCIP:

| # | Feature | Est. effort | Risk | Ships in |
|---:|---|:---:|:---:|:---:|
| 1 | ~~PDF export~~ ✅ shipped | — | — | RC2.0 |
| 2 | **9 malware family plugins** (Meterpreter, AsyncRAT, Lumma, DarkGate, **Remcos, AgentTesla, QuasarRAT, Cobalt Strike, Snake Keylogger**) + confidence-score model + per-family MITRE + YARA suggestions | 5 days | Med | **RC2.1a** |
| 3 | **STIX 2.1 bundle export** (`/api/v2/analyze/report?fmt=stix`) validated against MISP · OpenCTI · ThreatConnect · MS Sentinel · Splunk ES | 1.5 days | Low | **RC2.1b** |
| 4 | **Analyst Verdict panel** (in-UI) + **MITRE Navigator layer export** + **IOC CSV export** + **Sigma rule generator** | 2 days | Low | **RC2.1c** |
| 5 | Decoder expansion: Base58, Brotli, LZMA, Homoglyph, **UUID/GUID, JWT, shellcode detection, RC4/AES payload-ID** | 3 days | Low | RC2.2 |
| 6 | Advanced PowerShell reconstruction | 2 days | Med | RC2.3 |
| 7 | Advanced CMD reconstruction + **env-var resolution + multi-stage payload reconstruction** | 2 days | Med | RC2.4 |
| 8 | Golden Corpus 500–1000 real samples + CI regression gate | 3 days | High | RC2.5 |
| 9 | P3 cleanup: purge `operations.py` + `wrapper_archetypes.py`, resolve xfails, remove dead compat shims | 1 day | Low | RC2.6 |

Total remaining window: **~19.5 engineer-days**.
Each item ships as its own commit + regression gate. Any item can be paused without blocking the next.

---

## 1.5 · Owner Expansion — Enterprise MCIP Scope (2026-07-19)

Adopting owner's post-RC2.0 recommendations. Full text preserved verbatim in `/app/memory/OWNER_RECOMMENDATION_2026-07-19.md` (created when first RC2.1 branch opens).

### 🔥 RC2.1a — Malware Family Intelligence
**9 first-class `intelligence`-category plugins** (all deterministic, no LLM):
1. Meterpreter / MSFVenom (extracted from `xor-brute`)
2. AsyncRAT (`AsyncClient.Settings`, `<AsyncRAT`, `AsyncMutex_*`, `Aes256`)
3. Lumma Stealer (`Lumma`, `lumma-shop`, `/api/(steal|conf)`, `crypto/browsers/wallets/files/software`)
4. DarkGate (`%STAT%`, `%B64%`, AutoIt marker, `DGSNM`)
5. **Remcos RAT** (`Remcos-`, RC4 config-block magic `x1c`, mutex `Remcos_MUTEX_*`, screenshot markers)
6. **AgentTesla** (SMTP exfil templates, keylog format strings, `Panel` string, `pw_string_`)
7. **QuasarRAT** (`Quasar.Common`, TLS pinning cert-hash, `SETTINGS` AES-256 header)
8. **Cobalt Strike** (`beacon`, `Malleable-C2`, jitter `0xBEEF`, sleep-mask XOR pattern, HTTP staging URI `/updates.rss`, `.d?` extension pattern)
9. **Snake Keylogger** (`Snake-`, `SMTPServer=`, `PW-`, `Screenshot=`, panel string `pw_`)

**Every family plugin emits:**
- `family` (canonical name)
- `confidence` (0.0–1.0, calibrated via signature match count)
- `evidence` (structured list — each item has `type`, `pattern`, `location`)
- `mitre_techniques` (family-specific)
- `yara_suggestion` (auto-generated rule stub keyed off matched signatures)
- `atomic_red_test_hint` (link to relevant AtomicRedTeam T# test when present)

**Confidence scoring model:** Each family plugin has a weighted signature table. Confidence = `min(1.0, sum(matched_weights) / calibration_threshold)`. Calibration comes from golden corpus (locked once RC2.5 completes phase 1).

### ⭐ RC2.1b — STIX 2.1 Bundle Export
- New endpoint: `GET /api/v2/analyze/report?fmt=stix` (also POST for one-shot analyze+export)
- Uses `stix2` (OASIS-maintained Python SDK)
- Bundle content: `indicator` (per IOC), `malware` (per identified family), `attack-pattern` (per MITRE tech), `identity` (NivXRay as producer), `relationship` (indicator↔malware, malware↔attack-pattern), `report` (SDO wrapping all objects)
- Validated round-trip in tests against:
  - MISP (`stix2` → `misp-stix` importer)
  - OpenCTI (STIX bundle upload via v4 API test harness)
  - ThreatConnect (v3 STIX 2.1 endpoint schema)
  - Microsoft Sentinel (TAXII 2.1 STIX-DDS format)
  - Splunk Enterprise Security (Threat Intel Framework STIX-2.1 field mapping)
- Regression: `tests/test_stix_export.py` asserts every consumer's required fields are populated.

### ⭐ RC2.1c — Analyst Verdict Panel + Export Suite
**UI (new component in `AnalystWorkspacePage.jsx`):**
Consolidated "Analyst Verdict" card at top of report showing:
- Executive Summary (existing, promoted)
- Malware Family + confidence
- Decode Chain (existing, promoted)
- MITRE ATT&CK mapping (existing)
- LOLBins used
- Extracted IOCs (existing)
- **C2 Infrastructure** (dedicated sub-card: IP/domain/URL + geo/ASN lookup via existing OSINT stack)
- **Detection Rationale** (auto-composed narrative from signature-match evidence)
- **Recommended SOC Actions** (existing, enriched with playbook links)
- **Sigma rule** (auto-generated)
- **YARA rule** (auto-generated from family signatures)
- **STIX bundle download**
- **MITRE Navigator layer JSON export** (drag-drop into https://mitre-attack.github.io/attack-navigator/)
- **IOC exports:** CSV, JSON, STIX

**Sigma auto-gen:** New module `backend/engine/sigma_builder.py` — takes findings, produces Sigma YAML using process-creation / file-event / network-connection log-sources depending on which IOCs and MITRE tactics matched.

**MITRE Navigator export:** `backend/engine/navigator_layer.py` — emits Navigator v4.5 layer JSON with all matched techniques scored 100, unmatched greyed out.

---



## 2 · Feature Specs

### 🟢 RC2.0 · PDF Export

**Goal:** One-click PDF report from the Analyst Workspace, byte-similar layout to the existing Markdown export.

**Tech choice:** `reportlab` (pure-Python, no wkhtmltopdf/system dep, deterministic output). Alternative rejected: WeasyPrint (needs Cairo/Pango system libs — brittle in containers).

**Deliverables:**
- `backend/engine/report_pdf.py` — new module, `to_pdf(report) -> bytes`
- Reuses the same section order + copy as `to_markdown()`; no duplicated content logic (call `to_markdown()` internally and feed to a Markdown→PDF adapter OR share a section-builder helper).
- Extend `POST /api/v2/analyze/report?fmt=pdf` in `routers/analyst_v2.py` (Content-Type `application/pdf`).
- Frontend: add **"Download PDF"** button next to existing MD/JSON/TXT.
- Requirements.txt update via `pip freeze` (reportlab pinned).
- New tests: `tests/test_analyst_v2_pdf.py` — validates non-zero PDF, valid `%PDF-1.` header, presence of "149.28.81.19" via `pypdf` text extraction, `application/pdf` content-type.

**Regression gate:** RC1 113 tests + new PDF tests → all green.

**Rollout:** ship in isolation. No other RC2 items depend on this.

---

### 🟠 RC2.1 · Malware Family Plugins (Meterpreter · AsyncRAT · Lumma · DarkGate)

**Goal:** Move family-identification logic out of `xor-brute` into first-class plugins. Every family becomes single-file, single-responsibility, single-test.

**New plugin category:** `intelligence` — plugins that emit signals without transforming bytes. Fits the same `BaseDecoder` contract; `decode()` returns the input unchanged and populates `family_hints` + `mitre_hints` + `iocs`.

**Files (four one-file plugins under `backend/decoders/families/`):**
- `meterpreter.py` — moves shellcode-prologue table + XOR-recovery magic bonus out of `xor_brute.py` (backwards-compat: `xor-brute` still emits Meterpreter hint until the plugin registers; final removal in Phase F cut-over).
- `asyncrat.py` — signatures: `AsyncClient.Settings`, `Aes256`, XML config marker `<AsyncRAT`, mutex pattern `AsyncMutex_*`.
- `lumma.py` — signatures: `Lumma`, `lumma-shop`, C2 URL pattern `/api/(steal|conf)`, dictionary keys `crypto/browsers/wallets/files/software`.
- `darkgate.py` — signatures: `%STAT%`, `%B64%`, AutoIt marker, `DGSNM`, obfuscated CGI paths.

**Contract for family plugins:**
```python
class FamilyPlugin(BaseDecoder):
    category = "intelligence"
    def detect(payload, fp, ctx) -> DetectResult:
        # confidence based on distinctive strings/patterns present
    def decode(payload, args, ctx) -> PluginResult:
        # output unchanged; populate family_hints + mitre_hints + iocs
```

**Orchestrator changes:** `intelligence` category plugins run AFTER the deterministic decode terminates (i.e., on the final payload). They can also opt in to per-layer inspection via a `run_per_layer=True` class flag. Loop-detection continues to guard against duplicate emissions.

**Tests:** `tests/test_engine_family_plugins.py` — one class per family with (a) positive vector, (b) negative English text, (c) integration through `POST /api/v2/analyze`.

**Regression gate:** Existing Meterpreter e2e test (`test_engine_phase_b_batch3.py::test_orchestrator_base64_then_xor_then_shellcode`) must still pass because `xor-brute` continues to emit the family hint. If we cut over to the family plugin during RC2, the same assertion must hold via the new plugin.

---

### 🟢 RC2.2 · Decoder Expansion (owner-expanded 2026-07-19)

Eight single-file plugins.

**Original four:**
- `decoders/base58.py` — Bitcoin / Solana / IPFS. Alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`. Skip if `0OIl` present. Confidence 0.6 on pure alphabet + length ≥ 20.
- `decoders/brotli.py` — `brotli>=1.1.0`. No magic → entropy probe + try-decompress. Confidence 0.85 on successful decompress.
- `decoders/lzma.py` — stdlib `lzma`. Magic `FD 37 7A 58 5A 00` (`.xz`) or raw. Confidence 0.95 on magic, 0.4 on entropy probe.
- `decoders/homoglyph.py` — Category `normalize`. Cyrillic look-alikes → Latin, fires only on mixed-script + command-pattern.

**Owner additions:**
- `decoders/uuid_extract.py` — Category `pattern`. Extract UUIDs/GUIDs (both hex-4-2-2-2-6 and canonical `{...}` forms) as IOCs. Non-transforming (like family plugins).
- `decoders/jwt_decode.py` — Split `xxx.yyy.zzz`, base64url-decode header + body, emit `iss`, `sub`, `aud`, `exp`, `alg` as findings. Flag `alg=none` and `HS256` with obviously-weak keys.
- `decoders/shellcode_detect.py` — Category `intelligence`. Deterministic shellcode heuristic (opcode-histogram: high `MOV EAX/EBX`, `CALL EBP`, `XOR EAX,EAX`, low letters), independent of family match. Emits `shellcode_present: true/false` + arch guess (x86 vs x64).
- `decoders/crypto_payload_id.py` — Category `intelligence`. Detect encrypted payload wrappers: RC4 headers (repeated `0x01 0x02 0x03` schedule leak), AES-CBC IV pattern (16-byte block boundary), AES-GCM tag (16-byte trailer). Emits `encrypted_payload: {algo, iv_hex, ciphertext_len}` for the analyst even when we can't decrypt without the key.

**Tests:** `tests/test_engine_phase_c_extra.py` — one test class per plugin (+ negative case + integration).

**Regression gate:** RC1 + RC2.0 + RC2.1a/b/c all green.

---

### 🟠 RC2.3 · Advanced PowerShell Reconstruction

**Goal:** Handle the top PowerShell obfuscation techniques that Invoke-Obfuscation, Invoke-DOSfuscation, and modern droppers ship.

**Six single-file plugins under `decoders/ps_reconstruct/`:**

1. `char_from_int.py` — `[char]0x48 + [char]0x65 + [char]0x6c` → `Hel`. Handles decimal and hex.
2. `join_pattern.py` — `('a','b','c') -join ''` → `abc`. Also `"$('a','b','c' -join '')"`.
3. `format_string.py` — `"{0}{1}{2}" -f 'A','B','C'` → `ABC`. Full ordinal-substitution.
4. `env_var_expand.py` — `$env:PATH`, `${env:X}` → substitutes from a stub dictionary (env observability).
5. `tick_strip.py` — Category `normalize`. Removes PowerShell backtick escapes (`i`e`x` → `iex`) except within actual string literals.
6. `case_normalize.py` — Category `normalize`. Lowercases command names + variable references outside strings.

**Contract:** All are `category=reconstruct` or `normalize`. Idempotent (running twice yields same output). Emit `notes` describing the transform for the trace panel.

**Test corpus:** `tests/fixtures/ps_obfuscated/` — 30 curated samples from the Invoke-Obfuscation regression suite + Empire Framework loaders.

**Regression gate:** All existing tests + PS suite pass. No plugin fires on clean English (Principle 3 — never over-decode).

---

### 🟡 RC2.4 · Advanced CMD Reconstruction

**Goal:** Cover the DOSfuscation trick set — `%VAR%`, `!DELAYED!`, `^` escapes.

**Four single-file plugins under `decoders/cmd_reconstruct/`:**

1. `percent_var.py` — Expand `%COMSPEC%`, `%TEMP%`, and user-defined `set X=... & %X%`. Uses a small stub dictionary of well-known env vars.
2. `delayed_expansion.py` — Handle `!VAR!` with `setlocal EnableDelayedExpansion`.
3. `caret_escape.py` — Category `normalize`. Strip `^` character escapes (`c^md` → `cmd`, but not inside quoted strings).
4. `for_loop_expand.py` — Reconstruct simple `for /f "delims=..." %%i in (...) do ...` invocations to their canonical form (useful for T1059.003 detection).

**Tests:** `tests/fixtures/cmd_obfuscated/` — 15 curated DOSfuscation vectors.

---

### 🔴 RC2.5 · Golden Corpus (500–1000 real samples)

**Goal:** A permanent, versioned, byte-stable corpus that every future release must pass 100% on.

**Structure:**
```
backend/tests/corpus/
  meterpreter/
    001.yaml    # {input, expected_family, expected_ioc, expected_verdict, min_risk}
    002.yaml
    ...
  asyncrat/
  lumma/
  darkgate/
  ps_encoded_command/
  ps_downloadstring/
  cmd_dosfuscated/
  gzip_xor/
  clickfix/
  ...
```

**YAML fixture schema:**
```yaml
id: meterpreter-001
source: "MalwareBazaar SHA256 abc123..."
input: |
  [Byte[]]$var_code = [System.Convert]::FromBase64String('...')
expected:
  terminal: family-identified
  chain: [extract-wrapper, base64-decode, xor-brute]
  family: Meterpreter/MSFvenom stager
  min_family_confidence: 0.8
  min_risk_score: 80
  verdict: malicious
  iocs:
    ips: ["149.28.81.19"]
  mitre_must_contain: ["T1027", "T1055.012", "T1059.001"]
  lolbas_must_contain: ["powershell.exe"]
  max_elapsed_ms: 300
```

**Sourcing plan (public + safe):**
- MalwareBazaar (Abuse.ch) — filtered by family tag
- Any.Run public reports — PS/CMD command lines only (no live samples)
- Emotet epochs 1–5 spam campaigns
- Recorded Future / TAXII 2.1 public feeds
- Owner-provided Undecoded prod traffic (opt-in)

**Legal / ops:**
- Store only command-line strings + hashes, never live PE bytes.
- Each fixture MUST include `source:` provenance.
- Redact any real customer/victim IPs; keep only C2 IPs (already public).

**Test harness:**
- `tests/test_golden_corpus.py` — parametrised over every YAML file.
- CI gate: **100% pass required to cut a release.**
- Nightly job posts a corpus health dashboard (pass/fail per family) to `memory/CORPUS_HEALTH.md`.

**Sizing:**
- Phase 1 (RC2.5.a): 200 fixtures across 8 families → RC2 release blocker.
- Phase 2 (RC2.5.b): grow to 500–1000 fixtures for RC3.

---

## 3 · Engineering Standards (unchanged from RC1)

Every RC2 PR must uphold:

1. Backwards compat unless explicitly versioned (`/api/v2/*` stays stable; new endpoints use `/api/v2/*/beta` OR a new version namespace).
2. Every new feature ships with regression tests before merge.
3. Plugins remain deterministic and independently testable (one file, one purpose, one test class).
4. UI stays responsive; long-running analysis shows progress; cancel is supported (already RC1 for API, add cancel button in RC2 UI).
5. No duplicated logic — share via `engine/` helpers or new `engine/report_common.py`.
6. Performance is a feature — every plugin must justify its `cost` value; expensive plugins gated by fingerprint hints.
7. AI stays optional; the deterministic path never depends on an LLM.

---

## 4 · Rollout & Risk Management

| Risk | Mitigation |
|---|---|
| PDF library adds container weight | reportlab is pure-Python (~2 MB). Acceptable. |
| Family plugins change verdict for edge cases | Every family plugin ships with `run_per_layer=False` initially so it can only fire after decode completes — no risk to the existing chain-terminal logic. |
| Homoglyph plugin false-positives on legitimate Cyrillic prose | Fire only when payload also matches at least one Latin-script command pattern (`powershell`, `cmd`, `iex`, `mshta`). |
| Golden corpus contains sensitive customer payloads | Owner-provided fixtures are stored in a private repo submodule; public repo ships only public-source YAMLs. |
| PS/CMD reconstruction interacts unpredictably with existing decoders | Register with `cost` ≥ 3 so encoding decoders win first. Add regression test that a plain `powershell -e <b64>` still resolves the same as RC1. |

---

## 5 · Definition of Done

RC2 ships when **all** are true:
- 6 RC2 features merged in numbered order (or explicitly deprioritised by owner).
- 100% of RC1 tests + all new RC2 tests green.
- Golden corpus phase 1 (200 fixtures) at 100%.
- Live preview validation on the 4 canonical cases (`Testing for NonAI`, `Need_analysis`, DarkGate sample, Lumma sample) passes.
- Owner acceptance sign-off in this file.

---

## 6 · Awaiting Owner Approval

**No implementation begins until the owner explicitly approves this roadmap.**

Next actions on approval:
1. Create branch `feature/rc2` from `main`.
2. Cherry-pick nothing from `feature/plugin-decoder-engine` (RC1 already deployed).
3. Start with RC2.0 (PDF export) — smallest, lowest-risk win.
4. Ship each numbered milestone as its own PR with a per-item readiness note.
5. Cut `rc2` tag when all 6 items complete + golden corpus phase 1 passes.

---

_Document generated Feb 2026. Location: `/app/memory/RC2_ROADMAP.md`. Locked; no code changes performed._
