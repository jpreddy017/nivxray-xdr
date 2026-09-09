# NivXRay v1.0.0-RC2.1a · Release Notes

**Release date:** 2026-07-19
**Branch:** `feature/rc2` → merging to `main` at deploy
**Prior release:** v1.0.0-RC2.0 (production, https://nivxray.nivxforge.com)
**Test status:** 124/124 passing (46 new · zero regressions)

---

## 🔥 Highlights — Malware Family Intelligence

NivXRay moves from "decoder tool" to full **Malware Command Intelligence Platform (MCIP)** with deterministic first-class family identification. Every analyzed payload can now be attributed to a specific malware family with structured evidence, MITRE mapping, and an auto-generated YARA rule stub — 100 % deterministic, no LLM, no sandbox.

## 🆕 What's New in RC2.1a

### 9 First-Class Malware Family Plugins

Deterministic, signature-based, `intelligence`-category plugins in `backend/decoders/families/`:

| Family | Category | Key Evidence | Calibration |
|---|---|---|:---:|
| **Meterpreter / MSFvenom stager** | Stager / Shellcode | x86 & x64 stager prologues, `metsrv.dll`, `ws2_32`, block-API PEB walk, `shikata_ga_nai` FPU trick | 1.10 |
| **AsyncRAT** | .NET RAT | `AsyncClient.Settings`, `AsyncMutex_*`, `<AsyncRAT` config XML, `Aes256`, feature flags | 0.85 |
| **Lumma Stealer** | Info Stealer | `/api/steal`, `lumma-shop`, `TeslaBrowser/x.x` UA, `crypto/browsers/wallets` config, `build_id=` | 0.90 |
| **DarkGate** | AutoIt Loader | `%STAT%` / `%B64%` markers, `DGSNM`, `NIM##` mutex, AutoIt runtime, `Piece_N` config | 0.90 |
| **Remcos RAT** | Commercial RAT | `Remcos-RAT`, `Remcos_MUTEX_*`, `\x1cSETTINGS` RC4 config, `KEYL_STATE\|CAMS\|SCRN\|` | 0.90 |
| **AgentTesla / OriginLogger** | .NET Stealer / KL | SMTP-exfil template, `OriginLogger`, `pw_string_`, `[<CTRL>]` keylog markers | 0.85 |
| **QuasarRAT / xRAT** | .NET RAT | `Quasar.Common/.Client` namespaces, `CN=Quasar Server CA`, `BSF3lLtvGT3+dSagRhTG` key salt | 0.90 |
| **Cobalt Strike Beacon** | APT C2 | Beacon shellcode prologue, `Malleable-C2`, `i_am_key_statement`, `/updates.rss`, `0xBEEF` jitter | 1.00 |
| **Snake Keylogger** | Stealer / KL | `Snake-Keylogger`, `Snake.Client`, `404 keylogger`, Telegram bot exfil URLs, `PW-`/`KEYLOG-` | 0.90 |

### Confidence Scoring Model

Deterministic weighted-signature confidence:

```
confidence = min(1.0, sum(matched_weights) / calibration)
```

Where each signature carries a weight `[0.15..0.60]` based on how specific it is
to the family (e.g. a mutex-prefix regex is heavier than a generic string like
"beacon"). Calibration is per-family, tuned so ~2 strong signature matches
reach `≥ 0.9` confidence.

### Family-Specific Evidence

Every hit emits a structured `EvidenceItem` list with:
- `type` — `"regex"` / `"string"` / `"bytes"` / `"opcode"`
- `pattern` — human-readable description of what matched
- `location` — layer + byte offset
- `weight` — contribution to confidence

Analysts can now audit every signature match individually.

### Family-Specific MITRE Mapping

Each family plugin ships with 4–5 hand-curated MITRE ATT&CK techniques, e.g.
Cobalt Strike Beacon → `T1071.001`, `T1055`, `T1027`, `T1573.002`, `T1090.001`.
The orchestrator's aggregator merges family MITRE hits with in-line decoder
MITRE hits and dedupes by ID.

### Family-Specific YARA Rule Generation

Every family plugin auto-generates a `YaraRuleStub` when it fires:

```
YaraRuleStub(
    name="APT_Meterpreter_MSFvenom_Stager",
    strings=["$s0 = /\\xfc\\xe8[\\x82\\x89\\x8b\\x8c\\x8f]\\x00\\x00\\x00/ nocase", ...],
    condition="2 of them",
    tags=["meterpreter_msfvenom_stager", "nivxray-auto"],
)
```

Naming convention:
- `APT_*` prefix — APT-tier / targeted-attack families (Meterpreter, Cobalt Strike)
- `MAL_*` prefix — Commodity / crimeware families (all others)

Ready to drop into a threat-hunter's YARA repo. UI download endpoint arrives in RC2.1c.

### Orchestrator Enhancements

- **Post-decode intelligence pass**: family plugins now run on the raw input,
  the final decoded payload, AND every trace layer's preview — deduped by
  512-char prefix, one hit per plugin. Prevents mis-hits when aggressive
  intermediate decoders (base91 / xor-brute) mangle plain-text signatures.
- **Terminal-state promotion**: if the intelligence pass surfaces a family at
  `≥ 80 %` confidence, the report `terminal` is promoted to `family-identified`
  even when the main decode loop terminated in `complete` / `no-candidate`.
- **Registry auto-discovery** now walks one level deeper into sub-packages.

### Model Extensions

- New `EvidenceItem` type — `{type, pattern, location, weight}`
- `FamilyHint` and `FamilyMatch` gain: `evidence_items[]`, `mitre_techniques[]`,
  `yara_suggestion`, `atomic_red_hint`
- Aggregator lifts all four into `findings.family` so the JSON / MD / TXT / PDF
  exports all carry the enriched intelligence.

## 🧪 Regression Improvements

- **+46 new tests** in `tests/test_family_plugins.py`:
  - 9 positive-vector tests (one per family)
  - 9 english-prose negative tests (zero false positives)
  - 9 orchestrator-lift tests (end-to-end via the intelligence pass)
  - 9 contract tests (every plugin declares required attributes)
  - 10 content tests (MITRE, YARA naming conventions, Atomic-Red hints)
- **Two pre-existing tests updated** to accept the new richer decode chain
  (`test_engine_phase_b_batch4::test_full_meterpreter_chain`,
   `test_analyst_v2_api::test_meterpreter_full_report`) — the RC2.0 chain
  `[extract-wrapper → base64-decode → xor-brute]` is now followed by an
  additional confirming `family-meterpreter` step.
- **Zero regressions** across the rest of the phase A/B/C engine suites and
  the analyst-v2 PDF / JSON / MD / TXT export suites.

## 🎨 UI Enhancements (Preview Verified)

- Analyst Workspace correctly renders the new family-scored output:
  - Executive Summary now surfaces family + confidence + full MITRE list
    (previously it referenced only the aggregated `family_hints`)
  - Malware Family card shows evidence-count and calibrated confidence
  - Why-This-Score card correctly adds the family-match component (+55)
- Header, nav, and branding unchanged — no visual regression from RC2.0.
- Full Verdict Panel (with Sigma / YARA / MITRE-Navigator / IOC-CSV in-UI
  downloads) is scheduled for RC2.1c.

## 🔧 API Surface

Unchanged. RC2.1a is a purely additive plugin release.

- `GET /api/v2/plugins` — now returns **21 plugins** (12 base + 9 family)
- `POST /api/v2/analyze` — returns richer `findings.family` block; existing
  fields untouched (`terminal`, `verdict`, `risk_score`, `iocs`,
  `mitre_techniques`, `trace`, `plugin_report`, etc.)
- `POST /api/v2/analyze/report?fmt=…` — all four formats (MD / JSON / TXT /
  PDF) now include the new evidence items, YARA suggestion, and per-family
  Atomic-Red hint when a family matched.

## 📦 Files Changed

**Added** (12 files):
```
backend/decoders/families/__init__.py
backend/decoders/families/_base.py
backend/decoders/families/meterpreter.py
backend/decoders/families/asyncrat.py
backend/decoders/families/lumma.py
backend/decoders/families/darkgate.py
backend/decoders/families/remcos.py
backend/decoders/families/agenttesla.py
backend/decoders/families/quasarrat.py
backend/decoders/families/cobalt_strike.py
backend/decoders/families/snake_keylogger.py
backend/tests/test_family_plugins.py
```

**Modified** (5 files):
```
backend/engine/models.py            (+EvidenceItem, +FamilyHint/FamilyMatch fields, +model_rebuild)
backend/engine/orchestrator.py      (+_run_intelligence_pass, +terminal promotion, +intel filter in candidate loop, +aggregator lift)
backend/engine/registry.py          (+subpackage auto-discovery)
backend/tests/test_engine_phase_b_batch4.py  (assertion update for new chain)
backend/tests/test_analyst_v2_api.py         (assertion updates for chain + layers_run)
```

## 🔐 Compatibility

- **RC2.0 API contract**: fully backwards-compatible. Every existing field is
  preserved; new fields (`evidence_items`, `yara_suggestion`, `atomic_red_hint`)
  are additive.
- **Legacy `/api/analyze`, `/api/decode/smart`**: untouched.
- **RC1 decoder chain**: preserved for payloads that don't trigger any family
  plugin (english text, harmless data → same `no-candidate` terminal + zero-risk
  verdict as before).

## 🚀 Deployment Notes

- No new environment variables.
- No new database collections or migrations.
- No new external dependencies (RC2.1a is pure-Python; `reportlab`, `pypdf`,
  `base91` from RC2.0 are the last additions).
- Hot-reload will pick up new plugins on backend restart.
- Frontend production bundle rebuilds cleanly (14.6 s · zero warnings).

## 🔮 Coming Next

- **RC2.1b · STIX 2.1 Bundle Export** (1.5 days) — `?fmt=stix` endpoint
  validated against MISP · OpenCTI · ThreatConnect · MS Sentinel · Splunk ES.
- **RC2.1c · Analyst Verdict Panel + Export Suite** (2 days) — in-UI
  YARA / Sigma / MITRE-Navigator / IOC-CSV downloads.
- **RC2.2 · Decoder Expansion** — Base58, Brotli, LZMA, Homoglyph normalization,
  UUID/GUID, JWT, shellcode-detect, RC4/AES payload-ID.

Full roadmap: `/app/memory/RC2_ROADMAP.md`
