# NivXRay Changelog

Chronological record of significant releases (newest first).

---

## RC2.2 — Deterministic Decoder Expansion · 2026-07-20

**Status:** ✅ Ready to ship (Preview verified, awaiting Save-to-GitHub + Deploy)
**Tag recommended:** `v1.0.0-RC2.2`
**Tests:** 147/147 engine green (16 new · zero regressions)
**Release notes:** `/app/memory/RELEASE_NOTES_v1.0.0-RC2.2.md`

### Added — 7 new plugins

- `utf16-decode` — UTF-16LE/BE detection + decode (unblocks all `powershell -EncodedCommand` payloads)
- `ps-reconstruct` — `[char]NN`, `[char[]](nums)-join`, string-concat, backtick strip
- `data-uri-extract` — RFC 2397 `data:*;base64,` + percent-encoded body unwrap
- `ioc-extractor` — post-decode intelligence plugin (URLs / IPs / domains / emails / hashes / BTC / paths)
- `base58-decode` — Bitcoin / Solana / IPFS wallet alphabet
- `jwt-decode` — JWT header + payload → pretty JSON (marked terminal)
- `reverse-string` — string-reverse obfuscation recovery

### Changed

- `extract_wrapper._normalize()` — strips PowerShell backticks (mirror of the CMD `^` fix)
- `base64-decode` — defers to `base58-decode` for wallet-shaped payloads
- `base91-decode` — rejects whitespace-separated structured text (JSON, prose)
- `xor-brute` — skips high-printable structured text + short binary blobs (<32 B)
- `fingerprint_util._COMMON_EN` — added JSON claim names + short web tokens

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
