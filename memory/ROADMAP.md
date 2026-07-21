# NivXRay Roadmap — Post-RC2.3

**Baseline (frozen):** RC2.3 Stable, tagged `v1.0.0-RC2.3` on GitHub · 24/31 chain-complete (77.4%) · 0 FP-IOCs · deployed to `nivxray.nivxforge.com`


---
## 🔒 SHADOW-RUN CHARTER (locked 2026-02-23)

The 30-day shadow-run window is dedicated to **quality, coverage, and production validation** — **not new architecture**. Every workstream below MUST link to either a Golden Corpus sample or a stability/perf metric.

### Allowed during shadow-run
- **Golden Corpus expansion** → real malware families (Emotet, Qakbot, IcedID PS loaders), benign enterprise scripts (Exchange install, SCCM, Chocolatey, Winget), MSI LOLBIN chains (`msiexec /i http…`), HTA (mshta remote payloads), WMI event subscriptions, XSL Transform LOLBAS, `regsvr32 /s /n /u /i:` scriptlets. Target: GC-150 → GC-300.
- **Interpreter coverage patches** driven exclusively by corpus failures — surgical, one gap at a time.
- **Performance & latency instrumentation** surfaced via the PR delta report (`latency_p50`, `latency_p95`, per-sample decode ms).
- **Analyst UI polish** (SOC Prime-inspired — visibility improvements only, no detection logic changes).

### Blocked until Phase 10 (post-cutover)
- New detection rules, MITRE mappings, LOLBIN table entries.
- New verdict-math weights, floors, caps, or dimensions.
- New parsers or interpreters.
- New API endpoints or schema changes.


---
## 🎯 NEXT SESSION — POST-RC3.0 PRIORITIES (locked 2026-02-20 with user)

These 5 items land BEFORE Phase D (new malware family detectors). Order is intentional — verdict precision first because it has the biggest customer impact.

### P0 · Verdict Precision Sprint (15/31 → ≥ 90 %)
- **Root-cause the 16 verdict-precision misses** on the RC23 benchmark.
  - Diff the benchmark's `expected_verdict` vs `_classify` output for each miss.
  - Categorise: (a) benchmark rule stale vs new findings-aware logic, (b) genuine over-/under-classification, (c) missing indicator surface.
- **Deliverable:** verdict precision ≥ 28/31 (≥ 90 %). Add a lock test that fails if precision drops below 90 %.
- **File to read first:** `/app/backend/tests/rc23_benchmark/run_benchmark.py` — the ground-truth expectations.

### P0.5 · Regression Fixture Battery (net-new lock tests)
- For EVERY plugin decoder currently in `/app/backend/decoders/`, add a golden-input → golden-output fixture in `/app/backend/tests/fixtures/plugin_regression/`.
- Includes: `ps-reconstruct`, `cmd-reconstruct`, `js-reconstruct`, `vbs-reconstruct`, `ps-hex-escape`, `custom-hex-slash`, `nibble-swap`, `decimal-charcode-decode`, `octal-charcode-decode`, `rc4-decrypt`, `aes-cbc-decrypt`, `crypto-detect`.
- A single parametrised pytest test loads every fixture and asserts byte-identical output. Prevents silent regressions when a plugin's detect() thresholds are tuned.

### P1 · `crypto-key-required` Tradecraft Enrichment
Current tradecraft evidence text lists only algorithm + byte-length. Enhance to a machine-readable payload:
```json
{
  "algorithm":     "AES-CBC",
  "encoding":      "base64",
  "key_len_bits":  128,
  "iv_len_bits":   128,
  "nonce_required": false,
  "confidence":    0.85,
  "why":           "…"
}
```
Consumed by the Analyst Workspace Behavior panel to render an actionable "Provide key: 16 bytes hex/base64" prompt with a copy-paste-friendly form.

### P1 · Extend `crypto-detect` Framework (NOT separate plugins)
Reuse `crypto_hints.detect_encryption_shape` + the plugin pattern to add:
- **ChaCha20** — 32-byte key + 16-byte nonce; nonce-hint regex needed.
- **Salsa20** — same shape as ChaCha20; family alias.
- **DES / 3DES** — 8-byte block alignment; key sizes 8 / 16 / 24 bytes.
Each new algorithm = one entry in a `_ALGO_SPECS` table + regex additions, NOT a copy-pasted class. Keeps the codebase DRY.

### P1 · IR Handoff Export (`.md` / `.pdf`)
One-click export of the 7-panel Analyst Workspace as a shareable SOC brief:
- Backend: `/api/v2/report/ir-handoff?format=md|pdf` extending `engine/report.py` + `engine/report_pdf.py`.
- Frontend: "EXPORT · IR HANDOFF" button in the sticky Verdict panel header. Includes: Verdict + Confidence + Risk, Recovered Payload, Chain Recipe, MITRE, IOCs, Network, Behavior, timestamp, analyst name.
- Optional STIX-2.1 bundle export already exists at `/api/v2/analyze/report?fmt=stix` — reuse for machine-to-machine handoff.

---

## 🛡️ Phase R · Robustness Hardening (locked 2026-02-20 with user)

Cross-cutting production-grade capabilities. These items land alongside or after the numbered next-session sprint items — grouped here as a separate track because they're multi-owner and multi-release.

### R.1 · External Intelligence Integrations (analyst asks EVERY case)
- **VirusTotal** — /api/enrich/vt for hashes / URLs / IPs / domains. Cache 24h.
- **AlienVault OTX** — pulse membership + first-seen data.
- **MISP push** — one-click share Malicious-verdict IOCs to team feed.
- **Triage / Any.run detonation** — sandbox execution of recovered payload (Phase E backlog moved here).
- **Slack / Teams / Discord webhook** — auto-notify on Malicious verdict per workspace.

### R.2 · Detection Engineering Export
- **Sigma rule export** — one-click from a decoded case → shareable YAML rule.
- **YARA rule export** — pattern extraction from the recovered payload.
- STIX 2.1 export already exists · Sigma+YARA close the SOC value loop.

### R.3 · High-Value Tradecraft Detectors (rule-based, no AI)
- **AMSI / ETW bypass patterns** — flag red-team tradecraft even when the decoded output looks benign.
- **Sandbox / VM detection strings** — pafish/paranoiac fingerprints.
- **Registry-key persistence patterns** (`HKCU\...\Run`, `AutoRun`, IFEO, ServiceDll).
- **Scheduled-task / service persistence patterns** (`schtasks /create`, `sc.exe create`, `New-ScheduledTask`).
- **DGA domain heuristic** — n-gram entropy scorer.

### R.4 · Enterprise Hardening (compliance blockers for enterprise deals)
- **RBAC** — analyst / admin / read-only roles.
- **Audit log** — who decoded what, when, from where. Immutable.
- **API tokens** for headless / SIEM integration (currently JWT-only, per-user).
- **Multi-tenant workspaces** — team isolation.
- **Prometheus metrics endpoint** — SIEM push, alerting.

### R.5 · Payload-Type Coverage (beyond command lines — huge real-world gap)
- **Office VBA macros** extraction + deobfuscation.
- **LNK files** parser (Windows shortcuts — #1 phishing dropper vector).
- **XLM / Excel 4.0 macros**.
- **PDF JavaScript** extraction.
- **CHM / HTA / MSI / ISO** container unpacking.

### 🎯 If we ship 5 to make NivXRay unmistakably enterprise-robust:
1. **VirusTotal + OTX enrichment** (R.1)
2. **Sigma + YARA export** (R.2)
3. **AMSI/ETW bypass + sandbox-detection patterns** (R.3)
4. **Audit log + API tokens** (R.4)
5. **VBA + LNK payload extraction** (R.5)

Prioritisation: after the numbered sprint (D → A → B → C → E → F → G → H) completes,
Phase R items slot in based on customer/user pull. R.1 + R.2 are the highest-signal
because analysts request them on every case.





## RC2.4 — Analyst UX Polish (UI only, engine untouched)

**Scope frozen — 4 items:**
1. Separate Recovered Payload from Investigation Summary panel
2. Terminal decode reason block (replace binary garbage tail)
3. Split Decode Confidence vs Threat Confidence
4. Recovered Commands card with copy button

---

## RC2.5+ — Full Analyst Brain (from user spec, 2026-07-19)

### 1. Intelligent Command Line Recognition
Classify input before decoding: plain / encoded / mixed / multi-stage / script / binary / URL / archive / unknown.
Recognize: PowerShell, CMD, Bash, Python, JavaScript, VBScript, MSHTA, JScript, WSH, Regsvr32, Rundll32, MSBuild, InstallUtil, Certutil, Bitsadmin, WMIC, MSIExec, Office macros, LNK, Scheduled Tasks, WMI, Services.
Determine: encoding present? which one(s)? estimated layers? confidence per detection?

### 2. Recursive Layer Detection
Never stop after first decode. Recurse until: plaintext / binary / encrypted / unsupported / recursion limit / execution budget.

### 3. Decoder Expansion
Continue supporting: Base64, UTF16, UTF8, Hex, URL, Gzip, Deflate, Brotli, LZMA, XZ, Zstd, Base32, Base58, Base85, ROT13, ROT47, Caesar, ASCII, Unicode escapes, JWT, Data URI, PowerShell reconstruction, CMD reconstruction, JavaScript, VBScript, XOR, custom malware encodings. Every decoder self-registers.

### 4. Terminal Decode Classification
Do NOT show binary garbage in TEXT output.
When remaining content is encrypted/packed/compressed/binary/unsupported, show:
```
Terminal Decode State
Recovered maximum readable content.
Remaining content appears binary, encrypted or unsupported.
No further supported decoder matched.
```
Keep raw bytes available in HEX / Base64 / Raw. Do not lose evidence.

### 5. Decode Confidence
Separate:
- Recovery Status (Fully / Partially / Terminal / Failed)
- Decode Confidence (decoding success)
- Threat Confidence (maliciousness)
- Family Confidence (attribution)

Never show 0% Decode Confidence if the engine recovered commands / IOCs / MITRE / LOLBAS / URLs / domains / behavior / threat summary.

### 6. Output Layout (order)
Recovered Payload → Recovered Commands → Decode Status → Terminal Reason → Threat Summary → Behavior Summary → MITRE ATT&CK → LOLBAS → IOCs → Detection Logic → Threat Intel Correlation → OSINT Correlation → Recommendations → Investigation Summary.

Do not mix report text inside recovered payload. Recovered payload always copyable.

### 7. Explain Every Decode
For every layer show: Detected Encoding, Reason detected, Decoder used, Confidence, Output length, Output preview, Next decoder selected, Why next decoder was selected. When decoding stops, explain exactly why.

### 8. Threat Intelligence Correlation
Auto-correlate after decoding: MITRE, LOLBAS, Sigma, YARA, IOC/URL/domain/hash/IP reputation, malware families, behavioral patterns, campaign indicators, previously ingested TI / OSINT / KB. Explain why each correlation matched. Never invent matches.

### 9. Performance
Bounded execution. Prevent infinite recursion, duplicate layers, repeated outputs, recursive loops. Benchmark every new decoder. No regression.

### 10. Accuracy Requirements
- Recover every mathematically recoverable layer.
- NEVER fabricate decoded content.
- Never misrepresent encrypted/binary as plaintext.
- Preserve complete evidence.
- Prefer "Partial Decode with explanation" over incorrect "Fully Decoded."
- Zero false-positive IOCs introduced by decoder.
- Every enhancement must pass regression + benchmark + prod smoke before release.

---

## Suggested release breakdown (small, benchmark-gated)

- **RC2.4** — 4 UI polish items above
- **RC2.5** — Intelligent command-line classifier (spec §1) + Terminal Decode UI (§4)
- **RC2.6** — Recursive layer explanation (§7) + Recovery Status labels (§5)
- **RC2.7** — PowerShell P0.3 (`[char]` polish, ScriptBlock, IEX chains) + CMD reconstruction
- **RC2.8** — JavaScript / VBScript reconstruction
- **RC2.9** — Threat Intelligence Correlation (§8)
- **RC3.0** — XOR 9-16 byte keys + new families (XWorm, NjRAT, RedLine, FormBook, Emotet)

Each release: one benchmark, one commit block, one deploy.
