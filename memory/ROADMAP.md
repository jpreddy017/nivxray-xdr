# NivXRay Roadmap — Post-RC2.3

**Baseline (frozen):** RC2.3 Stable, tagged `v1.0.0-RC2.3` on GitHub · 24/31 chain-complete (77.4%) · 0 FP-IOCs · deployed to `nivxray.nivxforge.com`

---

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
