# NivXRay: A Deterministic-First Candidate-Scored Decoder & Threat-Attribution Framework for Cyber-Attack Payloads

**Author:** J. Hernandez (`jana017` on GitHub) — creator, NivXRay project
**Version:** 1.0 · Defensive-publication draft
**Date:** February 2026
**License:** CC-BY-4.0 (free to copy/redistribute with attribution)
**Prior-art disclosure notice:** This document is published for defensive purposes. It describes technical methods implemented in the NivXRay open-source project (https://github.com/jana017/NivXRAY_NivXForge, public since July 2026) and is offered as prior art against subsequent patent applications covering the same or substantially similar methods.

---

## Abstract

We present **NivXRay**, an open-source decoder and threat-attribution framework for cyber-attack payloads that combines (i) a deterministic candidate-scored decoding pipeline, (ii) a named "wrapper-archetype" dispatcher that maps regex+heuristic-matched inputs to first-class handlers producing verifiable outputs, (iii) a recursive reasoning engine that iteratively unwraps layered obfuscation while preserving auditability, and (iv) a parallel emitter that renders a single decoded payload as multiple detection artefacts — Sigma YAML, Sysmon Event 1 XML, MITRE ATT&CK mappings, YARA-lite rules, and Kill-Chain graphs. The framework introduces novel techniques for (a) confidence-scored encoding detection with a "why-not" breakdown for rejected candidates, (b) blind single-byte XOR recovery scored by printable-ratio + magic-byte + English-keyword bonus with baseline-delta gating, and (c) plaintext short-circuiting to prevent AI hallucination on already-decoded inputs. All methods are described in sufficient detail to serve as prior art.

**Keywords:** malware decoding, obfuscation reversal, MITRE ATT&CK, threat-intel enrichment, defensive publication, LOLBAS, XOR cryptanalysis, Sigma rules, Sysmon rules

---

## 1. Introduction

Attackers routinely obfuscate their payloads using multi-layered encodings: base64, gzip, XOR, ROT13, hex, ASCII-decimal joins, PowerShell `-EncodedCommand`, reversed strings, wildcard-glob path resolution, and combinations thereof. Existing tools (CyberChef [1], FLARE, Didier Stevens' scripts [2], YARA [3], Detect-It-Easy) address individual sub-problems but do not offer:
- a unified pipeline that produces a **confidence-scored decoded output** with rejected-candidate rationale
- **first-class named archetype handlers** for known obfuscation patterns (e.g., "reversed-base64 terminal", "hex-family with per-nibble marker substitution")
- **parallel emission** of Sigma + Sysmon + MITRE + YARA + Kill-Chain from a single decoded payload
- **plaintext short-circuiting** to prevent LLM-based decoders from hallucinating on already-decoded inputs

NivXRay addresses all four gaps in one framework. This paper describes the methods with sufficient specificity to serve as prior art.

## 2. Background & Prior Art

| System | Year | Strengths | Gaps addressed by NivXRay |
|---|---|---|---|
| CyberChef [1] | 2016 | Recipe-based interactive decoding | No confidence scoring; no automatic archetype recognition; no threat attribution |
| YARA [3] | 2014 | Rule-based static pattern matching | No decoding; rules must match ciphertext directly |
| FLARE / floss | 2016 | String extraction from binaries | No live commandline decoding; no MITRE mapping |
| Sigma-CLI [4] | 2018 | Sigma rule generation from analyst input | Requires human authoring; no automatic derivation from decoded payload |
| Didier Stevens scripts [2] | 2010–present | Individual per-encoding tools | Not integrated; no confidence scoring |
| MITRE ATT&CK Navigator | 2018 | Technique visualization | Manual mapping; no automatic attribution |

**Key differentiators of NivXRay:** deterministic + verifiable + explainable + multi-emission — with plaintext-guard and blind-XOR recovery as distinct novel methods.

## 3. Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────┐
│                     INPUT (raw payload string)                        │
└──────────────────────┬────────────────────────────────────────────────┘
                       │
                       ▼
             ┌─────────────────────┐
             │ 1. Plaintext Guard  │  ← §4.4
             │ (short-circuit if   │
             │  already decoded)   │
             └─────────┬───────────┘
                       │
                       ▼
       ┌───────────────────────────────────┐
       │ 2. Candidate Encoding Enumerator  │  ← §4.1
       │ Scores 40+ encoding candidates,   │
       │ produces ranked list + why-not    │
       └─────────────┬─────────────────────┘
                     │
                     ▼
       ┌────────────────────────────────────┐
       │ 3. Wrapper-Archetype Dispatcher    │  ← §4.2
       │ 70+ named handlers (regex+match)   │
       │ Terminal short-circuit flag        │
       └─────────────┬──────────────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
┌───────────────┐        ┌──────────────────┐
│ 4. Recursive  │        │ 5. Blind XOR /   │
│ Reasoning     │        │  brute-force     │  ← §4.3
│ engine        │        │  (last-resort)   │
└───────┬───────┘        └────────┬─────────┘
        │                         │
        └────────────┬────────────┘
                     ▼
      ┌─────────────────────────────────┐
      │ 6. Parallel Detection Emitters  │  ← §4.5
      │ • Sigma YAML                    │
      │ • Sysmon Event 1 XML + XPath    │
      │ • MITRE ATT&CK mapping          │
      │ • YARA-lite rules               │
      │ • IOC extraction (with shell-   │
      │   metachar-aware URL parsing)   │
      │ • Kill-Chain graph              │
      └─────────────────────────────────┘
```

## 4. Novel Methods

### 4.1 Candidate Encoding Enumerator with "Why-Not" Rationale

**Problem:** Existing decoders greedy-select one encoding. When they guess wrong (which happens on multi-layer obfuscation), the analyst has no visibility into which alternatives were considered or why they were rejected.

**Method:** For each layer, enumerate up to N candidate encodings (base64, hex, url-encode, gzip, zlib, snappy, rot13, reverse, ASCII-decimal, char-array-decimal, xor-known-key, unicode-escape-\uNNNN, backslash-hex-escape, etc.). For each candidate produce a tuple:

```
(candidate_id, score ∈ [0.0, 1.0], decode_bytes, why_not_reasons)
```

Where `score` is computed from a weighted sum of:
- printable-ASCII ratio of decoded output (weight w₁)
- IOC-presence bonus (URL, IP, path, cmdlet) (weight w₂)
- MITRE-marker bonus (weight w₃)
- structural-plausibility (e.g., base64 padding alignment) (weight w₄)
- deterministic magic-byte hits (MZ, PK, %PDF, <html) (weight w₅)

The `why_not_reasons` field is a **list of human-readable rejection tokens** for every candidate that did NOT win, such as:
- `"decoded output <5% printable"`
- `"base64 padding misaligned"`
- `"no MITRE markers post-decode"`
- `"reverse-only decode yielded lower score than base64+reverse"`

This produces an audit trail suitable for SOC analyst review and compliance evidence.

**Distinguishing prior art:** CyberChef surfaces recipes but has no candidate scoring; YARA has no decoding. To our knowledge, no prior system emits a ranked list of decoded candidates with explanatory rejection tokens.

### 4.2 Wrapper-Archetype Dispatcher with Terminal Short-Circuit

**Problem:** Layered obfuscation often follows known idioms (e.g., "PowerShell `-e` → base64 → UTF-16LE → invoke", or "ASCII decimals joined via ForEach [char]" or "reversed-base64 with `==` prefix"). A generic recursive decoder either times out or matches the wrong operation.

**Method:** Maintain a registry of **named archetype handlers** where each archetype declares:

```python
{
    "id":          "PS_MSF_XOR_Stage2",
    "description": "human-readable",
    "chain":       ["hex-decode", "xor-with-derived-key"],  # for docs
    "match":       lambda text: bool,   # regex + heuristic gate
    "handler":     lambda text: str,    # produces decoded output
    "terminal":    bool,                # if True, dispatcher stops here
}
```

The dispatcher iterates all archetypes. For each: if `match(text)` is True, call `handler(text)`; if the output differs from input, adopt it as the new layer. If `terminal=True`, halt the outer recursive loop for that branch. This prevents runaway recursion on blind-XOR-style handlers that would otherwise chain infinitely.

**Distinguishing prior art:** CyberChef recipes are hand-authored per input; there is no automatic archetype-dispatch model in prior art we are aware of.

### 4.3 Blind Single-Byte XOR Recovery with Baseline-Delta Gating

**Problem:** When an XOR-encrypted payload arrives with an unknown key (common in Cobalt Strike beacons, IcedID loaders, Emotet doc-macros), analysts brute-force all 256 keys manually. Automated systems either try nothing (miss the decode) or fire indiscriminately (false-positive noise).

**Method:** Given a hex- or base64-decoded byte-string `raw`:

1. Compute `baseline_score = _score_xor_plaintext(raw)` — the score of the un-XORed bytes
2. If `baseline_score ≥ 1.00`, RETURN unchanged (the raw bytes are already readable; no XOR needed)
3. For k in 1..255:
   - `candidate = raw ⊕ k`
   - `score = _score_xor_plaintext(candidate)`
   - Track best (k, score, candidate)
4. If `best_score < 0.90` OR `best_score - baseline_score < 0.20`, RETURN unchanged
5. Otherwise EMIT: `(k, decoded_bytes, score, baseline_score)` as a banner + decoded plaintext

Where `_score_xor_plaintext(raw)` is:
```
score = printable_ratio(raw)
      + 0.60  if raw starts with magic byte (MZ, PK\x03\x04, %PDF, ELF, PNG, GIF, JPEG, 7z)
      + min(0.40, 0.08 × count(english_keywords in raw.lower()))
      + 0.20  if 0.08 ≤ space_ratio ≤ 0.30
      + 0.25  if lowercase_alpha_ratio ≥ 0.35
        else 0.10  if lowercase_alpha_ratio ≥ 0.20
capped at 3.0
```

**Baseline-delta gating** is the key novel step — it prevents the algorithm from firing on inputs where the raw bytes are already readable (in which case no XOR key genuinely improves the output). This eliminates a whole class of false-positives that a naïve "brute-force + pick-highest-score" implementation would produce.

### 4.4 Plaintext Short-Circuit for LLM-Assisted Decoders

**Problem:** LLM-driven decoders (like ChatGPT integrations for security triage) hallucinate on plaintext commandlines — they propose transformations (base64, rot13, reverse) that don't apply. The naive fallback ("if no valid decoding, return input") makes the LLM output *identical* to the input, which is confusing to analysts who wonder "why did AI DECODE reverse my output back to input?"

**Method:** Before invoking the LLM (or any other decoder), run `_is_already_plaintext(text)`:

```
Return TRUE iff ALL of:
  (a) len(text) ≥ 4
  (b) printable_ratio ≥ 0.95
  (c) NO regex match for:
      • long base64 run   [A-Za-z0-9+/]{40,}={0,2}
      • long hex run      \b[0-9A-Fa-f]{32,}\b
      • -EncodedCommand   -e(?:c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}
      • url-encoding      ≥10 %XX pairs
      • gzip/zlib magic   \x1f\x8b, \x78\x9c, \x78\x01, \x78\xda
      • HTML-entity chain ≥8 &#N; occurrences
      • \xNN backslash-hex ≥8
      • \uNNNN unicode-escape ≥6
  (d) at least ONE positive-marker regex hits:
      cmd/powershell/[a-z]:\\..\\/http(s)://.../{lolbas-name}.exe/iex/curl/sudo/osascript/…
      OR at least 5 English words of length 3-30
```

When TRUE, the decoder endpoint short-circuits with:
```
{ "stopped_gracefully": true,
  "message": "Input already appears to be plaintext — use ANALYZE for MITRE + IOC + verdict." }
```

This is a **novel guard** that prevents LLM-induced hallucination on already-decoded inputs and provides clear next-step guidance to the analyst.

### 4.5 Parallel Multi-Format Detection Emission from a Single Decoded Payload

**Problem:** After decoding, analysts must manually author Sigma rules, Sysmon config fragments, MITRE mappings, and YARA rules. Each authoring step introduces analyst drift (different phrasings for the same technique).

**Method:** From the single decoded payload + extracted IOC set + LOLBAS matches + MITRE hits, emit in parallel (deterministically, no LLM):

1. **Sigma YAML** — standard Sigma format with `detection: selection: CommandLine|contains: [...]` blocks built from discriminating tokens (cmdlets, LOLBIN flags, file paths, URLs, domains).
2. **Sysmon Event 1 (ProcessCreate) XML rule** — `<Rule name="…" groupRelation="and">…<Image condition="end with">…</Image>…<CommandLine condition="contains">…</CommandLine>…</Rule>` fragment ready to drop into `sysmon-config.xml`.
3. **Sysmon Event Viewer XPath query** — for immediate `Get-WinEvent -FilterXPath …` hunting.
4. **PowerShell Get-WinEvent one-liner** — analyst-ready hunt command.
5. **MITRE ATT&CK mapping** — sorted, deduplicated (technique_id, technique_name, tactic) triples.
6. **YARA-lite rules** — regex-based lightweight rules with severity + human-readable description.

All emitters share a common token-extraction function `_discriminating_tokens()` that filters plain English + very-short tokens, preserving only cmdlets, LOLBIN flags, file paths, and rare identifiers.

**Distinguishing prior art:** Sigma-CLI [4] and Uncoder.io convert *between* SIEM formats but do not derive rules from decoded payloads. To our knowledge, no prior system emits Sigma + Sysmon + MITRE + YARA in parallel from a single automatic decoding pass.

## 5. Detection Rule Schema (v1.2.0)

The framework's YARA-lite rules use a lightweight JSON schema:

```json
{
  "rule": "LOLBAS_Curl_Rename",
  "severity": "high",
  "pattern": "copy(?:\\.exe)?\\s+.*?\\\\curl\\.exe[\\\"']?\\s+[\\\"']?[^\\\\/\\s]+\\.(?:exe|com|bat|cmd|scr)",
  "desc":    "curl.exe copied to random name (LOLBAS rename tradecraft)"
}
```

40+ rules ship with v1.2.0 covering Windows LOLBAS, macOS (osascript / LaunchAgent / Gatekeeper / Keychain), Cloud/Identity (OAuth device-code phishing, illicit-consent, Teams webhook, MS Graph, AAD PRT, AWS keys), and cryptographic obfuscation (XOR indicator, blind-XOR).

## 6. Reference Implementation

A working reference implementation is publicly available under the MIT License at:
**https://github.com/jana017/NivXRAY_NivXForge**

Version 1.2.0 (tagged 2026-07-18) implements all methods described in this paper. Key source files:
- `backend/wrapper_archetypes.py` — 70+ archetype registry + dispatcher (§4.2)
- `backend/operations.py` — MITRE + YARA-lite emission + IOC extraction (§4.5)
- `backend/chain_analyzer.py` — recursive reasoning (§4.1)
- `backend/sigma_generator.py` — Sigma + Sysmon emitters (§4.5)
- `backend/routers/ai.py::_is_already_plaintext` — plaintext guard (§4.4)
- `backend/wrapper_archetypes.py::_handle_blind_xor` — blind XOR (§4.3)

## 7. Ethical Considerations

NivXRay is defensive tooling. It decodes attacker payloads to *aid analysts*, not to help operators build better obfuscation. All detection rules and archetypes are derived from public threat-intelligence sources (MITRE ATT&CK, LOLBAS project, abuse.ch feeds, Wikipedia's XOR-cipher entry, security-vendor writeups). No 0-day or non-public tradecraft is documented.

## 8. Conclusion

We disclose the technical methods underlying NivXRay v1.2.0 as prior art. Any subsequent patent application covering (i) confidence-scored candidate decoding with "why-not" rationale, (ii) wrapper-archetype dispatchers with terminal short-circuiting, (iii) baseline-delta-gated blind XOR recovery, (iv) LLM-guarding plaintext short-circuits, or (v) parallel Sigma+Sysmon+MITRE+YARA emission from a single decoded payload should be examined against this disclosure and the NivXRay v1.2.0 open-source release.

## References

[1] G. Gwilt, "CyberChef — the Cyber Swiss Army Knife," GCHQ, 2016. https://gchq.github.io/CyberChef/
[2] D. Stevens, "Didier Stevens' Analysis Scripts," https://blog.didierstevens.com
[3] V. M. Alvarez, "YARA — the pattern matching swiss knife," VirusTotal, 2014. https://virustotal.github.io/yara/
[4] "Sigma — Generic Signature Format for SIEM Systems," https://github.com/SigmaHQ/sigma
[5] MITRE Corporation, "ATT&CK — Adversarial Tactics, Techniques, and Common Knowledge," https://attack.mitre.org
[6] LOLBAS Project, "Living Off The Land Binaries, Scripts and Libraries," https://lolbas-project.github.io
[7] "XOR cipher," Wikipedia, https://en.wikipedia.org/wiki/XOR_cipher (accessed Feb 2026)
[8] Microsoft, "Sysmon — System Monitor," https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Appendix A · How to publish this as prior art

**Preferred venues (rank-ordered by defensive strength):**

1. **arXiv** — https://arxiv.org
   - Category: `cs.CR` (Cryptography and Security)
   - Requires endorsement if this is your first submission; ask a security researcher to endorse
   - Publishes in ~48 hours
   - Timestamped, immutable, indexed by patent examiners
   - Free

2. **IP.com Prior Art Database** — https://ip.com/publish-your-ip/
   - The industry-standard defensive publication venue
   - Costs $155-$255 per publication
   - Explicitly searched by USPTO examiners
   - Best defensive strength

3. **SSRN** — https://ssrn.com
   - Free
   - Timestamped
   - Not as heavily searched by patent examiners but still valid prior art

4. **Zenodo** — https://zenodo.org
   - Free, DOI-assigned, CERN-backed archive
   - Perfect for software + whitepaper pair

**Recommended combo:** arXiv (indexed, cited) + IP.com (patent-examiner-searched) + GitHub tag `v1.2.0-whitepaper` (immutable timestamp on the source of truth).

## Appendix B · Attribution & License

This whitepaper is released under **CC-BY-4.0**. Anyone may copy, redistribute, and adapt this document provided they credit the author.

Copyright © 2026 J. Hernandez. NivXRay software is separately licensed under MIT.
