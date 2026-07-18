# NivXRay · Auto-Archetype Learner — Walkthrough Report

**Run**: 2026-07-18T09:40:00Z  ·  **Samples submitted**: 6

---

## 1. Purpose of the Learner

The Learner is a **content-engineering pipeline** — NOT an end-user analyst tool. Its job:

1. **Analyst submits** a payload that failed to decode + the expected output
2. Engine extracts features (entropy, charset, b64/hex ratio, LOLBAS tokens, bigrams)
3. Engine assigns a **cluster key** (e.g. `printable|small|b64|-|-`)
4. Similar failures collect in the same cluster
5. Engine **proposes a candidate archetype** (Python code stub + regex + decode chain + confidence)
6. Analyst reviews the proposal, refines the code, runs NXGEC regression gate
7. If regression passes → **admin approves** → merges into `wrapper_archetypes_learned.py`
8. If it breaks anything → rolled back

Think of it as: **"crowdsourced training data → auto-scaffolded archetype code → gated release."**

---

## 2. What we submitted (6 diverse samples)

| # | Sample | Tradecraft | Sample ID |
|---|---|---|---|
| 1 | macOS Amos Stealer — AppleScript wrapper | macOS · osascript | `134990eb` |
| 2 | Cobalt Strike Malleable C2 — hex+bxor | PowerShell · single-byte XOR | `d5b03468` |
| 3 | GCP Service Account JWT | Cloud · GCP · JWT | `c180f111` |
| 4 | AWS Cognito ID Token abuse | Cloud · AWS · Cognito | `755ed7ce` |
| 5 | VBScript character-code payload | VBS · char-code obfuscation | `fc0d2cb0` |
| 6 | PowerShell reflection AmsiScanBuffer patch | PowerShell · AMSI bypass | `6870cd02` |

---

## 3. Automatic clustering (from the engine)

The engine automatically grouped our 6 samples into 5 clusters based on features:

| Cluster Key | Members | Interpretation |
|---|---|---|
| `printable|small|b64|-|-` | 4 | Short printable text with some b64 chars — the default catch-all |
| `base64|medium|b64|-|-` | 2 | Mostly-base64 string, medium length — JWT-like tokens landed here |
| `printable|small|-|esc|-` | 1 | Small printable with escape sequences (e.g. `\x`, `\u`) |
| `base64|small|b64|-|lol` | 1 | Small b64 blob PLUS a LOLBAS binary token detected |
| `printable|small|b64|-|lol` | 1 | Small printable with some b64 chars AND a LOLBAS token (cmd/rundll32/wscript) |

**Insight**: 4 of our 6 samples collapsed into the same generic cluster (`printable|small|b64|-|-`). The engine noticed they *look* similar (short printable text, some base64 chars) but had zero domain knowledge to differentiate `osascript`, `bxor`, or `AMSI reflection`. **This is the first weakness surfaced.**

---

## 4. Auto-generated proposals (per sample)

### Sample 1: macOS Amos Stealer — AppleScript wrapper
- **Proposed archetype**: `LEARNED_PRINTABLE_SMALL_B64_N_N`
- **Decode chain proposed**: `base64-decode`
- **Confidence**: **55**/100
    - regex=5 · entropy=20 · charsets=15 · decode_path=5 · corpus_match=10
- **Why**: charset ~75% base64 alphabet; proposed decode chain: base64-decode
- **Why not (missing signals)**: no explicit byte-escape markers; no stable wrapper regex could be lifted
- **Recommendation**: *Need 2-3 more sibling samples to strengthen the pattern.*

### Sample 2: Cobalt Strike Malleable C2 — hex+bxor
- **Proposed archetype**: `LEARNED_PRINTABLE_SMALL_B64_N_N`
- **Decode chain proposed**: `base64-decode`
- **Confidence**: **85**/100
    - regex=35 · entropy=20 · charsets=15 · decode_path=5 · corpus_match=10
- **Why**: wrapper regex candidate: `FromBase64String\(\s*['\"](?P<b64>[A-Za-z0-9+/=]+)['\"]\s*\)`; charset ~70% base64 alphabet; proposed decode chain: base64-decode
- **Why not (missing signals)**: no explicit byte-escape markers
- **Recommendation**: *Need 2-3 more sibling samples to strengthen the pattern.*

### Sample 3: GCP Service Account JWT
- **Proposed archetype**: `LEARNED_BASE64_MEDIUM_B64_N_N`
- **Decode chain proposed**: `base64-decode`
- **Confidence**: **55**/100
    - regex=5 · entropy=20 · charsets=15 · decode_path=5 · corpus_match=10
- **Why**: charset ~99% base64 alphabet; proposed decode chain: base64-decode
- **Why not (missing signals)**: no explicit byte-escape markers; no stable wrapper regex could be lifted
- **Recommendation**: *Need 2-3 more sibling samples to strengthen the pattern.*

### Sample 4: AWS Cognito ID Token abuse
- **Proposed archetype**: `LEARNED_BASE64_MEDIUM_B64_N_N`
- **Decode chain proposed**: `base64-decode`
- **Confidence**: **55**/100
    - regex=5 · entropy=20 · charsets=15 · decode_path=5 · corpus_match=10
- **Why**: charset ~99% base64 alphabet; proposed decode chain: base64-decode
- **Why not (missing signals)**: no explicit byte-escape markers; no stable wrapper regex could be lifted
- **Recommendation**: *Need 2-3 more sibling samples to strengthen the pattern.*

### Sample 5: VBScript character-code payload
- **Proposed archetype**: `LEARNED_PRINTABLE_SMALL_B64_N_LOL`
- **Decode chain proposed**: `base64-decode → lolbas-annotate`
- **Confidence**: **90**/100
    - regex=35 · entropy=20 · charsets=15 · decode_path=10 · corpus_match=10
- **Why**: wrapper regex candidate: `WScript`; charset ~71% base64 alphabet; LOLBAS token(s): wscript; proposed decode chain: base64-decode → lolbas-annotate
- **Why not (missing signals)**: no explicit byte-escape markers
- **Recommendation**: *Need 2-3 more sibling samples to strengthen the pattern.*

### Sample 6: PowerShell reflection AmsiScanBuffer patch
- **Proposed archetype**: `LEARNED_PRINTABLE_SMALL_B64_N_N`
- **Decode chain proposed**: `base64-decode`
- **Confidence**: **55**/100
    - regex=5 · entropy=20 · charsets=15 · decode_path=5 · corpus_match=10
- **Why**: charset ~80% base64 alphabet; proposed decode chain: base64-decode
- **Why not (missing signals)**: no explicit byte-escape markers; no stable wrapper regex could be lifted
- **Recommendation**: *Need 2-3 more sibling samples to strengthen the pattern.*

---

## 5. Honest assessment of what happened

### ✅ What worked well
- All 6 samples ingested cleanly · unique IDs · feature extraction fired · clustering fired
- The engine correctly identified the base64 alphabet ratio for the JWTs
- Sample 5 (VBScript char-code with LOLBAS token) got the **highest confidence (90)** because it had both a b64 hint AND a LOLBAS token — a stronger signal cluster
- Every sample got a code scaffold generated (`_match_XXX` + `_handle_XXX` Python stubs)

### 🐛 What's weak (be honest)

1. **The generated wrapper regex is `^\s*$`** — a placeholder that matches empty strings only. It's a scaffold, not a working detector. The analyst has to **manually write the real regex** afterward. This is a big "jobs done here" mismatch: the UI promises "auto-archetype" but delivers stubs.

2. **Decode chain proposed is just `base64-decode`** for AmsiScanBuffer patch, GCP JWT, AWS Cognito, and Cobalt Strike XOR — **that's wrong for 3 of the 4**. JWTs need `.split('.')[1] → base64url-decode → JSON parse`. XOR needs a brute-force key scanner. AMSI needs static-analysis of the reflection call.

3. **All 4 unrelated samples clustered together** as `printable|small|b64|-|-` — meaning the cluster key isn't discriminative enough. Two AWS/GCP JWTs *did* land in their own cluster (`base64|medium|b64|-|-`), which is better, but still doesn't tell you "this is a JWT."

4. **Confidence scores don't reflect real accuracy** — 55/100 for all except one. The `entropy=20, charsets=15` breakdown suggests the scoring is heuristic and not calibrated to real decode success.

5. **No LLM assistance in code generation** — the code stub is templated, not synthesised. An LLM-powered version would examine the payload structure and propose a real regex + real decode logic.

### 🎯 The Learner's actual value proposition (today)

It's a **workflow scaffolder + regression-gated merge tool**, not an automatic archetype writer. Its real value:
- Prevents shipping regex changes that break existing tests (NXGEC gate)
- Gives content engineers a starting-point Python file with the right shape
- Tracks provenance: who submitted the failure, what expected output, when merged
- Enables rollback: every merge is versioned

### 🔮 What it SHOULD become

A. **LLM-powered code generation** — feed the payload + expected output to Claude, ask it to draft the regex + handler. Currently: templated stub.

B. **Cluster-level intelligence** — instead of 4 samples in `printable|small|b64|-|-`, cluster them by *semantic intent* ("cloud-token-abuse", "process-injection-loader", "amsi-bypass").

C. **Interactive refinement** — analyst pastes payload → engine proposes 3 candidate regexes → analyst picks one → engine tests against corpus.

D. **Public contribution mode** — external analysts submit failures via a web form (with hash-only dedup for privacy), authors get credit in changelog.

---

## 6. Full raw dataset

Full JSON with every request/response is saved alongside this file:

- **JSON**: `learner_walkthrough_sample.json` (raw API responses)
- **Markdown**: `learner_walkthrough_report.md` (this file)

---

*Generated on 2026-07-18 by NivXRay v1.3.0-preview*