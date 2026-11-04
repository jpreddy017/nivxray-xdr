# Diagnostic Report — RC4 → Shellcode Handoff (2026-02-28)

_Read-only diagnostic. **Nothing has been written to `REAL_WORLD_LOG.md`,
scorecard, `CIO`, ADR folder, or any code file.** This report may
change your R2 decision about drafting ADR-0002._

---

## 0 · Headline (one line)

**The observed "RC4 → shellcode gap" does NOT exist as originally
hypothesised.** The 220 T1027.013 rows are dominated by PowerShell
integer-array XOR patterns (the Case 0001 archetype) mislabelled as
RC4 shellcode by the `crypto-detect` op. Actual RC4 shellcode
encryption in the corpus is ~13 rows, not 220.

---

## 1 · What was measured

- Corpus: 220 rows tagged `MITRE:T1027.013 · RC4 shellcode`
  (or engine name containing `rc4`).
- Source: `workspace_cases` (protected) + `investigations` (E2b filter).
- Question: is the 1.0% `reached_shellcode` rate a pipeline gap or a
  corpus artefact?

## 2 · What was found

**`reached_shellcode` rate:** 1 / 220 = **0.5%** across this bucket.

### The single case that DID reach shellcode

| chain | out_len | confidence | source |
|---|---:|---:|---|
| `ps-reconstruct → extract-payload → base64-decode → crypto-detect → family-meterpreter` | 73 | 0 | investigations |

This case terminates in `family-meterpreter` — a genuine shellcode
signature. Its chain looks nothing like the other 219 rows.

### The 219 cases that did NOT

**Chain-op frequency across the 219:**

| op | count | interpretation |
|---|---:|---|
| `powershell-xor-inline-key` | **187 (85%)** | Case 0001 archetype — PowerShell integer-array + inline XOR key |
| `crypto-detect` | 118 | tags "XOR cipher" as tradecraft signal, feeds the T1027.013 label |
| `ioc-extract` | 65 | text-based IOC extraction |
| `extract-payload` | 42 | intermediate |
| `family-emotet` | 28 | family-classifier hit |
| `powershell-alias-normalize` | 22 | pre-normalizer |
| **`rc4-inline-decrypt`** | **13 (5.9%)** | *actual RC4 decoder* — this is the true RC4 population in the corpus |
| `ps-reconstruct` | 9 | |
| `family-cobaltstrike` | 7 | |

**Zero of the 219 chains contain a `shellcode`-named op.** There is
no dropped hand-off — the pipeline never chose to invoke a shellcode
analyzer, because the input never was shellcode.

### Sample of the 219 non-shellcode payloads (output heads)

```
powershell -NonInter "((97,68,95,66,83,27,126,89,69,66,22,17,126,83,90,90,89,22,...
powershell -nop -w hidden "((88,84,73,49,57,120,102,99,49,60,100,99,120,49,54,...
((\n    125, 88, 67, 94, 79, 7, 98, 69, 89, 94, 10, 13, 122, 125, 100, 111, 110, ...
powershell -nop -w hidden "((70,99,120,101,116,60,89,126,98,101,49,54,98,112,...
powershell -nop -w hidden "((99,111,114,10,2,67,93,88,10,13,66,94,94,90,16,5,5,...
powershell -nop -w hidden "((127,88,64,89,93,83,27,115,78,70,68,83,69,69,95,89,...
```

Every sample is a **PowerShell integer-array + `-bxor` key pattern**
— the same archetype we handled in Case 0001. None is actual RC4
shellcode encryption.

### Corpus-shape distribution

| Category | Count | % |
|---|---:|---:|
| PowerShell XOR pattern (Case 0001 family) | ~187 | ~85% |
| Uses genuine `rc4-inline-decrypt` decoder | 13 | 5.9% |
| Genuine shellcode reached (`family-meterpreter`) | 1 | 0.5% |
| Other (base64, url-decode fragments, etc.) | ~19 | 8.6% |

---

## 3 · Why this matters

The T1027.013 label is being applied by `crypto-detect` on the basis
of a **generic XOR-cipher signature**, without distinguishing:

- (a) **PowerShell string-XOR obfuscation** — Case 0001 family, benign
  or malicious depending on payload, NOT true "RC4 shellcode
  encryption" — no shellcode reached because there IS no shellcode.
- (b) **True RC4 shellcode encryption** — represented by the 13 rows
  with `rc4-inline-decrypt` and the 1 row that reached
  `family-meterpreter`.

MITRE T1027.013 is defined as "Encrypted/Encoded File" specifically for
**RC4** — a stream cipher applied to malicious binary blobs. The
PowerShell integer-array `-bxor` pattern is more accurately covered by
**T1027.010 (Command Obfuscation)** and/or **T1140 (Deobfuscate/Decode
Files or Information)**.

## 4 · What this changes

### Regarding **Candidate ADR-0002 (RC4 → IOC Bridge)**

**Recommendation: DO NOT draft ADR-0002 in its current form.**

The evidence hypothesized for it does not exist as described. The
`reached_shellcode` rate is low because 85% of the T1027.013-tagged
rows are not shellcode-carrying inputs — they are PowerShell XOR
scripts whose plaintext, once decoded, may itself contain no shellcode
at all. That is not a pipeline gap; it is correct engine behavior on
non-shellcode input.

### Regarding **Candidate ADR-0001 (Command-Line Obfuscation Coverage)**

**Recommendation: EVIDENCE FOR ADR-0001 IS STRONGER THAN THE INVENTORY
REPORT SUGGESTED.**

Adding the 187 mislabelled PowerShell XOR rows to the T1027.010
bucket (where they properly belong) gives:

| MITRE ID | Original count | Re-attributed count | Total |
|---|---:|---:|---:|
| T1027.010 (Command Obfuscation) | 414 | +187 | **~601** |
| T1027.013 (RC4 shellcode) | 220 | −187 | **~33** |

That's a substantially cleaner picture: **~601 real command-obfuscation
cases**, of which the Case 0001 archetype is the single most common
sub-pattern.

### Regarding a **new, smaller candidate**

The diagnostic surfaces a real, evidence-supported issue:

**Candidate ADR-0004 — MITRE Attribution Accuracy for PowerShell XOR**
- Supporting evidence: 187 rows currently mis-attributed to T1027.013
- Pattern: `crypto-detect` fires on generic XOR-cipher signature and
  the T1027.013 label is applied unconditionally; distinguishing
  PowerShell XOR-obfuscation from true RC4 shellcode encryption
  requires only a lightweight input-shape check (integer-array +
  IEX-style pipeline vs binary blob input to `rc4-inline-decrypt`).
- North Star linkage: Intelligence Layer · MITRE Engine
- Charter linkage: Rule 3 (evidence-backed conclusions) — the current
  label is not evidence-backed.
- Scope: small, deterministic rule refinement, zero engine additions.

---

## 5 · Recommended R2 revision

Given the diagnostic, I would revise the earlier Decision R2 options:

- (r2a) Draft **ADR-0001** (Command-Line Obfuscation Coverage) — **evidence stronger than before, now ~601 rows**
- (r2b) ~~Draft ADR-0002 (RC4 → IOC bridge)~~ **withdrawn**
- (r2b-new) Draft **ADR-0004** (MITRE Attribution Accuracy for PowerShell XOR) — small, high-confidence, deterministic
- (r2c) Draft both ADR-0001 and ADR-0004
- (r2d) Draft none — inspect a handful of the 187 mislabelled rows manually first

---

## 6 · What was NOT done in this diagnostic

- ❌ No writes to `REAL_WORLD_LOG.md`
- ❌ No scorecard update
- ❌ No CIO write
- ❌ No ADR drafted
- ❌ No code change
- ❌ No Workspace file modified
- ✅ Read-only queries against MongoDB only
- ✅ One new report file created here for your review

---

## 7 · Standing by for your call

Awaiting your revised R2 decision (r2a / r2b-new / r2c / r2d), and
your call on whether to move Candidate ADR-0002 into a "withdrawn"
status inside the earlier Evidence Inventory. 🛰️
