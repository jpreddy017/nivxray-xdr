# P0-1B · SCOPE CONTRACT · Universal Command Deobfuscation Engine

**Owner-locked 2026-09-02. This document is the authoritative scope
contract for P0-1B. Any agent executing P0-1B Phase 1 or Phase 2
MUST read this file first. Violations are automatic rejects.**

---

## Headline rule (never negotiate)

> **tommy-aa.lol proves the specific capability;**
> **the complete corpus proves the engine.**

`c*d.e?e → cmd.exe`, `c*u*r*l.e?e → curl.exe`, `p*ell.exe →
powershell.exe`, `h^t^t^p^s^:^/^/^t^o^m^m^y^-^a^a^.^l^o^l^/f →
https://tommy-aa.lol/f` is a MANDATORY REGRESSION. It is NOT the
engine's target. Passing it does NOT mean "universal command
deobfuscation is complete." Do NOT tune the engine for this sample.

---

## The engine must be tested against ALL available command-lines
## BEFORE it is allowed to claim capability expansion

Otherwise the engine could accidentally excel at tommy-aa.lol while
regressing existing PowerShell / Base64 / XOR / RC4 / AES / nested-
chain / benign-enterprise cases. That is feature progress but
product regression, and MUST be rejected.

Regression must be run against:

  A. Existing NivXRay decoder corpus
  B. Existing NivXRay command corpus
  C. P0-1 76-scenario corpus (immutable baseline)
  D. Existing historical regression suites
  E. Harvested external-project corpus (CyberChef / CMD-DeObfuscator /
     Invoke-DOSfuscation / Invoke-Obfuscation / PowerDecode /
     BatchDeobfuscator / …)
  F. New command-language semantic corpus (P0-1B additions)
  G. tommy-aa.lol mandatory regression

The engine is accepted only after comparison against all relevant
pre-existing behaviour.

---

## Three acceptance layers (all three must pass)

```
                UNIVERSAL DECODER
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Codec tests    Semantic tests   Full-chain tests
        │              │              │
   Base64/AES       CMD/PS/Bash     Real commandlines
   GZIP/XOR         variables       multi-stage
   Unicode          FOR/CALL        IOC/ATT&CK
                       │              │
                       └──────┬───────┘
                              ▼
                     COMPLETE CORPUS
                              │
                              ▼
                   ACCEPT / DO NOT ACCEPT
```

---

## Command-language coverage matrix (minimum)

### CMD
- caret escaping · quote manipulation · delayed expansion
- `%VAR%` · `!VAR!` · substring expansion · search/replace expansion
- environment-variable reconstruction · `SET` reconstruction
- `CALL` expansion · `FOR /F` · nested `FOR` · nested CMD
- `cmd /c` · `cmd /k` · `START` · pipes · redirection
- command concatenation · wildcard executable resolution
- `%COMSPEC%` · PATH-based executable resolution
- command substitution · token fragmentation

### PowerShell
- `-EncodedCommand` / `-enc` · Base64 · UTF-16LE
- string concatenation · string splitting · character arrays
- `[char]` · `[byte]` · `-join` · `-replace` · format strings
- variable indirection · environment variables · aliases
- invocation reconstruction · nested encoding
- compression · encoded/compressed payloads · multiple decode stages

### Bash / sh
- quoting · escaping · variable expansion · command substitution
- ANSI-C quoting · hex escapes · octal escapes
- string concatenation · command fragmentation · nested shell invocation

### Generic encoding
- Base16 · Base32 · Base36 · Base58 · Base64 (+ variants) · Base85
- hex · binary · octal · decimal character encoding
- URL encoding · Unicode · UTF variants · HTML/XML entities
- escaped strings

### Compression
- gzip · deflate · zlib · brotli · LZMA · XZ · Zstandard
- ZIP/archive-contained content where statically appropriate

### Crypto / byte transforms
- XOR · single-byte XOR · repeating-key XOR
- RC4 · AES · DES/3DES · Blowfish · Caesar/ROT
- substitution/byte transforms

### Recursive / multi-stage examples
- Base64 → UTF16LE → Base64
- Base64 → GZIP → PowerShell
- Base64 → XOR → shellcode indicator
- Base64 → GZIP → XOR → PowerShell
- CMD → encoded PowerShell → compressed payload
- CMD → variable reconstruction → URL
- PowerShell → string reconstruction → Base64 → payload

---

## Corpus discovery is mandatory (Phase 1 · read-only)

Before implementation, inventory ALL command-line samples already
available inside NivXRay/XDR:

- command-line test files
- golden corpora
- decoder corpora
- obfuscation corpora
- validation packs
- regression tests
- malware samples represented as command lines
- benign enterprise commands
- suspicious commands
- PowerShell samples · CMD samples · Bash/sh samples
- LOLBin commands · multi-stage commands · nested commands
- encoded commands · malformed commands · previously failing commands

**Do NOT assume the 76-scenario P0-1 corpus is sufficient.**
**Do NOT assume the decoder corpus is sufficient.**
Create an inventory of every command-line source.

---

## External-project harvest rules (Phase 1 · read-only)

For every source (CyberChef, CMD-DeObfuscator, Invoke-DOSfuscation,
Invoke-Obfuscation, PowerDecode, BatchDeObfuscator, others):

- Harvest applicable unit tests · fixtures · examples ·
  known-answer vectors · obfuscation samples · malformed samples
  · edge cases · recursive chains.
- Convert them into XDR-native STATIC regression tests.
- Do NOT copy implementation logic (Phase 2 concern, clean-room).
- The test corpus is equally important as the engine.

Classification per capability harvested:
`DECODER · DEOBFUSCATOR · TRANSFORM · PARSER · STATIC-ANALYZER ·
IOC · DETECTION · TEST-CORPUS · DYNAMIC (reject) · UI (reject) ·
IRRELEVANT (reject)`. Only static-safe capabilities enter the engine.

License hygiene: preserve Apache-2.0 / MIT / GPL obligations; if GPL
is incompatible, extract behavioural knowledge + test vectors + write
clean-room XDR-native implementation.

---

## Negative / benign corpus is MANDATORY

Include:
- normal Windows administration
- normal PowerShell administration
- software installation · patching · backup · monitoring
- developer commands · build commands · CI/CD commands
- legitimate encoded data · legitimate compressed data
- normal scripts · benign wildcard usage
- normal environment-variable usage

**Acceptance requires NO unnecessary benign FP increase.**

---

## Malformed / adversarial corpus is MANDATORY

Include malformed Base64 · Unicode · UTF-16 · compression · XOR ·
nested chains · broken CMD variables · incomplete caret escapes ·
malformed FOR statements · incomplete PowerShell expressions ·
truncated payloads · invalid encodings.

**Expected behaviour: PARTIAL / UNCERTAIN / UNRESOLVED.**
**Never fabricated reconstruction.**

---

## Absolute execution invariants

- All command-line testing is STATIC.
- Never execute CMD · PowerShell · Bash · shellcode · PE · scripts ·
  downloaders · URLs · decoded payloads.
- A test validates transformation / reconstruction, NOT execution.
- `DECODED ≠ EXECUTED`.
- Every layer keeps full provenance with
  `static_only=true, execution=false, attck_promotion=false`.
- LLM never authoritatively decodes.
- No dynamic execution of any language.

---

## Measurement contract (per-category, not one number)

Report Detection · Precision · Recall · F1 SEPARATELY for:
- CMD · PowerShell · Bash/sh
- generic encoding · compression · crypto/byte transforms
- command semantic reconstruction · recursive chains
- IOC extraction · ATT&CK evidence mapping

Also report:
- benign FP · malicious FN
- unresolved cases · partial decode cases
- false reconstructions · unsupported operations
- recursive depth
- latency p50 / p95 / p99

---

## Acceptance harness (test-every-command-line)

The harness MUST enumerate ALL available command-line samples
automatically. Do NOT manually select a small representative subset.

The test report MUST include:
- total command lines · tested command lines · passed · failed
- partially decoded · unsupported · false reconstruction
- benign FP · malicious FN
- category-level breakdown

---

## Documents to produce

Phase 1 (read-only, no engine implementation):
- `UNIVERSAL_DECODER_SOURCE_INVENTORY.md`
- `UNIVERSAL_DECODER_COVERAGE_MATRIX.md`
- `UNIVERSAL_DECODER_LICENSE_MATRIX.md`
- `UNIVERSAL_COMMAND_DEOBFUSCATION_CORPUS.md`
- `UNIVERSAL_COMMAND_DEOBFUSCATION_TEST_MATRIX.md` — columns:
  command/sample · language · obfuscation technique · source ·
  expected reconstruction · expected decoded layers · expected IOC ·
  expected ATT&CK evidence · expected verdict impact ·
  actual result · pass/fail · provenance verified ·
  static-only verified

Phase 2 (implementation, clean-room):
- Single XDR-owned `UniversalDecoderEngine` under `services/decoder/`
  with CMD / PowerShell / Bash / Base / Compression / Crypto /
  Recursive / Extraction sub-engines.
- No runtime bridge to any external project.

---

## Most important rule (verbatim from owner)

> Do NOT optimize for: "Can we decode tommy-aa.lol?"
>
> Optimize for: "Can NivXRay XDR deterministically reconstruct the
> semantics of real-world CMD, PowerShell and shell command lines
> across the full available corpus without execution, evidence
> fabrication, or regression?"
>
> tommy-aa.lol is ONE mandatory regression.
> The COMPLETE corpus is the acceptance target.
>
> STOP and report corpus coverage before declaring P0-1B complete.

---

## Anti-drift enforcement

- Do NOT let the engine pass on tommy-aa.lol alone.
- Do NOT let external tests silently drift into the runtime path.
- Do NOT copy code from GPL sources without a clean-room rewrite.
- Do NOT skip the benign / malformed / adversarial corpora.
- Do NOT declare P0-1B complete without per-category metrics vs
  the FULL harvested + existing + newly-generated corpus.
- **The engine must be tested against the command lines already
  present in NivXRay BEFORE it is allowed to claim capability
  expansion.** Feature progress + product regression = reject.
