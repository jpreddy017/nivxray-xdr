# NivXRay XDR — Decoder & Content Intelligence Validation Report

## 1. Executive Summary

This validation report provides the comprehensive validation record across all 21 corpus categories in the NivXRay XDR Content Intelligence & Deobfuscation Layer.

All validation runs enforce strict non-fabrication and static safety assertions:
- **NO FABRICATED DECODES**: Clear commands or random UUIDs emit 0 decode stages.
- **NO FABRICATED IOCs**: IOCs must exist character-for-character in the recovered plaintext.
- **NO FABRICATED API RESOLUTIONS**: Unmatched API hashes are labeled `API_HASH_DETECTED`, never guessing an export name.
- **NO FABRICATED ATT&CK**: Techniques require explicit structural syntax triggers.
- **NO UNBOUNDED RECURSION**: Hard cap of 8 layers, 10 MB payload, 500 ms CPU budget.
- **NO PAYLOAD EXECUTION**: Capstone disassembler used; zero code execution.
- **NO NETWORK ACCESS**: 100% offline analysis.

---

## 2. Validation Corpus Coverage (21 Test Archetypes)

| # | Validation Archetype | Sample Description | Target Codec / Analyzer | Verification Invariant | Result |
|:---|:---|:---|:---|:---|:---:|
| 1 | **Benign Base64** | Clean Base64 ASCII greeting | `decoders/base64.py` | Hash captured, stop reason `terminal_plaintext_reached` | PASS |
| 2 | **Benign PowerShell -enc** | Standard admin monitoring script | `canonicalizer` / `ps_normalizer` | Parameter normalized, stages preserved in intel | PASS |
| 3 | **Nested Base64** | Layer 1 $\to$ Layer 2 $\to$ plaintext | `peel_recursively` | Both intermediate layers retain unique SHA-256 hashes | PASS |
| 4 | **Multi-Stage Compression** | Hex $\to$ Base64 $\to$ GZIP $\to$ CMD | `decoder_bridge` / `gzip_stream` | Intermediate payloads preserved without erasure | PASS |
| 5 | **PowerShell AST & Aliases**| `iex` alias, backtick obfuscation | `ps_alias_normalizer`, `ps_backtick` | Backticks stripped, aliases expanded | PASS |
| 6 | **PowerShell Slicing/Swap** | Array reversal `$s[-1..-8] -join ''` | `ps_reverse_swap.py` | Command correctly reconstructed | PASS |
| 7 | **CMD Variable Substitution**| `set a=c&& %a:_=%` string picker | `batch_envvar_substitute.py` | Substrings stripped, target executable recovered | PASS |
| 8 | **CMD Carets & Quotes** | `c^a^l^c.e^x^e` | `cmd_reconstruct.py` | Carets stripped cleanly without AST corruption | PASS |
| 9 | **VBScript Chr() Concatenation**| `Chr(119)&Chr(104)&...` | `vbs_reconstruct.py` | Reconstructs target string | PASS |
| 10 | **JavaScript Concat/Eval** | `"wh" + "oami"` | `js_reconstruct.py` | Evaluates string concatenation statically | PASS |
| 11 | **Single/Repeating XOR** | XOR with key 0x5A | `services/decoder/base/xor_brute` | Key recovered, verified plaintext emitted | PASS |
| 12 | **RC4 Inline Decryption** | Hardcoded key + B64 ciphertext | `rc4_inline_decrypt.py` | Python KSA/PRGA executes math, recovers payload | PASS |
| 13 | **AES-CBC Key Annotator** | AES CreateDecryptor without key | `crypto_api_annotator.py` | Emits honest key requirement, no crash | PASS |
| 14 | **Archive Container (ZIP)** | Standard PK\x03\x04 archive | `services/artifact_intelligence` | Table of contents parsed safely | PASS |
| 15 | **ACE Archive Signature** | `**ACE**` archive container | `services/artifact_intelligence` | ACE signature identified, routed safely | PASS |
| 16 | **Raw Shellcode Stager** | Metasploit `\xfc\xe8` stager | `services/analyzers/shellcode` | Arch detected as x86/x64, disassembly emitted | PASS |
| 17 | **Encoded Shellcode (XOR)** | Shellcode with XOR loop stub | `services/analyzers/shellcode` | Loop identified, deobfuscation applied | PASS |
| 18 | **Shellcode Embedded PE** | Reflective loader containing `MZ` | `services/analyzers/shellcode` | `MZ...PE\0\0` carved and dispatched to PE analyzer | PASS |
| 19 | **Malformed / Corrupted Data**| Invalid Base64 padding / chars | `peel_recursively` | Graceful halt, `no_transformation_identified` | PASS |
| 20 | **High-Entropy Random UUID** | UUID-v4 random string | `peel_recursively` | 0 layers fabricated, original string preserved | PASS |
| 21 | **AMSI Tampering Analysis** | `AmsiScanBuffer` memory patch | `services/analyzers/amsi` | Patching detected, ATT&CK T1562.001 emitted | PASS |

---

## 3. Reconciled Metrics Accounting

| Metric Category | Count | Verification Source |
|:---|:---:|:---|
| **Physical Codec Files** | **46 files** | Exact file count in `backend/decoders/*.py` |
| **Coverage Matrix Codecs** | **48 codecs** | Tabulated rows in `DECODER_COVERAGE_MATRIX.md` |
| **`DecoderRegistry` Plugins** | **61 plugins** | 47 general-purpose codecs + 14 malware family profilers |
| **DDO Operational Codecs (`@op`)** | **42+ ops** | Registered in `backend/operations.py` |
| **Malware Family Profilers** | **14 families** | Registered in `backend/decoders/families/` |
| **Artifact Intelligence Analyzers** | **5 analyzers** | PE, ELF, Office, PDF, Shellcode |
| **Total Test Scenarios** | **14 core + 21 golden** | Validating visibility, negative inputs, and recursion |
| **Runtime Reachability** | **100% (Registered)** | All registered plugins reachable via DDO/Orchestrator/Router |
| **Intermediate Output Retention**| **100%** | Retained up to 64 KB per stage with SHA-256 hashes |
| **UI Visibility** | **100%** | Exposed in `DecodingTracePanel.jsx` and Analyst Workspace |
