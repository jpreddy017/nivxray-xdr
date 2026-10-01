# Universal Decoder, DDO Orchestrator & Deobfuscation Pipeline

**Category Directory**: `05_DECODERS/`  
**Authoritative Source Reference**: All source files referenced herein reside authoritatively in [`../01_COMPLETE_SOURCE/`](../01_COMPLETE_SOURCE/).  
**Total Associated Files**: 135 files  
**Total Category Size**: 1.20 MB  
**Total Lines of Code / Documentation**: 29,779 lines  

---

## Purpose & Scope

Deterministic Multi-Layer Deobfuscation, Command Reconstruction Engine (CRE), and Central Codec Registry.

## Unified Decoder Architecture & Invariants

NivXRay XDR enforces **ONE unified decoding architecture** with zero silent loss. Deobfuscation layers never overwrite history; every stage emits discrete `CanonicalDecodedLayer` records.

### Architecture Classification:
* **Deterministic Decoder Orchestrator (DDO)**: `services/decoder/orchestrator.py` — Multi-candidate race and fixed-point unwrapping.
* **Universal Decoder Engine**: `services/decoder/engine.py` — CMD Plane-B caret unescaping, environment variable reassembly.
* **Recursive Multi-Layer Decoder**: `services/die/preprocessor/recursive_decoder.py` — Plane-A payload peeling (Base64, GZIP, UTF-16LE, XOR, Hex).
* **Decoder Bridge**: `services/decoder_bridge/__init__.py` — Projects recursive layers into canonical child evidence with full provenance.
* **Decoder Registry**: `engine/registry.py` — Central registry containing:
  - **47 General-Purpose BaseCodecs**
  - **14 Malware-Family Profilers**
* **Specialized Codecs**:
  - `decoders/batch_envvar_substitute.py` — Variable substitution (`%VAR:from=to%`)
  - `decoders/js_reconstruct.py` — JS `fromCharCode`, `atob`, string concatenations
* **Verified Runtime Proof**: `backend/verify_decoder_truth_e2e.py` certifies 10 operational cases end-to-end.


---

## Associated File Index (Authoritative Paths in `01_COMPLETE_SOURCE/`)

| Relative Source Path | Size (Bytes) | Lines | Type | Status |
| :--- | :---: | :---: | :---: | :---: |
| [`01_COMPLETE_SOURCE/backend/decoders/__init__.py`](../01_COMPLETE_SOURCE/backend/decoders/__init__.py) | 302 | 7 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ascii85.py`](../01_COMPLETE_SOURCE/backend/decoders/ascii85.py) | 3,267 | 80 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/base32.py`](../01_COMPLETE_SOURCE/backend/decoders/base32.py) | 2,639 | 63 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/base58.py`](../01_COMPLETE_SOURCE/backend/decoders/base58.py) | 3,137 | 80 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/base64.py`](../01_COMPLETE_SOURCE/backend/decoders/base64.py) | 6,116 | 142 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/base91.py`](../01_COMPLETE_SOURCE/backend/decoders/base91.py) | 4,321 | 116 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/batch_envvar_substitute.py`](../01_COMPLETE_SOURCE/backend/decoders/batch_envvar_substitute.py) | 6,550 | 164 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/brotli_stream.py`](../01_COMPLETE_SOURCE/backend/decoders/brotli_stream.py) | 2,946 | 70 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/caesar.py`](../01_COMPLETE_SOURCE/backend/decoders/caesar.py) | 3,460 | 89 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/charcode_decoders.py`](../01_COMPLETE_SOURCE/backend/decoders/charcode_decoders.py) | 7,695 | 193 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/cmd_reconstruct.py`](../01_COMPLETE_SOURCE/backend/decoders/cmd_reconstruct.py) | 10,228 | 269 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/cmd_runtime_reconstruct.py`](../01_COMPLETE_SOURCE/backend/decoders/cmd_runtime_reconstruct.py) | 36,608 | 842 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/cobaltstrike_beacon_config.py`](../01_COMPLETE_SOURCE/backend/decoders/cobaltstrike_beacon_config.py) | 9,911 | 240 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/crypto_api_annotator.py`](../01_COMPLETE_SOURCE/backend/decoders/crypto_api_annotator.py) | 7,413 | 117 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/crypto_symmetric.py`](../01_COMPLETE_SOURCE/backend/decoders/crypto_symmetric.py) | 565 | 14 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/custom_hex_slash.py`](../01_COMPLETE_SOURCE/backend/decoders/custom_hex_slash.py) | 6,020 | 152 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/data_uri.py`](../01_COMPLETE_SOURCE/backend/decoders/data_uri.py) | 3,037 | 87 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/extract_wrapper.py`](../01_COMPLETE_SOURCE/backend/decoders/extract_wrapper.py) | 14,267 | 329 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/__init__.py`](../01_COMPLETE_SOURCE/backend/decoders/families/__init__.py) | 637 | 16 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/_base.py`](../01_COMPLETE_SOURCE/backend/decoders/families/_base.py) | 7,501 | 181 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/agenttesla.py`](../01_COMPLETE_SOURCE/backend/decoders/families/agenttesla.py) | 3,071 | 71 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/asyncrat.py`](../01_COMPLETE_SOURCE/backend/decoders/families/asyncrat.py) | 2,552 | 60 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/cobalt_strike.py`](../01_COMPLETE_SOURCE/backend/decoders/families/cobalt_strike.py) | 3,197 | 74 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/darkgate.py`](../01_COMPLETE_SOURCE/backend/decoders/families/darkgate.py) | 2,485 | 58 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/emotet.py`](../01_COMPLETE_SOURCE/backend/decoders/families/emotet.py) | 5,495 | 115 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/formbook.py`](../01_COMPLETE_SOURCE/backend/decoders/families/formbook.py) | 4,457 | 95 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/lumma.py`](../01_COMPLETE_SOURCE/backend/decoders/families/lumma.py) | 2,713 | 62 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/meterpreter.py`](../01_COMPLETE_SOURCE/backend/decoders/families/meterpreter.py) | 3,112 | 68 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/njrat.py`](../01_COMPLETE_SOURCE/backend/decoders/families/njrat.py) | 4,114 | 90 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/quasarrat.py`](../01_COMPLETE_SOURCE/backend/decoders/families/quasarrat.py) | 2,611 | 63 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/redline.py`](../01_COMPLETE_SOURCE/backend/decoders/families/redline.py) | 4,917 | 101 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/remcos.py`](../01_COMPLETE_SOURCE/backend/decoders/families/remcos.py) | 2,466 | 61 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/snake_keylogger.py`](../01_COMPLETE_SOURCE/backend/decoders/families/snake_keylogger.py) | 3,059 | 71 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/families/xworm.py`](../01_COMPLETE_SOURCE/backend/decoders/families/xworm.py) | 6,223 | 124 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/gzip_stream.py`](../01_COMPLETE_SOURCE/backend/decoders/gzip_stream.py) | 1,807 | 49 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/hex.py`](../01_COMPLETE_SOURCE/backend/decoders/hex.py) | 2,695 | 66 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/html_unicode_escape.py`](../01_COMPLETE_SOURCE/backend/decoders/html_unicode_escape.py) | 6,148 | 163 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ioc_extractor.py`](../01_COMPLETE_SOURCE/backend/decoders/ioc_extractor.py) | 8,826 | 213 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/js_reconstruct.py`](../01_COMPLETE_SOURCE/backend/decoders/js_reconstruct.py) | 7,777 | 232 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/jwt.py`](../01_COMPLETE_SOURCE/backend/decoders/jwt.py) | 3,385 | 99 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/lzma_stream.py`](../01_COMPLETE_SOURCE/backend/decoders/lzma_stream.py) | 3,183 | 79 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/nibble_swap.py`](../01_COMPLETE_SOURCE/backend/decoders/nibble_swap.py) | 4,366 | 117 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ps_alias_normalizer.py`](../01_COMPLETE_SOURCE/backend/decoders/ps_alias_normalizer.py) | 11,294 | 302 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ps_backtick_normalizer.py`](../01_COMPLETE_SOURCE/backend/decoders/ps_backtick_normalizer.py) | 8,934 | 225 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ps_encodedcommand_multilayer.py`](../01_COMPLETE_SOURCE/backend/decoders/ps_encodedcommand_multilayer.py) | 6,071 | 151 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ps_hex_escape.py`](../01_COMPLETE_SOURCE/backend/decoders/ps_hex_escape.py) | 5,571 | 142 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ps_inline_eval.py`](../01_COMPLETE_SOURCE/backend/decoders/ps_inline_eval.py) | 7,454 | 171 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ps_normalizer.py`](../01_COMPLETE_SOURCE/backend/decoders/ps_normalizer.py) | 13,542 | 324 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ps_reconstruct.py`](../01_COMPLETE_SOURCE/backend/decoders/ps_reconstruct.py) | 19,750 | 534 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ps_reverse_swap.py`](../01_COMPLETE_SOURCE/backend/decoders/ps_reverse_swap.py) | 3,944 | 99 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/ps_semantic_mini.py`](../01_COMPLETE_SOURCE/backend/decoders/ps_semantic_mini.py) | 4,243 | 105 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/rc40_orchestrator_plugins.py`](../01_COMPLETE_SOURCE/backend/decoders/rc40_orchestrator_plugins.py) | 17,690 | 353 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/rc4_inline_decrypt.py`](../01_COMPLETE_SOURCE/backend/decoders/rc4_inline_decrypt.py) | 4,234 | 115 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/reverse_string.py`](../01_COMPLETE_SOURCE/backend/decoders/reverse_string.py) | 6,033 | 144 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/rot13.py`](../01_COMPLETE_SOURCE/backend/decoders/rot13.py) | 2,204 | 55 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/rot47.py`](../01_COMPLETE_SOURCE/backend/decoders/rot47.py) | 1,954 | 55 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/url.py`](../01_COMPLETE_SOURCE/backend/decoders/url.py) | 2,311 | 59 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/utf16.py`](../01_COMPLETE_SOURCE/backend/decoders/utf16.py) | 3,770 | 104 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/vbs_reconstruct.py`](../01_COMPLETE_SOURCE/backend/decoders/vbs_reconstruct.py) | 6,707 | 180 | `implementation` | `PRE_EXISTING` |
| [`01_COMPLETE_SOURCE/backend/decoders/xor_brute.py`](../01_COMPLETE_SOURCE/backend/decoders/xor_brute.py) | 704 | 17 | `implementation` | `PRE_EXISTING` |

*... and 75 more files. Refer to [`DECODER_MANIFEST.json`](./DECODER_MANIFEST.json) for the exhaustive JSON catalog.*
