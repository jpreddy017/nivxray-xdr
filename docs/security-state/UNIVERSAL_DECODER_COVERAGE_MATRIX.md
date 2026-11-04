# NivXRay XDR — Universal Content Analysis & Deobfuscation Coverage Matrix

## Executive Summary

This matrix establishes the authoritative capability status across all content categories in NivXRay XDR. 
Status is proven across nine dimensions: **Discovered**, **Registered**, **Routed**, **Runtime Reachable**, **Tested**, **Output Retained**, **API Exposed**, **UI Visible**, and **Semantically Analyzed**.

---

## 1. Text & Character Encodings

| Capability | DISCOVERED | REGISTERED | ROUTED | RUNTIME_REACHABLE | TESTED | OUTPUT_RETAINED | API_EXPOSED | UI_VISIBLE | SEMANTICALLY_ANALYZED | Current Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **ASCII / Extended ASCII** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Native string normalization |
| **UTF-8** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Native canonical parser |
| **UTF-16LE Interleaved Nulls**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/utf16.py` |
| **UTF-16BE / UTF-32** | ✓ | ⚠️ Partial | ⚠️ Partial| ⚠️ Partial | ⚠️ Partial| ✓ | ✓ | ✓ | ⚠️ Partial| Codec planned in text normalizer |
| **Unicode Escapes (\uXXXX)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `html_unicode_escape.py` |
| **Unicode Normalization (NFKD)**| ✓ | ⚠️ Partial | ⚠️ Partial| ⚠️ Partial | ⚠️ Partial| ✓ | ✓ | ✓ | ⚠️ Partial| Planned in string preprocessor |
| **Homoglyph Detection** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Cyrillic/Greek confusables detector planned |
| **Bidi / Control-Char Stripping**| ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | RLO/LRO spoofing detector planned |
| **URL / Percent Encoding** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/url.py` |
| **HTML Entities** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `html_unicode_escape.py` |
| **Hex / Base16** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/hex.py` |
| **Custom Hex Slash (/x..)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `custom_hex_slash.py` |
| **Base32** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/base32.py` |
| **Base36** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Base36 encoder planned |
| **Base58 (Bitcoin/IPFS)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/base58.py` |
| **Base64 (Standard & URL-safe)**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/base64.py` |
| **Base85 / ASCII85** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/ascii85.py` |
| **Base91** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/base91.py` |
| **Data URI Scheme (RFC 2397)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/data_uri.py` |
| **JWT Claims Extraction** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/jwt.py` |

---

## 2. Compression & Container Formats

| Capability | DISCOVERED | REGISTERED | ROUTED | RUNTIME_REACHABLE | TESTED | OUTPUT_RETAINED | API_EXPOSED | UI_VISIBLE | SEMANTICALLY_ANALYZED | Current Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **GZIP Stream Decompression** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/gzip_stream.py` |
| **ZLIB / DEFLATE** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/zlib_deflate.py` |
| **Brotli Stream** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/brotli_stream.py` |
| **LZMA / XZ Stream** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/lzma_stream.py` |
| **Zstandard (ZSTD)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/zstd_stream.py` |
| **ZIP Container (PK\x03\x04)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `recipe_planner.py` / `zipfile` |
| **TAR Archive** | ✓ | ⚠️ Partial | ⚠️ Partial| ⚠️ Partial | ⚠️ Partial| ✓ | ✓ | ✓ | ⚠️ Partial| Python `tarfile` integration queued |
| **7z Archive** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Header detection & py7zr planned |
| **RAR Archive (Rar!\x1a\x07)** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Signature detection planned |
| **CAB Container (MSCF)** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Cabinet header detector planned |
| **ACE Archive Detection** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | `**ACE**` magic detection queued |

---

## 3. Cryptographic Transforms

| Capability | DISCOVERED | REGISTERED | ROUTED | RUNTIME_REACHABLE | TESTED | OUTPUT_RETAINED | API_EXPOSED | UI_VISIBLE | SEMANTICALLY_ANALYZED | Current Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **Single-Byte XOR Brute Force**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `services/decoder/base/xor_brute.py` |
| **Repeating-Key XOR** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `xor_brute.py` |
| **ADD / SUB Transforms** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Arithmetic unroller planned |
| **Bitwise NOT Inversion** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Bitwise inverter planned |
| **ROL / ROR Bit Shifts** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Bitwise rotation planned |
| **Nibble Swap** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/nibble_swap.py` |
| **String Reverse** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/reverse_string.py` |
| **Caesar Shift (1-25)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/caesar.py` |
| **ROT13 Alphabetic Substitution**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/rot13.py` |
| **ROT47 ASCII Substitution** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `decoders/rot47.py` |
| **RC4 Inline Stream Decryptor** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `rc4_inline_decrypt.py` |
| **AES-CBC Block Decryptor** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `services/decoder/base/crypto.py` |
| **AES-GCM Authenticated Decrypt**| ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | GCM parameter recovery planned |

---

## 4. Script & Command Obfuscation

| Capability | DISCOVERED | REGISTERED | ROUTED | RUNTIME_REACHABLE | TESTED | OUTPUT_RETAINED | API_EXPOSED | UI_VISIBLE | SEMANTICALLY_ANALYZED | Current Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **PS -EncodedCommand** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `canonicalizer` & `ps_encodedcommand_multilayer.py` |
| **PS Backtick Normalization** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `ps_backtick_normalizer.py` |
| **PS Parameter Canonicalization**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `ps_normalizer.py` |
| **PS Alias Expansion (iex->...)**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `ps_alias_normalizer.py` |
| **PS Variable Reconstruction** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `ps_reconstruct.py` |
| **PS Hex CSV (`43,61,6c`)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `ps_inline_eval.py` |
| **PS Array Slicing Reversal** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `ps_reverse_swap.py` |
| **PS Regex Capture Swapping** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `ps_reverse_swap.py` |
| **PS Semantic Mini-Eval** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `ps_semantic_mini.py` |
| **CMD Caret Stripping (`c^a^l^c`)**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `cmd_reconstruct.py` |
| **CMD Quote Stripping (`"c"a"l"c`)**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `cmd_reconstruct.py` |
| **CMD Environment Variables** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `batch_envvar_substitute.py` |
| **CMD Substring (`%VAR:~0,1%`)**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `batch_envvar_substitute.py` |
| **Decimal / Octal Charcode** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `charcode_decoders.py` |
| **JavaScript Reconstructor** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `js_reconstruct.py` |
| **VBScript Reconstructor** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `vbs_reconstruct.py` |
| **Download Cradle Extractor** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active in `extract_wrapper.py` |

---

## 5. Security Runtime & Defensive Analysis (AMSI & Controls)

| Capability | DISCOVERED | REGISTERED | ROUTED | RUNTIME_REACHABLE | TESTED | OUTPUT_RETAINED | API_EXPOSED | UI_VISIBLE | SEMANTICALLY_ANALYZED | Current Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **AMSI Loading Detection** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | AST detection of `amsi.dll` load mapped |
| **AmsiScanBuffer Patch Scan** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Memory patching signatures mapped |
| **AMSI Context Nullification** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | `amsiContext` reflection patterns mapped |
| **AMSI Provider Degradation** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | Registry provider hijacking detection mapped |
| **ETW Patching Detection** | ✓ | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | ⚠️ Gap | `EtwEventWrite` patching signatures mapped |
| **Security Control Degradation** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active via Detection Rule Pack (T1562.001) |
| **Token Tampering Indicators** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Active via Detection Rule Pack (T1134) |
