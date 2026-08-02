# Phase 5 · Hunk Validation — Runtime Proof

Each experiment ran the deterministic 11-sample corpus on `/tmp/wsp-bisect`
at HEAD `1a07de3` with the named hunk applied in isolation, then all three
together. Zero changes to `/app/backend`.

## Aggregate results

| Experiment | PASS |
|------------|:----:|
| `hunk_1_disable_rc22_preflight` | **10 / 11** |
| `hunk_2_append_not_insert` | **1 / 11** |
| `hunk_3_positional_ps_regex` | **1 / 11** |
| `hunk_4_ps_encodedcommand_abbrev` | **1 / 11** |
| `hunk_5_smart_ps_encoded_regex` | **1 / 11** |
| `combined_all_hunks` | **10 / 11** |

## Per-sample per-experiment

| Experiment | S001_ps_writeh | S01_ps_b64_utf | S02_bash_xxd_b | S03_cmd_caret_ | S04_ps_alias_h | S05_nested_b64 | S06_xor_obfusc | S07_rc4_openss | S08_unicode_ob | S09_hex_b64_gz | S10_bash_with_ |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `hunk_1_disable_rc22_preflight` | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `hunk_2_append_not_insert` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `hunk_3_positional_ps_regex` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `hunk_4_ps_encodedcommand_abbrev` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `hunk_5_smart_ps_encoded_regex` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `combined_all_hunks` | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### `hunk_1_disable_rc22_preflight` — 10 / 11

_hunk1 applied · rc22 preflight gated OFF_

| Sample | PASS | Ops |
|---|:-:|-----|
| `S001_ps_writehost_tweet` | ❌ | `['extract-payload', 'base64-decode', 'xor-brute', 'powershell-backtick-normalize` |
| `S01_ps_b64_utf16le` | ✅ | `['extract-b64', 'utf16le-or-utf8-decode']` |
| `S02_bash_xxd_b64_rev` | ✅ | `['extract-payload', 'base64-decode']` |
| `S03_cmd_caret_escaped` | ✅ | `['strip-carets', 'extract-b64', 'utf16le-or-utf8-decode']` |
| `S04_ps_alias_heavy` | ✅ | `['ps-string-concat']` |
| `S05_nested_b64_gzip` | ✅ | `['extract-payload', 'base64-decode', 'gzip-decompress']` |
| `S06_xor_obfuscated` | ✅ | `['ascii-decimal-decode', 'xor-brute', 'powershell-backtick-normalize', 'powershe` |
| `S07_rc4_openssl` | ✅ | `['extract-payload']` |
| `S08_unicode_obfuscation` | ✅ | `[]` |
| `S09_hex_b64_gzip_chain` | ✅ | `['hex-decode', 'base58-decode', 'xor-brute', 'powershell-backtick-normalize', 'p` |
| `S10_bash_with_powershell_comment` | ✅ | `[]` |

### `hunk_2_append_not_insert` — 1 / 11

_hunk2 applied · normalizers now append (not insert)_

| Sample | PASS | Ops |
|---|:-:|-----|
| `S001_ps_writehost_tweet` | ❌ | `['extract-payload', 'base64-decode', 'xor-brute', 'powershell-backtick-normalize` |
| `S01_ps_b64_utf16le` | ❌ | `['ps-encodedcommand-recovery', 'extract-payload', 'ioc-extract', 'family-emotet'` |
| `S02_bash_xxd_b64_rev` | ❌ | `['powershell-alias-normalize']` |
| `S03_cmd_caret_escaped` | ❌ | `['cmd-runtime-reconstruct', 'extract-payload', 'base64-decode', 'utf16le-or-utf8` |
| `S04_ps_alias_heavy` | ❌ | `['ps-reconstruct', 'powershell-alias-normalize', 'ioc-extract']` |
| `S05_nested_b64_gzip` | ❌ | `['extract-payload', 'base64-decode', 'crypto-detect']` |
| `S06_xor_obfuscated` | ✅ | `['ascii-decimal-decode', 'xor-brute', 'powershell-backtick-normalize', 'powershe` |
| `S07_rc4_openssl` | ❌ | `['rot47']` |
| `S08_unicode_obfuscation` | ❌ | `['extract-payload', 'ioc-extract', 'family-emotet']` |
| `S09_hex_b64_gzip_chain` | ❌ | `['hex-decode', 'base64-decode']` |
| `S10_bash_with_powershell_comment` | ❌ | `['powershell-alias-normalize']` |

### `hunk_3_positional_ps_regex` — 1 / 11

_hunk3 applied · PS-detection regex tightened to positional match_

| Sample | PASS | Ops |
|---|:-:|-----|
| `S001_ps_writehost_tweet` | ❌ | `['extract-payload', 'base64-decode', 'xor-brute', 'powershell-backtick-normalize` |
| `S01_ps_b64_utf16le` | ❌ | `['ps-encodedcommand-recovery', 'extract-payload', 'ioc-extract', 'family-emotet'` |
| `S02_bash_xxd_b64_rev` | ❌ | `['powershell-alias-normalize']` |
| `S03_cmd_caret_escaped` | ❌ | `['cmd-runtime-reconstruct', 'extract-payload', 'base64-decode', 'utf16le-or-utf8` |
| `S04_ps_alias_heavy` | ❌ | `['ps-reconstruct', 'powershell-alias-normalize', 'ioc-extract']` |
| `S05_nested_b64_gzip` | ❌ | `['extract-payload', 'base64-decode', 'crypto-detect']` |
| `S06_xor_obfuscated` | ✅ | `['ascii-decimal-decode', 'xor-brute', 'powershell-backtick-normalize', 'powershe` |
| `S07_rc4_openssl` | ❌ | `['rot47']` |
| `S08_unicode_obfuscation` | ❌ | `['extract-payload', 'ioc-extract', 'family-emotet']` |
| `S09_hex_b64_gzip_chain` | ❌ | `['hex-decode', 'base64-decode']` |
| `S10_bash_with_powershell_comment` | ❌ | `['powershell-alias-normalize']` |

### `hunk_4_ps_encodedcommand_abbrev` — 1 / 11

_hunk4 applied · both -EncodedCommand gates widened (multilayer + extract-payload)_

| Sample | PASS | Ops |
|---|:-:|-----|
| `S001_ps_writehost_tweet` | ❌ | `['extract-payload', 'base64-decode', 'xor-brute', 'powershell-backtick-normalize` |
| `S01_ps_b64_utf16le` | ❌ | `['ps-encodedcommand-recovery', 'extract-payload', 'ioc-extract', 'family-emotet'` |
| `S02_bash_xxd_b64_rev` | ❌ | `['powershell-alias-normalize']` |
| `S03_cmd_caret_escaped` | ❌ | `['cmd-runtime-reconstruct', 'extract-payload', 'base64-decode', 'utf16le-or-utf8` |
| `S04_ps_alias_heavy` | ❌ | `['ps-reconstruct', 'powershell-alias-normalize', 'ioc-extract']` |
| `S05_nested_b64_gzip` | ❌ | `['extract-payload', 'base64-decode', 'crypto-detect']` |
| `S06_xor_obfuscated` | ✅ | `['ascii-decimal-decode', 'xor-brute', 'powershell-backtick-normalize', 'powershe` |
| `S07_rc4_openssl` | ❌ | `['rot47']` |
| `S08_unicode_obfuscation` | ❌ | `['extract-payload', 'ioc-extract', 'family-emotet']` |
| `S09_hex_b64_gzip_chain` | ❌ | `['hex-decode', 'base64-decode']` |
| `S10_bash_with_powershell_comment` | ❌ | `['powershell-alias-normalize']` |

### `hunk_5_smart_ps_encoded_regex` — 1 / 11

_hunk5 applied · smart_decoder _PS_ENCODED_RE widened_

| Sample | PASS | Ops |
|---|:-:|-----|
| `S001_ps_writehost_tweet` | ❌ | `['extract-payload', 'base64-decode', 'xor-brute', 'powershell-backtick-normalize` |
| `S01_ps_b64_utf16le` | ❌ | `['ps-encodedcommand-recovery', 'extract-payload', 'ioc-extract', 'family-emotet'` |
| `S02_bash_xxd_b64_rev` | ❌ | `['powershell-alias-normalize']` |
| `S03_cmd_caret_escaped` | ❌ | `['cmd-runtime-reconstruct', 'extract-payload', 'base64-decode', 'utf16le-or-utf8` |
| `S04_ps_alias_heavy` | ❌ | `['ps-reconstruct', 'powershell-alias-normalize', 'ioc-extract']` |
| `S05_nested_b64_gzip` | ❌ | `['extract-payload', 'base64-decode', 'crypto-detect']` |
| `S06_xor_obfuscated` | ✅ | `['ascii-decimal-decode', 'xor-brute', 'powershell-backtick-normalize', 'powershe` |
| `S07_rc4_openssl` | ❌ | `['rot47']` |
| `S08_unicode_obfuscation` | ❌ | `['extract-payload', 'ioc-extract', 'family-emotet']` |
| `S09_hex_b64_gzip_chain` | ❌ | `['hex-decode', 'base64-decode']` |
| `S10_bash_with_powershell_comment` | ❌ | `['powershell-alias-normalize']` |

### `combined_all_hunks` — 10 / 11

_hunk_1 + hunk_2 + hunk_3 + hunk_4 applied together_

| Sample | PASS | Ops |
|---|:-:|-----|
| `S001_ps_writehost_tweet` | ❌ | `['extract-payload', 'base64-decode', 'xor-brute', 'powershell-backtick-normalize` |
| `S01_ps_b64_utf16le` | ✅ | `['extract-b64', 'utf16le-or-utf8-decode']` |
| `S02_bash_xxd_b64_rev` | ✅ | `['extract-payload', 'base64-decode']` |
| `S03_cmd_caret_escaped` | ✅ | `['strip-carets', 'extract-b64', 'utf16le-or-utf8-decode']` |
| `S04_ps_alias_heavy` | ✅ | `['ps-string-concat']` |
| `S05_nested_b64_gzip` | ✅ | `['extract-payload', 'base64-decode', 'gzip-decompress']` |
| `S06_xor_obfuscated` | ✅ | `['ascii-decimal-decode', 'xor-brute', 'powershell-backtick-normalize', 'powershe` |
| `S07_rc4_openssl` | ✅ | `['extract-payload']` |
| `S08_unicode_obfuscation` | ✅ | `[]` |
| `S09_hex_b64_gzip_chain` | ✅ | `['hex-decode', 'base58-decode', 'xor-brute', 'powershell-backtick-normalize', 'p` |
| `S10_bash_with_powershell_comment` | ✅ | `[]` |

## Approval verdict

**PARTIAL** — combined reaches 10/11. Investigate the remaining ❌ rows before promoting.