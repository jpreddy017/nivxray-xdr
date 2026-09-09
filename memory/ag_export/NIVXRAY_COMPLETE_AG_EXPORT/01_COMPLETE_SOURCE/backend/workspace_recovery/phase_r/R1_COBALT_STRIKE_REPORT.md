# Phase R1 · Cobalt Strike Coverage Report

**Family**: Cobalt Strike (Empire · Nishang · Invoke-CradleCrafter lineage)
**Version**: `r1-1.0.0`
**Sample count**: 30 (foundation pack)
**DCS**: **100.0%** (30/30 canonical convergence)
**Fingerprints locked**: 30/30 byte-identical to recorded canonical output
**Regressions on certification corpus (17 samples)**: **0**
**Strict-mode CI regression tests**: **62/62 passing** (`tests/test_phase_r1_cobalt_strike.py`)

## Sample distribution by variant

| Variant | Samples |
|---|:---:|
| iex_downloadstring_classic | 1 (CS001) |
| iex_downloadstring_lowercase | 1 (CS002) |
| iwr_useb_iex_pipeline / iwr_https_useb_iex | 2 (CS003, CS013) |
| string_concat_url_scheme_split / two_var / full_url / split_scheme | 4 (CS004, CS005, CS006, CS015) |
| powershell_encodedcommand_iex_cradle / _direct / _writehost_r1 / _getprocess_discovery / _reflective_assembly_load | 5 (CS007, CS017, CS022, CS027, CS028) |
| powershell_enc_short_writehost / nop_noni_wh_enc_flags | 2 (CS008, CS009) |
| cmd_powershell_enc_handoff / cmd_carets_ps_enc_handoff / caret_ps_enc_emotet_style / caret_over_ps_enc_iex | 4 (CS010, CS011, CS021, CS024) |
| env_slice_string_join_reconstruction | 1 (CS012) |
| curl_alias_useb_iex | 1 (CS014) |
| hex_over_b64_over_utf16le | 1 (CS016) |
| backtick_alias_noise_iwr_iex / backtick_iwr_useb_iex_sq / iwr_iex_backtick_on_iex | 3 (CS018, CS025, CS029) |
| sq_var_propagate_iex / three_var_concat_chain | 2 (CS019, CS020) |
| ps_encodedcommand_ie_alias | 1 (CS023) |
| random_case_iex_downloadstring | 1 (CS026) |
| iex_downloadstring_https_loader_ps1 | 1 (CS030) |
| **Total** | **30** |

## Obfuscation surface exercised

- **Alias expansion**: `iex`, `iwr`, `curl` (alias-only), backticked variants
- **Case obfuscation**: fully randomized case in cmdlets and aliases
- **Backtick noise**: `i` `w` `r`, `i` `e` `x`, embedded within identifiers
- **String concatenation folding**: 2-var, 3-var, and 4-part URL splits
- **Single-assignment SQ variable propagation**: `$u='http...'; iex ...`
- **Base64 `-EncodedCommand`**: full form, abbreviations `-Enc`, `-enc`
- **UTF-16LE decoding**: post-base64
- **Nested Hex \u2192 Base64 \u2192 UTF-16LE chains**
- **CMD caret stripping** (`c^m^d /c p^ow^ers^he^ll`)
- **CMD \u2192 PowerShell interpreter handoff** (Emotet-style staging)
- **Environment variable slicing + `[string]::Join` reconstruction**

## MITRE ATT&CK coverage (aggregated across the pack)

- `T1059.001` PowerShell command interpretation
- `T1059.003` Windows Command Shell (CMD handoff)
- `T1105` Ingress Tool Transfer (download cradle)
- `T1027` Obfuscated Files or Information
- `T1027.010` Command Obfuscation
- `T1140` Deobfuscate/Decode Files or Information
- `T1057` Process Discovery
- `T1564.003` Hidden Window
- `T1620` Reflective Code Loading

## Behavior taxonomy exercised

- `download_and_execute`
- `remote_code_execution`
- `obfuscated_command_line`
- `beacon_staging`
- `cmd_to_ps_handoff`
- `backtick_obfuscation`
- `case_obfuscation`
- `env_var_slicing`
- `multi_layer_obfuscation`
- `reflective_load`
- `hidden_window`
- `process_discovery`

## Operational surfaces

- **Loader**: `workspace_recovery.phase_r.r1_loader`
- **Corpus file**: `workspace_recovery/phase_r/families/cobalt_strike.json`
- **Builder** (source of truth for input strings): `workspace_recovery/phase_r/build_cobalt_strike.py`
- **Fingerprint generator**: `workspace_recovery/phase_r/r1_fingerprint_generator.py`
- **DCS runner**: `workspace_recovery/phase_r/r1_runner.py`  (add `--strict` for CI)
- **Strict pytest gate**: `tests/test_phase_r1_cobalt_strike.py`

## Regeneration protocol (byte-locked)

```bash
cd /app/backend
python -m workspace_recovery.phase_r.build_cobalt_strike        # regenerate inputs
python -m workspace_recovery.phase_r.r1_fingerprint_generator   # relock fingerprints
python -m workspace_recovery.phase_r.r1_runner --strict         # verify
python -m pytest tests/test_phase_r1_cobalt_strike.py -q        # CI gate
python -m workspace_recovery.dcs_runner --strict                # verify M8 corpus untouched
```

## Roadmap · what's next in R1

- Emotet (30\u201350 samples)
- QakBot (30\u201350 samples)
- GootLoader (30\u201350 samples)
- DarkGate, BumbleBee, IcedID, AsyncRAT, Lumma, SocGholish, NetSupport, Akira, Raspberry Robin

Each family follows the exact same schema and CI pattern. The infrastructure created in this pass (`r1_loader`, `r1_runner`, `r1_fingerprint_generator`, per-family builder) is reusable for every subsequent family with zero engine changes.
