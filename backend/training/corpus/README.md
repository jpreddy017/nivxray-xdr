# NivX Forge Training Corpus (v2 · Feb 2026)

Ground-truth samples for **fine-tuning the offline LLM** AND for **regression
testing** the deterministic decoder. Every sample carries the full ground
truth: expected plaintext, chain stages, IOCs, MITRE mapping, LOLBAS tags,
verdict, and confidence — so the corpus is simultaneously:

1. **A supervised fine-tuning dataset** for the offline model (Qwen 2.5 via
   Ollama today, any other model tomorrow).
2. **A regression test harness** — `test_training_corpus.py` walks every
   sample through `/api/decode/smart` and asserts the plaintext is recovered.
   Any decoder refactor that drops a shape flips a test red immediately.

## Files

| Path | Contents |
|---|---|
| `generator.py` | Deterministic v1 corpus builder. |
| `generator_v2.py` | v2 additions — real-world malware, LOLBAS, containers, encodings, crypto, reflection. |
| `samples.jsonl` | The full v1 + v2 corpus (one sample per line). |
| `negative_samples.jsonl` | Benign strings the model must NOT flag as malicious. |
| `../../tests/fixtures/corpus_*.txt` | Auto-mirrored fixture pairs consumed by `test_fixture_regression_matrix.py`. |

Regenerate with `python -m training.corpus.generator` from `/app/backend`. Idempotent — re-running produces byte-identical JSONL.

## Schema

```json
{
  "id":               "base64_utf16le_001",
  "category":         "base64_utf16le",
  "input":            "powershell -EncodedCommand SQBFAFgA...",
  "expected_decoded": "IEX (New-Object Net.WebClient)....",
  "chain_stages":     [{"op": "base64-decode", "output_preview": ""}],
  "iocs":             {"urls": [...], "domains": [...], "ips": [...]},
  "mitre":            [{"id": "T1059.001", "tactic": "execution", "technique": "PowerShell"}],
  "lolbas":           ["powershell"],
  "verdict":          "Malicious | Suspicious | Benign",
  "confidence":       0..100,
  "notes":            "one-line SOC context"
}
```

## Category totals

- **v1 categories (10 × 5 = 50 samples):**
  1. `base64_utf16le` — `powershell -EncodedCommand ...`
  2. `double_base64` — `Base64(Base64(cmd))`
  3. `gzip_base64` — PS `IO.Compression.GzipStream`
  4. `deflate_base64` — PS `IO.Compression.DeflateStream`
  5. `xor_ascii_decimal_iex` — Hancitor-shape XOR + ASCII decimal + IEX
  6. `xor_base64` — Base64 → XOR (analyst-provided key comment `# xor-key 0xNN`)
  7. `hex_bytes` — Raw hex ASCII payload
  8. `decimal_ascii` — Comma-separated ASCII decimal stream
  9. `base32_rfc4648`
  10. `rot13`

- **v2 categories (39 × 5 = 195 samples):**
  - **A. Real-world malware families** — `lumma_stealer`, `clickfix`, `asyncrat_stager`
  - **B. LOLBAS wrappers** — `lolbas_mshta`, `lolbas_rundll32`, `lolbas_regsvr32`, `lolbas_msiexec`, `lolbas_certutil`, `lolbas_bitsadmin`, `lolbas_msbuild`, `lolbas_installutil`, `lolbas_wmic`, `lolbas_schtasks`, `lolbas_reg_run`
  - **C. Container/script formats** — `hta_javascript`, `vbscript_execute`, `js_eval_atob`, `office_macro`, `lnk_launcher`, `onenote_embed`, `iso_lnk_wrapper`, `zip_password_paste`
  - **D. Encoding variants** — `triple_base64`, `url_encoding`, `octal_ascii`, `unicode_escapes`, `caret_escaping_cmd`, `env_var_expansion`, `string_concat_iex`, `char_arrays`, `join_split`, `format_operator`, `reverse_strings`, `batch_var_slicing`
  - **E. Crypto layers** — `aes_cbc_analyst` (`xfail`, live decrypt is v3), `rc4_analyst`, `multi_stage_b64_gz_xor`
  - **F. Reflection / in-memory loaders** — `reflection_assembly_load`, `shellcode_virtualalloc`

**Totals:** 49 categories × 5 = **245 supervised samples + 10 negative controls**.

## Known xfails (regression suite)

| Category | Reason |
|---|---|
| `aes_cbc_analyst` (×5) | Live AES-CBC decrypt with parsed analyst-provided key/IV — v3 target |
| `double_base64_001` | 2-char plaintext ("id") — magic min-length is 3 |
| `base64_utf16le_004` | Start-BitsTransfer scoring path returns wrapper text |

All other 250 samples PASS `/api/decode/smart` end-to-end (~85s parallel run on 2 xdist workers).

## v3 roadmap

- Confusion Matrix Dashboard (`/api/training/confusion`) — precision / recall / FP / FN per category
- Live AES / RC4 decrypt from analyst comments (`# key(b64): …`)
- TAXII 2.1 push endpoint
- Offline Ollama / Qwen fine-tune pipeline consuming this JSONL directly
