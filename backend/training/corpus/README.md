# NivX Forge Training Corpus (v1 · Feb 2026)

Ground-truth samples for **fine-tuning the offline LLM** AND for **regression
testing** the deterministic decoder. Every sample carries the full ground
truth: expected plaintext, chain stages, IOCs, MITRE mapping, LOLBAS tags,
verdict, and confidence — so the corpus is:

1. **A supervised fine-tuning dataset** for the offline model (Qwen 2.5 via
   Ollama today, any other model tomorrow).
2. **A regression test harness** — `test_training_corpus.py` walks every
   sample through `/api/decode/smart` and asserts the plaintext is recovered.
   Any decoder refactor that drops a shape flips a test red immediately.

## Files

| Path | Contents |
|---|---|
| `generator.py` | Deterministic corpus builder — regenerate the whole set with `python -m training.corpus.generator`. |
| `samples.jsonl` | The corpus (one sample per line, schema below). |
| `negative_samples.jsonl` | Benign strings the model must NOT flag as malicious. |
| `../../tests/fixtures/corpus_*.txt` | Auto-mirrored fixture pairs consumed by `test_fixture_regression_matrix.py`. |

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

## v1 categories (this release · 10 × 5 = 50 samples + 10 negatives)

1. `base64_utf16le` — `powershell -EncodedCommand ...`
2. `double_base64` — `Base64(Base64(cmd))`
3. `gzip_base64` — PS `IO.Compression.GzipStream` in-memory loader
4. `deflate_base64` — PS `IO.Compression.DeflateStream`
5. `xor_ascii_decimal_iex` — Hancitor-shape XOR + ASCII decimal + IEX
6. `xor_base64` — Base64 → XOR (with key hint)
7. `hex_bytes` — Raw hex-encoded ASCII payload
8. `decimal_ascii` — Comma-separated ASCII decimal stream
9. `base32_rfc4648` — Base32 payload
10. `rot13` — Simple substitution

## Roadmap (v2 · +35 categories)

Category | Notes
---|---
`triple_base64` | 3-layer Base64
`base85_ascii85` | Python + Adobe variants
`base91` | Rare in malware; still seen occasionally
`octal_ascii` | `110 145 154 154 157`
`binary_split` | Already covered by archetype; add fixtures
`caesar_shift` | Non-13 shifts
`url_encoding` | `%68%74%74%70...`
`unicode_escapes` | `\u0068\u0074...`
`caret_escaping` | `po^wer^shell`
`env_var_expansion` | `%COMSPEC%`, `%TEMP%`
`string_concatenation` | `'Inv'+'oke'+'-Expression'`
`char_arrays` | `[char[]](73,69,88)`
`join_split` | `-join`, `-split`
`format_operator` | `"{1}{0}"-f ...`
`reverse_strings` | `[array]::Reverse(...)`
`aes_cbc` / `rc4` | Common loaders
`clickfix` | Fake CAPTCHA copy-paste chains
`lolbas_mshta` / `_rundll32` / `_regsvr32` / `_certutil` | Individual per LOLBAS
`batch_var_slicing` | `%var:~x,y%`
`vbscript_execute` | `Execute(CreateObject(...))`
`js_eval_atob` | `eval(atob())`
`hta_javascript` | `mshta javascript:`
`wmi_process_call` | `wmic process call create`
`schtasks_persistence` | Scheduled tasks
`registry_run_keys` | `reg add ... Run`
`lnk_launchers` | LNK abuse fingerprints
`amsi_bypass` | Reflection techniques
`reflection_loading` | `[Reflection.Assembly]::Load()`
`shellcode_virtualalloc` | Byte arrays + VirtualAlloc
`multi_stage_chains` | Base64→Gzip→XOR→IEX

## Regeneration

```
cd /app/backend
python -m training.corpus.generator
```

Idempotent — re-running produces byte-identical JSONL (deterministic RNG-free
encoders) so the corpus can be checked into git without diff noise.
