# Phase 3.5 · Behavior-linked Workspace Dependency Graph

This graph is derived from **runtime evidence** (Phase 3 A/B matrix),
not static-import inference. For every ❌ sample we identify the
current-tree op that is not in the baseline chain, locate its owning
source file, and walk the import graph upward toward `routers/ops.py`.
Test files, `.pytest_cache`, and the `workspace_recovery/` harness are
excluded from the walk so tests do not pollute the production chain.

## Evidence Summary — Modules Ranked by Behavioral Blast Radius

The following modules are the **candidate root causes of decoder
drift** between the v1.5.6 baseline and current HEAD. Ranking is by
how many divergent corpus samples touch them (higher = higher risk).
These become the working set for Phase 4 (root cause) and the
minimal-fork target list for Phase 6 (isolation).

| Rank | Module | Classification | Samples Affected |
|-----:|--------|----------------|-----------------:|
| 1 | `operations` | Behavioral (candidate for restore / isolation) | 6 |
| 2 | `magic_decoder` | Behavioral (candidate for restore / isolation) | 5 |
| 3 | `analysis_core` | Behavioral (candidate for restore / isolation) | 3 |
| 4 | `engine.orchestrator` | Behavioral (candidate for restore / isolation) | 2 |
| 5 | `rc22_adapter` | Behavioral (candidate for restore / isolation) | 2 |
| 6 | `decoders.ps_alias_normalizer` | Behavioral (candidate for restore / isolation) | 2 |
| 7 | `server` | Behavioral (candidate for restore / isolation) | 2 |
| 8 | `nivxforge.investigation.customer_report` | Behavioral (candidate for restore / isolation) | 2 |
| 9 | `nivxforge.investigation.analyst_narrative` | Behavioral (candidate for restore / isolation) | 2 |
| 10 | `nivxforge.investigation.summary_composer` | Behavioral (candidate for restore / isolation) | 2 |
| 11 | `smart_decoder` | Behavioral (candidate for restore / isolation) | 2 |
| 12 | `decoders.cmd_runtime_reconstruct` | Behavioral (candidate for restore / isolation) | 1 |
| 13 | `decoders.ps_reconstruct` | Behavioral (candidate for restore / isolation) | 1 |
| 14 | `decoders.crypto_symmetric` | Behavioral (candidate for restore / isolation) | 1 |
| 15 | `decoders.rot47` | Behavioral (candidate for restore / isolation) | 1 |
| 16 | `decoders.base64` | Behavioral (candidate for restore / isolation) | 1 |

## Per-Sample Behavior-linked Chain

### `S01_ps_b64_utf16le` — Multi-layer PowerShell Base64 (UTF-16LE)

- First divergence stage: `interpreter`
- First divergent op (current only): `ps-encodedcommand-recovery`
- Owning files: ["/app/backend/routers/ops.py", "/app/backend/operations.py", "/app/backend/engine/orchestrator.py"]

Behavior-linked chain (leaf → root):

```
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  operations     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  engine.orchestrator     [Behavioral (candidate for restore / isolation)]
  rc22_adapter     [Behavioral (candidate for restore / isolation)]
  analysis_core     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

### `S02_bash_xxd_b64_rev` — Bash → xxd → Base64 → rev

- First divergence stage: `interpreter`
- First divergent op (current only): `powershell-alias-normalize`
- Owning files: ["/app/backend/routers/ops.py", "/app/backend/decoders/ps_alias_normalizer.py", "/app/backend/magic_decoder.py"]

Behavior-linked chain (leaf → root):

```
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  decoders.ps_alias_normalizer     [Behavioral (candidate for restore / isolation)]
  server     [Behavioral (candidate for restore / isolation)]
```

Behavior-linked chain (leaf → root):

```
  magic_decoder     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

### `S03_cmd_caret_escaped` — CMD ^-escaped

- First divergence stage: `interpreter`
- First divergent op (current only): `cmd-runtime-reconstruct`
- Owning files: ["/app/backend/routers/ops.py", "/app/backend/decoders/cmd_runtime_reconstruct.py", "/app/backend/magic_decoder.py"]

Behavior-linked chain (leaf → root):

```
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  decoders.cmd_runtime_reconstruct     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  magic_decoder     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

### `S04_ps_alias_heavy` — PowerShell alias-heavy pipeline

- First divergence stage: `decoder_chain`
- First divergent op (current only): `ps-reconstruct`
- Owning files: ["/app/backend/operations.py", "/app/backend/decoders/ps_reconstruct.py"]

Behavior-linked chain (leaf → root):

```
  operations     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  decoders.ps_reconstruct     [Behavioral (candidate for restore / isolation)]
```

### `S05_nested_b64_gzip` — Nested Base64 + GZIP

- First divergence stage: `decoder_chain`
- First divergent op (current only): `crypto-detect`
- Owning files: ["/app/backend/operations.py", "/app/backend/decoders/crypto_symmetric.py", "/app/backend/nivxforge/investigation/customer_report.py"]

Behavior-linked chain (leaf → root):

```
  operations     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  decoders.crypto_symmetric     [Behavioral (candidate for restore / isolation)]
```

Behavior-linked chain (leaf → root):

```
  nivxforge.investigation.customer_report     [Behavioral (candidate for restore / isolation)]
  nivxforge.investigation.analyst_narrative     [Behavioral (candidate for restore / isolation)]
  nivxforge.investigation.summary_composer     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

### `S07_rc4_openssl` — Crypto-wrapped payload (RC4/OpenSSL-style)

- First divergence stage: `decoder_chain`
- First divergent op (current only): `rot47`
- Owning files: ["/app/backend/operations.py", "/app/backend/decoders/rot47.py"]

Behavior-linked chain (leaf → root):

```
  operations     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  decoders.rot47     [Behavioral (candidate for restore / isolation)]
```

### `S08_unicode_obfuscation` — Unicode / UTF obfuscation

- First divergence stage: `decoder_chain`
- First divergent op (current only): `extract-payload`
- Owning files: ["/app/backend/routers/ops.py", "/app/backend/operations.py", "/app/backend/nivxforge/investigation/customer_report.py", "/app/backend/analysis_core.py", "/app/backend/smart_decoder.py", "/app/backend/magic_decoder.py"]

Behavior-linked chain (leaf → root):

```
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  operations     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  nivxforge.investigation.customer_report     [Behavioral (candidate for restore / isolation)]
  nivxforge.investigation.analyst_narrative     [Behavioral (candidate for restore / isolation)]
  nivxforge.investigation.summary_composer     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  analysis_core     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  smart_decoder     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  magic_decoder     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

### `S09_hex_b64_gzip_chain` — Mixed chain: Hex → Base64 → GZIP

- First divergence stage: `interpreter`
- First divergent op (current only): `base64-decode`
- Owning files: ["/app/backend/routers/ops.py", "/app/backend/operations.py", "/app/backend/decoders/base64.py", "/app/backend/engine/orchestrator.py", "/app/backend/analysis_core.py", "/app/backend/smart_decoder.py", "/app/backend/magic_decoder.py"]

Behavior-linked chain (leaf → root):

```
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  operations     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  decoders.base64     [Behavioral (candidate for restore / isolation)]
```

Behavior-linked chain (leaf → root):

```
  engine.orchestrator     [Behavioral (candidate for restore / isolation)]
  rc22_adapter     [Behavioral (candidate for restore / isolation)]
  analysis_core     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  analysis_core     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  smart_decoder     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  magic_decoder     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

### `S10_bash_with_powershell_comment` — Bash with literal token 'powershell' inside a comment (interpreter-routing regression guard)

- First divergence stage: `interpreter`
- First divergent op (current only): `powershell-alias-normalize`
- Owning files: ["/app/backend/routers/ops.py", "/app/backend/decoders/ps_alias_normalizer.py", "/app/backend/magic_decoder.py"]

Behavior-linked chain (leaf → root):

```
  routers.ops     [Workspace-owned (entry point)]
```

Behavior-linked chain (leaf → root):

```
  decoders.ps_alias_normalizer     [Behavioral (candidate for restore / isolation)]
  server     [Behavioral (candidate for restore / isolation)]
```

Behavior-linked chain (leaf → root):

```
  magic_decoder     [Behavioral (candidate for restore / isolation)]
  routers.ops     [Workspace-owned (entry point)]
```

## Module Rollup — modules exercised by divergent samples

| Module | Classification | Samples | Count |
|--------|----------------|---------|-------|
| `routers.ops` | Workspace-owned (entry point) | S01_ps_b64_utf16le, S02_bash_xxd_b64_rev, S03_cmd_caret_escaped, S04_ps_alias_heavy, S05_nested_b64_gzip, S07_rc4_openssl, S08_unicode_obfuscation, S09_hex_b64_gzip_chain, S10_bash_with_powershell_comment | 9 |
| `operations` | Behavioral (candidate for restore / isolation) | S01_ps_b64_utf16le, S04_ps_alias_heavy, S05_nested_b64_gzip, S07_rc4_openssl, S08_unicode_obfuscation, S09_hex_b64_gzip_chain | 6 |
| `magic_decoder` | Behavioral (candidate for restore / isolation) | S02_bash_xxd_b64_rev, S03_cmd_caret_escaped, S08_unicode_obfuscation, S09_hex_b64_gzip_chain, S10_bash_with_powershell_comment | 5 |
| `analysis_core` | Behavioral (candidate for restore / isolation) | S01_ps_b64_utf16le, S08_unicode_obfuscation, S09_hex_b64_gzip_chain | 3 |
| `engine.orchestrator` | Behavioral (candidate for restore / isolation) | S01_ps_b64_utf16le, S09_hex_b64_gzip_chain | 2 |
| `rc22_adapter` | Behavioral (candidate for restore / isolation) | S01_ps_b64_utf16le, S09_hex_b64_gzip_chain | 2 |
| `decoders.ps_alias_normalizer` | Behavioral (candidate for restore / isolation) | S02_bash_xxd_b64_rev, S10_bash_with_powershell_comment | 2 |
| `server` | Behavioral (candidate for restore / isolation) | S02_bash_xxd_b64_rev, S10_bash_with_powershell_comment | 2 |
| `nivxforge.investigation.customer_report` | Behavioral (candidate for restore / isolation) | S05_nested_b64_gzip, S08_unicode_obfuscation | 2 |
| `nivxforge.investigation.analyst_narrative` | Behavioral (candidate for restore / isolation) | S05_nested_b64_gzip, S08_unicode_obfuscation | 2 |
| `nivxforge.investigation.summary_composer` | Behavioral (candidate for restore / isolation) | S05_nested_b64_gzip, S08_unicode_obfuscation | 2 |
| `smart_decoder` | Behavioral (candidate for restore / isolation) | S08_unicode_obfuscation, S09_hex_b64_gzip_chain | 2 |
| `decoders.cmd_runtime_reconstruct` | Behavioral (candidate for restore / isolation) | S03_cmd_caret_escaped | 1 |
| `decoders.ps_reconstruct` | Behavioral (candidate for restore / isolation) | S04_ps_alias_heavy | 1 |
| `decoders.crypto_symmetric` | Behavioral (candidate for restore / isolation) | S05_nested_b64_gzip | 1 |
| `decoders.rot47` | Behavioral (candidate for restore / isolation) | S07_rc4_openssl | 1 |
| `decoders.base64` | Behavioral (candidate for restore / isolation) | S09_hex_b64_gzip_chain | 1 |

## Static Import Roots (for cross-reference)

**Current `routers/ops.py` direct imports** (first 25):
```
  {'kind': 'from', 'module': '__future__', 'names': ['annotations']}
  {'kind': 'import', 'module': 'base64'}
  {'kind': 'import', 'module': 'hashlib'}
  {'kind': 'import', 'module': 'logging'}
  {'kind': 'import', 'module': 're'}
  {'kind': 'from', 'module': 'typing', 'names': ['Any', 'Dict', 'List', 'Optional']}
  {'kind': 'from', 'module': 'fastapi', 'names': ['APIRouter', 'Depends', 'File', 'HTTPException', 'UploadFile']}
  {'kind': 'from', 'module': 'pydantic', 'names': ['BaseModel']}
  {'kind': 'from', 'module': 'schemas', 'names': ['RecipeStep', 'RunRecipeIn', 'RunRecipeOut', 'AutoIn', 'MagicIn', 'ShellcodeIn', 'CommandAnalyzeIn']}
  {'kind': 'from', 'module': 'deps', 'names': ['db', 'get_current_user', 'load_osint_keys']}
  {'kind': 'from', 'module': 'operations', 'names': ['OPERATIONS', 'list_operations', 'run_operation', 'detect_payload_type']}
  {'kind': 'from', 'module': 'smart_decoder', 'names': ['smart_decode']}
  {'kind': 'from', 'module': 'magic_decoder', 'names': ['magic_decode']}
  {'kind': 'import', 'module': 'models_studio'}
  {'kind': 'from', 'module': 'routers.helpers.decode_offload', 'names': ['run_offloaded']}
  {'kind': 'from', 'module': 'command_analyzer', 'names': ['extract_iocs', 'map_mitre', 'detect_lolbins', 'detect_interpreter']}
  {'kind': 'from', 'module': 'command_analyzer', 'names': ['analyze_command']}
  {'kind': 'from', 'module': 'shellcode_analyzer', 'names': ['analyze']}
  {'kind': 'from', 'module': 'analysis_core', 'names': ['deterministic_best_decode']}
  {'kind': 'from', 'module': 'operations', 'names': ['extract_iocs', 'mitre_map']}
  {'kind': 'from', 'module': 'lolbas', 'names': ['scan_lolbas']}
  {'kind': 'from', 'module': 'analysis_core', 'names': ['deterministic_best_decode']}
  {'kind': 'from', 'module': 'payload_sanitizer', 'names': ['sanitize_encapsulated_payload', 'find_all_base64_spans']}
  {'kind': 'from', 'module': 'reasoning.candidate_engine', 'names': ['score_candidates', 'classify_unknown', 'best_candidate', 'HIGH_THRESHOLD', 'MIN_ACCEPT']}
  {'kind': 'from', 'module': 'operations', 'names': ['extract_iocs', 'mitre_map']}
```

**Baseline `routers/ops.py` direct imports** (first 25):
```
  {'kind': 'from', 'module': '__future__', 'names': ['annotations']}
  {'kind': 'import', 'module': 'base64'}
  {'kind': 'import', 'module': 'hashlib'}
  {'kind': 'import', 'module': 'logging'}
  {'kind': 'import', 'module': 're'}
  {'kind': 'from', 'module': 'typing', 'names': ['Any', 'Dict', 'List', 'Optional']}
  {'kind': 'from', 'module': 'fastapi', 'names': ['APIRouter', 'Depends', 'File', 'HTTPException', 'UploadFile']}
  {'kind': 'from', 'module': 'pydantic', 'names': ['BaseModel']}
  {'kind': 'from', 'module': 'schemas', 'names': ['RecipeStep', 'RunRecipeIn', 'RunRecipeOut', 'AutoIn', 'MagicIn', 'ShellcodeIn', 'CommandAnalyzeIn']}
  {'kind': 'from', 'module': 'deps', 'names': ['db', 'get_current_user']}
  {'kind': 'from', 'module': 'operations', 'names': ['OPERATIONS', 'list_operations', 'run_operation', 'detect_payload_type']}
  {'kind': 'from', 'module': 'smart_decoder', 'names': ['smart_decode']}
  {'kind': 'from', 'module': 'magic_decoder', 'names': ['magic_decode']}
  {'kind': 'import', 'module': 'models_studio'}
  {'kind': 'from', 'module': 'routers.helpers.decode_offload', 'names': ['run_offloaded']}
  {'kind': 'from', 'module': 'command_analyzer', 'names': ['analyze_command']}
  {'kind': 'from', 'module': 'shellcode_analyzer', 'names': ['analyze']}
  {'kind': 'from', 'module': 'analysis_core', 'names': ['deterministic_best_decode']}
  {'kind': 'from', 'module': 'operations', 'names': ['extract_iocs', 'mitre_map']}
  {'kind': 'from', 'module': 'lolbas', 'names': ['scan_lolbas']}
  {'kind': 'from', 'module': 'analysis_core', 'names': ['deterministic_best_decode']}
  {'kind': 'from', 'module': 'payload_sanitizer', 'names': ['sanitize_encapsulated_payload', 'find_all_base64_spans']}
  {'kind': 'from', 'module': 'reasoning.candidate_engine', 'names': ['score_candidates', 'classify_unknown', 'best_candidate', 'HIGH_THRESHOLD', 'MIN_ACCEPT']}
  {'kind': 'from', 'module': 'operations', 'names': ['extract_iocs', 'mitre_map']}
  {'kind': 'from', 'module': 'v2.investigation.pipeline', 'names': ['_atomic_ioc_kind']}
```