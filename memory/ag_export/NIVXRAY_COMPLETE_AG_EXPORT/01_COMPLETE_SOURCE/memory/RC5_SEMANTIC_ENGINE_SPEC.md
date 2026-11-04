# RC5 · Semantic Execution Engine — Architecture Specification (v2, edits applied)

**Status:** APPROVED WITH EDITS (Feb 24, 2026) — Phase 1 code may proceed.
**Owner:** NivXRay Deterministic Core Team
**Feature Flag:** `SEMANTIC_ENGINE_V2` (env var; false by default until Phase 10 cutover)
**Cutover Target:** Phase 10 (~week 8 from spec approval).

---

## 0 · Purpose & Guiding Principles

Today's NivXRay decodes command lines well but its **semantic layer** is heuristic:
verdicts / MITRE / LOLBIN attribution derive from regex keyword matches. RC5 replaces
this layer with a **deterministic command interpreter** that reconstructs the executable
command as CMD / PowerShell would run it, materialises every operation as a node in an
immutable **Execution Graph**, and derives Behaviors / MITRE / LOLBIN / Verdict *strictly
from that graph*.

**Immutable principles — never violated:**

1. **Deterministic-first.** Two runs of the same input on the same version produce byte-identical output.
2. **Evidence-driven.** Every conclusion cites Node IDs and Behavior IDs.
3. **Explainable.** Every verdict / MITRE / LOLBIN / IOC has a provenance trail to a reconstructed command.
4. **Extensible.** Node kinds, side-effect verbs, behaviors, and detector plugins evolve via schema versioning — never by touching core.
5. **Language-agnostic.** The engine's downstream layers know only the Semantic IR + Execution Graph, never a specific parser.
6. **AI-optional.** With `--no-ai` (or persona absent) the engine produces **byte-identical semantic output**. AI persona is a *narrative advisor only*.
7. No detector may infer behavior from **syntax alone**.
8. No verdict may be based on **keywords**.
9. No AI-generated reasoning may influence deterministic analysis or verdict scoring.

*Think like a deterministic command interpreter first, a security engine second.*

---

## 1 · Goals & Non-Goals

**In-scope:**

- Deterministic CMD interpreter (built-ins, SET, expansion, delayed, CALL, FOR, IF, escape, quoting).
- Deterministic PowerShell interpreter (AST-driven; aliases, `-f`, `-join`, `-split`, `Replace`, `Substring`, arrays, `[char]`, `[Convert]::FromBase64String`, XOR, ScriptBlock, `IEX`).
- **Semantic Intermediate Representation (SIR)** — the common language shared by every parser.
- Immutable, append-only Execution Graph with confidence propagation.
- 15+ top-level attacker-tactic behaviors + 7 supporting behaviors.
- MITRE / LOLBIN / Verdict engines that *require* graph evidence.
- Full explainability: every conclusion references Node IDs.
- 1000+ regression tests; every historical bug becomes a permanent test.
- Frozen plugin API so future parsers (Bash / Python / VBScript / JScript / MSBuild / HTA / WMI) integrate without core changes.
- 30-day shadow-run + delta-report before cutover.

**Non-goals:**

- Behavior *simulation*. The engine never `os.system()`s the reconstructed command.
- Sandbox / dynamic analysis. RC5 remains 100 % static.
- Deep-learning verdicts. Deterministic reconstruction ⇒ deterministic verdict.

---

## 2 · Universal Pipeline (Enforced Order)

```
   ┌────────────┐
   │  Decoder   │  46 existing decoders — unchanged.
   └─────┬──────┘
         │  raw text
   ┌─────▼──────┐
   │ Normalizer │  UTF-16, backtick, quote-splice, delayed-expansion prep.
   └─────┬──────┘
         │  normalized text
   ┌─────▼──────────────────────────────────────────────┐
   │ Semantic IR                (§ 3, new in v2)        │
   │   Language-agnostic AST-like tree emitted by       │
   │   every parser (CMD, PS, Bash, Py, VBScript,       │
   │   JScript, MSBuild, HTA, WMI, …future).            │
   └─────┬──────────────────────────────────────────────┘
         │  SIR tree
   ┌─────▼──────────────────────────────────────────────┐
   │ Semantic Reconstruction                            │
   │   ├── CMD interpreter    (Phase 2)                 │
   │   └── PowerShell interp. (Phase 3)                 │
   │   Both consume SIR, emit ExecGraph nodes.          │
   └─────┬──────────────────────────────────────────────┘
         │  ExecGraph (immutable, append-only)
   ┌─────▼──────────────┐
   │ Behavior Extractor │  Phase 4 — walks graph, emits Behavior[].
   └─────┬──────────────┘
         │  Behaviors[]
   ┌─────▼──────┐    ┌──────────────┐    ┌───────────────┐
   │ MITRE v2   │    │  LOLBIN v2   │    │  Verdict v2   │
   └─────┬──────┘    └──────┬───────┘    └───────┬───────┘
         │  Techniques[]    │  Executed[]        │  Scores{}
         └─────────────┬────┴─────────┬──────────┘
                       │              │
                 ┌─────▼──────────────▼──────┐
                 │  Explainability Compiler  │  Phase 8.
                 └─────────────┬─────────────┘
                               │
                       result["semantic_ir"]       (Phase 1 stub)
                       result["exec_graph"]        (Phase 1)
                       result["behaviors"]         (Phase 4)
                       result["mitre_v2"]          (Phase 5)
                       result["lolbins_v2"]        (Phase 6)
                       result["verdict_v2"]        (Phase 7)
                       result["explain"]           (Phase 8)
```

**Invariants:**

- Detectors are forbidden from short-circuiting the pipeline.
- **No detector may parse `result["output"]` (raw decoded text) directly.** Consumers read `exec_graph` only.
- No detector may write to `mitre_v2` / `lolbins_v2` / `verdict_v2` / `behaviors` without a Node/Behavior evidence pointer.

CI enforces this via static import gates (§ 12).

---

## 3 · Semantic Intermediate Representation (SIR) — v2 Addition

`/app/backend/engine/semantic_ir.py`

Every parser (CMD, PowerShell, Bash, Python, VBScript, JScript, MSBuild, HTA, WMI, future)
produces a **SIR tree** — a language-agnostic structured representation of the source
program. The Execution Graph builder consumes SIR, not raw text.

**SIR node types** (frozen; new types require a spec revision):

```
Program · Statement · Expression
Assignment · CallExpr · MemberExpr · IndexExpr
StringLiteral · NumberLiteral · ArrayLiteral · MapLiteral
VarRef · EnvRef · DelayedRef
BinaryOp · UnaryOp · FormatOp · JoinOp · SplitOp · ReplaceOp · SubstringOp
Pipeline · Block · If · Loop · Try · Return
ScriptBlockLiteral · InvocationExpr
Comment · Unresolved
```

**Why SIR exists:** without it, every parser reimplements downstream logic (variable
lifetime, scope, string ops, control flow) and downstream detectors duplicate parsing.
SIR makes CMD-vs-PS a *parser choice* — the rest of the pipeline is identical.

**SIR contract:**

- Serializable to JSON. Roundtrip-safe.
- Every SIR node carries a `source_span` (byte offsets in normalized text) and `parser` tag.
- Parsers emit `Unresolved` for constructs they can't fully model — never a lossy guess.

---

## 4 · Node Kinds (Reserved Schema — Frozen for Plugin API)

`NodeKind` is a **frozen enum**. All 34 kinds below are reserved at Phase 1 even if
implementation lands in a later phase. Adding a kind after Phase 1 is a schema-version bump.

### Execution
- `ProcessNode`
- `ScriptNode`
- `AssemblyLoadNode`
- `ShellcodeNode`
- `NativeApiNode`
- `COMNode`

### Persistence
- `RegistryNode`
- `ScheduledTaskNode`
- `ServiceNode`
- `StartupNode`
- `WMINode`
- `EventSubscriptionNode`

### Filesystem
- `FileNode`
- `DirectoryNode`
- `ArchiveNode`

### Network
- `HttpNode`
- `DNSNode`
- `SocketNode`
- `SMBNode`
- `NamedPipeNode`

### Security
- `CredentialNode`
- `TokenNode`
- `CertificateNode`
- `FirewallNode`

### System
- `ClipboardNode`
- `EnvironmentNode`
- `MemoryNode`

### Cloud
- `CloudStorageNode`
- `IdentityNode`

### Core / Interpreter Plumbing (always implemented)
- `DecodeNode` — one per decoder layer.
- `NormalizeNode` — one per normalization step.
- `VarBindNode` — SET, `$x = …`.
- `VarExpandNode` — `%VAR%`, `!VAR!`, `$var`.
- `StringOpNode` — format / join / split / replace / substring / char.
- `ConcatNode` — string concatenation.
- `ScriptBlockNode` — `{…}` unevaluated until `.Invoke()`.
- `DelayNode` — sleep / delayed expansion boundary.
- `ReflectionNode` — .NET reflective calls (mid-tier; wraps AssemblyLoad + NativeApi).
- `UnresolvedNode` — emitted whenever reconstruction is incomplete. **Never a guess.**

**Shared ExecNode schema:**

```python
class ExecNode(BaseModel):
    id: str                               # short uuid — stable within one analysis
    kind: NodeKind                        # frozen enum, see above
    inputs:  list[str] = []               # ids of parent nodes (append-only)
    outputs: list[str] = []               # ids of children (populated on graph build)
    args:    dict = {}                    # kind-specific structured payload
    reconstructed: str = ""               # the exact text the interpreter would execute
    side_effects: list[SideEffect] = []   # see § 5
    confidence:   int = 100               # 0-100. child ≤ parent (see § 6).
    source_span:  tuple[int, int] | None  # byte offsets in original decoded text
    parent_layer: int | None              # which decoder layer produced this
    parser:       str | None              # which parser emitted the SIR
    schema_version: int = 1               # bump on any kind addition
    notes:        list[str] = []          # analyst-facing rationale, never a verdict driver
```

---

## 5 · Side-Effect Vocabulary (Expanded, Frozen)

Each side-effect is a `(verb, node_id, evidence_text)` triple. Every triple MUST resolve
to an ExecNode.

**Process**
- `create_process` · `inject_process` · `terminate_process` · `suspend_process` · `resume_process`

**Filesystem**
- `create_file` · `read_file` · `write_file` · `modify_file` · `delete_file` · `rename_file` · `move_file`

**Registry**
- `read_registry` · `write_registry` · `delete_registry`

**Network**
- `dns_query` · `http_request` · `https_request` · `tcp_connect` · `udp_connect` · `upload` · `download`

**Memory**
- `allocate_memory` · `protect_memory` · `read_memory` · `write_memory` · `execute_memory`

**Security**
- `dump_credentials` · `elevate_token` · `disable_security` · `bypass_amsi` · `bypass_etw`

**Persistence**
- `install_service` · `create_task` · `install_wmi_subscription` · `autorun_registration`

**Interpreter Plumbing**
- `var_bind`

**Total: 36 frozen verbs.** New verbs require a schema-version bump + spec revision.

---

## 6 · Confidence Propagation

Confidence is an integer 0-100 on each node. Rules (locked, non-negotiable):

1. `DecodeNode.confidence` inherits from the decoder's reported confidence.
2. **Child confidence ≤ min(parent confidences).** Never higher.
3. If any input is `UnresolvedNode`, child confidence drops by ≥ 20.
4. **Behavior.confidence = min(evidence_nodes[*].confidence).**
5. **Verdict score inputs = only nodes/behaviors with confidence ≥ 40**, unless ≥ 2 corroborating pieces of evidence at the same tier.
6. Nodes with `origin="advisor"` (AI-derived) are **never** aggregated into verdict math. They surface only in `explain.narrative`.
7. Confidence is **never assigned arbitrarily**. Every drop / cap has a rule number in `node.notes` (e.g. `"conf capped by rule-3 (unresolved child)"`).

Rule 6 enforces the user's "AI never influences deterministic verdict" constraint.

---

## 7 · Behavior Taxonomy (Attacker-Tactic Aligned)

Behaviors represent *attacker actions*, not parser observations. Aligned to MITRE ATT&CK top-level tactics.

**Top-level attacker tactics (14):**

- `initial_access`
- `execution`
- `persistence`
- `privilege_escalation`
- `defense_evasion`
- `credential_access`
- `discovery`
- `lateral_movement`
- `collection`
- `command_and_control`
- `exfiltration`
- `impact`
- `reconnaissance`
- `resource_development`

**Supporting behaviors (7) for finer-grained evidence:**

- `dns_query`
- `firewall_rule`
- `named_pipe`
- `clipboard`
- `certificate`
- `token_manipulation`
- `wmi_subscription`

**Behavior record schema:**

```python
class Behavior(BaseModel):
    id: str
    tactic: TacticKind                  # top-level enum
    sub_kind: str | None                # optional refinement (e.g. "download", "reflective_dll")
    evidence_nodes: list[str]           # ExecNode ids — REQUIRED, min len 1
    reconstructed: str                  # exact reconstructed command
    confidence: int                     # = min(evidence_nodes[*].confidence)
    parameters: dict                    # tactic-specific structured detail
    schema_version: int = 1
```

**Extractor invariants:**

- One node ↦ 0 or 1 Behavior. Never many.
- One Behavior ⇒ ≥ 1 evidence node.
- `Behavior.reconstructed` MUST equal `evidence_nodes[0].reconstructed` (or canonical join).
- Behaviors are derived **only** from the ExecGraph. Extractor is forbidden from reading raw output.

---

## 8 · MITRE Engine v2

Old `_KEYWORD_MITRE_MAP` deleted at cutover. Replaced by declarative Behavior-to-Technique rules:

```python
MITRE_RULES = [
    Rule(
        technique="T1059.001",
        title="PowerShell",
        requires_all=[Behavior.execution(image_contains="powershell")],
        requires_any=[Behavior.command_and_control, Behavior.execution(sub="reflective"),
                      Behavior.execution(sub="shellcode_exec")],
        # syntax-only PS (`Start-Process notepad`) does NOT match this rule.
    ),
    Rule(technique="T1105", title="Ingress Tool Transfer",
         requires_all=[Behavior.command_and_control(sub="download")]),
    Rule(technique="T1547.001", title="Registry Run Keys",
         requires_all=[Behavior.persistence(
             sub="autorun_registration",
             key_prefix=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")]),
    …
]
```

Every emitted MITRE mapping carries `evidence_behavior_ids`. Dangling references fail CI.

---

## 9 · LOLBIN Engine v2

Three-state model. Only `executed` drives verdict math.

| State          | Meaning                                                    | Reported?                                       |
| -------------- | ---------------------------------------------------------- | ----------------------------------------------- |
| **referenced** | Binary name appears as a string in decoded text            | `seen_strings.lolbins[]` — grey badge in UI     |
| **expanded**   | Binary name is the value of a resolved variable            | `seen_strings.lolbins[]` — distinct badge       |
| **executed**   | A `ProcessNode` (§ 4) targets this binary                  | `lolbins_v2.executed[]` — full report row       |

Architecturally impossible to false-attribute a string as a LOLBIN — the interpreter never
spawns from a raw string, only from a fully-reconstructed `ProcessNode`.

---

## 10 · Verdict Engine v2 (7 Dimensions)

**Verdict is derived from 7 orthogonal scores, each 0-100, computed from Behaviors only.**

| Dimension          | Answers                                                            |
| ------------------ | ------------------------------------------------------------------ |
| **intent**         | Does the sample try to hide / evade / anti-analyse?                |
| **capability**     | What could the reconstructed graph do if fully executed?           |
| **execution**      | *Did this actually occur?* — count of behaviors actually emitted   |
| **impact**         | Severity of the reconstructed outcome (data loss, C2, persistence) |
| **stealth**        | Anti-forensic markers (ETW/AMSI bypass, log clearing)              |
| **persistence**    | Does the graph install autoruns / tasks / services / WMI subs?     |
| **defense_evasion**| Obfuscation, packing, LOLBIN abuse for evasion (not for capability)|

**Verdict tiers (updated):**

- `Benign`      : composite risk `0 – 24`
- `Suspicious`  : composite risk `25 – 49`
- `Malicious`   : composite risk `50 – 74`
- `Critical`    : composite risk `75 – 100`

**Composite formula (Phase 7 opens tuning; initial linear weights):**

```
risk = weighted_sum(intent, capability, execution, impact, stealth, persistence, defense_evasion)
     with weights tuned per corpus + capped-and-floored.
```

**Critical invariant — locked by user directive:**

> "Execution alone must never determine maliciousness. An obfuscated but benign command
> must remain benign if reconstructed behavior is benign."

Mechanism: `impact` and `capability` dominate the tier ceiling. If reconstructed behavior
is trivially benign (e.g. `calc.exe` spawn only), `impact` = low and `capability` = low
regardless of how obfuscated / high-entropy the source was. Intent can float high without
lifting the tier.

**Worked examples:**

| Sample                                              | intent | cap | exec | impact | stealth | persist | evasion | risk | Verdict     |
| --------------------------------------------------- | -----: | --: | ---: | -----: | ------: | ------: | ------: | ---: | ----------- |
| Obfuscated `calc.exe`                               |  75    |  10 |  10  |   5    |    0    |    0    |   15    |  16  | Benign      |
| PS builds string constant via XOR + never runs it   |  60    |   5 |   0  |   0    |    0    |    0    |   10    |  10  | Benign      |
| `certutil -urlcache -f https://…` (download only)   |  20    |  60 |  55  |  35    |   10    |    0    |   40    |  35  | Suspicious  |
| XOR-decoded MSFvenom stager → C2 149.28.81.19       |  90    |  95 |  90  |  85    |   70    |    0    |   80    |  81  | Critical    |
| Persistence via HKCU Run + downloads next stage     |  70    |  75 |  70  |  60    |   40    |   85    |   55    |  67  | Malicious   |

---

## 11 · Explainability Contract

Every conclusion in the final response MUST include a provenance pointer:

```json
{
  "iocs": {
    "ips": [
      {"value": "149.28.81.19", "evidence_node_id": "n_47",
       "reconstructed": "connect(149.28.81.19:443)"}
    ]
  },
  "mitre_v2": [
    {"technique": "T1105", "evidence_behavior_ids": ["b_09"]}
  ],
  "lolbins_v2": {
    "executed":   [{"image": "cmd.exe",    "evidence_node_id": "n_31"}],
    "referenced": [{"image": "Expand.exe", "evidence_span": [412, 421]}]
  },
  "verdict_v2": {
    "verdict": "Critical",
    "risk": 81,
    "scores": {"intent": 90, "capability": 95, "execution": 90,
               "impact": 85, "stealth": 70, "persistence": 0, "defense_evasion": 80},
    "top_reasons": [
      {"reason": "shellcode reflectively loaded",  "evidence_behavior_id": "b_11"},
      {"reason": "C2 connect to routable IP",      "evidence_behavior_id": "b_09"}
    ]
  },
  "explain": {
    "narrative": "…AI-generated paragraph…",
    "narrative_origin": "advisor",
    "narrative_model": "claude-sonnet-4-5-…"
  }
}
```

UI (WorkspacePage / AnalystResults) surfaces provenance links so clicking any IOC / MITRE
row / verdict reason highlights the exact ExecNode + reconstructed command.

---

## 12 · Locked Architectural Invariants (Non-Negotiable)

Enforced by CI, static analysis, and code review. Violation blocks merge.

1. **Execution Graph is immutable.** Nodes are append-only. No mutation after creation.
   ExecGraph is `frozen=True` on the Pydantic model. Any mutation attempt raises.
2. **Detectors consume ExecGraph only.** No detector may parse `result["output"]` (raw text)
   directly. CI gate: static import check on `backend/engine/behavior_extractor.py`,
   `backend/engine/mitre_v2.py`, `backend/engine/lolbin_v2.py`, `backend/engine/verdict_v2.py`
   fails the build if these modules import regex/re.match against raw output.
3. **Evidence-first.** Every MITRE technique, every LOLBIN row, every IOC, every behavior,
   every verdict MUST carry evidence Node/Behavior IDs. CI dangling-ref check enforces.
4. **Confidence propagation is deterministic.** Never arbitrary. Rules 1-7 in § 6.
5. **Plugin API frozen at Phase 1.** New parsers extend the SIR + emit ExecNodes of
   existing kinds. Adding a new kind is a schema-version bump — never a silent addition.
6. **`--no-ai` mode is byte-identical.** The CLI flag `--no-ai` (and equivalently absence
   of persona) MUST produce identical `semantic_ir` / `exec_graph` / `behaviors` /
   `mitre_v2` / `lolbins_v2` / `verdict_v2`. Only `explain.narrative` differs.

CI test: `pytest backend/tests/rc5/invariants/test_no_ai_deterministic.py` runs the entire
corpus twice (once with AI advisor, once with `--no-ai`) and asserts field-by-field equality
on all deterministic fields.

---

## 13 · Kill-List — Code Retired at Phase 10 Cutover

Deleted the day `SEMANTIC_ENGINE_V2` flips to `true` on Prod:

- `backend/operations.py`
  - `_KEYWORD_MITRE_MAP`, `_KEYWORD_LOLBAS_HITS` → replaced by MITRE v2 / LOLBIN v2.
  - `_regex_verdict_score()` → replaced by Verdict Engine v2.
- `backend/routers/ops.py`
  - Any `mitre = []` / `lolbas = []` accumulation via keyword regex on `result["output"]`.
- `backend/rc42_semantic_evaluator.py`
  - Heuristic scoring paths retained *only* for `explain.narrative` context; scoring hooks removed.
- Tests referencing old keyword maps → migrated to Behavior-based fixtures in Phase 9.

CI gate added in Phase 1: any new import of `_KEYWORD_MITRE_MAP` / `_KEYWORD_LOLBAS_HITS`
outside a legacy shim fails the build.

---

## 14 · AI Persona Role (Locked by User Constraint)

**Allowed:**
- Populating `explain.narrative` — plain-language paragraph summarising the reconstructed graph.
- Suggesting analyst-facing labels for `UnresolvedNode.reason` (never a verdict input).

**Forbidden:**
- Writing to `mitre_v2`, `lolbins_v2`, `verdict_v2`, `behaviors`, or any `evidence_*` field.
- Being called *before* the deterministic verdict is finalised.
- Being consulted when `personaId` is empty (PLAIN mode remains fully deterministic).
- Changing any deterministic field between `--no-ai` and AI-on runs (§ 12 invariant 6).

CI gate: any `emergentintegrations.` import in files matching `backend/engine/verdict*`,
`backend/engine/mitre*`, `backend/engine/lolbin*`, or `backend/engine/behavior*` fails the build.

---

## 15 · Feature Flag & Cutover Strategy

**Flag:** `SEMANTIC_ENGINE_V2` env var. Default `false`.

- **Phases 1-4:** Flag `false`. New code runs *in parallel* with old, writes `semantic_ir` /
  `exec_graph` / `behaviors` on the response. Old `mitre` / `lolbas` / `risk` drive UI.
  Zero user-visible change.
- **Phases 5-8:** Flag `false` on Prod, `true` on Preview. UI reads `mitre_v2` / `lolbins_v2` /
  `verdict_v2` when flag on; falls back to legacy fields when off.
- **Phase 9:** Shadow-run on Preview begins.
- **Phase 10:** Cutover after shadow-run gate passes.

### Shadow-Run Duration & Metrics (updated per user directive)

- **Minimum:** 14 days.
- **Preferred:** 30 days.
- **Recommended:** 30 days on Preview + 7 days shadow-emit on Prod (v2 fields present but UI still reads v1).

**Metrics tracked continuously via `scripts/rc5_delta_report.py`:**

1. **Crash rate** — exceptions per 1000 analyses (target: < 0.5).
2. **False positives** — v2 marks Malicious/Critical where v1 was Benign/Suspicious AND corpus label = benign.
3. **False negatives** — v2 marks Benign/Suspicious where corpus label = malicious.
4. **Graph integrity** — dangling-ref count (target: 0).
5. **Schema validation** — non-conforming records (target: 0).
6. **Confidence calibration** — Brier score against corpus labels (target: < 0.15).
7. **Performance** — p50 / p95 / p99 latency vs v1 (regression cap: p95 ≤ v1 × 1.3).
8. **Memory usage** — peak RSS per analysis vs v1 (regression cap: v1 × 1.25).
9. **Latency** — end-to-end wall clock (regression cap: v1 × 1.3).
10. **Execution-graph correctness** — sample 100 cases/day, human-review flag for divergence.

**Rollback:** flip flag to `false`, revert cutover + kill-list commits. Legacy code lives on
tag `rc5-legacy-safety-net` for 90 days after cutover.

---

## 16 · Test Framework (Phase 9, seeded from Phase 1)

Directory: `/app/backend/tests/rc5/`.

```
rc5/
├── invariants/
│   ├── test_no_ai_deterministic.py        # § 12.6: --no-ai == AI-on for deterministic fields
│   ├── test_graph_immutability.py         # § 12.1
│   ├── test_no_raw_output_parsing.py      # § 12.2 static-import check
│   ├── test_evidence_ref_integrity.py     # § 12.3 dangling-ref check
│   ├── test_confidence_rules.py           # § 6 rules 1-7
│   └── test_plugin_api_frozen.py          # § 12.5 schema-version stability
├── unit/
│   ├── semantic_ir/                       # 25 tests — SIR schema, roundtrip, parser contract
│   ├── exec_graph/                        # 30 tests — graph construction, immutability, confidence
│   ├── cmd/                               # 100 tests — SET / expansion / delayed / CALL / FOR / IF / escape
│   ├── powershell/                        # 200 tests — aliases / -f / -join / arrays / [char] / IEX / SB
│   ├── behavior_extractor/                # 60 tests — one per (tactic × primary node type)
│   ├── mitre_v2/                          # 50 tests — one per MITRE_RULES entry, +ve & -ve
│   ├── lolbin_v2/                         # 30 tests — referenced vs expanded vs executed
│   └── verdict_v2/                        # 40 tests — 7-dimension scoring, tier cutoffs, obfuscated-benign
├── corpus/                                # 1000+ real payloads with expected {verdict, behaviors, mitre, lolbins}
│   ├── benign_admin_scripts/
│   ├── enterprise_deployment/
│   ├── windows_installer/
│   ├── real_malware/
│   ├── edge_cases/
│   └── regression/                        # every historical bug lands here permanently
└── shadow/
    └── delta_report.py                    # 10-metric divergence detector (§ 15)
```

**Corpus coverage matrix (Phase 9 exit criterion):**

- CMD: 200+ · PowerShell: 300+ · MSHTA: 40 · WScript/CScript: 40
- Rundll32/Regsvr32/InstallUtil/MSBuild: 60
- BitsAdmin/Certutil/Curl/FTP: 40 · WMIC/Forfiles/Schtasks/Reg: 50
- SSH: 20 · Encoded/nested/multi-stage: 150 · Benign: 100 · Edge: 100

Every historical bug fixed in RC1-RC4 becomes a permanent regression test at Phase 9 start.

---

## 17 · Anti-Patterns Forbidden Under RC5

Enforced by code review + CI static analysis:

1. **Regex verdict shortcuts** (`if "powershell" in output: risk += X`).
2. **Keyword MITRE mapping** — every mapping must reference a Behavior ID.
3. **Speculative LOLBIN attribution** — no report row without a `ProcessNode`.
4. **AI-driven fields in verdict math** — advisor narrative is read-only downstream.
5. **Silent guesses** — the interpreter emits `UnresolvedNode.reason`, never a wrong reconstruction.
6. **Pipeline bypass** — no detector may write a v2 field without going through the extractor.
7. **Dangling evidence IDs** — every reference must resolve.
8. **Layer-skipping** — Behavior extractor may only read the graph, never re-parse raw output.
9. **Node mutation** — modifying an ExecNode after append violates § 12.1.
10. **Cross-phase leakage** — a Phase 5 detector calling into a Phase 7 verdict internal is forbidden.

---

## 18 · Long-Term Principles — Every Sample Must Answer

The Semantic Engine must be able to answer these questions for **every** sample:

- What was actually executed?
- How was it reconstructed?
- Which variables expanded?
- Which branches executed?
- Which binaries actually ran?
- Which behaviors actually occurred?
- Which MITRE techniques are supported by evidence?
- Which LOLBINs actually executed?
- Why was this verdict assigned?
- Which evidence supports every conclusion?

**If the engine cannot prove something, it emits an `UnresolvedNode` — never a guess.**

Non-negotiables (echo of § 0):
- No heuristic-only conclusions.
- No keyword-driven verdicts.
- No unsupported MITRE mappings.
- No unsupported LOLBIN attribution.
- No unsupported behavior claims.
- Deterministic semantic reconstruction always precedes detection.

---

## 19 · Open Questions (Reduced — Most Locked in v2)

| # | Question                                                                                 | Owner            | Target Phase |
| - | ---------------------------------------------------------------------------------------- | ---------------- | ------------ |
| 1 | Should the CMD interpreter model `chcp` / codepage effects?                              | Deferred RC5.1   | —            |
| 2 | ScriptBlock fixed-point iteration cap: 4? 6? Cost/coverage trade-off.                    | Phase 3 kickoff  | 3            |
| 3 | Verdict weight tuning: start from corpus median or hand-tuned?                           | Phase 7 kickoff  | 7            |
| 4 | Corpus sourcing: MalwareBazaar direct ingest vs hand-curated small set?                  | Phase 9 kickoff  | 9            |
| 5 | UI provenance link: inline chip or side-drawer?                                          | Phase 8 kickoff  | 8            |

*Locked in v2 (previously deferred):* verdict tier cutoffs · verdict dimensions · shadow-run duration · schema freeze · SIR position in pipeline · plugin API stability.

---

## 20 · Cutover Success Gate

Cutover to `SEMANTIC_ENGINE_V2=true` on Prod is blocked until **all** are true:

- ✅ Unit tests: 100 % pass on `/app/backend/tests/rc5/unit/`.
- ✅ Invariant tests: 100 % pass on `/app/backend/tests/rc5/invariants/`.
- ✅ Corpus tests: ≥ 98 % pass on `/app/backend/tests/rc5/corpus/` with per-category floors.
- ✅ Shadow-run: ≥ 14 days (preferred 30) with all 10 metrics inside thresholds (§ 15).
- ✅ Zero **verdict regressions** — no case where v2 downgrades a real-malware verdict.
- ✅ Kill-list retired: static-analysis gate green.
- ✅ Explainability: every response field has provenance; dangling-ref check green.
- ✅ Rollback rehearsed on Preview: flag off → old behavior restored, no exceptions.
- ✅ `--no-ai` invariant: byte-identical deterministic output.
- ✅ Performance regression caps met (§ 15 metrics 7-9).

---

## 21 · Immediate Next Steps (Phase 1 — Upon Sign-Off)

**File-level deliverables (all behind `SEMANTIC_ENGINE_V2=false`; zero prod impact):**

1. `/app/backend/engine/semantic_ir.py` — SIR node types + serialization.
2. `/app/backend/engine/exec_graph.py` — `ExecNode` (frozen), `ExecGraph`, `Behavior`, `SideEffect` models.
3. `/app/backend/engine/plugin_api.py` — the frozen parser contract.
4. `/app/backend/deps.py` — add `semantic_engine_v2_enabled()` env reader.
5. `/app/backend/routers/ops.py` — wire `result["semantic_ir"] = None` and `result["exec_graph"] = []` stubs.
6. `/app/backend/tests/rc5/invariants/` — 6 invariant tests (§ 12).
7. `/app/backend/tests/rc5/unit/semantic_ir/` — 25 schema tests.
8. `/app/backend/tests/rc5/unit/exec_graph/` — 30 model + confidence tests.
9. `.github/workflows/rc5_gates.yml` — CI static-import + dangling-ref + immutability checks.

**Definition of Phase-1 done:**

- All 8 immutable principles from § 0 encoded as either code or CI test.
- All 34 NodeKinds present as frozen enum (implementation stubs OK).
- All 36 side-effect verbs present.
- All 14 top-level tactics + 7 supporting behaviors present as frozen enum.
- All 6 architectural invariants (§ 12) enforced by ≥ 1 CI test each.
- `--no-ai` invariant test scaffolded (returns pass with empty ExecGraph until Phase 2).
- Plugin API doc drafted at `/app/memory/RC5_PLUGIN_API.md`.

---

**End of spec v2. Phase 1 code may proceed on approval of this document.**
