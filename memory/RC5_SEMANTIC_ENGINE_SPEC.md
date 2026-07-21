# RC5 · Semantic Execution Engine — Architecture Specification

**Status:** DRAFT (Feb 24, 2026) — awaiting user approval before Phase 1 code lands.
**Owner:** NivXRay Deterministic Core Team
**Feature Flag:** `SEMANTIC_ENGINE_V2` (env var; false by default until Phase 10 cutover)
**Cutover Target:** Phase 10 (~week 8 from spec approval).

---

## 0 · Why This Exists

Today's NivXRay pipeline decodes command lines well but its **semantic layer** is heuristic:
verdicts / MITRE / LOLBIN attribution derive from regex keyword matches against the
decoded output. This causes three failure classes we must eliminate permanently:

1. **False attribution** — LOLBINs that appear as strings inside a payload are reported as *executed*.
2. **Keyword-only verdicts** — an obfuscated `calc.exe` scores as high as a real reflective shellcode injector.
3. **Untraceable conclusions** — analysts cannot see *which reconstructed command* produced a given MITRE mapping.

RC5 replaces this layer with a **deterministic command interpreter** that reconstructs the
executable command exactly as CMD / PowerShell would execute it, builds an **Execution
Graph** of every operation, and derives Behaviors / MITRE / LOLBIN / Verdict *strictly from
that graph*. No keyword shortcuts. No syntax-based mappings.

**Guiding principle:** *Think like a deterministic command interpreter first, a security
engine second.*

---

## 1 · Goals

**In-scope:**
- Deterministic CMD interpreter (all built-ins, SET / expansion / delayed / CALL / FOR / IF / escape).
- Deterministic PowerShell interpreter (AST-driven, not regex; aliases / -f / -join / -split / Replace / Substring / arrays / [char] / [Convert]::FromBase64String / XOR / ScriptBlock / IEX).
- Serializable `ExecGraph` model with confidence propagation.
- Behavior taxonomy of 15 verbs (file_create … shellcode_exec … dll_load).
- MITRE / LOLBIN / Verdict engines that *require* graph evidence.
- Explainability: every conclusion cites the exact ExecNode + reconstructed command.
- 1000+ regression tests; every historical bug becomes a permanent test.
- Shadow-run + delta-report before cutover.

**Non-goals:**
- Any behavior *simulation* (we do not `os.system` reconstructed commands, ever).
- Sandbox / dynamic analysis. RC5 remains 100 % static.
- Deep learning for verdicts. Deterministic reconstruction ⇒ deterministic verdict.

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
   │ Semantic Reconstruction                            │
   │   ├── CMD interpreter    (Phase 2)                 │
   │   └── PowerShell interp. (Phase 3)                 │
   └─────┬──────────────────────────────────────────────┘
         │  ExecGraph (nodes + edges)
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
                       result["exec_graph"]        (Phase 1)
                       result["behaviors"]         (Phase 4)
                       result["mitre_v2"]          (Phase 5)
                       result["lolbins_v2"]        (Phase 6)
                       result["verdict_v2"]        (Phase 7)
                       result["explain"]           (Phase 8)
```

**Invariant:** Detectors are **forbidden** from short-circuiting the pipeline. No detector
may write to `mitre_v2` / `lolbins_v2` / `verdict_v2` without a Behavior evidence pointer.
CI enforces this via a static import gate (see § 12).

---

## 3 · ExecNode Data Model (Phase 1)

`/app/backend/engine/exec_graph.py`

```python
class ExecNode(BaseModel):
    id: str                               # short uuid — stable within one analysis
    kind: NodeKind                        # see § 4
    inputs:  list[str] = []               # ids of parent nodes
    outputs: list[str] = []               # ids of children (populated on graph build)
    args:    dict = {}                    # kind-specific structured payload
    reconstructed: str = ""               # the FINAL text the interpreter would execute
    side_effects: list[SideEffect] = []   # see § 5
    confidence:   int = 100               # 0-100. child ≤ parent (see § 6).
    source_span:  tuple[int, int] | None  # byte offsets in original decoded text
    parent_layer: int | None              # which decoder layer produced this
    notes:        list[str] = []          # analyst-facing rationale, never a verdict driver
```

**ExecGraph = list[ExecNode] + adjacency built from `inputs`/`outputs`.**

Serialized to JSON on `result["exec_graph"]`. All node IDs referenced elsewhere in the
result (MITRE evidence, LOLBIN evidence, Behavior evidence, IOC provenance) MUST resolve
to a node in this list. CI enforces this (dangling-ref check).

---

## 4 · Node Kinds

Each `NodeKind` has an explicit schema. Kinds are frozen — adding a new one is a spec change.

| Kind                 | Emitted by            | `args` shape                                                      | Side effects              |
| -------------------- | --------------------- | ----------------------------------------------------------------- | ------------------------- |
| `DecodeNode`         | Decoder layer         | `{op, input_preview, output_preview}`                             | none                      |
| `NormalizeNode`      | Normalizer            | `{op, before, after}`                                             | none                      |
| `VarBindNode`        | CMD / PS interpreter  | `{name, value, scope, mode: assign/append/env}`                   | `var_bind`                |
| `VarExpandNode`      | Both interpreters     | `{name, expansion_kind: normal/delayed/substring/replace, value}` | none                      |
| `StringOpNode`       | Both                  | `{op: format/join/split/replace/substring/char, args, result}`    | none                      |
| `ConcatNode`         | Both                  | `{parts, result}`                                                 | none                      |
| `ScriptBlockNode`    | PS                    | `{body, evaluated: bool, result}`                                 | none until `.Invoke()`    |
| `DelayNode`          | CMD                   | `{seconds, reason: delayed_expansion/timeout}`                    | none                      |
| `ProcessSpawnNode`   | CMD / PS              | `{image, args, cwd, integrity, parent_pid_hint}`                  | `process_spawn`           |
| `FileOpNode`         | CMD / PS              | `{op: create/read/write/delete/rename, path, size_hint}`          | `file_*`                  |
| `NetIONode`          | CMD / PS              | `{proto, method, url, headers, body_hint}`                        | `net_io`                  |
| `RegNode`            | CMD / PS              | `{op, hive, key, value_name, value, type}`                        | `reg_*`                   |
| `TaskNode`           | CMD / PS              | `{op, name, cmd, trigger}`                                        | `schedule_task`           |
| `ServiceNode`        | CMD / PS              | `{op, name, image, start_type}`                                   | `service_create`          |
| `MemoryOpNode`       | PS                    | `{op: alloc/protect/write/execute, size, protection}`             | `mem_alloc`, `mem_exec`   |
| `DllLoadNode`        | PS                    | `{path, method: LoadLibrary/reflective, exported}`                | `dll_load`                |
| `ReflectionNode`     | PS                    | `{type, member, method}`                                          | `reflection`              |
| `UnresolvedNode`     | Any interpreter       | `{reason, partial_result}`                                        | none — confidence < 100   |

**Rule:** if the interpreter cannot fully reconstruct a fragment, it emits an
`UnresolvedNode` with a diagnostic `reason` and confidence drop, **never a guess.**

---

## 5 · Side-Effect Vocabulary

Fixed enum. New verbs require a spec change:

```
process_spawn · file_create · file_write · file_read · file_delete · file_rename
net_io · reg_write · reg_delete · schedule_task · service_create
mem_alloc · mem_exec · dll_load · reflection · cred_access · injection
persistence_run_key · persistence_startup · persistence_task
var_bind
```

Every side-effect line is `(verb, node_id, evidence_text)`. Behaviors aggregate side-effects.

---

## 6 · Confidence Propagation

Confidence is an integer 0-100 stored on each node. Rules:

1. `DecodeNode.confidence` = inherit from the decoder layer's reported confidence.
2. Child node confidence ≤ min(parent confidences).
3. If any input is an `UnresolvedNode`, the child confidence drops by at least 20.
4. Nodes derived from **AI persona narrative** are marked `origin="advisor"` and are
   **never** aggregated into verdict math — they appear only in `Explain.narrative`.
5. A verdict cannot use evidence with confidence < 40 unless there are ≥ 2 corroborating
   pieces of evidence at the same confidence.

Rule 4 enforces the user's constraint: "AI persona = advisor for narrative only, never verdicts."

---

## 7 · Behavior Extractor (Phase 4)

Walks the ExecGraph and emits one `Behavior` record per real-world outcome. Behavior schema:

```python
class Behavior(BaseModel):
    id: str
    kind: BehaviorKind              # 15 fixed verbs, see below
    evidence_nodes: list[str]       # ExecNode.id references — REQUIRED, min len 1
    reconstructed: str              # the exact reconstructed command that caused it
    confidence: int                 # min of evidence_nodes' confidence
    parameters: dict                # kind-specific (path, url, key, image, size…)
```

**BehaviorKind enum (frozen):**

```
file_create · file_delete · download · upload · process_spawn
service_create · persistence_reg · persistence_task · net_c2
credential_access · injection · reflection · memory_alloc
shellcode_exec · dll_load
```

**Extractor invariants:**

- One node ↦ 0 or 1 Behavior. Never many.
- One Behavior needs ≥ 1 evidence node. Never zero.
- `Behavior.reconstructed` MUST equal `evidence_nodes[0].reconstructed` (or a canonical
  join for multi-node behaviors like injection).

---

## 8 · MITRE Engine v2 (Phase 5)

Old `mitre_map` is deleted (see § 12 kill-list). Replaced by declarative behavior-to-technique
rules:

```python
MITRE_RULES = [
    Rule(
        technique="T1059.001",
        title="PowerShell",
        requires_all=[Behavior.process_spawn(image="powershell")],
        requires_any=[Behavior.download, Behavior.reflection, Behavior.shellcode_exec,
                      Behavior.memory_alloc, Behavior.injection],
        # syntax-only powershell (Start-Process notepad) → does NOT match
    ),
    Rule(
        technique="T1105",
        title="Ingress Tool Transfer",
        requires_all=[Behavior.download],
    ),
    Rule(
        technique="T1547.001",
        title="Registry Run Keys",
        requires_all=[
            Behavior.persistence_reg(
                key_prefix=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
            ),
        ],
    ),
    …
]
```

**Every emitted MITRE mapping carries `evidence_behavior_ids` — dangling references fail CI.**

---

## 9 · LOLBIN Engine v2 (Phase 6)

Three-state model:

| State          | Meaning                                          | Reported?                          |
| -------------- | ------------------------------------------------ | ---------------------------------- |
| **referenced** | Binary name appears as a string in decoded text  | Yes — in `seen_strings.lolbins`, greyed out in UI |
| **expanded**   | Binary name is the value of a resolved variable  | Yes — in `seen_strings.lolbins`, distinct badge  |
| **executed**   | A `ProcessSpawnNode` targets this binary         | **Yes — in `lolbins_v2[].executed[]` only**       |

Only `executed` rows drive verdict math. The previous over-attribution class ("Expand.exe
LOLBIN found" when Expand.exe is a string inside a shellcode dump) is architecturally
impossible under this model — the interpreter never spawns from a string.

---

## 10 · Verdict Engine v2 (Phase 7)

Verdict is derived from **four orthogonal scores**, each 0-100, computed from Behaviors only:

| Score          | Definition                                                                        |
| -------------- | --------------------------------------------------------------------------------- |
| **intent**     | Presence of obfuscation / evasion / anti-analysis behaviors                       |
| **capability** | What the reconstructed graph *can* do (spawn, download, inject, persist…)         |
| **execution**  | What actually happens in the reconstructed graph (behaviors emitted)              |
| **risk**       | Composite: `f(intent, capability, execution)` with weights tuned via corpus       |

**Verdict tiers** (composite risk):

- `Benign`      : risk < 20
- `Suspicious`  : 20 ≤ risk < 55
- `Malicious`   : 55 ≤ risk < 85
- `Critical`    : risk ≥ 85

**Worked examples (from the user's mandate):**

| Sample                                            | intent | capability | execution | risk | Verdict     |
| ------------------------------------------------- | -----: | ---------: | --------: | ---: | ----------- |
| Obfuscated `calc.exe` (base64 + XOR wrap)         |  75    |     10     |     10    |  22  | Suspicious  |
| PowerShell using XOR to build a string constant   |  60    |      5     |      0    |  15  | Benign      |
| Certutil `certutil -urlcache -f https://…`        |  20    |     60     |     55    |  55  | Malicious   |
| XOR-decoded MSFvenom stager (149.28.81.19 C2)     |  90    |     95     |     90    |  93  | Critical    |

The scoring function itself is a linear combination with a **cap-and-floor**: execution < 20
downgrades risk one tier regardless of intent+capability. This is the direct mechanism
that keeps obfuscated-calc benign.

---

## 11 · Explainability Contract (Phase 8)

Every conclusion in the final response MUST include a provenance pointer:

```json
{
  "iocs": {
    "ips": [
      {"value": "149.28.81.19", "evidence_node_id": "n_47", "reconstructed": "connect(149.28.81.19:443)"}
    ]
  },
  "mitre_v2": [
    {"technique": "T1105", "evidence_behavior_ids": ["b_09"]}
  ],
  "lolbins_v2": {
    "executed":   [{"image": "cmd.exe",   "evidence_node_id": "n_31"}],
    "referenced": [{"image": "Expand.exe", "evidence_span": [412, 421]}]
  },
  "verdict_v2": {
    "verdict": "Critical",
    "risk": 93,
    "scores": {"intent": 90, "capability": 95, "execution": 90},
    "top_reasons": [
      {"reason": "shellcode reflectively loaded", "evidence_behavior_id": "b_11"},
      {"reason": "C2 connect to routable IP",     "evidence_behavior_id": "b_09"}
    ]
  },
  "explain": {
    "narrative": "…AI-generated paragraph…",     // advisor-only, NEVER a verdict driver
    "narrative_origin": "advisor",
    "narrative_model": "claude-sonnet-4-5-…"
  }
}
```

The UI (WorkspacePage / AnalystResults) will surface these provenance links so clicking any
IOC / MITRE row / verdict reason highlights the exact ExecNode + reconstructed command.

---

## 12 · Kill-List — Old Code Paths Retired at Phase 10 Cutover

Deleted the day `SEMANTIC_ENGINE_V2` flips to `true` on Prod:

- `backend/operations.py`
  - `_KEYWORD_MITRE_MAP`, `_KEYWORD_LOLBAS_HITS` — replaced by MITRE v2 / LOLBIN v2.
  - `_regex_verdict_score()` — replaced by Verdict Engine v2.
- `backend/routers/ops.py`
  - Any `mitre = []` / `lolbas = []` accumulation via keyword regex on `result["output"]`.
- `backend/rc42_semantic_evaluator.py`
  - Heuristic scoring paths — retained only for `Explain.narrative` context.
- Tests referencing old keyword maps — migrated to Behavior-based fixtures in Phase 9.

CI gate added in Phase 1: **any new import of `_KEYWORD_MITRE_MAP` or `_KEYWORD_LOLBAS_HITS`
outside the legacy shim fails the build.**

---

## 13 · AI Persona Role (Locked by User Constraint)

Per user directive: "Keep as advisor for `ExplainabilityNode.narrative` field only, never verdicts."

**Allowed:**
- Populating `explain.narrative` — a plain-language paragraph summarizing the reconstructed graph.
- Suggesting *analyst-facing labels* for `UnresolvedNode.reason` (never a verdict input).

**Forbidden:**
- Writing to `mitre_v2`, `lolbins_v2`, `verdict_v2`, `behaviors`, or any `evidence_*` field.
- Being called before the deterministic verdict is finalized.
- Being consulted when `personaId` is empty (PLAIN mode remains fully deterministic).

CI gate: any `emergentintegrations.` import in files matching `backend/engine/verdict*` or
`backend/engine/mitre*` or `backend/engine/lolbin*` or `backend/engine/behavior*` fails the
build.

---

## 14 · Feature Flag Strategy

**Flag:** `SEMANTIC_ENGINE_V2` (env var on backend). Default: `false`.

- Phases 1-4: Flag `false`. New code runs *in parallel* with old, writes to `exec_graph` /
  `behaviors` fields on the response. Old `mitre` / `lolbas` / `risk` continue to drive UI.
  Zero user-visible behavior change.
- Phases 5-8: Flag `false` on Prod, `true` on Preview. UI reads `mitre_v2` / `lolbins_v2` /
  `verdict_v2` when flag is on; falls back to old fields when off.
- Phase 9: Shadow-run on Preview. Delta report: `python scripts/rc5_delta_report.py` walks
  the last 30 days of `investigation_events` and produces a diff table (old vs new verdict).
- Phase 10: Flip flag on Prod. Delete kill-list. Rename `*_v2` fields to canonical names.

**Rollback plan:** flip flag to `false`, revert two commits (cutover + kill-list). Old code
is preserved on the `rc5-legacy-safety-net` branch tag for 60 days after cutover.

---

## 15 · Test Framework (Phase 9, seeded from Phase 1)

Directory: `/app/backend/tests/rc5/`. Structure:

```
rc5/
├── unit/
│   ├── exec_graph/               # 30 tests — graph construction, confidence propagation
│   ├── cmd/                      # 100 tests — SET / expansion / delayed / CALL / FOR / IF / escape
│   ├── powershell/               # 200 tests — aliases / -f / -join / arrays / [char] / IEX / SB
│   ├── behavior_extractor/       # 60 tests — one per (kind × primary node type)
│   ├── mitre_v2/                 # 50 tests — one per MITRE_RULES entry, positive + negative
│   ├── lolbin_v2/                # 30 tests — referenced vs expanded vs executed
│   └── verdict_v2/               # 40 tests — score math + tier cutoffs
├── corpus/                       # 1000+ real payloads with expected {verdict, behaviors, mitre, lolbins}
│   ├── benign_admin_scripts/
│   ├── enterprise_deployment/
│   ├── windows_installer/
│   ├── real_malware/
│   ├── edge_cases/
│   └── regression/               # every historical bug lands here as an eternal test
└── shadow/
    └── delta_report.py           # Prod-vs-Preview divergence detector
```

**Corpus coverage matrix (Phase 9 exit criterion):**

- CMD: 200+ · PowerShell: 300+ · MSHTA: 40 · WScript/CScript: 40
- Rundll32/Regsvr32/InstallUtil/MSBuild: 60
- BitsAdmin/Certutil/Curl/FTP: 40 · WMIC/Forfiles/Schtasks/Reg: 50
- SSH: 20 · Encoded/nested/multi-stage: 150 · Benign: 100 · Edge cases: 100

Every historical bug fixed in RC1-RC4 becomes a permanent regression test at Phase 9 start.

---

## 16 · Anti-Patterns Forbidden Under RC5

Enforced by code review + CI static analysis:

1. **Regex verdict shortcuts** — `if "powershell" in output: risk += X`. Verdicts derive from Behaviors only.
2. **Keyword MITRE mapping** — every mapping must reference a Behavior ID.
3. **Speculative LOLBIN attribution** — no report row without a `ProcessSpawnNode`.
4. **AI-driven fields in verdict math** — advisor narrative is read-only downstream.
5. **Silent guesses** — the interpreter emits `UnresolvedNode` with `reason`, never a wrong reconstruction.
6. **Pipeline bypass** — no detector may write to a v2 field without going through the extractor.
7. **Dangling evidence IDs** — every reference must resolve. CI test verifies.
8. **Layer-skipping** — Behavior extractor may only read the graph, never re-parse the raw output.

---

## 17 · Open Questions & Risks

| # | Question / Risk                                                                                | Decision Owner   | Target Phase |
| - | ---------------------------------------------------------------------------------------------- | ---------------- | ------------ |
| 1 | Should the CMD interpreter also model `chcp` / codepage effects?                               | Deferred to RC5.1 | —            |
| 2 | PowerShell ScriptBlock fixed-point iteration cap: 4 rounds? 6? Cost vs coverage tradeoff.      | Phase 3 kickoff  | 3            |
| 3 | `certutil -decode` — treat as `FileOpNode` + `DecodeNode` chained, or a single `DownloadNode`? | Phase 4 kickoff  | 4            |
| 4 | Verdict scoring weights — start from corpus median or hand-tuned?                              | Phase 7 kickoff  | 7            |
| 5 | Corpus sourcing: do we ingest MalwareBazaar samples directly, or hand-curate a smaller set?    | Phase 9 kickoff  | 9            |
| 6 | UI provenance link rendering — inline chip or side-drawer?                                     | Phase 8 kickoff  | 8            |

---

## 18 · Success Criteria (Phase 10 Gate)

Cutover to `SEMANTIC_ENGINE_V2=true` on Prod is blocked until **all** are true:

- ✅ Unit tests: 100 % pass on `/app/backend/tests/rc5/unit/`.
- ✅ Corpus tests: ≥ 98 % pass on `/app/backend/tests/rc5/corpus/` (with per-category floors).
- ✅ Shadow-run delta report: zero **regressions** (a "regression" = a case where v2 downgrades a real-malware verdict).
- ✅ Kill-list retired: static-analysis gate is green.
- ✅ Explainability: every response field has provenance; dangling-ref check green.
- ✅ Rollback tested on Preview: flip flag off → old behavior restored, no exceptions.

---

## 19 · Immediate Next Steps (Upon Spec Approval)

1. Create `/app/backend/engine/exec_graph.py` — the `ExecNode` / `ExecGraph` / `Behavior` models.
2. Wire `result["exec_graph"] = []` into `/api/decode/smart` output. Empty until Phase 2 populates it.
3. Add feature flag reader `deps.semantic_engine_v2_enabled()` — reads `SEMANTIC_ENGINE_V2` env var.
4. Add CI gates:
   - dangling-evidence-ref check
   - forbidden-import check (v2 modules ↛ advisor code)
   - old-keyword-map import check (kill-list enforcement seeded early)
5. Author `/app/backend/tests/rc5/unit/exec_graph/test_node_schema.py` — 15 tests locking the schema.
6. Author `/app/backend/tests/rc5/unit/exec_graph/test_confidence_propagation.py` — 10 tests locking rule § 6.

All Phase 1 code will land behind `SEMANTIC_ENGINE_V2=false`. Zero production impact.

---

**End of spec. Awaiting sign-off before Phase 1 code lands.**
