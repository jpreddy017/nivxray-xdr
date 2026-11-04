# RC5 · Plugin API

**Status:** Frozen at Phase 1. Any change here is a `SCHEMA_VERSION` bump.
**Import path:** `from engine.plugin_api import SemanticParser, SemanticInterpreter, Detector`
**Contract lock test:** `backend/tests/rc5/invariants/test_plugin_api_frozen.py`

This document is the single source of truth for authors of parsers,
interpreters, and detectors that plug into the RC5 Semantic Engine.

If you're extending NivXRay with a new language (Bash / Python / VBScript /
JScript / MSBuild / HTA / WMI …) or a new detector (a new MITRE technique
rule, a new LOLBIN behavior, an alternate verdict scorer), read this file
first. **Do not touch core modules.**

---

## 1 · Three plug points

The engine has exactly **three** extension surfaces. Every plugin fits into
one of them; anything that tries to bypass the surface fails a CI gate.

| Plug point            | Consumes            | Produces        | ABC                    |
| --------------------- | ------------------- | --------------- | ---------------------- |
| **SemanticParser**    | normalized text     | `SIRTree`       | `plugin_api.SemanticParser`    |
| **SemanticInterpreter** | `SIRTree`         | `ExecGraph`     | `plugin_api.SemanticInterpreter` |
| **Detector**          | `ExecGraph`         | Behaviors / MITRE / LOLBIN / Verdict scores | `plugin_api.Detector` |

---

## 2 · Universal invariants (violation = merge block)

1. **No raw-text parsing after the parser stage.** Interpreters and detectors
   consume `SIRTree` / `ExecGraph` only. They never read `result["output"]`.
2. **No execution.** No `os.system`, no `subprocess`, no `eval`. RC5 is 100 %
   static.
3. **Immutable outputs.** Every model is `frozen=True`. Never mutate a
   returned `ExecNode` / `Behavior`.
4. **Evidence-first.** Every conclusion carries `evidence_node_ids` (for
   Behaviors) or `evidence_behavior_ids` (for MITRE) or a `node_id` (for
   IOCs / LOLBIN executed rows). CI dangling-ref check enforces.
5. **`--no-ai` byte-identity.** If your plugin consults an AI advisor, its
   output MUST be gated behind `origin="advisor"` so it can't enter
   deterministic verdict math (see § 6.6 of the main spec).
6. **Schema version discipline.** A new `NodeKind` / `SideEffectVerb` /
   `TacticKind` bumps `SCHEMA_VERSION` — no silent additions.

---

## 3 · Authoring a `SemanticParser`

```python
from engine.plugin_api import SemanticParser, register_parser
from engine.semantic_ir import SIRTree, SIRNode, SIRKind


class BashParser(SemanticParser):
    name = "bash"

    def parse(self, normalized_text: str) -> SIRTree:
        # Return an SIRTree. Emit `SIRKind.unresolved` for any fragment
        # you cannot fully model — NEVER a lossy guess.
        root = SIRNode(kind=SIRKind.program, parser=self.name)
        return SIRTree(root=root, parser=self.name,
                       original_length=len(normalized_text))


register_parser(BashParser())
```

**Contract:**
- `name` must be unique and lowercase (`bash`, `powershell`, `vbscript`, …).
- Every emitted `SIRNode.parser` should equal `self.name` for provenance.
- No I/O. No network. No filesystem.

---

## 4 · Authoring a `SemanticInterpreter`

```python
from engine.plugin_api import SemanticInterpreter, register_interpreter
from engine.exec_graph import ExecGraph, ExecNode, NodeKind
from engine.semantic_ir import SIRTree, SIRKind


class BashInterpreter(SemanticInterpreter):
    parser_name = "bash"          # must match a registered SemanticParser

    def interpret(self, sir: SIRTree) -> ExecGraph:
        g = ExecGraph()
        for stmt in sir.root.children:
            if stmt.kind == SIRKind.call_expr:
                node = ExecNode(
                    kind=NodeKind.process,
                    args={"image": stmt.value},
                    reconstructed=stmt.value or "",
                    parser=self.parser_name,
                )
                g = g.add_node(node)
            # else … emit UnresolvedNode with a `reason` in notes.
        return g


register_interpreter(BashInterpreter())
```

**Contract:**
- If you can't fully reconstruct a fragment, emit `NodeKind.unresolved` with a
  `notes=("reason: <what stopped you>",)` — never a wrong reconstruction.
- Confidence rules § 6 are enforced by `ExecGraph.add_node()`. If your child
  node's declared confidence exceeds the min-parent rule, `add_node` raises.
- Never mutate parent nodes. `add_node` returns a new graph.

---

## 5 · Authoring a `Detector`

```python
from engine.plugin_api import Detector, register_detector
from engine.exec_graph import Behavior, ExecGraph, NodeKind, TacticKind


class SpawnDetector(Detector):
    name = "spawn_detector"

    def detect(self, graph: ExecGraph) -> dict:
        behaviors = []
        for n in graph.by_kind(NodeKind.process):
            behaviors.append(Behavior(
                tactic=TacticKind.execution,
                evidence_nodes=(n.id,),
                reconstructed=n.reconstructed,
                confidence=n.confidence,
                parameters={"image": n.args.get("image")},
            ))
        return {"behaviors": behaviors}


register_detector(SpawnDetector())
```

**Contract:**
- Detectors are **pure functions** of `ExecGraph`. Same graph in ⇒ same output.
- Every `Behavior` MUST carry ≥ 1 `evidence_nodes` — enforced by the model.
- MITRE / LOLBIN / Verdict detectors MUST reference `Behavior.id`s or
  `ExecNode.id`s in their evidence fields.
- Never read `result["output"]`. If you need the reconstructed command,
  read `ExecNode.reconstructed`.

---

## 6 · Discovery order

At server startup:

1. All parsers register themselves (`register_parser`).
2. All interpreters register themselves (`register_interpreter`).
3. All detectors register themselves (`register_detector`).
4. The pipeline coordinator (Phase 5+) picks the right parser+interpreter
   per language tag, runs all detectors on the resulting `ExecGraph`, and
   compiles the final response.

Registration is import-time — put `register_*(...)` calls at module
bottom, and make sure the module is imported somewhere in the startup
graph (typically via `backend/engine/__init__.py` or an explicit
`import_registry()` in `deps.py`).

---

## 7 · Testing your plugin

Every plugin author MUST provide:

- **Unit tests** at `backend/tests/rc5/unit/plugins/<your_plugin>/`.
- **Corpus tests** at `backend/tests/rc5/corpus/<your_plugin>/` — at least
  20 real samples with expected `ExecGraph` / `Behavior` / `MITRE` shapes.
- **Invariant compliance** — running `pytest tests/rc5/invariants/` after
  your plugin loads MUST pass.
- **Golden JSON** for every corpus sample — `git diff` on the golden file
  is the visible signal when your plugin's output changes.

---

## 8 · Frozen enums (schema-version-bump territory)

Adding to any of these lists requires:

1. A spec revision (`RC5_SEMANTIC_ENGINE_SPEC.md` § 4 / § 5 / § 7).
2. A `SCHEMA_VERSION` bump in `engine/exec_graph.py`.
3. Updates to the corresponding test in
   `tests/rc5/invariants/test_plugin_api_frozen.py`.
4. Updates to this doc's example lists below.

**Current NodeKinds (39):** see `NodeKind` in `engine/exec_graph.py`.
**Current SideEffectVerbs (37):** see `SideEffectVerb`.
**Current TacticKinds (21 = 14 top-level + 7 supporting):** see `TacticKind`.
**Current SIRKinds (31):** see `SIRKind` in `engine/semantic_ir.py`.

---

## 9 · Rejected patterns (fail CI)

- Any detector importing `re` and matching against `result["output"]`.
- Any plugin that mutates an `ExecNode` after construction.
- Any Behavior emitted without `evidence_nodes`.
- Any parser that fills in a "best guess" instead of emitting `Unresolved`.
- Any `emergentintegrations.` import in a `verdict*` / `mitre*` / `lolbin*` /
  `behavior*` module.
- Any addition to a frozen enum without a `SCHEMA_VERSION` bump.

---

## 10 · Getting help

- Full architecture spec: `/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md`
- Invariant tests (read these to understand what CI will check):
  `backend/tests/rc5/invariants/`
- Reference plugin (Phase 2 CMD parser lands as the first real example).
