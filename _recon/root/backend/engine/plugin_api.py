"""RC5 · Plugin API — frozen contract for every parser & detector.

See § 12.5 of `/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md` and
`/app/memory/RC5_PLUGIN_API.md` for the full plugin contract.

Every parser (CMD, PowerShell, Bash, Python, VBScript, JScript, MSBuild, HTA,
WMI, future) implements `SemanticParser`. Every detector implements
`Detector`. The plugin registry lives in this module — new parsers /
detectors register themselves at import time.

INVARIANT (§ 12.2): a `Detector` receives an `ExecGraph` — never raw text.
Any attempt to inject a raw-text-consuming detector will fail the
`test_no_raw_output_parsing` CI gate.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Protocol

from .exec_graph import Behavior, ExecGraph, SCHEMA_VERSION
from .semantic_ir import SIRTree, SIR_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Parser contract — Normalizer → SIRTree.
# ---------------------------------------------------------------------------
class SemanticParser(ABC):
    """A language parser.

    Contract:
      * Consumes normalized text (already through the Normalizer layer).
      * Emits a valid `SIRTree`.
      * MAY emit `Unresolved` SIR nodes when it can't fully model a fragment.
      * MUST NOT do any semantic reconstruction — that's the interpreter's job.
      * MUST NOT read anything outside the input text.
    """
    name: str = ""                    # "cmd" | "powershell" | ...
    schema_version: int = SIR_SCHEMA_VERSION

    @abstractmethod
    def parse(self, normalized_text: str) -> SIRTree:
        ...


# ---------------------------------------------------------------------------
# Interpreter contract — SIRTree → ExecGraph.
# ---------------------------------------------------------------------------
class SemanticInterpreter(ABC):
    """A language-specific semantic interpreter.

    Contract:
      * Consumes an `SIRTree` produced by the matching parser.
      * Produces an `ExecGraph` (immutable, append-only).
      * On any fragment it cannot fully reconstruct, emits an
        `UnresolvedNode` — never a guess.
      * MUST NOT execute anything (no `os.system`, no subprocess, no eval).
    """
    parser_name: str = ""             # must equal `SemanticParser.name`
    schema_version: int = SCHEMA_VERSION

    @abstractmethod
    def interpret(self, sir: SIRTree) -> ExecGraph:
        ...


# ---------------------------------------------------------------------------
# Detector contract — ExecGraph → Behaviors / MITRE / LOLBIN / Verdict.
# ---------------------------------------------------------------------------
class Detector(ABC):
    """A downstream detector.

    Contract:
      * Consumes an `ExecGraph`. MUST NOT read raw `result["output"]` text.
        (Enforced by the § 12.2 CI gate.)
      * Emits either `Behavior[]`, a MITRE technique list, a LOLBIN row list,
        or Verdict scores. Never mixes concerns.
      * Every output MUST carry evidence Node/Behavior IDs (§ 12.3).
    """
    name: str = ""
    schema_version: int = SCHEMA_VERSION

    @abstractmethod
    def detect(self, graph: ExecGraph) -> Dict[str, object]:
        ...


# ---------------------------------------------------------------------------
# Registry — parsers / interpreters / detectors register themselves here.
# ---------------------------------------------------------------------------
_PARSERS: Dict[str, SemanticParser] = {}
_INTERPRETERS: Dict[str, SemanticInterpreter] = {}
_DETECTORS: Dict[str, Detector] = {}


def register_parser(p: SemanticParser) -> SemanticParser:
    if not p.name:
        raise ValueError("parser must set `name`")
    _PARSERS[p.name] = p
    return p


def register_interpreter(i: SemanticInterpreter) -> SemanticInterpreter:
    if not i.parser_name:
        raise ValueError("interpreter must set `parser_name`")
    _INTERPRETERS[i.parser_name] = i
    return i


def register_detector(d: Detector) -> Detector:
    if not d.name:
        raise ValueError("detector must set `name`")
    _DETECTORS[d.name] = d
    return d


def get_parser(name: str) -> Optional[SemanticParser]:
    return _PARSERS.get(name)


def get_interpreter(parser_name: str) -> Optional[SemanticInterpreter]:
    return _INTERPRETERS.get(parser_name)


def list_detectors() -> List[Detector]:
    return list(_DETECTORS.values())


# The frozen public API surface (§ 12.5).
__all__ = [
    "SemanticParser",
    "SemanticInterpreter",
    "Detector",
    "register_parser",
    "register_interpreter",
    "register_detector",
    "get_parser",
    "get_interpreter",
    "list_detectors",
]
