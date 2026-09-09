"""RC5 · Phase 6 · LOLBIN v2 — deterministic 3-state model.

See § 9 of `/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md`.

State model (per spec § 9):

  | State       | Meaning                                                       |
  | ----------- | ------------------------------------------------------------- |
  | referenced  | Binary name appears as a string somewhere in the graph        |
  | expanded    | Binary name is the resolved value of a VarBindNode            |
  | executed    | A ProcessNode targets this binary                             |

**Only `executed` enters Verdict v2 math** (Phase 7 will enforce this). The
other two are analyst context. This is architecturally guaranteed here by
`LolbinRow.enters_verdict` being a computed property equal to
`state == executed`.

Invariants:
  * NO regex on raw `result["output"]` text. We walk the graph.
  * Every emitted row carries ≥ 1 `evidence_node_ids` reference.
  * Deterministic: same graph in → same (byte-equal) LolbinRow[] out.
  * The mapper never spawns from a raw string — the interpreter is what
    produces a `ProcessNode`. Consequently a `referenced` hit can NEVER
    be false-attributed to an execution.

Data source: the existing `backend/lolbas.py` catalog (curated 40-entry
default + optionally the ~239-entry official LOLBAS remote catalog). We
read the ACTIVE list at module import; refreshes are picked up on process
restart (in line with how the legacy scanner operates).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from ..exec_graph import ExecGraph, ExecNode, NodeKind, SCHEMA_VERSION
from ..plugin_api import Detector, register_detector


class LolbinState(str, Enum):
    referenced = "referenced"
    expanded   = "expanded"
    executed   = "executed"


# ---------------------------------------------------------------------------
# LolbinRow — one emitted classification per binary observed.
# ---------------------------------------------------------------------------
class LolbinRow(BaseModel):
    """One (binary, state) row.

    Immutable. `enters_verdict` is computed — enforces § 9 invariant.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    binary: str                              # canonical lower-case name
    display_name: str                        # e.g. "certutil.exe"
    state: LolbinState
    purposes: Tuple[str, ...] = ()
    mitre: Tuple[str, ...] = ()              # T-ids referenced by the LOLBAS entry
    evidence_node_ids: Tuple[str, ...]
    reconstructed_snippets: Tuple[str, ...] = ()
    url: str = ""
    description: str = ""
    confidence: int = 100
    schema_version: int = SCHEMA_VERSION

    @field_validator("evidence_node_ids")
    @classmethod
    def _at_least_one(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if not v:
            raise ValueError("LolbinRow.evidence_node_ids must contain ≥ 1 id")
        return v

    @field_validator("confidence")
    @classmethod
    def _clamp(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError(f"confidence must be in [0, 100], got {v}")
        return v

    @computed_field
    @property
    def enters_verdict(self) -> bool:
        """§ 9 invariant — only `executed` rows enter verdict math."""
        return self.state == LolbinState.executed


# ---------------------------------------------------------------------------
# Catalog access — read curated + active LOLBAS entries once at import.
# ---------------------------------------------------------------------------
def _load_catalog() -> List[Dict[str, Any]]:
    """Read the ACTIVE list from `backend/lolbas.py`.

    Returns each entry as {bin, purposes, mitre, desc, url}. Robust to the
    module missing — falls back to a small curated core so tests still run.
    """
    try:
        from lolbas import _ACTIVE  # type: ignore
        entries: List[Dict[str, Any]] = list(_ACTIVE)
    except Exception:
        entries = []
    if not entries:
        # Fallback: hard-coded LOLBAS core (matches the curated defaults).
        entries = [
            {"bin": "certutil.exe", "purposes": ["Download", "Decode"],
             "mitre": ["T1140", "T1105"], "desc": "certutil abuse",
             "url": "https://lolbas-project.github.io/lolbas/Binaries/Certutil/"},
            {"bin": "bitsadmin.exe", "purposes": ["Download"],
             "mitre": ["T1197", "T1105"], "desc": "BITS transfer",
             "url": "https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/"},
            {"bin": "mshta.exe", "purposes": ["Execute"], "mitre": ["T1218.005"],
             "desc": "MSHTA host", "url": "https://lolbas-project.github.io/lolbas/Binaries/Mshta/"},
            {"bin": "rundll32.exe", "purposes": ["Execute"], "mitre": ["T1218.011"],
             "desc": "RunDLL host", "url": "https://lolbas-project.github.io/lolbas/Binaries/Rundll32/"},
            {"bin": "regsvr32.exe", "purposes": ["Execute"], "mitre": ["T1218.010"],
             "desc": "RegSvr32 proxy", "url": "https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/"},
            {"bin": "wmic.exe", "purposes": ["Execute"], "mitre": ["T1047"],
             "desc": "WMI CLI", "url": "https://lolbas-project.github.io/lolbas/Binaries/Wmic/"},
            {"bin": "installutil.exe", "purposes": ["Execute"], "mitre": ["T1218.004"],
             "desc": "InstallUtil proxy", "url": "https://lolbas-project.github.io/lolbas/Binaries/Installutil/"},
            {"bin": "msbuild.exe", "purposes": ["Execute"], "mitre": ["T1127.001"],
             "desc": "MSBuild inline task", "url": "https://lolbas-project.github.io/lolbas/Binaries/Msbuild/"},
            {"bin": "schtasks.exe", "purposes": ["Persistence"], "mitre": ["T1053.005"],
             "desc": "Scheduled task creation", "url": "https://lolbas-project.github.io/lolbas/Binaries/Schtasks/"},
            {"bin": "powershell.exe", "purposes": ["Execute"], "mitre": ["T1059.001"],
             "desc": "PowerShell CLI", "url": "https://lolbas-project.github.io/lolbas/Binaries/Powershell/"},
            {"bin": "cmd.exe", "purposes": ["Execute"], "mitre": ["T1059.003"],
             "desc": "Windows Command Shell", "url": "https://lolbas-project.github.io/lolbas/Binaries/Cmd/"},
            {"bin": "cscript.exe", "purposes": ["Execute"], "mitre": ["T1059.005"],
             "desc": "Windows Script Host", "url": "https://lolbas-project.github.io/lolbas/Binaries/Cscript/"},
            {"bin": "wscript.exe", "purposes": ["Execute"], "mitre": ["T1059.005"],
             "desc": "Windows Script Host", "url": "https://lolbas-project.github.io/lolbas/Binaries/Wscript/"},
        ]
    return entries


CATALOG: Tuple[Dict[str, Any], ...] = tuple(_load_catalog())


def _norm(name: str) -> Tuple[str, str]:
    """Return (bare, exe) lower-case forms.

    Strips any Windows/POSIX path prefix so `C:\\Windows\\System32\\certutil.exe`
    normalises to ('certutil', 'certutil.exe').
    """
    n = str(name or "").strip().lower()
    for sep in ("\\", "/"):
        if sep in n:
            n = n.rsplit(sep, 1)[-1]
    if n.endswith(".exe"):
        return n[:-4], n
    return n, n + ".exe"


# Pre-build fast lookup: bare-name → catalog entry
_LOOKUP: Dict[str, Dict[str, Any]] = {}
for _e in CATALOG:
    bare, _ = _norm(_e["bin"])
    if bare:
        _LOOKUP[bare] = _e


def catalog_bare_names() -> FrozenSet[str]:
    """Frozen set of all LOLBAS bare names (no `.exe`), lower-case."""
    return frozenset(_LOOKUP)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class LolbinDetector(Detector):
    """Emits `LolbinRow[]` (3-state) by walking the ExecGraph."""
    name = "lolbin_v2"

    # Kinds where args["value"] contains a variable's resolved value.
    _VAR_BIND_KIND = NodeKind.var_bind

    # Kinds we scan for `referenced` (string appearances) — everything except
    # the two kinds we already handle explicitly above.
    def detect(self, graph: ExecGraph) -> Dict[str, Any]:
        rows = self.classify(graph)
        return {"lolbins_v2": rows}

    # ── Main classify ────────────────────────────────────────────────
    def classify(self, graph: ExecGraph) -> List[LolbinRow]:
        # Per-binary aggregators; the strongest observed state wins.
        # bare_name → {state, evidence_nodes[], snippets[], confidences[]}
        agg: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        names = catalog_bare_names()

        def _touch(bare: str, state: LolbinState, node: ExecNode,
                   snippet: str, conf: int) -> None:
            entry = _LOOKUP[bare]
            if bare not in agg:
                agg[bare] = {
                    "state": state,
                    "entry": entry,
                    "nodes": [],
                    "snippets": [],
                    "confidences": [],
                    "seen_nodes": set(),
                }
                order.append(bare)
            g = agg[bare]
            # Upgrade to a stronger state if applicable.
            g["state"] = _strongest(g["state"], state)
            if node.id not in g["seen_nodes"]:
                g["nodes"].append(node.id)
                g["seen_nodes"].add(node.id)
            s = _trim(snippet)
            if s and s not in g["snippets"]:
                g["snippets"].append(s)
            g["confidences"].append(int(conf))

        for n in graph.nodes:
            if n.origin == "advisor":
                # Advisor nodes never enter deterministic outputs (§ 6.6).
                continue

            # (1) executed — ProcessNode.args["image"]
            if n.kind == NodeKind.process:
                img = str(n.args.get("image") or "")
                bare, _exe = _norm(img)
                if bare in names:
                    _touch(bare, LolbinState.executed, n,
                           n.reconstructed or img, n.confidence)

            # (2) expanded — VarBindNode.args["value"] whose token equals a LOLBIN
            elif n.kind == self._VAR_BIND_KIND:
                val = str(n.args.get("value") or "")
                for token in _extract_binary_tokens(val):
                    if token in names:
                        _touch(token, LolbinState.expanded, n,
                               n.reconstructed or f"var={val}", n.confidence)

            # (3) referenced — any other node with a LOLBIN name in reconstructed
            #     or in args (structured). We only look at string values and
            #     tokenise on whitespace / path separators; NO regex on raw text.
            else:
                for text in _gather_strings(n):
                    for token in _extract_binary_tokens(text):
                        if token in names:
                            _touch(token, LolbinState.referenced, n,
                                   n.reconstructed or text, n.confidence)

        # Emit rows in deterministic order (first-observation order).
        out: List[LolbinRow] = []
        for bare in order:
            g = agg[bare]
            entry = g["entry"]
            state: LolbinState = g["state"]
            node_ids = tuple(g["nodes"])
            confidences = g["confidences"] or [100]
            row_conf = min(confidences)
            digest = hashlib.sha1(
                f"{bare}|{state.value}|{','.join(node_ids)}".encode("utf-8")
            ).hexdigest()[:12]
            out.append(LolbinRow(
                id="l_" + digest,
                binary=bare,
                display_name=str(entry.get("bin") or (bare + ".exe")),
                state=state,
                purposes=tuple(entry.get("purposes") or ()),
                mitre=tuple(entry.get("mitre") or ()),
                evidence_node_ids=node_ids,
                reconstructed_snippets=tuple(g["snippets"]),
                url=str(entry.get("url") or ""),
                description=str(entry.get("desc") or ""),
                confidence=row_conf,
            ))
        return out


# ---------------------------------------------------------------------------
# Helpers — all deterministic, no regex on decoded text.
# ---------------------------------------------------------------------------
def _strongest(a: LolbinState, b: LolbinState) -> LolbinState:
    """Executed > Expanded > Referenced."""
    order = {LolbinState.referenced: 0, LolbinState.expanded: 1,
             LolbinState.executed: 2}
    return a if order[a] >= order[b] else b


def _trim(s: str, cap: int = 200) -> str:
    s = " ".join(str(s or "").split())
    return s[:cap]


_SPLITTERS = " \t\r\n\"'|&;=<>()[]{},"  # deterministic split characters


def _extract_binary_tokens(text: str) -> List[str]:
    """Break `text` on shell-style delimiters and normalise each token.

    Returns bare (no `.exe`) lower-case tokens whose form is `<name>` or
    `<name>.exe`. Path components (like `C:\\Windows\\System32\\certutil.exe`)
    are handled by taking the basename after the last `/` or `\\`.
    """
    if not text:
        return []
    # Replace splitter chars with spaces, then split
    buf = []
    for ch in text:
        buf.append(" " if ch in _SPLITTERS else ch)
    joined = "".join(buf)
    out: List[str] = []
    for raw in joined.split():
        # Take basename off any embedded path
        for sep in ("\\", "/"):
            if sep in raw:
                raw = raw.rsplit(sep, 1)[-1]
        low = raw.lower()
        if not low:
            continue
        # Strip a leading option-dash so `-urlcache` doesn't survive.
        if low.startswith("-") or low.startswith("/"):
            continue
        if low.endswith(".exe"):
            low = low[:-4]
        # Filter obvious non-executables (still may hit LOLBAS names, but
        # short / non-alnum tokens are ignored to reduce noise).
        if len(low) < 2 or not any(c.isalpha() for c in low):
            continue
        out.append(low)
    return out


def _gather_strings(node: ExecNode) -> List[str]:
    """Collect string material from a node's reconstructed + args payload.

    We ONLY read structured fields; never touch `result["output"]`.
    """
    strs: List[str] = []
    if node.reconstructed:
        strs.append(node.reconstructed)
    # Depth-limited walk of args (dicts/lists/tuples/strings).
    def _walk(v: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(v, str):
            if v:
                strs.append(v)
        elif isinstance(v, (list, tuple)):
            for x in v:
                _walk(x, depth + 1)
        elif isinstance(v, dict):
            for x in v.values():
                _walk(x, depth + 1)
    _walk(node.args)
    return strs


# ---------------------------------------------------------------------------
# Register + module-level accessors
# ---------------------------------------------------------------------------
_INSTANCE = LolbinDetector()
register_detector(_INSTANCE)


def classify_lolbins(graph: ExecGraph) -> List[LolbinRow]:
    return _INSTANCE.classify(graph)


def get_lolbin_detector() -> LolbinDetector:
    return _INSTANCE


__all__ = [
    "LolbinState",
    "LolbinRow",
    "LolbinDetector",
    "classify_lolbins",
    "get_lolbin_detector",
    "catalog_bare_names",
    "CATALOG",
]
