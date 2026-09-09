"""UAIE · Transformer Op Adapter (Priority 3 · frozen).

Bridge for the 5 legacy PowerShell decoders that ship as bare
``@op`` transformer functions (not ``BaseDecoder`` subclasses):

    ps_encodedcommand_multilayer   →  ``ps-encodedcommand-multilayer``
    ps_inline_eval                 →  ``powershell-hex-csv-inline``
                                       ``powershell-xor-inline-key``
    ps_normalizer                  →  ``powershell-normalize``
    ps_reverse_swap                →  ``powershell-reverse-string``
                                       ``powershell-reverse-regex-swap``
    ps_semantic_mini               →  ``powershell-semantic-mini``

These modules never had a ``detect(...)`` classifier, only a
transformer ``fn(data: str, args) -> str``.  This adapter provides
a minimal Recognizer that fires on marker presence, then executes
the underlying op via ``operations.run_operation`` — one source of
truth, no re-implementation.

R26 compliance
──────────────
    · pure wrapper — same input, same output as the underlying op
    · never mutates the op function
    · falls through as a no-op when the op returns its own
      "(<op_id> · no match)" sentinel string (each PS op already
      emits that shape when it cannot decode)

Contract
────────
    adapt_op_and_register(
        op_id="powershell-hex-csv-inline",
        markers=(re.compile(r"\\$\\w+\\s*=\\s*'[0-9a-fA-F,\\s]{16,}'"),),
        artifact_types=["text", "powershell", "powershell_normalized"],
        child_artifact_type="powershell_normalized",
    )

The adapter registers exactly one UAIE Recognizer + Capability pair
for the given op_id, so all the deterministic Planner priorities and
ledger provenance work identically to BaseDecoder-shaped plugins.
"""
from __future__ import annotations

import re
from time    import perf_counter
from typing  import Any, Dict, Iterable, List, Optional, Pattern

from .artifact   import Artifact, make_artifact
from .recognizer import Recognition, Reason, HIGH, LIKELY
from .capability import CapabilityResult, register as _register_cap
from .evidence   import make_evidence
from . import plugins as _plugin_registry


# The op registry lives in ``operations.py``.  Importing it triggers
# the decorator-based registration of every ``@op(...)`` function.
import operations as _ops        # noqa: E402
import decoders.ps_encodedcommand_multilayer   # noqa: F401,E402
import decoders.ps_inline_eval                  # noqa: F401,E402
import decoders.ps_normalizer                   # noqa: F401,E402
import decoders.ps_reverse_swap                 # noqa: F401,E402
import decoders.ps_semantic_mini                # noqa: F401,E402
import decoders.rc4_inline_decrypt              # noqa: F401,E402
import decoders.crypto_api_annotator            # noqa: F401,E402


_NO_MATCH_PREFIX = "("     # every op's sentinel starts with "(op_id · …)"


def _looks_like_no_match(out: str, op_id: str) -> bool:
    """The 5 legacy ops all emit their `(op_id · reason)` sentinel
    on no-match.  Detect that so we don't produce a false child artifact."""
    if not out:
        return True
    if out.startswith(f"({op_id}"):
        return True
    return False


class _OpRecognizer:
    """Marker-driven recognizer for a function-only op.

    Emits a single Recognition when ANY of the provided regex markers
    matches the artifact's text form.  Confidence is HIGH when the
    match count ≥ ``high_at_matches`` else LIKELY.
    """
    def __init__(self, *,
                  op_id:            str,
                  markers:          Iterable[Pattern[str]],
                  artifact_type:    str,
                  min_len:          int = 0,
                  high_at_matches:  int = 2):
        self.name = f"op.{op_id}"
        self._op_id = op_id
        self._markers = list(markers)
        self._artifact_type = artifact_type
        self._min_len = min_len
        self._high_at = high_at_matches

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        if artifact.size < self._min_len:
            return []
        try:
            text = artifact.payload.decode("utf-8", errors="ignore")
        except Exception:
            return []
        if not text:
            return []
        hits = 0
        reasons: List[Reason] = []
        for pat in self._markers:
            if pat.search(text):
                hits += 1
                reasons.append(Reason(pat.pattern[:40], 0.40, "marker match"))
                if hits >= self._high_at:
                    break
        if hits == 0:
            return []
        confidence = HIGH if hits >= self._high_at else LIKELY
        return [Recognition(
            artifact_type=self._artifact_type,
            confidence=confidence,
            reasons=reasons or [Reason("marker", 0.40, "op marker")],
            recognizer=self.name,
        )]


class _OpCapability:
    """UAIE Capability that runs one legacy op-function.

    On successful decode: emits one ``transformer_output`` evidence and
    (if a child artifact type is configured) one child artifact carrying
    the decoded payload for further loop iteration.
    """
    def __init__(self, *,
                  op_id:               str,
                  requires_types:      List[str],
                  child_artifact_type: Optional[str],
                  category:            str,
                  description:         str):
        self.name = f"op.{op_id}"
        self._op_id = op_id
        self._child_type = child_artifact_type
        self.requires_artifact_type = list(requires_types)
        self.requires_evidence      = []
        self._category    = category
        self._description = description

    def execute(self, artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        try:
            text_in = artifact.payload.decode("utf-8", errors="ignore")
        except Exception:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)

        try:
            out = _ops.run_operation(self._op_id, text_in, None)
        except Exception:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)

        # Sentinel: op tells us it couldn't decode.  No evidence, no child.
        if not isinstance(out, str) or _looks_like_no_match(out, self._op_id):
            return CapabilityResult(
                notes={"op_id": self._op_id, "op_status": "no_match"},
                elapsed_ms=(perf_counter() - t0) * 1000.0,
            )
        # Op returned unchanged (accepts gate skipped it).
        if out == text_in:
            return CapabilityResult(
                notes={"op_id": self._op_id, "op_status": "unchanged"},
                elapsed_ms=(perf_counter() - t0) * 1000.0,
            )

        evidence = [make_evidence(
            artifact_uri=artifact.uri,
            kind="transformer_output",
            value=f"{self._op_id} · {len(out)}B out",
            source_capability=self.name,
            confidence=0.85,
            severity="info",
            location=f"decoders.op.{self._op_id}",
            meta={"category": self._category,
                    "description": self._description,
                    "op_id":       self._op_id},
        )]
        children = []
        if self._child_type:
            children.append(make_artifact(
                payload=out.encode("utf-8", errors="replace"),
                artifact_type=self._child_type,
                parent_uri=artifact.uri,
                depth=artifact.depth + 1,
                discovered_by=self.name,
                meta={"op_id": self._op_id},
            ))
        return CapabilityResult(
            evidence=evidence,
            child_artifacts=children,
            notes={"op_id": self._op_id, "op_status": "decoded"},
            elapsed_ms=(perf_counter() - t0) * 1000.0,
        )


# ═════════════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════════════
def adapt_op_and_register(
    *,
    op_id:                str,
    markers:              Iterable[Pattern[str]],
    artifact_types:       Iterable[str] = ("text", "powershell",
                                                 "powershell_normalized"),
    child_artifact_type:  Optional[str] = "powershell_normalized",
    profiles:             Optional[Iterable[str]] = None,
    version:              str = "1.0.0",
    min_len:              int = 0,
) -> Dict[str, Any]:
    """Adapt one ``@op(...)`` transformer into a UAIE plugin.

    Returns the resulting plugin dict (see plugins.register_plugin).
    """
    if op_id not in _ops.OPERATIONS:
        raise ValueError(f"transformer_op_adapter: op {op_id!r} is not "
                         f"registered in operations.OPERATIONS")
    spec = _ops.OPERATIONS[op_id]
    artifact_types = list(artifact_types) or ["text"]

    recognizer = _OpRecognizer(
        op_id=op_id,
        markers=markers,
        artifact_type=artifact_types[0],
        min_len=min_len,
    )
    capability = _OpCapability(
        op_id=op_id,
        requires_types=artifact_types,
        child_artifact_type=child_artifact_type,
        category=str(spec.get("category") or ""),
        description=str(spec.get("description") or ""),
    )
    _register_cap(capability)
    _plugin_registry.register_plugin(
        f"op.{op_id}", version, recognizer, capability,
        wraps_legacy=f"operations.OPERATIONS[{op_id!r}].fn",
    )
    plugins = _plugin_registry.all_plugins()
    if plugins and plugins[-1]["name"] == f"op.{op_id}":
        plugins[-1]["semantic"]           = "transformer"
        plugins[-1]["profiles"]           = list(profiles or ["powershell",
                                                                "malware",
                                                                "universal"])
        plugins[-1]["artifact_types"]     = artifact_types
        plugins[-1]["child_artifact_type"] = child_artifact_type
    return plugins[-1]


__all__ = ["adapt_op_and_register"]
