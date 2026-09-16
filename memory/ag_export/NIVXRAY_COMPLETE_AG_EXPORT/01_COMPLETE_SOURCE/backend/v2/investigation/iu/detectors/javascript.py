"""JavaScript detector — mshta / HTA / ActiveX / Node contexts."""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import ArtefactType, Capability

_JS_STRONG_RE = re.compile(r"(?ix)^\s*javascript\s*:")
_JS_WEAK_RE = re.compile(
    r"(?ix)"
    r"\bnew\s+ActiveXObject\s*\("
    r"|\bWScript\.CreateObject\b"
    r"|\bXMLHttpRequest\b"
    r"|\brequire\s*\(\s*['\"](?:child_process|fs|net|http)['\"]\)"
    r"|\bdocument\.write\s*\("
    r"|\beval\s*\(\s*['\"]"
)


class JavaScriptDetector:
    NAME = "javascript"
    ARTEFACT_TYPE = ArtefactType.JAVASCRIPT
    CAPABILITIES = (Capability.JAVASCRIPT_ENGINE, Capability.DECODER,
                    Capability.IOC, Capability.MITRE, Capability.VERDICT)

    def score(self, text: str) -> Evidence | None:
        if not text:
            return None
        # `javascript:` scheme anchors the input as JS with high
        # confidence (outranks incidental VBS-shared tokens like
        # `WScript.Shell`).
        m = _JS_STRONG_RE.match(text)
        conf = 98
        if not m:
            m = _JS_WEAK_RE.search(text)
            conf = 85
        if not m:
            return None
        return Evidence(
            source=f"input_understanding.{self.NAME}",
            observation=m.group(0)[:80],
            confidence=conf,
            rationale=(
                "JavaScript-shape detected (`javascript:` scheme, "
                "ActiveXObject, XMLHttpRequest, or Node built-in "
                "require). Should route to a JS analyzer once available."
            ),
            meta={"detector": self.NAME},
        )


DETECTOR = JavaScriptDetector()
