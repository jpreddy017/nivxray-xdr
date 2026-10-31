"""Coverage Reporter — ADR-0001.

Given a case that has been through classify → handlers → CIO append,
report:
  - which family fired
  - which handler(s) ran
  - whether residual output still looks obfuscated (heuristic)

The reporter is descriptive, not prescriptive. It does not modify
the CIO or decide anything. Deterministic and pure.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class CoverageReport:
    family: str                        # classifier output family
    handler_names: List[str]           # handlers that fired, in order
    residual_looks_obfuscated: bool    # heuristic — see rationale below
    residual_entropy: float
    residual_printable_ratio: float
    rationale: List[str] = field(default_factory=list)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in "\r\n\t") / len(s)


# Heuristic thresholds — deterministic, no ML.
# Tuned conservatively to avoid false "obfuscated" claims on legitimate
# base64 / hex text. See ADR-0001 §6 success criteria.
_ENTROPY_HIGH = 5.5
_PRINTABLE_LOW = 0.85


def report(family: str, handler_names: List[str], residual_output: str) -> CoverageReport:
    """Build a CoverageReport for one classified+handled case.

    Args:
        family: classifier output family.
        handler_names: names of handlers that fired, in order.
        residual_output: the deepest artifact reached after handlers ran.
    """
    entropy = _shannon_entropy(residual_output)
    printable = _printable_ratio(residual_output)
    obfuscated = (entropy >= _ENTROPY_HIGH) and (printable < _PRINTABLE_LOW)
    rationale = [
        f"entropy={entropy:.2f} (threshold {_ENTROPY_HIGH})",
        f"printable_ratio={printable:.2f} (threshold {_PRINTABLE_LOW})",
        f"residual_length={len(residual_output)}",
    ]
    if not residual_output:
        rationale.append("empty residual — nothing to assess")
    return CoverageReport(
        family=family,
        handler_names=list(handler_names),
        residual_looks_obfuscated=obfuscated,
        residual_entropy=entropy,
        residual_printable_ratio=printable,
        rationale=rationale,
    )
