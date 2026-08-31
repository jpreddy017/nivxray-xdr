"""
P0.2b · Strict pySigma Parse
────────────────────────────

Authoritative Sigma parser.  Replaces the permissive YAML-based
recognition previously used in `sigma_ingest.py` with the official
`pySigma` library's SigmaRule AST parser.

Every parse produces a deterministic outcome:

    SigmaParseResult
      • status                 PARSED · PARSE_ERROR · COMPILE_ERROR
      • rule                   SigmaRule instance (when PARSED)
      • error_type             library error class name (when errored)
      • error_message          exception detail
      • parse_source_line      YAML line the parser choked on (if any)
      • rule_id, title, ...    surface metadata (available even on
                                partial parses, from raw YAML fallback)

Nothing here silently coerces malformed Sigma into a "usable"
rule.  A rule that fails to parse is marked INVALID with the real
reason preserved — the Rule↔Capability Matcher (P0.2d) will never
be given a rule that hasn't already been strictly validated.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

try:
    from sigma.rule import SigmaRule                # type: ignore
    from sigma.exceptions import SigmaError         # type: ignore
    _PYSIGMA_AVAILABLE = True
except Exception as _e:  # pragma: no cover — playbooks pin the lib
    SigmaRule = None            # type: ignore
    SigmaError = Exception      # type: ignore
    _PYSIGMA_AVAILABLE = False


class StrictParseStatus:
    PARSED         = "PARSED"
    PARSE_ERROR    = "PARSE_ERROR"
    COMPILE_ERROR  = "COMPILE_ERROR"
    LIB_MISSING    = "LIB_MISSING"


@dataclass
class SigmaParseResult:
    status:            str
    rule:              Optional["SigmaRule"] = None
    error_type:        Optional[str] = None
    error_message:     Optional[str] = None
    error_location:    Optional[str] = None
    surface:           dict = field(default_factory=dict)

    def is_ok(self) -> bool:
        return self.status == StrictParseStatus.PARSED

    def to_dict(self) -> dict:
        return {
            "status":         self.status,
            "error_type":     self.error_type,
            "error_message":  self.error_message,
            "error_location": self.error_location,
            "surface":        self.surface,
        }


def _surface_from_yaml(y: Any) -> dict:
    """
    Extract identity fields from a raw YAML document even when the
    Sigma AST parse fails — so downstream reports still know
    WHICH rule blew up, not just that A rule blew up.
    """
    if not isinstance(y, dict):
        return {"title": "(non-dict yaml)", "id": None}
    ls = y.get("logsource") or {}
    return {
        "id":          y.get("id"),
        "title":       y.get("title"),
        "level":       y.get("level"),
        "author":      y.get("author"),
        "product":     ls.get("product") if isinstance(ls, dict) else None,
        "category":    ls.get("category") if isinstance(ls, dict) else None,
        "service":     ls.get("service") if isinstance(ls, dict) else None,
        "tags":        y.get("tags") if isinstance(y.get("tags"), list) else [],
    }


def strict_parse(text: str) -> SigmaParseResult:
    """
    Deterministically parse one Sigma rule document.

    Order:
        1.  YAML load (structural).
        2.  Surface extraction (for provenance on failure).
        3.  pySigma SigmaRule.from_dict / from_yaml.
        4.  Return a status + optional AST reference.

    Never returns a partially-valid SigmaRule.  Either the AST is
    complete and the status is PARSED, or the rule is honestly
    marked as errored with the real exception preserved.
    """
    # ---- 1. YAML structural parse -----------------------------------
    try:
        y = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return SigmaParseResult(
            status=StrictParseStatus.PARSE_ERROR,
            error_type="YAMLError",
            error_message=str(e),
            error_location=getattr(getattr(e, "problem_mark", None),
                                            "line", None) and
                              f"line {e.problem_mark.line + 1}" or None,  # type: ignore
        )
    surface = _surface_from_yaml(y)
    if not isinstance(y, dict) or "detection" not in y:
        return SigmaParseResult(
            status=StrictParseStatus.PARSE_ERROR,
            error_type="NotASigmaRule",
            error_message="Document missing required 'detection' section",
            surface=surface,
        )

    # ---- 2. pySigma AST parse ---------------------------------------
    if not _PYSIGMA_AVAILABLE:
        return SigmaParseResult(
            status=StrictParseStatus.LIB_MISSING,
            error_type="ImportError",
            error_message="pysigma is not installed in this runtime",
            surface=surface,
        )

    try:
        rule = SigmaRule.from_dict(y)   # authoritative AST parse
    except SigmaError as e:
        return SigmaParseResult(
            status=StrictParseStatus.COMPILE_ERROR,
            error_type=type(e).__name__,
            error_message=str(e),
            surface=surface,
        )
    except Exception as e:
        # Unknown parser exception — record honestly.
        return SigmaParseResult(
            status=StrictParseStatus.PARSE_ERROR,
            error_type=type(e).__name__,
            error_message=str(e),
            surface=surface,
        )

    return SigmaParseResult(
        status=StrictParseStatus.PARSED,
        rule=rule,
        surface=surface,
    )


def is_pysigma_available() -> bool:
    return _PYSIGMA_AVAILABLE
