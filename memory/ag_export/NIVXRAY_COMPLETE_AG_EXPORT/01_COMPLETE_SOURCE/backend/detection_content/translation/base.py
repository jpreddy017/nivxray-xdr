"""
NivXRay XDR — Deterministic Translation Base Contract.
Enforces the cardinal rule: NO SILENT WEAKENING.
Any query or construct that cannot be faithfully evaluated is marked UNSUPPORTED/PARTIAL
with exact explanation and preserved raw syntax.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..canonical_ir.models import CanonicalIR, TranslationFidelity, UnsupportedConstruct


@dataclass
class TranslationResult:
    success: bool
    ir: Optional[CanonicalIR] = None
    fidelity: TranslationFidelity = TranslationFidelity.UNSUPPORTED
    unsupported_constructs: List[UnsupportedConstruct] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "fidelity": self.fidelity.value,
            "errors": self.errors,
            "unsupported_constructs": [
                {
                    "construct_name": u.construct_name,
                    "raw_snippet": u.raw_snippet,
                    "explanation": u.explanation,
                    "fatal": u.fatal,
                }
                for u in self.unsupported_constructs
            ],
            "ir": self.ir.to_dict() if self.ir else None,
        }


class BaseTranslator(ABC):
    """Abstract base class for all language-to-NIR translators."""

    @property
    @abstractmethod
    def source_format(self) -> str:
        """Format identifier: sigma, spl, kql, eql, etc."""
        raise NotImplementedError

    @abstractmethod
    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        """Translate source query text into CanonicalIR."""
        raise NotImplementedError
