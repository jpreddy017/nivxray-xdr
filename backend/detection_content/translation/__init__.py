"""
NivXRay XDR — Deterministic Translation Package.
"""
from .base import BaseTranslator, TranslationResult
from .sigma_translator import SigmaTranslator
from .spl_translator import SPLTranslator
from .kql_translator import KQLTranslator
from .eql_translator import EQLTranslator
from .manager import TranslationManager, TRANSLATION_MANAGER

__all__ = [
    "BaseTranslator",
    "TranslationResult",
    "SigmaTranslator",
    "SPLTranslator",
    "KQLTranslator",
    "EQLTranslator",
    "TranslationManager",
    "TRANSLATION_MANAGER",
]
