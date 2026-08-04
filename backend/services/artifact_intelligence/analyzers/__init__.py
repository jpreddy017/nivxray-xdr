"""Analyzers package — importing this registers every analyzer.

Phase 3 · Cycle A · 2026-02.

New analyzer types plug in here in one line:
    from .apk import APKAnalyzer
    register(APKAnalyzer())
"""
from .. import register
from .pe import PEAnalyzer
from .pdf import PDFAnalyzer

# ─── Register in priority order (higher-confidence types first) ───────
register(PEAnalyzer())
register(PDFAnalyzer())

__all__ = ["PEAnalyzer", "PDFAnalyzer"]
