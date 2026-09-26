"""Analyzers package — importing this registers every analyzer.

Phase 3 · Cycle A · 2026-02.

New analyzer types plug in here in one line:
    from .apk import APKAnalyzer
    register(APKAnalyzer())
"""
from .. import register
from .pe import PEAnalyzer
from .pdf import PDFAnalyzer
from .elf import ELFAnalyzer
from .office import OfficeAnalyzer
from .shellcode import ShellcodeAnalyzer
from .archive import ArchiveAnalyzer

# ─── Register in priority order (higher-confidence types first) ───────
register(PEAnalyzer())
register(PDFAnalyzer())
register(ELFAnalyzer())
register(ShellcodeAnalyzer())
register(ArchiveAnalyzer())
# Office is registered LAST — its magic_matcher does a full ZIP-parse
# so it should only fire when the earlier magic hits (PE / PDF / ELF) miss.
register(OfficeAnalyzer())

__all__ = ["PEAnalyzer", "PDFAnalyzer", "ELFAnalyzer", "OfficeAnalyzer", "ShellcodeAnalyzer", "ArchiveAnalyzer"]

