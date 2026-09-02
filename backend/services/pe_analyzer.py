"""Legacy path — PE (Portable Executable) analyzer.

Gate 2D-B3.2: authoritative implementation moved to
    services.analyzers.pe

This module is retained ONLY as a backward-compat re-export so
existing UAIE plugin wrappers, imports, and integration code
continue to work. Do NOT add new call-sites here.
"""
from services.analyzers.pe import *          # noqa: F401,F403
from services.analyzers.pe import (          # noqa: F401
    analyze_pe, is_available,
)
