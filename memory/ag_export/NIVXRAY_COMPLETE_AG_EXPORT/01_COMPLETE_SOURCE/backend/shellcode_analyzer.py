"""Legacy path — Shellcode analyzer.

Gate 2D-B3.2: authoritative implementation moved to
    services.analyzers.shellcode

This module is retained ONLY as a backward-compat re-export so
existing UAIE plugin wrappers, imports, and integration code
continue to work. Do NOT add new call-sites here.
"""
from services.analyzers.shellcode import *          # noqa: F401,F403
from services.analyzers.shellcode import (          # noqa: F401
    analyze, is_shellcode, starts_with_known_prologue,
    shannon_entropy, detect_arch, disassemble,
    extract_iocs, _family_recognise,
)
