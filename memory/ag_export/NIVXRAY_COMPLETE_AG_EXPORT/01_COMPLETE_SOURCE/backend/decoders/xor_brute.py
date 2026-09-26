"""Legacy path — XOR brute-force decoder plugin.

Gate 2D-B3.1 · Family 4 (repeating-key XOR): the authoritative
implementation moved to
    services.decoder.base.xor_brute

This module is retained ONLY as a backward-compat re-export so
existing UAIE plugin adapters and legacy imports continue to work.
Do NOT add new call-sites here.

Note the star-import intentionally re-triggers the class definition
in the authoritative module — `DecoderRegistry.register` runs
exactly once there, not twice, because Python's import system
caches the module.
"""
from services.decoder.base.xor_brute import *          # noqa: F401,F403
from services.decoder.base.xor_brute import XorBruteDecoder  # noqa: F401
