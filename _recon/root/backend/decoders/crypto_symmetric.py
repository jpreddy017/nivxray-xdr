"""Legacy path — symmetric-crypto decoder plugins (AES / RC4).

Gate 2D-B3.1 · Families 5 (RC4) + 6 (AES-CBC): the authoritative
implementation moved to
    services.decoder.base.crypto

This module is retained ONLY as a backward-compat re-export so
existing UAIE plugin adapters and legacy imports continue to work.
Do NOT add new call-sites here.
"""
from services.decoder.base.crypto import *                    # noqa: F401,F403
from services.decoder.base.crypto import (                    # noqa: F401
    Rc4Decoder, AesCbcDecoder, CryptoDetectDecoder,
)
