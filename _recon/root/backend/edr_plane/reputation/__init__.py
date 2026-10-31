"""B4 · reputation foundation. Provider-neutral by construction.

`CANONICAL EVIDENCE → OBSERVABLE → ADAPTER → PROVIDER(S) → RESULT`.

Reputation CONSUMES observables. It never owns, rewrites or reinterprets
evidence, and it never produces a detection.
"""
from .contract import (KNOWN_GOOD, KNOWN_MALICIOUS, LOOKUP_FAILED,
                       NOT_SUPPORTED, OBSERVABLE_TYPES, OBS_DOMAIN, OBS_IP,
                       OBS_MD5, OBS_SHA1, OBS_SHA256, OBS_URL,
                       SUBJECT_DNS_QUESTION, SUBJECT_FILE_CONTENT,
                       SUBJECT_NETWORK_PEER, SUBJECT_PROCESS_IMAGE,
                       SUBJECT_URL, UNKNOWN, VERDICTS, Observable,
                       ReputationProvider, ReputationResult)
from .observables import extract
from .service import (AGG_GOOD_ASSERTED, AGG_MALICIOUS_ASSERTED,
                      AGG_NO_INTELLIGENCE, AGG_NO_LOOKUP_COMPLETED,
                      AGG_NOT_SUPPORTED, ReputationService)

__all__ = [
    "Observable", "ReputationProvider", "ReputationResult",
    "ReputationService", "extract",
    "OBSERVABLE_TYPES", "OBS_SHA256", "OBS_SHA1", "OBS_MD5", "OBS_DOMAIN",
    "OBS_IP", "OBS_URL",
    "SUBJECT_PROCESS_IMAGE", "SUBJECT_FILE_CONTENT", "SUBJECT_NETWORK_PEER",
    "SUBJECT_DNS_QUESTION", "SUBJECT_URL",
    "VERDICTS", "KNOWN_MALICIOUS", "KNOWN_GOOD", "UNKNOWN", "LOOKUP_FAILED",
    "NOT_SUPPORTED",
    "AGG_MALICIOUS_ASSERTED", "AGG_GOOD_ASSERTED", "AGG_NO_INTELLIGENCE",
    "AGG_NO_LOOKUP_COMPLETED", "AGG_NOT_SUPPORTED",
]
