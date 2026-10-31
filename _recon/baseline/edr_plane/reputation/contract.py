"""B4 · REPUTATION CONTRACT — provider-neutral by construction.

```
CANONICAL EVIDENCE
        ↓
OBSERVABLE EXTRACTION        (observables.py)
        ↓
SHA256 / SHA1 / MD5 / DOMAIN / IP / URL
        ↓
REPUTATION ADAPTER INTERFACE (this file)
        ↓
one or more intelligence providers
        ↓
REPUTATION RESULT            (per provider, never collapsed)
        ↓
detection / correlation / retrospection
```

The separations this file exists to keep:

* an OBSERVABLE is a value we extracted from evidence;
* a LOOKUP is an act we performed at a point in time;
* an INTELLIGENCE SOURCE is who we asked;
* a VERDICT is what THAT source said;
* a MATCH is a verdict that names the observable;
* a DETECTION is a conclusion an engine reached — never a verdict alone.

Verdict rules that are not negotiable:

* `UNKNOWN` means *no source knows this observable*. It NEVER means
  benign.
* `LOOKUP_FAILED` means *we failed to ask*. It is not intelligence and it
  must never be read as `UNKNOWN`.
* `NOT_SUPPORTED` means *this provider cannot judge this observable
  type*. It is not an answer about the observable.
* Provider disagreement stays VISIBLE. Results are retained per provider.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Protocol, Sequence, runtime_checkable

# ── observable types ─────────────────────────────────────────────────
OBS_SHA256 = "SHA256"
OBS_SHA1 = "SHA1"
OBS_MD5 = "MD5"
OBS_DOMAIN = "DOMAIN"
OBS_IP = "IP"
OBS_URL = "URL"
#: Extensible by design: a new observable type is added here and adapters
#: declare whether they support it. Nothing about canonical evidence or
#: detection semantics changes to admit one.
OBSERVABLE_TYPES = (OBS_SHA256, OBS_SHA1, OBS_MD5, OBS_DOMAIN, OBS_IP,
                    OBS_URL)

#: WHICH OBJECT the observable identifies. A process-image SHA-256 and a
#: written-file SHA-256 are both SHA-256 observables, but they are facts
#: about different objects and a result must say which.
SUBJECT_PROCESS_IMAGE = "PROCESS_IMAGE"
SUBJECT_FILE_CONTENT = "FILE_CONTENT"
SUBJECT_NETWORK_PEER = "NETWORK_PEER"
SUBJECT_DNS_QUESTION = "DNS_QUESTION"
SUBJECT_URL = "URL_RESOURCE"

# ── verdicts ─────────────────────────────────────────────────────────
KNOWN_MALICIOUS = "KNOWN_MALICIOUS"
KNOWN_GOOD = "KNOWN_GOOD"
UNKNOWN = "UNKNOWN"
LOOKUP_FAILED = "LOOKUP_FAILED"
NOT_SUPPORTED = "NOT_SUPPORTED"
VERDICTS = (KNOWN_MALICIOUS, KNOWN_GOOD, UNKNOWN, LOOKUP_FAILED,
            NOT_SUPPORTED)
#: The two states that are ACTUAL intelligence about the observable.
INTELLIGENCE_VERDICTS = (KNOWN_MALICIOUS, KNOWN_GOOD)
#: States that must never be presented as a judgement of the observable.
NON_JUDGEMENTS = (UNKNOWN, LOOKUP_FAILED, NOT_SUPPORTED)

VERDICT_MEANING = {
    KNOWN_MALICIOUS: "this source asserts the observable is malicious",
    KNOWN_GOOD: "this source asserts the observable is known good",
    UNKNOWN: ("the lookup SUCCEEDED and this source holds no reputation "
              "for the observable. This is not benign"),
    LOOKUP_FAILED: ("the lookup itself did not complete, so no "
                    "intelligence was obtained. This is not UNKNOWN"),
    NOT_SUPPORTED: ("this provider cannot judge this observable type at "
                    "all; it is not an answer about the observable"),
}

# ── cache / freshness ────────────────────────────────────────────────
CACHE_MISS = "CACHE_MISS"
CACHE_HIT_FRESH = "CACHE_HIT_FRESH"
CACHE_HIT_STALE = "CACHE_HIT_STALE"
CACHE_BYPASSED = "CACHE_BYPASSED"
CACHE_NOT_CACHEABLE = "CACHE_NOT_CACHEABLE"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Observable:
    """A value extracted from evidence, with WHERE it came from."""
    type: str
    value: str
    subject: str
    source_field: str
    evidence_refs: tuple[str, ...] = ()
    tenant_id: str = ""
    endpoint_id: str = ""
    provenance: str = ""

    def __post_init__(self) -> None:
        if self.type not in OBSERVABLE_TYPES:
            raise ValueError(f"unknown observable type {self.type!r}")
        if not self.value:
            raise ValueError("an observable with no value is not an "
                             "observable")

    @property
    def cache_key(self) -> str:
        return f"{self.type}|{self.value}"


@dataclass(frozen=True)
class ReputationResult:
    """What ONE provider said about ONE observable at ONE point in time."""
    observable: str
    observable_type: str
    subject: str
    provider_id: str
    verdict: str
    #: Only when the SOURCE supplied one. Never synthesised.
    confidence: Optional[float] = None
    severity: Optional[str] = None
    #: When WE asked.
    queried_at: str = field(default_factory=now_iso)
    #: When the INTELLIGENCE was stated / last updated by its source.
    intelligence_timestamp: Optional[str] = None
    intelligence_version: Optional[str] = None
    expires_at: Optional[str] = None
    #: How the provider matched: which namespace / list / record.
    match_basis: Optional[str] = None
    matched: bool = False
    tenant_scope: Optional[str] = None
    cache_state: str = CACHE_MISS
    failure_reason: Optional[str] = None
    provenance: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {self.verdict!r}")
        if self.verdict in NON_JUDGEMENTS and self.matched:
            raise ValueError(
                f"{self.verdict} cannot be a MATCH: a non-judgement never "
                f"names the observable as known")

    @property
    def is_intelligence(self) -> bool:
        return self.verdict in INTELLIGENCE_VERDICTS

    def to_dict(self) -> dict[str, Any]:
        return {
            "observable": self.observable,
            "observable_type": self.observable_type,
            "subject": self.subject,
            "provider_id": self.provider_id,
            "verdict": self.verdict,
            "verdict_meaning": VERDICT_MEANING[self.verdict],
            "confidence": self.confidence,
            "severity": self.severity,
            "queried_at": self.queried_at,
            "intelligence_timestamp": self.intelligence_timestamp,
            "intelligence_version": self.intelligence_version,
            "expires_at": self.expires_at,
            "match_basis": self.match_basis,
            "matched": self.matched,
            "tenant_scope": self.tenant_scope,
            "cache_state": self.cache_state,
            "failure_reason": self.failure_reason,
            "tags": list(self.tags),
            "provenance": dict(self.provenance),
        }


@runtime_checkable
class ReputationProvider(Protocol):
    """The ONLY thing a new intelligence source has to implement.

    A provider answers about observables. It does not read canonical
    evidence, it does not write evidence, and it does not produce
    detections — those authorities live elsewhere and adding a provider
    must never require touching them.
    """
    provider_id: str
    provider_version: str
    #: Observable types this provider can actually judge.
    supported_types: tuple[str, ...]
    #: True when the provider needs no network / third-party service, so
    #: core EDR operation can be proven to work offline.
    offline: bool

    async def lookup(self, observables: Sequence[Observable], *,
                     tenant_id: str) -> list[ReputationResult]:
        ...
