"""B4 · the LOCAL / CUSTOM IOC provider.

A real provider, not a stub. It reads the platform's EXISTING IOC
authority — the `iocs` collection that
`detection_content.ioc_watchlist` already binds its rules to — so local
intelligence has ONE home rather than two.

It is offline by construction: no third-party service, no API key, no
network. Core EDR reputation therefore works with no external dependency
at all.

Tenant rule, carried over verbatim from the watchlist contract: an entry
scoped to a tenant may only judge that tenant's evidence. An unscoped
entry is platform intelligence and is cited as `platform`.

Disposition rule: an IOC list is an assertion of MALICIOUSNESS unless the
entry says otherwise, so a record with no explicit disposition is
`KNOWN_MALICIOUS`. An allow-list entry must state
`disposition: KNOWN_GOOD` explicitly — nothing is ever inferred to be
good.
"""
from __future__ import annotations

from typing import Any, Optional, Sequence

from ..contract import (KNOWN_GOOD, KNOWN_MALICIOUS, LOOKUP_FAILED,
                        NOT_SUPPORTED, OBS_DOMAIN, OBS_IP, OBS_MD5, OBS_SHA1,
                        OBS_SHA256, OBS_URL, UNKNOWN, Observable,
                        ReputationResult, now_iso)

WATCHLIST_COLLECTION = "iocs"

#: Observable type → the `kind` value the IOC store uses. The store's
#: vocabulary is REUSED, never translated into a second one.
_KIND = {
    OBS_SHA256: "sha256",
    OBS_SHA1: "sha1",
    OBS_MD5: "md5",
    OBS_DOMAIN: "domain",
    OBS_IP: "ip",
    OBS_URL: "url",
}

_ALLOWED_DISPOSITIONS = {KNOWN_MALICIOUS, KNOWN_GOOD}


class LocalIOCProvider:
    """Local / customer-supplied intelligence."""

    provider_id = "nivxforge.local_ioc"
    provider_version = "1.0.0"
    supported_types = (OBS_SHA256, OBS_SHA1, OBS_MD5, OBS_DOMAIN, OBS_IP,
                       OBS_URL)
    offline = True

    def __init__(self, db: Any, *,
                 collection: str = WATCHLIST_COLLECTION) -> None:
        self._db = db
        self._collection = collection

    async def lookup(self, observables: Sequence[Observable], *,
                     tenant_id: str) -> list[ReputationResult]:
        results: list[ReputationResult] = []
        for obs in observables:
            kind = _KIND.get(obs.type)
            if kind is None:
                results.append(ReputationResult(
                    observable=obs.value, observable_type=obs.type,
                    subject=obs.subject, provider_id=self.provider_id,
                    verdict=NOT_SUPPORTED,
                    failure_reason=(f"{self.provider_id} holds no list for "
                                    f"observable type {obs.type}"),
                    provenance={"provider_version": self.provider_version}))
                continue
            try:
                doc = await self._find(kind, obs, tenant_id=tenant_id)
            except Exception as e:  # noqa: BLE001
                # An operational failure is NOT intelligence. It is
                # reported as LOOKUP_FAILED so nothing can read it as
                # "no known reputation".
                results.append(ReputationResult(
                    observable=obs.value, observable_type=obs.type,
                    subject=obs.subject, provider_id=self.provider_id,
                    verdict=LOOKUP_FAILED,
                    failure_reason=f"{type(e).__name__}: {str(e)[:200]}",
                    provenance={"provider_version": self.provider_version,
                                "collection": self._collection}))
                continue
            results.append(self._result(obs, doc, kind))
        return results

    async def _find(self, kind: str, obs: Observable, *,
                    tenant_id: str) -> Optional[dict[str, Any]]:
        value = obs.value.lower() if obs.type != OBS_URL else obs.value
        doc = await self._db[self._collection].find_one(
            {"kind": kind, "value": value}, {"_id": 0})
        if not doc:
            return None
        scoped = doc.get("tenant_id")
        if scoped and scoped != (tenant_id or obs.tenant_id):
            # A tenant's IOC never judges another tenant's evidence.
            return None
        return doc

    def _result(self, obs: Observable, doc: Optional[dict[str, Any]],
                kind: str) -> ReputationResult:
        base = {"provider_version": self.provider_version,
                "collection": self._collection,
                "observable_source_field": obs.source_field}
        if not doc:
            return ReputationResult(
                observable=obs.value, observable_type=obs.type,
                subject=obs.subject, provider_id=self.provider_id,
                verdict=UNKNOWN, queried_at=now_iso(),
                match_basis=f"{self._collection}:kind={kind} · no entry",
                provenance=base)
        disposition = str(doc.get("disposition")
                          or KNOWN_MALICIOUS).upper().strip()
        if disposition not in _ALLOWED_DISPOSITIONS:
            return ReputationResult(
                observable=obs.value, observable_type=obs.type,
                subject=obs.subject, provider_id=self.provider_id,
                verdict=LOOKUP_FAILED,
                failure_reason=(f"IOC entry declares an unknown disposition "
                                f"{disposition!r}; an unreadable entry is "
                                f"refused rather than guessed"),
                provenance=base)
        confidence = doc.get("confidence")
        return ReputationResult(
            observable=obs.value, observable_type=obs.type,
            subject=obs.subject, provider_id=self.provider_id,
            verdict=disposition, matched=True,
            confidence=(float(confidence)
                        if isinstance(confidence, (int, float)) else None),
            severity=doc.get("severity"),
            queried_at=now_iso(),
            intelligence_timestamp=(doc.get("updated_at")
                                    or doc.get("first_seen")),
            intelligence_version=doc.get("intelligence_version"),
            expires_at=doc.get("valid_until"),
            match_basis=f"{self._collection}:kind={kind} value=exact",
            tenant_scope=doc.get("tenant_id") or "platform",
            tags=tuple((doc.get("tags") or [])[:8]),
            provenance={**base, "source": doc.get("source")})
