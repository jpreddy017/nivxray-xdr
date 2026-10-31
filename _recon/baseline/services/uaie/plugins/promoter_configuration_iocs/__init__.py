"""Plugin · promoter.configuration_iocs  (R28.7.3 · Plugin 3 / 3)

Consumes a ``configuration`` artifact emitted by Plugin 2
(``extractor.binary_configuration``) and promotes every typed IOC
element into a first-class investigation artifact:

    { "type": "ipv4",   "value": "1.2.3.4" }   →  ip_artifact
    { "type": "url",    "value": "https://…" } →  url_artifact
    { "type": "domain", "value": "evil.tld" }  →  domain_artifact

Plugin 3 also emits ONE evidence record per IOC so the analyst can
see the extracted intelligence surface at the top of the SSOT
without walking the artifact tree.  It knows NOTHING about malware
— it simply promotes typed configuration elements.
"""
from __future__ import annotations

import json

from ...artifact   import make_artifact
from ...capability import CapabilityResult
from ...contract   import (CAT_ANALYZER, CapabilityContract, IMPROVES_IOC,
                              IMPROVES_ATTRIBUTION, register)
from ...evidence   import make_evidence


_TYPE_TO_ARTIFACT_TYPE = {
    "ipv4":   "ip_artifact",
    "url":    "url_artifact",
    "domain": "domain_artifact",
}
_TYPE_TO_EVIDENCE_KIND = {
    "ipv4":   "ioc.ip",
    "url":    "ioc.url",
    "domain": "ioc.domain",
}


class _Impl:
    name = "promoter.configuration_iocs"
    requires_artifact_type = ["configuration"]
    requires_evidence      = []

    def execute(self, artifact) -> CapabilityResult:
        try:
            elements = json.loads(artifact.payload.decode("utf-8"))
        except Exception:
            return CapabilityResult()
        if not isinstance(elements, list):
            return CapabilityResult()

        children = []
        evidence_records = []
        for e in elements:
            if not isinstance(e, dict):
                continue
            t = e.get("type")
            v = e.get("value")
            if not t or not v or t not in _TYPE_TO_ARTIFACT_TYPE:
                continue
            new_type = _TYPE_TO_ARTIFACT_TYPE[t]
            children.append(make_artifact(
                v.encode("utf-8"), new_type,
                parent_uri=artifact.uri,
                depth=artifact.depth + 1,
                discovered_by=self.name,
                meta={"source_offset": e.get("offset"), "original_type": t},
            ))
            evidence_records.append(make_evidence(
                artifact_uri=artifact.uri,
                kind=_TYPE_TO_EVIDENCE_KIND[t],
                value=v,
                source_capability=self.name,
                confidence=0.95,
                severity="medium",
            ))
        return CapabilityResult(evidence=evidence_records,
                                  child_artifacts=children)


_impl = _Impl()

register(
    CapabilityContract(
        id="promoter.configuration_iocs",
        version="1.0",
        category=CAT_ANALYZER,
        requires=("configuration",),
        produces=("ip_artifact", "url_artifact", "domain_artifact"),
        improves=(IMPROVES_IOC, IMPROVES_ATTRIBUTION),
        confidence_gain=0.60,
        produces_confidence=(
            ("ioc_confidence",         0.60),
            ("attribution_confidence", 0.20),
        ),
        cost=1,
        priority_hint=5,
        parallelizable=True,
        deterministic=True,
        description=(
            "Promotes typed configuration elements (ipv4/url/domain) "
            "from a `configuration` artifact into first-class "
            "ip_artifact / url_artifact / domain_artifact children, "
            "emitting one evidence record per IOC.  Generic — no "
            "malware-family logic."
        ),
    ),
    impl=_impl,
)

__all__ = ["_impl"]
