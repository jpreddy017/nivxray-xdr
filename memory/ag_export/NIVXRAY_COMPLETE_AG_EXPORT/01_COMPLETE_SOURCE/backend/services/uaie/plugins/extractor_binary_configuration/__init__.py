"""Plugin · extractor.binary_configuration  (R28.7.3 · Plugin 2 / 3)

Generic binary-configuration extractor.  Consumes ``binary_bytes``
(the output of Plugin 1 or any other transformer that produces raw
bytes) and emits ONE ``configuration`` child artifact whose payload
is a deterministic JSON document of TYPED configuration elements:

    [
      { "type": "ipv4",   "value": "1.2.3.4",           "offset": 128 },
      { "type": "url",    "value": "https://c2/beacon", "offset": 240 },
      { "type": "domain", "value": "evil.example.com",  "offset": 512 },
      { "type": "string", "value": "MSF-Mutex-Beacon",  "offset": 640 },
    ]

The plugin knows NOTHING about malware families.  It simply scans
the buffer for printable ASCII spans and recognises well-known IOC
shapes with strict regexes.  Downstream Plugin 3 promotes each
element to a first-class ``ip_artifact`` / ``domain_artifact`` /
``url_artifact`` — no re-parsing required.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from ...artifact   import make_artifact
from ...capability import CapabilityResult
from ...contract   import (CAT_ANALYZER, CapabilityContract, IMPROVES_ANALYSIS,
                              IMPROVES_IOC, register)


# ── Regex vocabulary (strict, deterministic) ───────────────────────
_STRING_RE  = re.compile(rb"[\x20-\x7e]{4,}")
_IPV4_RE    = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b"
)
_URL_RE     = re.compile(r"\bhttps?://[^\s\"'<>()\[\]{}]+", re.IGNORECASE)
_DOMAIN_RE  = re.compile(
    r"\b((?=.{4,253}\b)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.){1,}"
    r"(?:com|net|org|io|co|uk|de|ru|cn|jp|info|xyz|top|biz|tk|ml|ga|cf|gq|dev|app|us|cc))\b"
)


def _extract_config(buf: bytes) -> List[Dict[str, Any]]:
    """Walk the buffer once collecting printable spans and typed
    IOC hits.  Deterministic — same bytes in → same list out."""
    elements: List[Dict[str, Any]] = []
    seen: set = set()   # dedup on (type, value)

    for match in _STRING_RE.finditer(buf):
        s = match.group().decode("ascii", errors="ignore")
        off = match.start()
        # ── URL takes precedence over domain/ipv4 ──
        for u in _URL_RE.findall(s):
            key = ("url", u)
            if key not in seen:
                seen.add(key)
                elements.append({"type": "url", "value": u, "offset": off})
        # ── IPv4 ──
        for ip in _IPV4_RE.findall(s):
            # Ignore obvious noise like 0.0.0.0 / 255.255.255.255 / 127.0.0.1
            if ip in ("0.0.0.0", "255.255.255.255"):
                continue
            octets = [int(o) for o in ip.split(".")]
            if all(o == octets[0] for o in octets):    # 4.4.4.4 shape
                continue
            key = ("ipv4", ip)
            if key not in seen:
                seen.add(key)
                elements.append({"type": "ipv4", "value": ip, "offset": off})
        # ── Domains ──
        for d in _DOMAIN_RE.findall(s):
            key = ("domain", d.lower())
            if key not in seen:
                seen.add(key)
                elements.append({"type": "domain", "value": d.lower(),
                                    "offset": off})
        # ── Long printable strings kept as ``string`` (candidate
        #    mutex/campaign/user-agent).  Only if not already covered.
        if len(s) >= 8 and not any(
                match.start() <= e["offset"] < match.end()
                and e["type"] in ("url", "ipv4", "domain")
                for e in elements):
            key = ("string", s)
            if key not in seen:
                seen.add(key)
                elements.append({"type": "string", "value": s, "offset": off})
    # Deterministic ordering — by offset, then type, then value.
    elements.sort(key=lambda e: (e["offset"], e["type"], e["value"]))
    return elements


class _Impl:
    name = "extractor.binary_configuration"
    requires_artifact_type = ["binary_bytes"]
    requires_evidence      = []

    def execute(self, artifact) -> CapabilityResult:
        buf = artifact.payload or b""
        if not buf:
            return CapabilityResult()
        elements = _extract_config(buf)
        if not elements:
            return CapabilityResult()
        payload = json.dumps(elements, sort_keys=True,
                                separators=(",", ":")).encode("utf-8")
        child = make_artifact(
            payload, "configuration",
            parent_uri=artifact.uri,
            depth=artifact.depth + 1,
            discovered_by=self.name,
            meta={"element_count": len(elements),
                    "types": sorted({e["type"] for e in elements})},
        )
        return CapabilityResult(child_artifacts=[child])


_impl = _Impl()

register(
    CapabilityContract(
        id="extractor.binary_configuration",
        version="1.0",
        category=CAT_ANALYZER,
        requires=("binary_bytes",),
        produces=("configuration",),
        improves=(IMPROVES_ANALYSIS, IMPROVES_IOC),
        confidence_gain=0.40,
        produces_confidence=(
            ("analysis_confidence", 0.40),
            ("ioc_confidence",      0.30),
        ),
        cost=2,
        priority_hint=2,
        parallelizable=True,
        deterministic=True,
        description=(
            "Scans binary_bytes for printable ASCII spans and emits a "
            "typed configuration JSON of IPv4 / URL / domain / string "
            "elements with byte offsets.  Generic — no malware-family "
            "logic."
        ),
    ),
    impl=_impl,
)

__all__ = ["_impl"]
