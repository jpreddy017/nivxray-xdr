"""Deterministic Entity Classifier — Feb 2026.

Purpose
-------
Retires a whole class of false positives: numeric artefacts (dotted quads,
build numbers, version strings) that a naive regex flags as IPv4 addresses.
The IOC extractor now consults this classifier *before* filing anything
into ``iocs["ips"]``.

Zero AI. Purely deterministic rules over:

* the token itself (structural signals — octet ranges, all-zero suffixes,
  Win10/11 build patterns), and
* a small context window (± ``CTX_CHARS`` chars around the match).

Every classification returns a rich :class:`EntityClassification` with a
``reason`` string enumerating which signals fired — this is what the
Evidence Graph and the (future) Analyst UI surface for transparency.

Categories
----------
* ``ipv4``               — real network IPv4 (context clues + valid octets)
* ``windows_build``      — Windows 10/11 build (``10.0.<major>.<minor>``)
* ``software_version``   — semver-ish version literal (``[Version] "9.0.0.0"``)
* ``generic_dotted_quad``— dotted-quad shape with no context; not enough to
                           call it an IP but also not clearly a version
* ``unknown``            — bail-out for anything that does not fit

The classifier is idempotent and pure — same input, same output — which
lets the Golden Corpus tests pin exact classifications with byte-perfect
determinism.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple
import re

# -- Public categories ------------------------------------------------
KIND_IPV4               = "ipv4"
KIND_WINDOWS_BUILD      = "windows_build"
KIND_SOFTWARE_VERSION   = "software_version"
KIND_GENERIC_DOTTED_QUAD = "generic_dotted_quad"
KIND_UNKNOWN            = "unknown"

ALL_KINDS = (
    KIND_IPV4,
    KIND_WINDOWS_BUILD,
    KIND_SOFTWARE_VERSION,
    KIND_GENERIC_DOTTED_QUAD,
    KIND_UNKNOWN,
)

CTX_CHARS = 48  # radius of the context window in characters

# -- Result payload ---------------------------------------------------
@dataclass(frozen=True)
class EntityClassification:
    """Immutable result — hashable so evidence-graph nodes can dedup."""
    token: str
    kind: str
    confidence: float
    reason: str
    signals: Tuple[str, ...]      # ordered list of atomic signals that fired
    context: str                  # ±CTX_CHARS window (trimmed, single-line)

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "kind": self.kind,
            "confidence": round(self.confidence, 3),
            "reason": self.reason,
            "signals": list(self.signals),
            "context": self.context,
        }


# -- Regex library ----------------------------------------------------
_RX_DOTTED_QUAD = re.compile(
    r"\b(?:\d{1,5})(?:\.(?:\d{1,5})){3}\b"
)

# Network-context keywords — presence in the surrounding window is a
# strong hint the token is an actual IPv4.  Kept lowercase; matched
# against a lowercased context view.
_NET_CONTEXT = (
    "connect(", "connect ", "socket", "tcpclient", "udpclient",
    "webrequest", "httpwebrequest", "invoke-webrequest", "iwr ",
    "invoke-restmethod", "irm ", "downloadstring", "downloadfile",
    "net.webclient", "webclient", "wget", "curl ", "curl.exe",
    "-uri ", "-headers ", "-outfile ", " host=", " server=",
    "://", "endpoint", "192.168", "10.", "172.16", "172.17",
    "172.18", "172.19", "172.20", "172.21", "172.22", "172.23",
    "172.24", "172.25", "172.26", "172.27", "172.28", "172.29",
    "172.30", "172.31", "ipaddress", "iphostentry", "dns.resolve",
    "gethostbyname", "resolve-dnsname", "ping ", "traceroute",
    "tracert", "nslookup", "bind(", "bind ", "listen(", "0.0.0.0",
    "127.0.0.1",
)

# Version-context keywords — presence flips the interpretation to a
# software version literal.
_VERSION_CONTEXT = (
    "assemblyversion", "assemblyfileversion", "[version]", "version=",
    "-version ", "psversion", "fileversion", "productversion",
    "clrversion", "version:", "\"version\"", "'version'",
    "assembly.loadwithpartialname", "reflection.assembly", "loadwithpartialname",
    "system.version",
    ".dll,version=", ",version=", "publickeytoken=",
    ",culture=", "-assembly ", "app version", "package version",
    "release ", "chocolatey", "installutil", "gacutil",
)

# Windows-build context keywords.
_WIN_BUILD_CONTEXT = (
    "osversion", "buildnumber", "current build", "currentbuild",
    "windows nt ", "windows 10", "windows 11", "winver", "kernel",
    "ntkernel", "ntoskrnl", "wmi.win32_operatingsystem",
    "win32_operatingsystem", "systeminfo", "[environment]::osversion",
)

# Well-known Windows 10 / 11 major-build tags. Any dotted-quad whose
# first three parts match one of these strongly leans "windows_build".
_WIN_BUILD_PREFIXES = frozenset({
    (10, 0, 10240), (10, 0, 10586),  (10, 0, 14393), (10, 0, 15063),
    (10, 0, 16299), (10, 0, 17134),  (10, 0, 17763), (10, 0, 18362),
    (10, 0, 18363), (10, 0, 19041),  (10, 0, 19042), (10, 0, 19043),
    (10, 0, 19044), (10, 0, 19045),
    # Windows 11 mainline (Cobalt/Nickel/Copper/Iron/Zinc/Germanium):
    (10, 0, 22000), (10, 0, 22621),  (10, 0, 22631), (10, 0, 26100),
})


# -- Helpers ----------------------------------------------------------
def _parse_octets(token: str) -> Optional[Tuple[int, int, int, int]]:
    """Split a dotted-quad into a 4-tuple of ints, else None."""
    parts = token.split(".")
    if len(parts) != 4:
        return None
    try:
        vals = tuple(int(p) for p in parts)
    except ValueError:
        return None
    return vals  # may include > 255 — caller decides


def _valid_ipv4_octets(vals: Tuple[int, int, int, int]) -> bool:
    return all(0 <= v <= 255 for v in vals)


def _slice_context(text: str, start: int, end: int) -> str:
    lo = max(0, start - CTX_CHARS)
    hi = min(len(text), end + CTX_CHARS)
    window = text[lo:hi]
    return " ".join(window.split())  # collapse whitespace / newlines


def _has_any(hay: str, needles) -> Optional[str]:
    for n in needles:
        if n in hay:
            return n
    return None


# -- Core rules -------------------------------------------------------
def classify_token(token: str, context: str) -> EntityClassification:
    """Classify a single dotted-quad-shaped token given its ±CTX_CHARS window.

    ``context`` MAY be empty; the classifier still gets useful signals
    from the token's own structure.
    """
    ctx_l = context.lower()
    signals: List[str] = []

    vals = _parse_octets(token)
    if vals is None:
        return EntityClassification(
            token=token, kind=KIND_UNKNOWN, confidence=0.0,
            reason="not a dotted-quad", signals=(), context=context,
        )

    a, b, c, d = vals

    # ---- Rule 1 — Windows build (structural + context) --------------
    if (a, b, c) in _WIN_BUILD_PREFIXES:
        signals.append(f"win-build-prefix-hit({a}.{b}.{c})")
        # High confidence — no version-context signal even needed
        return EntityClassification(
            token=token, kind=KIND_WINDOWS_BUILD, confidence=0.99,
            reason="Well-known Windows 10/11 build prefix",
            signals=tuple(signals), context=context,
        )

    win_build_ctx = _has_any(ctx_l, _WIN_BUILD_CONTEXT)
    if win_build_ctx and a == 10 and b == 0:
        signals.append(f"win-build-context({win_build_ctx!r})")
        signals.append("prefix-10.0")
        return EntityClassification(
            token=token, kind=KIND_WINDOWS_BUILD, confidence=0.93,
            reason="'10.0.*' inside Windows OS context",
            signals=tuple(signals), context=context,
        )

    # ---- Rule 2 — Software version ----------------------------------
    version_ctx = _has_any(ctx_l, _VERSION_CONTEXT)
    all_octets_small = all(v <= 99 for v in vals)
    trailing_zeros = (c == 0 and d == 0) or (b == 0 and c == 0 and d == 0)

    if version_ctx:
        signals.append(f"version-context({version_ctx!r})")
        if all_octets_small:
            signals.append("small-octets(<=99)")
        return EntityClassification(
            token=token, kind=KIND_SOFTWARE_VERSION, confidence=0.95,
            reason="Version keyword adjacent to the token",
            signals=tuple(signals), context=context,
        )

    # Structural version: first octet ≤ 99, trailing zeros — classic
    # dotnet AssemblyVersion / MSI shape (e.g. "9.0.0.0", "1.2.0.0").
    if all_octets_small and trailing_zeros and a >= 1:
        signals.append("small-octets(<=99)")
        signals.append("trailing-zeros")
        return EntityClassification(
            token=token, kind=KIND_SOFTWARE_VERSION, confidence=0.75,
            reason="Structural semver-like shape",
            signals=tuple(signals), context=context,
        )

    # ---- Rule 3 — IPv4 (context) ------------------------------------
    if not _valid_ipv4_octets(vals):
        # Cannot be a real IPv4 (some octet > 255). Falls through to
        # generic_dotted_quad unless the shape screams "version".
        signals.append("octet>255")
        if all_octets_small:
            signals.append("small-octets(<=99)")
            return EntityClassification(
                token=token, kind=KIND_SOFTWARE_VERSION, confidence=0.55,
                reason="Small octets, one >255 — likely version",
                signals=tuple(signals), context=context,
            )
        return EntityClassification(
            token=token, kind=KIND_GENERIC_DOTTED_QUAD, confidence=0.30,
            reason="Not a valid IPv4 (octet > 255)",
            signals=tuple(signals), context=context,
        )

    net_ctx = _has_any(ctx_l, _NET_CONTEXT)
    if net_ctx:
        signals.append(f"net-context({net_ctx!r})")
        return EntityClassification(
            token=token, kind=KIND_IPV4, confidence=0.95,
            reason="Networking keyword adjacent to the token",
            signals=tuple(signals), context=context,
        )

    # Private / loopback special cases even without context word
    if (a == 127) or (a == 10) or (a == 192 and b == 168) \
       or (a == 172 and 16 <= b <= 31):
        # 10.0.0.0 all-zero is ambiguous — bias to generic to avoid FP.
        if not (a == 10 and b == 0 and c == 0 and d == 0):
            signals.append("private-loopback-range")
            return EntityClassification(
                token=token, kind=KIND_IPV4, confidence=0.80,
                reason="Well-known private / loopback range",
                signals=tuple(signals), context=context,
            )
        signals.append("all-zero-suffix")

    # ---- Rule 4 — Generic dotted-quad (fallback) --------------------
    return EntityClassification(
        token=token, kind=KIND_GENERIC_DOTTED_QUAD, confidence=0.40,
        reason="Ambiguous dotted-quad — no context signals",
        signals=tuple(signals) if signals else ("no-signals",),
        context=context,
    )


def classify_dotted_quads(text: str) -> List[EntityClassification]:
    """Sweep ``text`` for every dotted-quad candidate and classify each.

    Returns results in match order. Duplicate tokens are classified
    once *per position* because context may differ (e.g. same "1.2.3.4"
    appears twice in the same script, once inside ``connect(...)`` and
    once inside an ``AssemblyVersion`` block).
    """
    if not text:
        return []
    out: List[EntityClassification] = []
    for m in _RX_DOTTED_QUAD.finditer(text):
        token = m.group(0)
        ctx = _slice_context(text, m.start(), m.end())
        out.append(classify_token(token, ctx))
    return out


def summarise(results: List[EntityClassification]) -> dict:
    """Bucket a list of classifications for API/UI consumption."""
    buckets: dict = {k: [] for k in ALL_KINDS}
    for r in results:
        buckets[r.kind].append(r.to_dict())
    return buckets


__all__ = [
    "EntityClassification",
    "classify_token",
    "classify_dotted_quads",
    "summarise",
    "KIND_IPV4",
    "KIND_WINDOWS_BUILD",
    "KIND_SOFTWARE_VERSION",
    "KIND_GENERIC_DOTTED_QUAD",
    "KIND_UNKNOWN",
    "ALL_KINDS",
]
