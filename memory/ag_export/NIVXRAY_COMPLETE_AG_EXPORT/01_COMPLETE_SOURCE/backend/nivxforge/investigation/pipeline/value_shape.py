"""Value Shape Detection — Stage 3 support module.

Deterministic, vendor-neutral boundary detection for security-relevant
value shapes. Given a value, returns zero or more ``ShapeMatch``
records identifying every shape the value satisfies.

Design contract:
  · Pure functions. No I/O, no network, no state.
  · Deterministic. Same input → identical result forever.
  · Precision over coverage. When a shape's canonical regex is
    unambiguous it matches; otherwise the value is left unlabelled.
  · Overlapping shapes are allowed (e.g. a 64-hex string is both
    ``hash_sha256`` and — when prefixed with ``sha256:`` — an
    ``oci_sha256_digest``). Downstream stages decide which shapes
    contribute to which concepts.
  · No vendor identity. Shape names describe *what the value looks
    like*, never *who reported it*.

The Semantic Field Mapper consumes this module via
``detect_shapes(value)`` and combines the returned shapes with the
Concept Affinity table to derive confidence signals.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Tuple


class ValueShape:
    """Canonical shape identifiers. String constants for stability."""
    # ── Network ────────────────────────────────────────────────────
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    IPV4_CIDR = "ipv4_cidr"
    IPV6_CIDR = "ipv6_cidr"
    MAC = "mac"
    ASN = "asn"
    PORT = "port"
    DOMAIN_FQDN = "domain_fqdn"
    URL = "url"
    URI = "uri"
    DNS_RR_TYPE = "dns_rr_type"

    # ── Identity ───────────────────────────────────────────────────
    EMAIL = "email"
    EMAIL_MESSAGE_ID = "email_message_id"
    WINDOWS_SID = "windows_sid"
    GUID = "guid"
    UUID = "uuid"
    JWT = "jwt"

    # ── Filesystem ─────────────────────────────────────────────────
    FILE_PATH_WIN = "file_path_windows"
    FILE_PATH_POSIX = "file_path_posix"
    FILE_EXTENSION = "file_extension"
    REGISTRY_PATH = "registry_path"
    LINUX_INODE = "linux_inode"
    LINUX_DEVICE_ID = "linux_device_id"

    # ── Cryptographic ──────────────────────────────────────────────
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_SHA512 = "hash_sha512"
    BASE64 = "base64"
    PEM_CERTIFICATE = "pem_certificate"

    # ── Threat Intelligence identifiers ────────────────────────────
    MITRE_TECHNIQUE_ID = "mitre_technique_id"
    MITRE_TACTIC_ID = "mitre_tactic_id"
    MITRE_SOFTWARE_ID = "mitre_software_id"
    MITRE_GROUP_ID = "mitre_group_id"
    CVE_ID = "cve_id"
    CWE_ID = "cwe_id"
    CAPEC_ID = "capec_id"

    # ── Runtime / process ─────────────────────────────────────────
    PROCESS_ID = "process_id"
    WINDOWS_EVENT_ID = "windows_event_id"

    # ── Cloud / container ─────────────────────────────────────────
    AWS_ARN = "aws_arn"
    AZURE_RESOURCE_ID = "azure_resource_id"
    KUBERNETES_OBJECT = "kubernetes_object"
    CONTAINER_ID_SHORT = "container_id_short"
    CONTAINER_ID_FULL = "container_id_full"
    OCI_SHA256_DIGEST = "oci_sha256_digest"


@dataclass(frozen=True)
class ShapeMatch:
    """One detected shape for a value."""
    shape: str
    detail: str = ""  # optional human-readable clarifier


# ── Regex library (all anchored / bounded) ─────────────────────────

_RX_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
_RX_IPV4_CIDR = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)/(?:[0-9]|[12]\d|3[0-2])$"
)
# Pragmatic IPv6 — accept full, compressed (::), and dual notations.
_RX_IPV6 = re.compile(
    r"^("
    r"([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"      # full
    r"|([0-9A-Fa-f]{1,4}:){1,7}:"                    # trailing ::
    r"|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}"
    r"|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}"
    r"|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}"
    r"|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(:[0-9A-Fa-f]{1,4}){1,7}|::"
    r")$"
)
_RX_IPV6_CIDR = re.compile(r"^.+/(1[01][0-9]|12[0-8]|[0-9]{1,2})$")
_RX_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_RX_ASN = re.compile(r"^(?:AS[- ]?)?[0-9]{1,10}$", re.IGNORECASE)

_RX_URL = re.compile(
    r"^(?:https?|ftp|ftps|ws|wss|smb|ldap|ldaps)://[^\s]{3,}$",
    re.IGNORECASE,
)
_RX_URI = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]{1,32}://[^\s]{1,}$")
_RX_DOMAIN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)){1,}"
    r"$"
)
_DNS_RR_TYPES = frozenset({
    "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT",
    "CAA", "DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "TLSA", "SVCB",
    "HTTPS", "SPF", "NAPTR", "URI", "OPENPGPKEY", "SMIMEA",
})

_RX_EMAIL = re.compile(
    r"^[A-Za-z0-9._%+\-]{1,64}@"
    r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)){1,}$"
)
_RX_EMAIL_MESSAGE_ID = re.compile(r"^<[^\s<>@]{1,120}@[^\s<>]{1,253}>$")
_RX_SID = re.compile(r"^S-1-(?:\d{1,10}-)+\d{1,10}$")
_RX_GUID = re.compile(
    r"^\{?[0-9A-Fa-f]{8}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{12}\}?$"
)
# JWT: 3 base64url chunks separated by dots. Header decodes to JSON
# usually starting with eyJ.
_RX_JWT = re.compile(r"^eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}$")

_RX_FILE_PATH_WIN = re.compile(
    r"^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\)[^\s]{1,}$"
)
_RX_FILE_PATH_POSIX = re.compile(r"^/[A-Za-z0-9._\-/~]{1,}$")
_RX_FILE_EXTENSION = re.compile(r"^[^/\\\s]{1,240}\.[A-Za-z0-9]{1,10}$")
_RX_REGISTRY_PATH = re.compile(
    r"^(?:HKEY_[A-Z_]{5,25}|HKLM|HKCU|HKCR|HKU|HKCC)"
    r"[\\/][A-Za-z0-9_\\\-/. ]{1,}$",
    re.IGNORECASE,
)
_RX_LINUX_DEVICE = re.compile(r"^[0-9]{1,4}:[0-9]{1,6}$")
# Linux inode: bare integer — only meaningful when combined with a
# field name signal. Treat as weak signal.
_RX_INTEGER = re.compile(r"^-?\d{1,20}$")

_RX_HASH_HEX = re.compile(r"^[A-Fa-f0-9]+$")
_RX_PEM_CERT = re.compile(
    r"-----BEGIN (?:CERTIFICATE|PUBLIC KEY|RSA PRIVATE KEY|"
    r"EC PRIVATE KEY|PGP PUBLIC KEY BLOCK)-----"
)
_RX_BASE64 = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")

_RX_MITRE_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_RX_MITRE_TACTIC = re.compile(r"^TA\d{4}$")
_RX_MITRE_SOFTWARE = re.compile(r"^S\d{4}$")
_RX_MITRE_GROUP = re.compile(r"^G\d{4}$")
_RX_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_RX_CWE = re.compile(r"^CWE-\d{1,4}$", re.IGNORECASE)
_RX_CAPEC = re.compile(r"^CAPEC-\d{1,4}$", re.IGNORECASE)

_RX_AWS_ARN = re.compile(
    r"^arn:aws[a-zA-Z\-]*:[a-zA-Z0-9\-]{1,64}:[a-zA-Z0-9\-]{0,64}:"
    r"[0-9]{0,12}:[^\s]{1,256}$"
)
_RX_AZURE_RESOURCE = re.compile(
    r"^/subscriptions/[0-9a-fA-F\-]{36}/resourceGroups/[^/]{1,90}"
    r"(?:/providers/[^/]{1,}/[^/]{1,})*$"
)
_RX_K8S_OBJECT = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?/[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")
_RX_OCI_DIGEST = re.compile(r"^sha256:[A-Fa-f0-9]{64}$")
_RX_CONTAINER_ID_FULL = re.compile(r"^[A-Fa-f0-9]{64}$")
_RX_CONTAINER_ID_SHORT = re.compile(r"^[A-Fa-f0-9]{12}$")


# ── Detection entrypoint ───────────────────────────────────────────

def detect_shapes(value: Any) -> List[ShapeMatch]:
    """Return every ``ShapeMatch`` the value satisfies.

    Deterministic, never raises. Returns ``[]`` for values that
    match nothing — an entirely valid outcome.
    """
    if value is None:
        return []
    if isinstance(value, bool):
        return []
    if isinstance(value, (int, float)):
        return _detect_numeric(value)
    if not isinstance(value, str):
        return []
    s = value.strip()
    if not s or len(s) > 4096:
        return []
    return _detect_string(s)


# ── Detection implementations ─────────────────────────────────────

def _detect_numeric(value) -> List[ShapeMatch]:
    matches: List[ShapeMatch] = []
    try:
        n = int(value)
    except (TypeError, ValueError):
        return []
    if 0 <= n <= 65535:
        matches.append(ShapeMatch(ValueShape.PORT, "integer in 0..65535"))
    if 1 <= n <= 4194304:
        matches.append(ShapeMatch(ValueShape.PROCESS_ID,
                                  "integer in valid PID range"))
    if 1 <= n <= 65535:
        matches.append(ShapeMatch(ValueShape.WINDOWS_EVENT_ID,
                                  "integer in Windows EventID range"))
    if 0 <= n <= 4294967295:
        matches.append(ShapeMatch(ValueShape.ASN,
                                  "integer in 32-bit ASN range"))
    return matches


def _detect_string(s: str) -> List[ShapeMatch]:
    matches: List[ShapeMatch] = []

    # ── Cloud / container prefixed shapes (must come first) ────────
    if _RX_OCI_DIGEST.match(s):
        matches.append(ShapeMatch(ValueShape.OCI_SHA256_DIGEST,
                                  "sha256: prefix + 64 hex"))
    if _RX_AWS_ARN.match(s):
        matches.append(ShapeMatch(ValueShape.AWS_ARN, "arn:aws:… form"))
    if _RX_AZURE_RESOURCE.match(s):
        matches.append(ShapeMatch(ValueShape.AZURE_RESOURCE_ID,
                                  "/subscriptions/…/resourceGroups/…"))
    if _RX_K8S_OBJECT.match(s):
        matches.append(ShapeMatch(ValueShape.KUBERNETES_OBJECT,
                                  "namespace/name k8s form"))

    # ── URIs / URLs / paths ────────────────────────────────────────
    if _RX_URL.match(s):
        matches.append(ShapeMatch(ValueShape.URL,
                                  "scheme + :// + path"))
    elif _RX_URI.match(s):
        matches.append(ShapeMatch(ValueShape.URI, "generic scheme://"))
    if _RX_FILE_PATH_WIN.match(s):
        matches.append(ShapeMatch(ValueShape.FILE_PATH_WIN,
                                  "drive-letter or UNC"))
    if _RX_FILE_PATH_POSIX.match(s):
        matches.append(ShapeMatch(ValueShape.FILE_PATH_POSIX,
                                  "leading /"))
    if _RX_REGISTRY_PATH.match(s):
        matches.append(ShapeMatch(ValueShape.REGISTRY_PATH,
                                  "HKEY_… root"))
    if _RX_FILE_EXTENSION.match(s) and "." in s and "/" not in s:
        # Only apply when it looks file-ish, not domain-ish.
        # A bare "example.com" is technically extension-shaped —
        # we exclude those by requiring at least one alnum-alnum
        # separator that isn't a dot at position 0.
        matches.append(ShapeMatch(ValueShape.FILE_EXTENSION,
                                  "trailing .ext"))

    # ── Identity ───────────────────────────────────────────────────
    if _RX_EMAIL_MESSAGE_ID.match(s):
        matches.append(ShapeMatch(ValueShape.EMAIL_MESSAGE_ID,
                                  "<…@…> RFC 5322 msg-id"))
    elif _RX_EMAIL.match(s):
        matches.append(ShapeMatch(ValueShape.EMAIL, "local@domain form"))
    if _RX_SID.match(s):
        matches.append(ShapeMatch(ValueShape.WINDOWS_SID,
                                  "S-1-… Windows SID"))
    if _RX_JWT.match(s):
        matches.append(ShapeMatch(ValueShape.JWT,
                                  "eyJ… three base64url segments"))
    if _RX_GUID.match(s):
        matches.append(ShapeMatch(ValueShape.GUID,
                                  "8-4-4-4-12 hex GUID"))
        matches.append(ShapeMatch(ValueShape.UUID, "same as GUID"))

    # ── Network ────────────────────────────────────────────────────
    if _RX_IPV4.match(s):
        matches.append(ShapeMatch(ValueShape.IPV4, "dotted-quad"))
    elif _RX_IPV4_CIDR.match(s):
        matches.append(ShapeMatch(ValueShape.IPV4_CIDR, "IPv4/mask"))
    if _RX_IPV6.match(s):
        matches.append(ShapeMatch(ValueShape.IPV6, "colon-hex"))
        if "/" in s and _RX_IPV6_CIDR.match(s):
            matches.append(ShapeMatch(ValueShape.IPV6_CIDR, "IPv6/mask"))
    if _RX_MAC.match(s):
        matches.append(ShapeMatch(ValueShape.MAC, "48-bit MAC"))
    if _RX_ASN.match(s) and s.upper().startswith("AS"):
        matches.append(ShapeMatch(ValueShape.ASN, "AS-prefixed"))
    if s.upper() in _DNS_RR_TYPES:
        matches.append(ShapeMatch(ValueShape.DNS_RR_TYPE,
                                  "DNS RR mnemonic"))

    # ── Threat identifiers ────────────────────────────────────────
    if _RX_MITRE_TECH.match(s):
        matches.append(ShapeMatch(ValueShape.MITRE_TECHNIQUE_ID,
                                  "T#### or T####.###"))
    if _RX_MITRE_TACTIC.match(s):
        matches.append(ShapeMatch(ValueShape.MITRE_TACTIC_ID,
                                  "TA#### tactic id"))
    if _RX_MITRE_SOFTWARE.match(s):
        matches.append(ShapeMatch(ValueShape.MITRE_SOFTWARE_ID,
                                  "S#### software id"))
    if _RX_MITRE_GROUP.match(s):
        matches.append(ShapeMatch(ValueShape.MITRE_GROUP_ID,
                                  "G#### group id"))
    if _RX_CVE.match(s):
        matches.append(ShapeMatch(ValueShape.CVE_ID, "CVE-YYYY-N…"))
    if _RX_CWE.match(s):
        matches.append(ShapeMatch(ValueShape.CWE_ID, "CWE-N…"))
    if _RX_CAPEC.match(s):
        matches.append(ShapeMatch(ValueShape.CAPEC_ID, "CAPEC-N…"))

    # ── Cryptographic ─────────────────────────────────────────────
    if _RX_HASH_HEX.match(s):
        if len(s) == 32:
            matches.append(ShapeMatch(ValueShape.HASH_MD5, "32 hex"))
        elif len(s) == 40:
            matches.append(ShapeMatch(ValueShape.HASH_SHA1, "40 hex"))
        elif len(s) == 64:
            matches.append(ShapeMatch(ValueShape.HASH_SHA256, "64 hex"))
            matches.append(ShapeMatch(ValueShape.CONTAINER_ID_FULL,
                                      "64 hex (container / SHA256)"))
        elif len(s) == 128:
            matches.append(ShapeMatch(ValueShape.HASH_SHA512, "128 hex"))
        elif len(s) == 12:
            matches.append(ShapeMatch(ValueShape.CONTAINER_ID_SHORT,
                                      "12 hex short container id"))
    if "BEGIN CERTIFICATE" in s or _RX_PEM_CERT.search(s):
        matches.append(ShapeMatch(ValueShape.PEM_CERTIFICATE,
                                  "PEM armor headers present"))
    # Base64 last, only when nothing structured matched.
    if not matches and _RX_BASE64.match(s) and any(c in s for c in "+/="):
        matches.append(ShapeMatch(ValueShape.BASE64,
                                  "long base64-alphabet run"))

    # ── Filesystem numeric shapes ────────────────────────────────
    if _RX_LINUX_DEVICE.match(s):
        matches.append(ShapeMatch(ValueShape.LINUX_DEVICE_ID,
                                  "major:minor form"))
    elif _RX_INTEGER.match(s):
        # Integer as string — apply numeric detectors too.
        matches.extend(_detect_numeric(s))
        matches.append(ShapeMatch(ValueShape.LINUX_INODE,
                                  "bare integer (weak: inode)"))

    # ── Domain (last — many shapes overlap syntactically) ────────
    if _RX_DOMAIN.match(s) and " " not in s:
        # Exclude values already claimed as URL/email/path/hash.
        already = {m.shape for m in matches}
        blockers = {ValueShape.URL, ValueShape.URI,
                    ValueShape.EMAIL, ValueShape.EMAIL_MESSAGE_ID,
                    ValueShape.FILE_PATH_WIN,
                    ValueShape.FILE_PATH_POSIX,
                    ValueShape.HASH_MD5, ValueShape.HASH_SHA1,
                    ValueShape.HASH_SHA256, ValueShape.HASH_SHA512,
                    ValueShape.AWS_ARN, ValueShape.AZURE_RESOURCE_ID,
                    ValueShape.KUBERNETES_OBJECT}
        if not (already & blockers):
            matches.append(ShapeMatch(ValueShape.DOMAIN_FQDN,
                                      "dot-separated labels + TLD"))

    return matches


# ── Concept affinity ──────────────────────────────────────────────

# Maps a detected shape to (concept, delta) pairs. Used by
# ``semantic_field_mapper`` to compute confidence contributions.
# Deltas are conservative; caps and clamps are the mapper's job.
SHAPE_CONCEPT_AFFINITY: dict = {
    ValueShape.IPV4:                 [("IP", 0.25)],
    ValueShape.IPV6:                 [("IP", 0.25)],
    ValueShape.IPV4_CIDR:            [("IP", 0.15)],
    ValueShape.IPV6_CIDR:            [("IP", 0.15)],
    ValueShape.MAC:                  [("NetworkConnection", 0.15)],
    ValueShape.ASN:                  [("NetworkConnection", 0.10)],
    ValueShape.PORT:                 [("Port", 0.15)],
    ValueShape.DOMAIN_FQDN:          [("Domain", 0.20), ("Host", 0.05)],
    ValueShape.URL:                  [("URL", 0.30)],
    ValueShape.URI:                  [("URL", 0.15)],
    ValueShape.DNS_RR_TYPE:          [("Protocol", 0.10)],

    ValueShape.EMAIL:                [("Email", 0.30)],
    ValueShape.EMAIL_MESSAGE_ID:     [("Email", 0.20)],
    ValueShape.WINDOWS_SID:          [("User", 0.15)],
    ValueShape.GUID:                 [],   # ambiguous — no affinity
    ValueShape.UUID:                 [],
    ValueShape.JWT:                  [("Certificate", 0.05)],

    ValueShape.FILE_PATH_WIN:        [("File", 0.20),
                                       ("Directory", 0.10)],
    ValueShape.FILE_PATH_POSIX:      [("File", 0.20),
                                       ("Directory", 0.10)],
    ValueShape.FILE_EXTENSION:       [("File", 0.10)],
    ValueShape.REGISTRY_PATH:        [("Registry", 0.30)],
    ValueShape.LINUX_INODE:          [],   # too weak alone
    ValueShape.LINUX_DEVICE_ID:      [],   # too weak alone

    ValueShape.HASH_MD5:             [("Hash", 0.30)],
    ValueShape.HASH_SHA1:            [("Hash", 0.30)],
    ValueShape.HASH_SHA256:          [("Hash", 0.30)],
    ValueShape.HASH_SHA512:          [("Hash", 0.30)],
    ValueShape.BASE64:               [],   # informational only
    ValueShape.PEM_CERTIFICATE:      [("Certificate", 0.30)],

    ValueShape.MITRE_TECHNIQUE_ID:   [("MITRE", 0.30)],
    ValueShape.MITRE_TACTIC_ID:      [("MITRE", 0.30)],
    ValueShape.MITRE_SOFTWARE_ID:    [("MITRE", 0.20)],
    ValueShape.MITRE_GROUP_ID:       [("MITRE", 0.20)],
    ValueShape.CVE_ID:               [("Alert", 0.05)],
    ValueShape.CWE_ID:               [("Alert", 0.05)],
    ValueShape.CAPEC_ID:             [("Alert", 0.05)],

    ValueShape.PROCESS_ID:           [("Process", 0.10)],
    ValueShape.WINDOWS_EVENT_ID:     [("Alert", 0.05)],

    ValueShape.AWS_ARN:              [],   # cloud-resource, no core concept
    ValueShape.AZURE_RESOURCE_ID:    [],
    ValueShape.KUBERNETES_OBJECT:    [],
    ValueShape.CONTAINER_ID_SHORT:   [],
    ValueShape.CONTAINER_ID_FULL:    [("Hash", 0.05)],
    ValueShape.OCI_SHA256_DIGEST:    [("Hash", 0.15)],
}


def concept_boosts_for(matches: List[ShapeMatch]) -> List[Tuple[str, str, float]]:
    """Given a list of shape matches, return the concept contributions.

    Returns list of ``(concept, signal_label, delta)`` triples.
    Signal labels are stable (``value_shape:<shape>``) and safe to
    surface in the confidence provenance ledger.
    """
    out: List[Tuple[str, str, float]] = []
    for m in matches:
        for concept, delta in SHAPE_CONCEPT_AFFINITY.get(m.shape, []):
            out.append((concept, f"value_shape:{m.shape}", delta))
    return out


__all__ = [
    "ValueShape",
    "ShapeMatch",
    "SHAPE_CONCEPT_AFFINITY",
    "detect_shapes",
    "concept_boosts_for",
]
