"""Identity Parser — pre-Stage-3 enrichment.

Owner mandate (2026-02-XX): identity parsing is deterministic string
work — it does not belong inside Semantic Mapping. This module runs
alongside the Composite Value Extractor and BEFORE Schema
Understanding.

Handles three deterministic identity formats (v1):

    DOMAIN\\User      (Windows down-level)
    alice@example.com (User Principal Name)
    S-1-5-21-...     (Windows SID)

Each recognised value emits SIBLING fields prefixed by the origin
field name, mirroring ``composite_extractor.py``:

    "User": "CORP\\\\alice"
        ->  User.username         = "alice"
            User.user_domain      = "CORP"
            User.identity_format  = "domain_user"

    "user_email": "alice@corp.com"
        ->  user_email.username         = "alice"
            user_email.user_domain      = "corp.com"
            user_email.upn              = "alice@corp.com"
            user_email.identity_format  = "upn"

    "account_sid": "S-1-5-21-..."
        ->  account_sid.sid              = "S-1-5-21-..."
            account_sid.identity_format  = "sid"

Contract:
  * Pure function, never raises.
  * Never mutates the input record.
  * Emits new sibling keys; origin value retained for provenance.
  * Vendor-neutral. No hard-coded field-name allowlist beyond the
    ``_SKIP_FIELDS`` guard (URL / URI / command-line - these values
    can legitimately contain a backslash or an at-sign without being
    identities).
  * Returns a NEW ParsedInput; the same-instance short-circuit is
    preserved when no identity values are found.

Downstream Semantic Mapping will pick up the emitted ``username``,
``user_domain``, and ``upn`` siblings via its existing leaf-lookup -
no registry additions required.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .parser import ParsedInput


# ── Deterministic identity regex library ─────────────────────────

# DOMAIN\User : short-form NetBIOS domain + username. Both sides
# constrained to safe character sets so prose like "C:\Windows"
# never matches.
_RX_DOMAIN_USER = re.compile(
    r"^(?P<domain>[A-Za-z][A-Za-z0-9_.\-]{0,15})\\"
    r"(?P<user>[A-Za-z][A-Za-z0-9_.\-$]{0,63})$"
)

# UPN: canonical local@domain form. Local part accepts common email
# specials; domain matches FQDN. Adopted from RFC 5322 pragmatic
# subset.
_RX_UPN = re.compile(
    r"^(?P<local>[A-Za-z0-9._%+\-]{1,64})@"
    r"(?P<domain>(?=.{4,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)){1,})$"
)

# Windows SID: strict S-1-<auth>-(<subauth>-)+RID format.
_RX_SID = re.compile(r"^(?P<sid>S-1-(?:\d{1,10}-)+\d{1,10})$")

# Fields whose values MUST NOT be identity-expanded even when they
# structurally contain a backslash / at-sign / SID-like token.
_SKIP_FIELDS = frozenset({
    "url", "uri",
    "requesturl", "request_url",
    "http.url", "http.request.url",
    "commandline", "command_line", "cmdline",
    "processcommandline",
    "file.path", "filepath", "path",
    "image", "imagepath", "parentimage",
    "targetfilename",
})


def expand_identities(parsed: ParsedInput,
                       *,
                       diagnostics_prefix: str = "identity:",
                       ) -> ParsedInput:
    """Return a NEW ParsedInput with identity strings enriched by
    sibling fragments.

    Deterministic. Never raises. Vendor-neutral.
    """
    if not parsed.records:
        return parsed

    new_diagnostics = list(parsed.diagnostics or ())
    new_records: List[Dict[str, Any]] = []
    expanded_any = False

    for rec in parsed.records:
        if not isinstance(rec, dict):
            new_records.append(rec)
            continue
        expanded_rec, expansions = _expand_record(rec)
        if expansions:
            expanded_any = True
            for origin, fmt in expansions:
                new_diagnostics.append(
                    f"{diagnostics_prefix}{origin}=format:{fmt}"
                )
        new_records.append(expanded_rec)

    if not expanded_any:
        return parsed

    return ParsedInput(
        kind=parsed.kind,
        records=new_records,
        text=parsed.text,
        diagnostics=new_diagnostics,
    )


def _expand_record(rec: Dict[str, Any]
                    ) -> Tuple[Dict[str, Any], List[Tuple[str, str]]]:
    """Return an enriched record + a list of ``(origin_field,
    identity_format)`` records for diagnostics."""
    out: Dict[str, Any] = dict(rec)
    expansions: List[Tuple[str, str]] = []

    for key, val in list(rec.items()):
        if not isinstance(val, str):
            continue
        if not val:
            continue
        if key.lower() in _SKIP_FIELDS:
            continue
        fragments = _classify_identity(val)
        if fragments is None:
            continue
        fmt = fragments.pop("identity_format")
        # Emit sibling fields prefixed by the origin key.
        _emit_sibling(out, key, "identity_format", fmt)
        for frag_key, frag_val in fragments.items():
            _emit_sibling(out, key, frag_key, frag_val)
        expansions.append((key, fmt))

    return out, expansions


def _emit_sibling(out: Dict[str, Any], origin: str,
                   frag_key: str, frag_val: str) -> None:
    sibling = f"{origin}.{frag_key}"
    if sibling in out:
        return
    out[sibling] = frag_val


def _classify_identity(value: str) -> Optional[Dict[str, str]]:
    """Return canonical fragments for the first-matching identity
    format, or ``None`` if the value is not a recognized identity.
    """
    if len(value) > 512:
        return None

    m = _RX_SID.match(value)
    if m:
        return {
            "identity_format": "sid",
            "sid": m.group("sid"),
        }

    m = _RX_DOMAIN_USER.match(value)
    if m:
        return {
            "identity_format": "domain_user",
            "user_domain": m.group("domain"),
            "username": m.group("user"),
        }

    m = _RX_UPN.match(value)
    if m:
        return {
            "identity_format": "upn",
            "upn": value,
            "user_domain": m.group("domain"),
            "username": m.group("local"),
        }

    return None


__all__ = ["expand_identities"]
