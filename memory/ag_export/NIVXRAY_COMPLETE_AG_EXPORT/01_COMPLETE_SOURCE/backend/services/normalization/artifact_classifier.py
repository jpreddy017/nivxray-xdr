"""Deterministic artifact classifier.

Fixes the P0 IOC-misclassification bug: strings like
``ascii.getstring``, ``system.convert``, ``net.credentialcache``,
``w.proxy`` MUST NEVER be surfaced as *domains* just because they
happen to have a dot in them.

The classifier operates on a candidate string and returns a canonical
artifact type:

    class_reference       —  System.Net.WebClient, System.Convert
    method_reference      —  DownloadString, GetSystemWebProxy
    namespace_reference   —  System.Text.Encoding
    variable_reference    —  $w, ${OB}, Variable:OB
    provider_reference    —  HKLM:\\, Env:PATH, Variable:x
    domain                —  pwned.local, evil.example.com
    ip                    —  10.0.0.1
    url                   —  http(s)://…
    file_path             —  C:\\Users\\..., /tmp/x
    unknown               —  fallback

The point isn't to be exhaustive — it's to *NEVER* mislabel a .NET
identifier as a domain.  The existing IOC extractor's TLD-restricted
regex already avoids most of these, but two attack surfaces bypass it:

  1. Downstream string containers that skip the TLD guard (some
     projections use a looser domain regex).
  2. Free-form graph nodes that treat "anything with a dot" as a host.

Downstream consumers use :func:`classify` before adding a candidate to
any host/domain container.
"""
from __future__ import annotations

import re
from typing import Optional


# ─── Well-known .NET namespace roots (case-insensitive) ───────────────
# A candidate whose leading token matches ANY of these is guaranteed
# to be a .NET reference, not a domain.  We intentionally keep this
# list small and precise; growing it doesn't cost correctness.
_DOTNET_ROOTS = frozenset(x.lower() for x in [
    "system", "microsoft", "net", "windows", "mscorlib",
    "powershell", "management", "diagnostics", "security",
    "activedirectory", "runtime", "reflection", "text",
    "io", "web", "xml", "linq", "collections",
])

# Well-known .NET *nested* tokens — if a candidate's SECOND segment is
# one of these AND the first isn't a real TLD, we're looking at a .NET
# identifier (e.g. ``net.credentialcache``, ``net.webclient``).
_DOTNET_NESTED = frozenset(x.lower() for x in [
    "webclient", "credentialcache", "webrequest", "webresponse",
    "getstring", "getbytes", "getchars", "getencoding",
    "convert", "encoding", "textinfo", "cultureinfo",
    "process", "runspace", "servicecontroller", "management",
    "reflection", "assembly", "type", "activator",
    "principal", "identity", "windowsidentity",
    "networkinformation", "getsystemwebproxy", "defaultcredentials",
    "downloadstring", "downloaddata", "downloadfile", "uploadstring",
    "invokemember", "getmethod", "getproperty", "getfield",
])

# PowerShell provider prefixes.  When a candidate leads with these,
# it is a provider reference, not a URL/host/file path.
_PS_PROVIDER_ROOTS = frozenset(x.lower() for x in [
    "variable", "env", "function", "alias", "hklm", "hkcu", "hkcr",
    "hku", "hkcc",
])

# Cheap URL / IP / file-path / registry sniffers.  These MUST match the
# main extractor's shape or we risk classification drift.
_URL_RE   = re.compile(r"^https?://", re.I)
_IP_RE    = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_PATH_RE  = re.compile(r"^(?:[a-zA-Z]:\\|/)")
_REGKEY_RE = re.compile(r"^HK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)[:\\]", re.I)
_VAR_RE    = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")
_METHOD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\(\s*\)?$")  # foo(  or foo()

# TLDs the main IOC extractor accepts.  Kept in sync with
# command_analyzer._URL_RE / dom_re on 2026-02-06.  If a candidate's
# LAST segment isn't here, we should never call it a domain (except
# for the special-case allow-list below, e.g. ``.local`` for internal
# networks the user explicitly opts-in to).
_REAL_TLDS = frozenset([
    "com", "net", "org", "io", "ai", "gov", "edu", "co", "ru", "cn",
    "us", "uk", "de", "xyz", "top", "info", "biz", "club", "shop",
    "online", "site", "app", "dev", "pw", "cc", "to", "ly", "me",
    "tv", "su",
])
# Internal-network TLDs — enable domain classification but tag them.
_INTERNAL_TLDS = frozenset(["local", "lan", "corp", "internal", "home",
                              "test", "example", "invalid", "localhost"])


def classify(candidate: str) -> str:
    """Return the canonical artifact type for ``candidate``.

    Never raises; ``None`` / non-str / empty → ``"unknown"``.
    """
    if not isinstance(candidate, str):
        return "unknown"
    s = candidate.strip()
    if not s:
        return "unknown"

    # ── Highly specific shapes ────────────────────────────────────
    if _URL_RE.match(s):
        return "url"
    if _IP_RE.match(s):
        return "ip"
    if _REGKEY_RE.match(s):
        return "registry_key"
    if _VAR_RE.match(s):
        return "variable_reference"
    if _METHOD_RE.match(s):
        return "method_reference"
    if _PATH_RE.match(s) and re.search(r"\.(exe|dll|ps1|vbs|js|bat|hta|cmd|scr|msi|zip|txt|dat|bin|tmp)$", s, re.I):
        return "file_path"

    # ── PowerShell provider prefix (checked BEFORE dot logic
    # because `Variable:OB` has NO dot yet is still a provider).
    if ":" in s:
        head = s.split(":", 1)[0].lower()
        if head in _PS_PROVIDER_ROOTS:
            return "provider_reference"

    # ── Dot-separated candidates ──────────────────────────────────
    if "." in s and " " not in s and "/" not in s and "\\" not in s:
        parts = s.split(".")
        first = parts[0].lower()
        second = parts[1].lower() if len(parts) > 1 else ""
        last = parts[-1].lower()

        # PowerShell provider: `Variable:OB`, `Env:PATH`, `HKLM:\\...`
        if ":" in parts[0] and parts[0].split(":", 1)[0].lower() in _PS_PROVIDER_ROOTS:
            return "provider_reference"

        # .NET root (System.*, Microsoft.*, Net.*, ...)
        if first in _DOTNET_ROOTS:
            # Distinguish namespace (e.g. "System.Text.Encoding")
            # from class (e.g. "System.Net.WebClient") by CamelCase in the
            # last segment.
            if any(c.isupper() for c in parts[-1][1:]) or parts[-1][:1].isupper():
                return "class_reference"
            return "namespace_reference"

        # .NET nested identifier (e.g. "net.credentialcache") — the
        # LAST segment is a well-known type / member.
        if second in _DOTNET_NESTED or last in _DOTNET_NESTED:
            return "class_reference"

        # PowerShell variable-property access: "$w.Proxy", "$_.Status"
        if parts[0].startswith("$") or parts[0].startswith("${"):
            return "method_reference"

        # Real domain — LAST segment must be a real TLD.
        if last in _REAL_TLDS:
            return "domain"
        # Internal-network domain — tag differently so downstream
        # containers can decide whether to include them.
        if last in _INTERNAL_TLDS:
            return "domain"

        # Everything else with a dot is very likely a .NET / language
        # identifier of some kind — never a domain.
        return "class_reference"

    # ── No dot: nothing to classify as a host ─────────────────────
    return "unknown"


def is_domain(candidate: str) -> bool:
    """Convenience predicate — for downstream code that only wants to
    know 'is this really a host I should look up?'."""
    return classify(candidate) == "domain"


def is_dotnet_reference(candidate: str) -> bool:
    """Predicate — True when the candidate should NEVER appear in a
    domain / URL container."""
    return classify(candidate) in {
        "class_reference", "namespace_reference", "method_reference",
        "variable_reference", "provider_reference",
    }
