"""
NivXRay Content License Policy Engine
=====================================

A single, deterministic license-policy evaluator used by every content
adapter (Sigma, Snort, Suricata, YARA, ATT&CK, CVE, …).  Replaces the
prior binary "allowed / blocked" model with a 4-state policy that
preserves original licenses and provenance for every rule.

Policy states (canonical):

    PERMITTED       — free to import, ATT&CK-map, enable, redistribute.
    RESTRICTED      — importable and activatable inside NivXRay, BUT
                      redistribution / repackaging may require
                      compliance action.  Content is retained WITH its
                      original license string; badge is visible in UI.
    LICENSE_REVIEW  — recognisable license, but distribution model must
                      be reviewed before enable.  Retained, NOT ACTIVE.
    LICENSE_BLOCKED — no-redistribution / proprietary / unknown.  Rule
                      is retained with metadata for audit but never
                      enters ACTIVE state.

Every rule that flows through a content adapter is stamped with:
    license                 (verbatim, from upstream)
    license_id              (canonical spdx-style id, best-effort)
    license_policy_state    ∈ {PERMITTED, RESTRICTED, LICENSE_REVIEW,
                               LICENSE_BLOCKED}
    license_policy_reason   (deterministic explanation)

The evaluator is deterministic and side-effect free.
"""
from __future__ import annotations

import re
from typing import Any

# Canonical policy tables — every entry is deliberate.
_PERMITTED = {
    "MIT": "MIT",
    "APACHE-2.0": "Apache-2.0",
    "APACHE 2.0": "Apache-2.0",
    "APACHE LICENSE 2.0": "Apache-2.0",
    "BSD-2-CLAUSE": "BSD-2-Clause",
    "BSD-3-CLAUSE": "BSD-3-Clause",
    "BSD 3-CLAUSE": "BSD-3-Clause",
    "ISC": "ISC",
    "CC0-1.0": "CC0-1.0",
    "CC0": "CC0-1.0",
    "PUBLIC DOMAIN": "CC0-1.0",
    "DRL 1.1": "DRL-1.1",
    "DRL-1.1": "DRL-1.1",
    "DETECTION RULE LICENSE 1.1": "DRL-1.1",
    "ELASTIC LICENSE 2.0": "Elastic-2.0",
    "ELASTIC-2.0": "Elastic-2.0",
    "NIVXRAY PUBLIC CONTENT": "NivXRay-Public-Content",
    "MITRE ATT&CK": "MITRE-Attack-License",
    "MITRE-ATT&CK": "MITRE-Attack-License",
}
_RESTRICTED = {
    # Strong-copyleft licenses — allowed for internal detection use;
    # redistribution obligations exist and are surfaced in UI.
    "GPL-2.0":            "GPL-2.0",
    "GPL-2.0-ONLY":       "GPL-2.0",
    "GPL-2.0-OR-LATER":   "GPL-2.0",
    "GPL-3.0":            "GPL-3.0",
    "GPL-3.0-ONLY":       "GPL-3.0",
    "GPL-3.0-OR-LATER":   "GPL-3.0",
    "LGPL-2.1":           "LGPL-2.1",
    "LGPL-3.0":           "LGPL-3.0",
    "AGPL-3.0":           "AGPL-3.0",
    "CC-BY-4.0":          "CC-BY-4.0",
    "CC-BY-SA-4.0":       "CC-BY-SA-4.0",
    "MPL-2.0":            "MPL-2.0",
}
_BLOCKED = {
    # Never activatable — retained purely for audit visibility.
    "PROPRIETARY":        "Proprietary",
    "COMMERCIAL":         "Commercial",
    "ALL RIGHTS RESERVED":"All-Rights-Reserved",
    "NON-COMMERCIAL":     "Non-Commercial",
}

# Rough spdx-ish extractor — handles "Apache License, Version 2.0",
# "GNU General Public License v2", etc.  Best-effort ONLY.
_NORMALISE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bapache(?:\s+license)?[,\s]*(?:version\s*)?2(?:\.0)?\b", re.I),
     "APACHE-2.0"),
    (re.compile(r"\bgnu\s+general\s+public\s+license.*v?2", re.I),
     "GPL-2.0"),
    (re.compile(r"\bgnu\s+general\s+public\s+license.*v?3", re.I),
     "GPL-3.0"),
    (re.compile(r"\bgnu\s+affero\s+general\s+public\s+license.*v?3", re.I),
     "AGPL-3.0"),
    (re.compile(r"\bmit\s+license\b", re.I), "MIT"),
    (re.compile(r"\bbsd\b.*\b3", re.I),  "BSD-3-CLAUSE"),
    (re.compile(r"\bbsd\b.*\b2", re.I),  "BSD-2-CLAUSE"),
    (re.compile(r"\bdetection\s+rule\s+license\s*1(?:\.1)?\b", re.I),
     "DRL 1.1"),
    (re.compile(r"\belastic\s+license\s*(?:v?2(?:\.0)?)?\b", re.I),
     "ELASTIC-2.0"),
    (re.compile(r"\bmitre\b.*\battack\b", re.I), "MITRE ATT&CK"),
]

STATE_PERMITTED       = "PERMITTED"
STATE_RESTRICTED      = "RESTRICTED"
STATE_LICENSE_REVIEW  = "LICENSE_REVIEW"
STATE_LICENSE_BLOCKED = "LICENSE_BLOCKED"

_ACTIVATABLE = {STATE_PERMITTED, STATE_RESTRICTED}


def _normalise(license_str: str) -> str:
    up = license_str.strip().upper()
    for pat, canonical in _NORMALISE_PATTERNS:
        if pat.search(license_str):
            return canonical
    return up


def evaluate_license(license_str: str | None) -> dict[str, Any]:
    """Return {state, reason, license_id} for any license string.

    Never raises.  Missing/empty licenses → LICENSE_REVIEW so operators
    can inspect the rule rather than losing it.
    """
    if not license_str or not isinstance(license_str, str):
        return {
            "state":      STATE_LICENSE_REVIEW,
            "reason":     "no license metadata present",
            "license_id": None,
        }
    up = _normalise(license_str)
    if up in _PERMITTED:
        return {"state": STATE_PERMITTED,
                    "reason": "permissive open-source license",
                    "license_id": _PERMITTED[up]}
    if up in _RESTRICTED:
        return {"state": STATE_RESTRICTED,
                    "reason": "copyleft/attribution license — internal use permitted, "
                            "redistribution obligations apply",
                    "license_id": _RESTRICTED[up]}
    if up in _BLOCKED:
        return {"state": STATE_LICENSE_BLOCKED,
                    "reason": "proprietary / no-redistribution license",
                    "license_id": _BLOCKED[up]}
    # Fuzzy detection of proprietary-language licenses — anything that
    # smells "commercial" / "proprietary" / "all rights reserved" is
    # BLOCKED so it cannot ever enter ACTIVE, but it stays in the
    # registry for audit.
    for keyword in ("PROPRIETARY", "COMMERCIAL", "ALL RIGHTS RESERVED"):
        if keyword in up:
            return {"state": STATE_LICENSE_BLOCKED,
                        "reason": f"license text implies '{keyword.title()}' "
                                        "— no redistribution",
                        "license_id": None}
    return {"state": STATE_LICENSE_REVIEW,
                "reason": f"unrecognised license `{license_str}` — manual review required",
                "license_id": None}


def is_activatable(policy_state: str) -> bool:
    """True iff a rule with this policy state may enter ACTIVE."""
    return policy_state in _ACTIVATABLE


def policy_matrix() -> dict[str, Any]:
    """Deterministic snapshot of the current policy — surfaced in UI."""
    return {
        "permitted":       sorted(set(_PERMITTED.values())),
        "restricted":      sorted(set(_RESTRICTED.values())),
        "blocked":         sorted(set(_BLOCKED.values())),
        "activatable_states": sorted(_ACTIVATABLE),
        "version":         "1.0.0",
    }
