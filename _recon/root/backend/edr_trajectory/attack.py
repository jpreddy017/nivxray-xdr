"""E3 ATT&CK adapter for Device Trajectory: no parallel mapper.

The source of truth is E1's attribution, as already attached to each trajectory row by
edr_plane.trajectory_window._project: `mitre` (ids), `mitre_basis`, and `findings[]` (the
producing rule's declared `attck`). This module only decorates those ids from the vendored
official STIX catalogue (services.mitre_catalogue, the same catalogue the ATT&CK HeatMap uses):
names, short descriptions, tactic order, and revoked/deprecated status.

Semantics: a mapping is not a verdict; an observed technique is not a confirmed attack; no mapping
is not proof of no attack.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from services.mitre_catalogue import get_catalogue

ATTACK_RE = re.compile(r"\b(T\d{4})(?:\.(\d{3}))?\b", re.I)
TACTIC_RE = re.compile(r"^TA\d{4}$", re.I)
LABEL = "Observed on this device (from detections and behavioral matches)"
SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
#: E1 basis -> on-screen attribution type. A heuristic or source tag is never shown as a detection.
TYPES = {"RULE_DECLARED_BY_MATCHED_DETECTION": "Rule-mapped",
         "SOURCE_NORMALIZER_TAG_NOT_VALIDATED_DETECTION": "Heuristic",
         "HEURISTIC_TEXT_PATTERN": "Heuristic", "BEHAVIOR_MAPPER_V2": "Heuristic", "TI_DERIVED": "Intel-derived"}
SEMANTICS = "Observed technique is not a confirmed attack; a mapping is not a verdict; no mapping is not proof of no attack."


def version() -> str:
    return get_catalogue().version


def tactics() -> list[dict[str, Any]]:
    return [{"shortname": t["shortname"], "external_id": t["external_id"], "name": t["name"],
             "url": f"https://attack.mitre.org/tactics/{t['external_id']}/"} for t in get_catalogue().tactics]


def _norm(x: Any) -> str | None:
    m = ATTACK_RE.search(str(x or ""))
    return (f"{m.group(1).upper()}.{m.group(2)}" if m.group(2) else m.group(1).upper()) if m else None


def technique(tid: str) -> dict[str, Any]:
    """One id -> catalogue decoration. Retired ids are surfaced (revoked -> replacement / deprecated), never dropped."""
    cat = get_catalogue()
    order = {t["shortname"]: i for i, t in enumerate(cat.tactics)}
    row, status, repl = cat.technique(tid), "active", None
    if not row:
        old = cat.retired_entry(tid)
        if not old:
            return {"technique": tid, "status": "unknown", "name": None, "display": f"{tid} (not in ATT&CK Enterprise v{cat.version})",
                    "tactics": [], "description": None, "url": None, "catalogue_version": cat.version}
        status, repl = ("revoked" if old["revoked"] else "deprecated"), old.get("revoked_by")
        row = cat.technique(repl) if repl else old
    parent = cat.technique(row["parent_id"]) if row.get("parent_id") else None
    name = f"{parent['name']}: {row['name']}" if parent else row["name"]
    disp = name if status == "active" else (f"revoked → {repl} {name}" if repl else f"deprecated · {row['name']}")
    return {"technique": tid, "status": status, "replacement": repl, "name": row["name"], "parent_id": row.get("parent_id"),
            "parent_name": parent and parent["name"], "display": disp,
            "description": row.get("short_description") or row.get("description"),
            "tactics": sorted(row.get("tactics") or [], key=lambda s: order.get(s, 99)),
            "url": f"https://attack.mitre.org/techniques/{(repl if status == 'revoked' and repl else tid).replace('.', '/')}/",
            "catalogue_version": cat.version}


def annotate_row(row: dict[str, Any]) -> dict[str, Any] | None:
    """E1 trajectory row -> display attribution. None when E1 attributed nothing (UI keeps the ◇ empty state)."""
    ids = [str(x) for x in row.get("mitre") or [] if x]
    techs = sorted({t for t in (_norm(x) for x in ids if not TACTIC_RE.match(x)) if t})
    tac_ids = [x.upper() for x in ids if TACTIC_RE.match(x)]
    if not techs and not tac_ids:
        return None
    cat, findings = get_catalogue(), [f for f in row.get("findings") or [] if f.get("attck")]
    by_id = {t["external_id"]: t["shortname"] for t in cat.tactics}
    dec = [technique(t) for t in techs]
    order = [t["shortname"] for t in cat.tactics]
    tacs = sorted({*(s for d in dec for s in d["tactics"]), *(by_id[t] for t in tac_ids if t in by_id)}, key=order.index)
    sev = max((f.get("severity") for f in findings if f.get("severity")), key=lambda s: SEV.get(str(s).upper(), -1), default=None)
    return {"type": TYPES.get(row.get("mitre_basis"), "Heuristic"), "basis": row.get("mitre_basis"),
            "techniques": dec, "tactics": tacs, "tactic_ids": tac_ids, "severity": sev, "catalogue_version": cat.version,
            "sources": [{"rule_id": f.get("rule_id"), "rule_name": f.get("rule_name"), "rule_version": f.get("rule_version"),
                         "engine": f.get("engine"), "confidence": f.get("confidence"), "attck_basis": f.get("attck_basis"),
                         "attck": f.get("attck")} for f in findings]}


def matches(mapped: str, query: str) -> bool:
    q = (query or "").upper()
    return mapped == q or mapped.startswith(q + ".")


DETECTION_TYPES = ("Rule-mapped", "Intel-derived")


def device_summary(rows: Iterable[dict[str, Any]], t0_ms: int | None, t1_ms: int | None, ms_of,
                   include_heuristic: bool = False) -> dict[str, Any]:
    """Per-tactic columns (official kill-chain order) of techniques E1 attributed in [t0, t1]. Empty tactics are kept.
    Default = detections only (rule-mapped / intel-derived); heuristic ingest tags only when asked, and labelled."""
    techs: dict[str, dict[str, Any]] = {}
    for r in rows:
        a, ms = r.get("e3_attack") or annotate_row(r), ms_of(r)
        if a and not include_heuristic and a["type"] not in DETECTION_TYPES:
            continue
        if not a or ms is None or (t0_ms is not None and ms < t0_ms) or (t1_ms is not None and ms > t1_ms):
            continue
        for d in a["techniques"]:
            x = techs.setdefault(d["technique"], {**{k: d[k] for k in ("technique", "name", "display", "description", "tactics", "url", "status")},
                                                  "count": 0, "first_ms": ms, "last_ms": ms, "event_iids": [], "max_severity": None,
                                                  "types": [], "rules": []})
            x["count"] += 1
            x["first_ms"], x["last_ms"] = min(x["first_ms"], ms), max(x["last_ms"], ms)
            x["event_iids"].append(r.get("event_iid"))
            if SEV.get(str(a["severity"]).upper(), -1) > SEV.get(str(x["max_severity"]).upper(), -1):
                x["max_severity"] = a["severity"]
            for k, v in (("types", a["type"]), *(("rules", s["rule_id"]) for s in a["sources"])):
                if v and v not in x[k]:
                    x[k].append(v)
    cols = [{**t, "techniques": sorted((x for x in techs.values() if t["shortname"] in x["tactics"]), key=lambda x: x["technique"])}
            for t in tactics()]
    for c in cols:
        c["observed"] = bool(c["techniques"])
    return {"catalogue": "mitre-attack-enterprise", "catalogue_version": version(), "label": LABEL, "tactics": cols,
            "includes_heuristic": include_heuristic, "catalogue_modified": get_catalogue().modified,
            "semantics": SEMANTICS, "source": "E1 trajectory attribution (findings.attck / event.mitre), decorated from the vendored STIX catalogue"}
