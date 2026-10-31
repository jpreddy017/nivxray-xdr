"""RC5 · Phase 5 · STIX 2.1 export for MITRE mappings.

Produces a minimal but valid STIX 2.1 `bundle` containing:
  - one `attack-pattern` per (technique_id, sub_technique_id) referenced,
    with `external_references[]` pointing at the MITRE ATT&CK page.
  - one `x-nivxray-mapping` custom SDO per MitreMapping preserving
    evidence_behavior_ids / evidence_node_ids / rule_id / confidence /
    data_sources / detections. `x-*` custom types are permitted by STIX 2.1
    (§ 11.2 Custom Objects).
  - one `report` SDO stitching everything together.

Deterministic: IDs are derived from stable input hashes so identical
mappings produce byte-identical bundles.

Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .mitre_mapper import MitreMapping


STIX_VERSION = "2.1"
_FIXED_CREATED = "2020-01-01T00:00:00.000Z"       # deterministic timestamp
_NIVXRAY_IDENTITY = ("identity--"
                     "f0f0f0f0-1111-2222-3333-444444444444")  # constant


def _sha1_uuid(namespace: str, payload: str) -> str:
    """Deterministic UUIDv4-shaped string derived from sha1(namespace|payload)."""
    h = hashlib.sha1(f"{namespace}|{payload}".encode("utf-8")).hexdigest()
    # 8-4-4-4-12 UUID layout — set version=4, variant=8
    return f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def _attack_pattern_id(technique: str, sub: Optional[str]) -> str:
    return "attack-pattern--" + _sha1_uuid("attack-pattern", technique + (sub or ""))


def _mapping_sdo_id(m: MitreMapping) -> str:
    payload = json.dumps({
        "technique": m.technique_id,
        "sub":       m.sub_technique_id,
        "rule":      m.rule_id,
        "behavior_ids": list(m.evidence_behavior_ids),
        "node_ids":     list(m.evidence_node_ids),
    }, sort_keys=True, separators=(",", ":"))
    return "x-nivxray-mapping--" + _sha1_uuid("mapping", payload)


def _attack_url(technique: str, sub: Optional[str]) -> str:
    if sub:
        return f"https://attack.mitre.org/techniques/{technique}/{sub.split('.')[1]}/"
    return f"https://attack.mitre.org/techniques/{technique}/"


def build_stix_bundle(
    mappings: Iterable[MitreMapping],
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    mappings = list(mappings)
    objects: List[Dict[str, Any]] = []

    # Identity — constant so the bundle is stable
    objects.append({
        "type": "identity",
        "spec_version": STIX_VERSION,
        "id": _NIVXRAY_IDENTITY,
        "created": _FIXED_CREATED,
        "modified": _FIXED_CREATED,
        "name": "NivXRay",
        "identity_class": "system",
    })

    # attack-pattern per unique (technique, sub) pair — deterministic order
    seen_ap: Dict[Tuple[str, Optional[str]], str] = {}
    for m in sorted(mappings, key=lambda x: (x.technique_id, x.sub_technique_id or "")):
        key = (m.technique_id, m.sub_technique_id)
        if key in seen_ap:
            continue
        ap_id = _attack_pattern_id(m.technique_id, m.sub_technique_id)
        seen_ap[key] = ap_id
        display_id = m.sub_technique_id or m.technique_id
        objects.append({
            "type": "attack-pattern",
            "spec_version": STIX_VERSION,
            "id": ap_id,
            "created": _FIXED_CREATED,
            "modified": _FIXED_CREATED,
            "created_by_ref": _NIVXRAY_IDENTITY,
            "name": m.technique_name,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": display_id,
                    "url": _attack_url(m.technique_id, m.sub_technique_id),
                },
            ],
            "kill_chain_phases": [{
                "kill_chain_name": "mitre-attack",
                "phase_name": m.tactic,
            }],
        })

    # One x-nivxray-mapping per MitreMapping, evidence preserved.
    mapping_ids: List[str] = []
    for m in sorted(mappings, key=lambda x: (x.technique_id,
                                             x.sub_technique_id or "",
                                             x.rule_id)):
        sdo_id = _mapping_sdo_id(m)
        mapping_ids.append(sdo_id)
        ap_ref = seen_ap[(m.technique_id, m.sub_technique_id)]
        objects.append({
            "type": "x-nivxray-mapping",
            "spec_version": STIX_VERSION,
            "id": sdo_id,
            "created": _FIXED_CREATED,
            "modified": _FIXED_CREATED,
            "created_by_ref": _NIVXRAY_IDENTITY,
            "attack_pattern_ref": ap_ref,
            "technique_id": m.technique_id,
            "sub_technique_id": m.sub_technique_id,
            "tactic": m.tactic,
            "tactic_id": m.tactic_id,
            "confidence": m.confidence,
            "rule_id": m.rule_id,
            "evidence_behavior_ids": list(m.evidence_behavior_ids),
            "evidence_node_ids": list(m.evidence_node_ids),
            "reconstructed": list(m.reconstructed),
            "data_sources": list(m.data_sources),
            "detections": dict(m.detections),
        })

    # Report SDO — stitches everything together
    if mappings:
        report_id = "report--" + _sha1_uuid(
            "report",
            (case_id or "") + "|" + "|".join(sorted(m.id for m in mappings)),
        )
        objects.append({
            "type": "report",
            "spec_version": STIX_VERSION,
            "id": report_id,
            "created": _FIXED_CREATED,
            "modified": _FIXED_CREATED,
            "created_by_ref": _NIVXRAY_IDENTITY,
            "name": ("NivXRay RC5 ATT&CK Mapping"
                     + (f" · case={case_id}" if case_id else "")),
            "published": _FIXED_CREATED,
            "report_types": ["threat-report"],
            "object_refs": list(seen_ap.values()) + mapping_ids,
        })

    return {
        "type": "bundle",
        "id": "bundle--" + _sha1_uuid(
            "bundle", "|".join(sorted(o["id"] for o in objects))
        ),
        "objects": objects,
    }


__all__ = ["build_stix_bundle", "STIX_VERSION"]
