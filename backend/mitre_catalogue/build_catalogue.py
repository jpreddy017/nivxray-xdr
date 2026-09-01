"""
Distill the official MITRE ATT&CK Enterprise STIX 2.1 bundle into a
compact NivXRay catalogue.  Owner rules:

  · Source of truth is the versioned STIX bundle
    (`enterprise-attack-v16.1.json`, ~27MB, downloaded from
    https://github.com/mitre/cti at tag ATT&CK-v16.1).
  · We do NOT invent techniques, sub-techniques, tactics, platforms
    or descriptions — we project the fields already in STIX.
  · Deprecated / revoked techniques are excluded (STIX flags them).
  · Every technique keeps its stable `external_id` (T####), its
    parent id when it is a sub-technique, its tactic short-names,
    and the canonical attack.mitre.org URL from STIX.

Run:
    python3 /app/backend/mitre_catalogue/build_catalogue.py
Emits:
    /app/backend/mitre_catalogue/enterprise_v16_1.compact.json
    /app/backend/mitre_catalogue/enterprise_v16_1.compact.meta.json
"""
from __future__ import annotations
import json
import pathlib
import sys
from datetime import datetime, timezone

HERE     = pathlib.Path(__file__).parent
STIX_IN  = HERE / "enterprise-attack-v16.1.json"
OUT_JSON = HERE / "enterprise_v16_1.compact.json"
OUT_META = HERE / "enterprise_v16_1.compact.meta.json"


def _external_attack_id(refs: list[dict]) -> str | None:
    for r in refs or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def _external_attack_url(refs: list[dict]) -> str | None:
    for r in refs or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("url")
    return None


def build() -> dict:
    raw = json.loads(STIX_IN.read_text())
    objects = raw.get("objects", [])

    tactics_by_shortname: dict[str, dict] = {}
    techniques: dict[str, dict] = {}      # external_id -> record
    stix_id_to_ext: dict[str, str] = {}   # STIX id -> T####

    for obj in objects:
        t = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        if t == "x-mitre-tactic":
            ext = _external_attack_id(obj.get("external_references") or [])
            shortname = obj.get("x_mitre_shortname")
            if not shortname:
                continue
            tactics_by_shortname[shortname] = {
                "shortname":  shortname,
                "external_id": ext,
                "name":       obj.get("name"),
                "url":        _external_attack_url(obj.get("external_references") or []),
            }

        elif t == "attack-pattern":
            ext = _external_attack_id(obj.get("external_references") or [])
            if not ext:
                continue
            stix_id_to_ext[obj["id"]] = ext
            kill_chain = [
                kc.get("phase_name")
                for kc in obj.get("kill_chain_phases") or []
                if kc.get("kill_chain_name") == "mitre-attack"
            ]
            techniques[ext] = {
                "external_id": ext,
                "name":        obj.get("name"),
                "tactics":     [k for k in kill_chain if k],
                "platforms":   list(obj.get("x_mitre_platforms") or []),
                "data_sources": list(obj.get("x_mitre_data_sources") or []),
                "is_sub":      bool(obj.get("x_mitre_is_subtechnique")),
                "description": (obj.get("description") or "").strip(),
                "url":         _external_attack_url(obj.get("external_references") or []),
                "parent_id":   None,     # patched below via subtechnique-of relationships
                "stix_id":     obj["id"],
            }

    # Wire sub-technique → parent via STIX relationships.
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "subtechnique-of":
            continue
        src = stix_id_to_ext.get(obj.get("source_ref"))
        dst = stix_id_to_ext.get(obj.get("target_ref"))
        if src and dst and src in techniques:
            techniques[src]["parent_id"] = dst

    # Sanity: T####.### style ids should have a parent.  For any
    # stragglers, derive parent from the id prefix and cross-check.
    for ext, rec in techniques.items():
        if "." in ext and not rec["parent_id"]:
            rec["parent_id"] = ext.split(".", 1)[0]
        if not rec["is_sub"] and rec["parent_id"]:
            # STIX contradicts itself — trust the id shape.
            rec["parent_id"] = None
        # drop the STIX opaque id from the emitted record.
        rec.pop("stix_id", None)

    tactics_order = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    ]
    tactics = [tactics_by_shortname[t] for t in tactics_order
                                            if t in tactics_by_shortname]

    parents = [t for t in techniques.values() if not t["is_sub"]]
    subs    = [t for t in techniques.values() if t["is_sub"]]
    return {
        "catalogue": "mitre-attack-enterprise",
        "version":   "16.1",
        "source":    "https://github.com/mitre/cti/tree/ATT%26CK-v16.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tactics":   tactics,
        "techniques": sorted(techniques.values(),
                                       key=lambda r: r["external_id"]),
        "stats": {
            "tactic_count":            len(tactics),
            "technique_count":         len(parents),
            "sub_technique_count":     len(subs),
            "total_row_count":         len(parents) + len(subs),
        },
    }


def main() -> int:
    if not STIX_IN.exists():
        print(f"ERROR: missing {STIX_IN}", file=sys.stderr)
        return 2
    compact = build()
    OUT_JSON.write_text(json.dumps(compact, indent=2, sort_keys=False))
    OUT_META.write_text(json.dumps({
        "catalogue":            compact["catalogue"],
        "version":              compact["version"],
        "generated_at":         compact["generated_at"],
        "source":               compact["source"],
        "stats":                compact["stats"],
    }, indent=2))
    print("stats:", json.dumps(compact["stats"], indent=2))
    print("wrote:", OUT_JSON, "size=",
          f"{OUT_JSON.stat().st_size/1024:.1f} KiB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
