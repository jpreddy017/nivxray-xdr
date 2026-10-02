"""
Distill the OFFICIAL MITRE ATT&CK Enterprise STIX 2.1 bundle into the compact
NivXRay catalogue shared by the ATT&CK HeatMap and Device Trajectory.

Source: https://github.com/mitre-attack/attack-stix-data (releases), file
`enterprise-attack/enterprise-attack-<ver>.json`. Build-time only; the raw bundle
(~50 MB) is NOT committed. Runtime never touches the network.

Rules: nothing is invented. Tactic order is the official x-mitre-matrix tactic_refs
order. Active techniques go in `techniques` (unchanged shape for the HeatMap).
Deprecated or revoked ones go in `retired`, with `revoked_by` taken from the
"revoked-by" relationships, so a stale rule mapping can be shown as
"revoked → T…" rather than being dropped.

Run (from the repo root):
    curl -fLo /tmp/ea.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack-19.2.json
    python3 backend/mitre_catalogue/build_catalogue.py /tmp/ea.json v19.2
    python3 backend/mitre_catalogue/build_name_index.py
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).parent
REPO = "https://github.com/mitre-attack/attack-stix-data"
CITE = re.compile(r"\(Citation:[^)]*\)")


def _ext(refs, key="external_id"):
    return next((r.get(key) for r in refs or [] if r.get("source_name") == "mitre-attack"), None)


def _short(desc: str) -> str:
    s = " ".join(CITE.sub("", desc or "").split())
    m = re.search(r"^(.{40,320}?[.!?])(\s|$)", s)
    return m.group(1) if m else s[:320]


def build(raw: dict, tag: str, sha256: str) -> dict:
    objs = raw["objects"]
    coll = next(o for o in objs if o["type"] == "x-mitre-collection")
    version = coll.get("x_mitre_version") or tag.lstrip("v")
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
    tac_by_id = {o["id"]: o for o in objs if o["type"] == "x-mitre-tactic" and live(o)}
    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix" and live(o))
    tactics = [{"shortname": t["x_mitre_shortname"], "external_id": _ext(t["external_references"]), "name": t["name"],
                "url": _ext(t["external_references"], "url")} for t in (tac_by_id[r] for r in matrix["tactic_refs"] if r in tac_by_id)]

    id2ext, active, retired = {}, {}, {}
    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        ext = _ext(o.get("external_references"))
        if not ext:
            continue
        id2ext[o["id"]] = ext
        tacs = [k["phase_name"] for k in o.get("kill_chain_phases") or [] if k.get("kill_chain_name") == "mitre-attack"]
        if live(o):
            active[ext] = {"external_id": ext, "name": o.get("name"), "tactics": tacs, "platforms": list(o.get("x_mitre_platforms") or []),
                           "data_sources": list(o.get("x_mitre_data_sources") or []), "is_sub": bool(o.get("x_mitre_is_subtechnique")),
                           "description": (o.get("description") or "").strip(), "short_description": _short(o.get("description")),
                           "url": _ext(o["external_references"], "url"), "parent_id": None}
        else:
            retired[ext] = {"external_id": ext, "name": o.get("name"), "tactics": tacs, "deprecated": bool(o.get("x_mitre_deprecated")),
                            "revoked": bool(o.get("revoked")), "revoked_by": None, "_id": o["id"]}
    for o in objs:
        if o["type"] != "relationship":
            continue
        src, dst = id2ext.get(o.get("source_ref")), id2ext.get(o.get("target_ref"))
        if o.get("relationship_type") == "subtechnique-of" and src in active and dst:
            active[src]["parent_id"] = dst
        if o.get("relationship_type") == "revoked-by" and src in retired and dst:
            retired[src]["revoked_by"] = dst
    for ext, rec in active.items():
        if "." in ext and not rec["parent_id"]:
            rec["parent_id"] = ext.split(".", 1)[0]
        if not rec["is_sub"]:
            rec["parent_id"] = None
    for rec in retired.values():
        rec.pop("_id")
    parents = sum(1 for t in active.values() if not t["is_sub"])
    return {
        "catalogue": "mitre-attack-enterprise",
        "version": version,
        "modified": coll.get("modified"),
        "source": f"{REPO}/blob/{tag}/enterprise-attack/enterprise-attack-{version}.json",
        "source_sha256": sha256,
        "generated_at": coll.get("modified"),
        "attribution": "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation (ATT&CK® Terms of Use).",
        "tactics": tactics,
        "techniques": sorted(active.values(), key=lambda r: r["external_id"]),
        "retired": sorted(retired.values(), key=lambda r: r["external_id"]),
        "stats": {"tactic_count": len(tactics), "technique_count": parents, "sub_technique_count": len(active) - parents,
                  "total_row_count": len(active)},
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, tag = pathlib.Path(sys.argv[1]), sys.argv[2]
    data = src.read_bytes()
    compact = build(json.loads(data), tag, hashlib.sha256(data).hexdigest())
    stem = "enterprise_v" + compact["version"].replace(".", "_") + ".compact"
    (HERE / f"{stem}.json").write_text(json.dumps(compact, indent=1))
    (HERE / f"{stem}.meta.json").write_text(json.dumps({k: compact[k] for k in ("catalogue", "version", "modified", "source", "source_sha256", "stats")}, indent=2))
    print(json.dumps(compact["stats"]), "retired:", len(compact["retired"]), "->", stem)
    return 0


if __name__ == "__main__":
    sys.exit(main())
