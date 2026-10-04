"""Rule-mapping lint: every ATT&CK id E1's mappers (and the E3 preview rules) emit, checked against the
vendored official catalogue (services.mitre_catalogue). Reports revoked / deprecated / unknown ids, renamed
techniques (name recorded in code differs from catalogue), and tactic drift (e.g. v19 split of Defense Evasion).
Read-only: it never changes E1 semantics. Run: python3 tools/e3ui/mitre_mapping_diff.py [--json]"""
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from services.mitre_catalogue import get_catalogue  # noqa: E402

SOURCES = {
    "v2/ingestion/mitre_map.py": "Heuristic: ingest keyword tag → event.mitre (DT basis SOURCE_NORMALIZER_TAG_NOT_VALIDATED_DETECTION)",
    "operations.py": "Heuristic: MITRE_HEURISTICS regex → incident.mitre (HeatMap coverage via workspace_cases)",
    "engine/detectors/mitre_mapper.py": "Heuristic: behavior mapper v2 (MITRE_RULES) → incident mappings",
    "canonical/projections/attck.py": "Static table: _TECHNIQUE_META (tactic + kill-chain per id)",
    "edr_trajectory/artifacts_overlay.py": "E3 preview rule specs (mitre_attack) → E1 DeterministicRuleAnalyzer findings",
}
TID = re.compile(r"\"(T\d{4}(?:\.\d{3})?)\"")
TRIPLE = re.compile(r"\(\"(T\d{4}(?:\.\d{3})?)\",\s*\"([^\"]+)\",\s*\"([^\"]+)\"\)")
NAMED = re.compile(r"(?:sub_)?technique_id=\"(T\d{4}(?:\.\d{3})?)\"[^)]*?technique_name=\"([^\"]+)\"", re.S)
TACTIC_KEY = lambda s: re.sub(r"[^a-z]", "", s.lower())


def scan() -> dict:
    cat, out = get_catalogue(), {"catalogue_version": get_catalogue().version, "sources": {}}
    tac_names = {TACTIC_KEY(t["name"]): t["shortname"] for t in cat.tactics} | {TACTIC_KEY(t["shortname"]): t["shortname"] for t in cat.tactics}
    for rel, kind in SOURCES.items():
        text = (ROOT / "backend" / rel).read_text()
        ids = sorted(set(TID.findall(text)))
        names = dict(NAMED.findall(text))  # only mapper fields that claim to BE the technique name (operations.py names are rationales)
        tactics = {t: tc for t, _, tc in TRIPLE.findall(text)}
        rows = []
        for t in ids:
            row, old = cat.technique(t), cat.retired_entry(t)
            status = "active" if row else ("revoked" if old and old["revoked"] else "deprecated" if old else "unknown")
            issue = {"technique": t, "status": status}
            if old:
                issue["revoked_by"] = old.get("revoked_by")
            if row and t in names:
                coded, real = names[t].split(":")[-1].strip().lower(), row["name"].lower()
                if real not in names[t].lower() and coded not in real:
                    issue["renamed"] = {"code": names[t], "catalogue": row["name"]}
            if row and t in tactics:
                k = tac_names.get(TACTIC_KEY(tactics[t]))
                if k not in (row.get("tactics") or []):
                    issue["tactic_drift"] = {"code": tactics[t], "catalogue": row.get("tactics")}
            if status != "active" or "renamed" in issue or "tactic_drift" in issue:
                rows.append(issue)
        out["sources"][rel] = {"kind": kind, "ids": len(ids), "issues": rows}
    return out


def markdown(r: dict) -> str:
    lines = [f"Catalogue: ATT&CK Enterprise v{r['catalogue_version']}", "", "| Source | Kind | Ids | Issue |", "|---|---|---|---|"]
    for rel, s in r["sources"].items():
        if not s["issues"]:
            lines.append(f"| `{rel}` | {s['kind']} | {s['ids']} | none |")
        for i in s["issues"]:
            bits = [i["status"] + (f" → {i['revoked_by']}" if i.get("revoked_by") else "")]
            if "renamed" in i:
                bits.append(f"renamed: code '{i['renamed']['code']}' vs '{i['renamed']['catalogue']}'")
            if "tactic_drift" in i:
                bits.append(f"tactic: code '{i['tactic_drift']['code']}' vs {', '.join(i['tactic_drift']['catalogue'])}")
            lines.append(f"| `{rel}` | {s['kind']} | {i['technique']} | {'; '.join(bits)} |")
    return "\n".join(lines)


if __name__ == "__main__":
    res = scan()
    print(json.dumps(res, indent=1) if "--json" in sys.argv else markdown(res))
