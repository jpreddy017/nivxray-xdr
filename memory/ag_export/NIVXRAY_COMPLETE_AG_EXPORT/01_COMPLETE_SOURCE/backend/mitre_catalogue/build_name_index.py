"""
Emit a compact name → external_id index of the entire MITRE ATT&CK
Enterprise v16.1 catalogue for consumers that receive technique
NAMES instead of canonical T-ids:

  · Frontend `attackLink.js` — bundles the generated index so every
    catalogue-published NAME resolves to a live attack.mitre.org
    deep-link, no hand-maintenance required.
  · Backend `routers/mitre_catalogue.py` — uses the same index at
    runtime so future incidents that carry a bare NAME still land
    on their real technique in the coverage projection.

Output:
  /app/backend/mitre_catalogue/name_index.json
  /app/apps/nivxray-xdr/src/xdr/mitre/attackNameIndex.generated.js

Runs after `build_catalogue.py`.
"""
from __future__ import annotations
import json
import pathlib
import re
import sys

HERE     = pathlib.Path(__file__).parent
CAT_IN   = HERE / "enterprise_v16_1.compact.json"
OUT_BE   = HERE / "name_index.json"
OUT_FE   = (pathlib.Path("/app/apps/nivxray-xdr/src/xdr/mitre")
              / "attackNameIndex.generated.js")


_ATT_ID_RE = re.compile(r"\b(T\d{4})(?:\.(\d{3}))?\b")


def _to_external_url_slug(ext: str) -> str:
    """`T1059.001` → `T1059/001` for the attack.mitre.org URL path."""
    return ext.replace(".", "/")


def _keys_for(name: str) -> list[str]:
    """Normalised lookup keys emitted by real backends when they
    leak a technique NAME.  Everything is uppercased and
    whitespace-collapsed.  We deliberately do NOT invent extra
    aliases — only faithful shape variants of the published name.
    """
    if not name:
        return []
    n = re.sub(r"\s+", " ", name).strip()
    upper = n.upper()
    out = {upper}
    # Alias: strip a "Parent: " prefix that some products prepend.
    if ":" in upper:
        out.add(upper.split(":", 1)[1].strip())
    # Alias: replace fancy Unicode dashes with plain ASCII.
    out.add(upper.replace("\u2013", "-").replace("\u2014", "-"))
    return sorted(k for k in out if k)


def build() -> dict:
    raw = json.loads(CAT_IN.read_text())
    techniques = raw.get("techniques", [])
    idx: dict[str, str] = {}
    for t in techniques:
        ext = t["external_id"]
        for k in _keys_for(t.get("name") or ""):
            # Prefer the first mapping for a given key — the ATT&CK
            # catalogue does not repeat exact names across parents.
            idx.setdefault(k, ext)
    return {
        "catalogue_version": raw.get("version"),
        "generated_at":      raw.get("generated_at"),
        "name_to_external_id": idx,
        "count":             len(idx),
    }


def main() -> int:
    if not CAT_IN.exists():
        print(f"ERROR: run build_catalogue.py first — missing {CAT_IN}",
              file=sys.stderr)
        return 2
    payload = build()
    OUT_BE.write_text(json.dumps(payload, indent=2, sort_keys=False))

    js = [
        "/**",
        " * AUTO-GENERATED — do not hand-edit.",
        " *",
        " * MITRE ATT&CK Enterprise v"
              + str(payload["catalogue_version"])
              + " name → canonical id index.  Regenerate with:",
        " *",
        " *   python3 /app/backend/mitre_catalogue/build_name_index.py",
        " *",
        " * Every entry is a real technique/sub-technique published on",
        " * attack.mitre.org.  Unknown names fall through to the honest",
        " * `no attack id` pill in `attackLink.js` — never a fabricated",
        " * search fallback.",
        " */",
        "export const CATALOGUE_VERSION = "
              + json.dumps(payload["catalogue_version"]) + ";",
        "export const ATTACK_NAME_INDEX = "
              + json.dumps({k: _to_external_url_slug(v)
                                    for k, v in payload["name_to_external_id"].items()},
                                     indent=2, sort_keys=True)
              + ";",
        "",
    ]
    OUT_FE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FE.write_text("\n".join(js))
    print(f"wrote: {OUT_BE}  ({payload['count']} keys)")
    print(f"wrote: {OUT_FE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
