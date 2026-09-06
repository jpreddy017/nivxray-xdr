"""JSON Schema export for the twelve Wave 0 contracts.

Directive §4 requires explicit capability contracts at the plane
boundaries so a future Windows / macOS / Linux agent — written in another
language, by someone who will never read this Python — can populate the
same canonical evidence model. A JSON Schema is how that contract crosses
the language boundary.

The export annotates every evidence field with `nivxforge_evidence: true`,
so an agent author can see at a glance which fields carry an epistemic
obligation and which are mere bookkeeping.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import CONTRACTS
from .epistemic import EpistemicState, FORBIDDEN_EQUIVALENCES

SCHEMA_VERSION = "nivxforge-edr/wave0/v1"
DEFAULT_OUT = Path(__file__).resolve().parents[3] / "docs" / "contracts" / "edr"


def export_one(name: str) -> dict[str, Any]:
    model = CONTRACTS[name]
    schema = model.model_json_schema(mode="serialization")
    schema["$id"] = f"{SCHEMA_VERSION}/{name}.schema.json"
    schema["x-nivxforge-contract"] = name
    schema["x-nivxforge-evidence-fields"] = list(
        getattr(model, "evidence_fields", lambda: ())())
    schema["x-nivxforge-epistemic-states"] = [s.value for s in EpistemicState]
    return schema


def export_all() -> dict[str, dict[str, Any]]:
    return {name: export_one(name) for name in CONTRACTS}


def manifest() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "contracts": sorted(CONTRACTS),
        "epistemic_states": [s.value for s in EpistemicState],
        "forbidden_equivalences": [
            {"left": a, "right": b, "because": why}
            for a, b, why in FORBIDDEN_EQUIVALENCES],
        "rule": (
            "An evidence field may be null ONLY if an explicit epistemic "
            "state says why. There is no silent gap."),
    }


def write_to_disk(out_dir: Path | str = DEFAULT_OUT) -> list[str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, schema in export_all().items():
        p = out / f"{name}.schema.json"
        p.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
        written.append(str(p))
    m = out / "manifest.json"
    m.write_text(json.dumps(manifest(), indent=2, sort_keys=True) + "\n")
    written.append(str(m))
    return written


if __name__ == "__main__":
    for path in write_to_disk():
        print(path)
