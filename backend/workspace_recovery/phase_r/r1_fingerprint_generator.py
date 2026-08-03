"""
Phase R1 fingerprint generator (technique-first schema).

Runs the Convergence Engine on every R1 sample and writes its
deterministic output+certificate fingerprint back to the family JSON
file under ``expected.fingerprint``. Walks the ``techniques[].samples[]``
hierarchy.

Usage
-----
    cd /app/backend && python -m workspace_recovery.phase_r.r1_fingerprint_generator
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from workspace.convergence import Artifact, converge
from workspace_recovery.phase_r.r1_loader import FAMILIES_DIR


def _fingerprint(sample: dict) -> dict:
    art = Artifact.from_input(sample["input"])
    result = converge(art)
    out = result.final_artifact.content
    return {
        "canonical_output_sha256": hashlib.sha256(out.encode("utf-8")).hexdigest(),
        "certificate_fingerprint": result.certificate.fingerprint,
        "expected_iterations": result.certificate.iterations_executed,
        "expected_canonical_state": result.certificate.canonical_state,
        "expected_terminated_reason": result.terminated_reason,
        "recorded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


def _update_family_file(path: Path) -> int:
    with path.open("r", encoding="utf-8") as fh:
        doc = json.load(fh)

    count = 0
    for tech in doc.get("techniques", []) or []:
        for sample in tech.get("samples", []) or []:
            fp = _fingerprint(sample)
            expected = sample.setdefault("expected", {})
            existing = expected.get("fingerprint") or {}
            unchanged = all(
                existing.get(k) == v for k, v in fp.items() if k != "recorded_at"
            ) and existing
            if unchanged:
                fp["recorded_at"] = existing.get("recorded_at", fp["recorded_at"])
            expected["fingerprint"] = fp
            count += 1

    doc["fingerprint_schema_version"] = "r1-2.0.0"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return count


def main() -> int:
    total = 0
    files = sorted(FAMILIES_DIR.glob("*.json"))
    for family_path in files:
        n = _update_family_file(family_path)
        print(f"  {family_path.name:<30}  {n:>3} samples fingerprinted")
        total += n
    print(f"Total: {total} samples across {len(files)} family/families")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
