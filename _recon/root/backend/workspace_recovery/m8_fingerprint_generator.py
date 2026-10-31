"""
M8 · Corpus Fingerprint Generator.

Reads the current corpus, runs the Convergence Engine on each sample,
and writes back the following fingerprint fields to
``expected.fingerprint`` for regression protection:

  * ``canonical_output_sha256``   — SHA-256 of the final artifact
    content produced by the current engine
  * ``certificate_fingerprint``   — SHA-256 of the canonical JSON
    Convergence Certificate
  * ``expected_iterations``       — number of iterations
  * ``expected_canonical_state``  — whether the engine reached
    canonical state
  * ``expected_terminated_reason``— why the engine stopped
  * ``recorded_at``               — ISO 8601 timestamp (audit trail)

Usage
-----
    cd /app/backend && python -m workspace_recovery.m8_fingerprint_generator

Writes ``corpus.json`` in place. Idempotent — re-running produces
the same bytes IF the engine is deterministic.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from workspace.convergence import Artifact, converge


CORPUS_PATH = Path(__file__).resolve().parent / "corpus.json"


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


def main() -> int:
    with CORPUS_PATH.open("r", encoding="utf-8") as fh:
        doc = json.load(fh)

    updated_count = 0
    for cat_name, cat in (doc.get("categories") or {}).items():
        for sample in cat.get("samples") or []:
            fp = _fingerprint(sample)
            expected = sample.setdefault("expected", {})
            existing = expected.get("fingerprint") or {}
            # Preserve recorded_at if fingerprint values did not
            # otherwise change — keeps the audit-trail idempotent.
            changed = any(
                existing.get(k) != v
                for k, v in fp.items()
                if k != "recorded_at"
            )
            if not changed and existing:
                # Re-run produces the same fingerprint values → keep
                # the original recorded_at.
                fp["recorded_at"] = existing.get("recorded_at", fp["recorded_at"])
            expected["fingerprint"] = fp
            updated_count += 1

    doc["fingerprint_schema_version"] = "m8-1.0.0"
    CORPUS_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"Fingerprints written for {updated_count} samples.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
