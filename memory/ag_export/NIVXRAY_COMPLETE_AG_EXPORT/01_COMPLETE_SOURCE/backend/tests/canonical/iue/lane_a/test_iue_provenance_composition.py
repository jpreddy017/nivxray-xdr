"""Lane-A · Provenance composition (STEP 6c.2 refactor).

Every payload dataclass carries ``canonical.ssot.models.Provenance``.
Lineage chains walk from intake → collect → parse → normalize → aggregate.
No parallel provenance representation exists.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


def test_all_payloads_carry_ssot_provenance_type():
    from canonical.ssot.models import Provenance
    from services.iue.intake import intake
    from services.iue.collectors.log_collector import collect
    from services.iue.parsers.ndjson_parser import iter_records
    from services.iue.normalizers.field_map import normalize
    from services.iue.aggregator import aggregate
    from services.iue.failure import IUEFailure

    d = intake("plain", allow_prev_fallback=True)
    assert isinstance(d.provenance, Provenance)
    assert d.provenance.engine == "iue.intake"

    raw = collect(b'{"a":1}\n{"a":2}\n', mime="application/x-ndjson",
                    input_id=d.input_id, tenant_id=d.tenant_id,
                    upstream=d.provenance)
    assert isinstance(raw.provenance, Provenance)
    assert raw.provenance.engine == "iue.collectors.log"

    parsed = list(iter_records(raw))
    assert all(isinstance(p.provenance, Provenance) for p in parsed)
    assert all(p.provenance.engine == "iue.parsers.ndjson" for p in parsed)

    normalized = [normalize(p) for p in parsed]
    assert all(n.provenance.engine == "iue.normalizers.field_map"
                for n in normalized)

    events = aggregate(normalized)
    assert all(ev.provenance.engine == "iue.aggregator" for ev in events)

    fail = IUEFailure(status="terminal", stage="collect",
                       error_code="collect_size_exceeded",
                       message="x", recoverable=False)
    assert isinstance(fail.provenance, Provenance)
    assert fail.provenance.engine == "iue.failure.collect"


def test_lineage_chain_walks_end_to_end():
    """Downstream provenance.upstream_evidence_ids contains upstream's
    engine tag — proves the chain is walkable without re-running the
    pipeline."""
    from services.iue.intake import intake
    from services.iue.collectors.log_collector import collect
    from services.iue.parsers.ndjson_parser import iter_records
    from services.iue.normalizers.field_map import normalize
    from services.iue.aggregator import aggregate

    d = intake("plain", allow_prev_fallback=True)
    raw = collect(b'{"src_ip":"10.0.0.1","event_time":"2026-02-14T12:00:00Z"}\n',
                    mime="application/x-ndjson",
                    input_id=d.input_id, tenant_id=d.tenant_id,
                    upstream=d.provenance)
    parsed = list(iter_records(raw))
    normalized = [normalize(p) for p in parsed]
    events = aggregate(normalized)

    chain = events[0].provenance.upstream_evidence_ids
    # Must include a tag from the immediate upstream (normalize)
    assert any("iue.normalizers.field_map" in s for s in chain), (
        f"Aggregator provenance does not reference normalize upstream: {chain}"
    )


def test_no_parallel_provenance_dataclass_exists_in_iue():
    """Sweep services/iue/**.py: no @dataclass declares fields matching
    the Provenance signature (engine + version + at) — that would be a
    forbidden parallel representation."""
    import ast
    import pathlib

    iue_root = pathlib.Path(__file__).resolve().parents[4] / "services" / "iue"
    provenance_signature = {"engine", "version", "at"}
    hits = []

    for py in iue_root.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                is_dataclass = any(
                    (isinstance(dec, ast.Name) and dec.id == "dataclass") or
                    (isinstance(dec, ast.Call) and getattr(dec.func, "id", "") == "dataclass")
                    for dec in node.decorator_list
                )
                if not is_dataclass:
                    continue
                field_names = {
                    stmt.target.id for stmt in node.body
                    if isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                }
                if provenance_signature <= field_names:
                    hits.append(f"{py}::{node.name}")
    assert not hits, (
        f"Parallel Provenance dataclass detected in IUE package: {hits}"
    )
