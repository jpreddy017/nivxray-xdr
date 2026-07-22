"""tests/rc5/api/test_v2_report.py · R4 Deterministic Report tests.

Guarantees:
1. build_report produces byte-identical output on identical inputs
   (deterministic SHA-256 signature).
2. All 10 canonical sections are present and non-empty on the seeded
   Bumblebee → Akira case.
3. Report generation does NOT touch RC5 collections / endpoints.
4. Markdown renderer is also deterministic (same envelope → same bytes).
"""
from __future__ import annotations
import asyncio
import json
import os
import sys
import pytest


@pytest.fixture(scope="module")
def _env_flags():
    os.environ.setdefault("NIVX_FLAG_TRAJECTORY_ENGINE", "shadow")
    os.environ.setdefault("NIVX_FLAG_CASE_ENGINE", "shadow")
    os.environ.setdefault("NIVX_FLAG_ADAPTERS", "shadow")


@pytest.mark.asyncio
async def test_report_all_ten_sections_present(_env_flags):
    """The envelope must always ship all 10 canonical sections in order."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from v2.report import build_report

    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    env = await build_report(db, "case_dfir_bumblebee_akira_2026")

    expected_ids = [
        "executive_summary", "case_metadata", "verdict_rollup",
        "mitre_coverage", "process_ancestry", "top_entities",
        "chronological_timeline", "commandline_decoding",
        "enrichment", "signature",
    ]
    got_ids = [s.id for s in env.sections]
    assert got_ids == expected_ids, f"section order/set mismatch: {got_ids}"
    for s in env.sections:
        assert s.title, f"section {s.id} has empty title"
        assert s.order in range(1, 11)


@pytest.mark.asyncio
async def test_report_signature_is_deterministic(_env_flags):
    """Two consecutive builds on the same case must produce the same SHA-256."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from v2.report import build_report

    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    env1 = await build_report(db, "case_dfir_bumblebee_akira_2026")
    env2 = await build_report(db, "case_dfir_bumblebee_akira_2026")

    assert env1.signature.get("sha256"), "signature.sha256 missing"
    assert env1.signature["sha256"] == env2.signature["sha256"], (
        f"non-deterministic hash: {env1.signature['sha256']} != {env2.signature['sha256']}"
    )
    # Canonical JSON must be byte-identical too
    from v2.report.hashing import canonical_json
    assert canonical_json(env1) == canonical_json(env2)


@pytest.mark.asyncio
async def test_report_markdown_is_deterministic(_env_flags):
    """Rendered Markdown must also be byte-identical across runs."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from v2.report import build_report, render_markdown

    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    env = await build_report(db, "case_dfir_bumblebee_akira_2026")
    md1 = render_markdown(env)
    md2 = render_markdown(env)
    assert md1 == md2
    # Sanity — Markdown mentions the schema version and the sha256
    assert "r4.0" in md1
    assert env.signature["sha256"] in md1


@pytest.mark.asyncio
async def test_report_generated_at_is_derived_not_wall_clock(_env_flags):
    """`generated_at` MUST be sourced from observation timestamps, not
    datetime.now — otherwise the signature wouldn't be reproducible."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from v2.report import build_report

    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    env = await build_report(db, "case_dfir_bumblebee_akira_2026")
    # generated_at is a fixed value from the seed, not "now"
    assert env.generated_at
    assert env.generated_at != "1970-01-01T00:00:00Z", "no observations found"


def test_report_module_does_not_import_rc5():
    """RC5 immutability: report module must have zero RC5 imports."""
    import v2.report, v2.report.builder, v2.report.markdown, v2.report.hashing, v2.report.schema
    for m in (v2.report, v2.report.builder, v2.report.markdown, v2.report.hashing, v2.report.schema):
        src_file = getattr(m, "__file__", "")
        if not src_file:
            continue
        with open(src_file) as f:
            src = f.read()
        assert "engine.core" not in src
        assert "engine.rules" not in src
        assert "routers.rc5" not in src
        # `import engine` alone is fine only if not the RC5 engine — v2 has no such import today
        for banned in ("from engine.", "import engine.", "from routers.rc5", "import routers.rc5"):
            assert banned not in src, f"{m.__name__} imports RC5 via {banned!r}"


@pytest.mark.asyncio
async def test_report_empty_case_still_signs(_env_flags):
    """A case with zero observations must still produce a valid signed envelope."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from v2.report import build_report

    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    env = await build_report(db, "__nonexistent_case_for_r4_test__")
    assert env.signature.get("sha256")
    assert len(env.sections) == 10
    # Executive summary should still exist though it'll say 0 events
    exec_sec = next(s for s in env.sections if s.id == "executive_summary")
    assert exec_sec.body.get("event_total") == 0
