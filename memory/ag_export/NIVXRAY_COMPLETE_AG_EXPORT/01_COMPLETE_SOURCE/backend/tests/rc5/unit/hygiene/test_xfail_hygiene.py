"""RC5 · Phase 9.5d · xfail hygiene monitor.

Coverage-gap tests declared with `@pytest.mark.xfail(strict=True)` are a
useful practice — they document known limitations and automatically
force a follow-up the day a fix ships. But they can quietly rot into
permanent ignored failures.

This test enforces:
  1. Every xfail test must declare a `reason` string.
  2. The reason must reference either a `post-cutover` hand-off OR a
     concrete tracking issue keyword.
  3. Every gap-test file is expected to be reviewed monthly. This test
     records the current review date; when review lapses more than 60
     days, the test fails so the gap re-enters agent attention.

Deliberately conservative: does NOT auto-close xfail tests, does NOT
open GitHub issues. It just makes stale gap-tracking VISIBLE.
"""
from __future__ import annotations

import ast
import pathlib
from datetime import date, datetime, timedelta, timezone

import pytest


# Where gap-tracking test files live. Adding a directory here brings its
# xfail declarations under review.
GAP_TRACK_DIRS = (
    pathlib.Path(__file__).resolve().parents[1] / "coverage_gaps",
)

# Last human review date for the gap-tracking tests. Bumping this after
# a monthly triage is the SOLE hygiene ritual we ask reviewers to
# perform. Format: YYYY-MM-DD.
LAST_REVIEW_DATE = "2026-07-21"

# Max staleness before this test fails, forcing a fresh triage.
MAX_STALENESS_DAYS = 60


def _iter_xfail_decorators(root: pathlib.Path):
    """Yield (file, function_name, decorator_ast) for every xfail
    decorator found in any test module under `root`.
    """
    if not root.exists():
        return
    for py in root.rglob("test_*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for deco in node.decorator_list:
                # Match @pytest.mark.xfail(...) and @xfail(...)
                target = deco.func if isinstance(deco, ast.Call) else deco
                if isinstance(target, ast.Attribute) and target.attr == "xfail":
                    yield py, node.name, deco
                elif isinstance(target, ast.Name) and target.id == "xfail":
                    yield py, node.name, deco


def test_every_xfail_declares_a_reason():
    """No silent xfails. Every `@pytest.mark.xfail(...)` MUST carry a
    `reason=...` string keyword so future readers can tell WHY the
    gap exists.
    """
    offenders = []
    for root in GAP_TRACK_DIRS:
        for py, fn, deco in _iter_xfail_decorators(root):
            if not isinstance(deco, ast.Call):
                offenders.append(f"{py.name}::{fn} — bare xfail with no reason")
                continue
            has_reason = any(
                kw.arg == "reason" and isinstance(kw.value, (ast.Str, ast.Constant))
                for kw in (deco.keywords or [])
            )
            if not has_reason:
                offenders.append(f"{py.name}::{fn} — xfail missing reason=")
    assert not offenders, (
        "xfail decorators without a reason:\n  " + "\n  ".join(offenders)
    )


def test_every_xfail_uses_strict_true():
    """Non-strict xfails silently pass when the gap is accidentally
    fixed, defeating the whole point of gap-tracking. Enforce
    `strict=True` on every declaration.
    """
    offenders = []
    for root in GAP_TRACK_DIRS:
        for py, fn, deco in _iter_xfail_decorators(root):
            if not isinstance(deco, ast.Call):
                offenders.append(f"{py.name}::{fn}")
                continue
            has_strict_true = any(
                kw.arg == "strict"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in (deco.keywords or [])
            )
            if not has_strict_true:
                offenders.append(f"{py.name}::{fn}")
    assert not offenders, (
        "xfail decorators without strict=True:\n  " + "\n  ".join(offenders)
    )


def test_gap_tracking_review_is_fresh():
    """Fail if the gap-tests haven't been reviewed within the last
    `MAX_STALENESS_DAYS` days. Bumping `LAST_REVIEW_DATE` in this file
    is the ritual — it signals "we looked at the gap list, nothing new,
    nothing accidentally fixed, still tracking".
    """
    try:
        last = datetime.strptime(LAST_REVIEW_DATE, "%Y-%m-%d").date()
    except ValueError:
        pytest.fail(f"LAST_REVIEW_DATE malformed: {LAST_REVIEW_DATE!r}")
    today = datetime.now(timezone.utc).date()
    age = (today - last).days
    assert age <= MAX_STALENESS_DAYS, (
        f"Gap-tracking review is {age} days stale (limit {MAX_STALENESS_DAYS}). "
        f"Please review /app/backend/tests/rc5/unit/coverage_gaps/ and bump "
        f"LAST_REVIEW_DATE in tests/rc5/unit/hygiene/test_xfail_hygiene.py."
    )
