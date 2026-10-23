"""Portable tests for the Windows installer's pre-mutation enrollment preflight.

Import only the exact function AST so the tests do not need Windows SCM,
privileged APIs, credentials, or a service. Separate Windows-native acceptance
remains mandatory.
"""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = (
    Path(__file__).resolve().parents[3]
    / "agents" / "nivxforge-windows" / "nivxforge_setup.py"
)


def _tree():
    return ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))


def _preflight(*, existing, validation_error=None):
    node = next(
        n for n in _tree().body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == "_preflight_install_enrolment"
    )
    calls = []
    def validate():
        calls.append("validate")
        if validation_error:
            raise SystemExit(validation_error)
    def tenant(value):
        calls.append(("tenant", value))
        if not value:
            raise SystemExit("no tenant")
        return value
    context = {
        "sensor": SimpleNamespace(
            IDENTITY_FILE=SimpleNamespace(exists=lambda: existing),
            STDIN_ONLY_NOTICE="secret required on stdin",
        ),
        "_validate_identity": validate,
        "_assert_tenant": tenant,
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), "exec"), context)
    return context["_preflight_install_enrolment"], calls


def test_invalid_existing_identity_is_refused_before_mutation():
    preflight, calls = _preflight(existing=True, validation_error="bad identity")
    with pytest.raises(SystemExit, match="bad identity"):
        preflight(None, False, False)
    assert calls == ["validate"]


def test_existing_valid_identity_can_resume_without_new_token():
    preflight, calls = _preflight(existing=True)
    preflight(None, False, False)
    assert calls == ["validate"]


def test_new_install_missing_token_is_refused():
    preflight, calls = _preflight(existing=False)
    with pytest.raises(SystemExit, match="token-stdin is required"):
        preflight("ten_lab1", False, False)
    assert calls == [("tenant", "ten_lab1")]


def test_new_install_rejects_missing_tenant():
    preflight, calls = _preflight(existing=False)
    with pytest.raises(SystemExit, match="no tenant"):
        preflight(None, True, False)
    assert calls == [("tenant", "")]


def test_new_install_with_token_and_tenant_passes_preflight():
    preflight, calls = _preflight(existing=False)
    preflight("ten_lab1", True, False)
    assert calls == [("tenant", "ten_lab1")]


def test_reenrollment_does_not_bypass_token_preflight():
    preflight, calls = _preflight(existing=True)
    with pytest.raises(SystemExit, match="token-stdin is required"):
        preflight("ten_lab1", False, True)
    assert calls == [("tenant", "ten_lab1")]


def test_install_calls_preflight_before_admin_and_mutations():
    install = next(
        n for n in _tree().body
        if isinstance(n, ast.FunctionDef) and n.name == "install"
    )
    call_order = [
        n.value.func.id for n in install.body
        if isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Call)
        and isinstance(n.value.func, ast.Name)
    ]
    assert "_preflight_install_enrolment" in call_order
    assert "_assert_admin" in call_order
    assert call_order.index("_preflight_install_enrolment") < call_order.index("_assert_admin")
    assert call_order.index("_assert_admin") < call_order.index("print")
