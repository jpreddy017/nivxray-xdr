"""Execute the real deployment route body with instrumented authority and token boundaries.

No live backend, database, endpoint or token is used.
"""
import ast
import asyncio
import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[3] / "backend/routers/edr_connector.py"


class Refused(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail


def _route_for(release_id, *, authorize=True):
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
    fn = copy.deepcopy(next(n for n in tree.body
                            if isinstance(n, ast.AsyncFunctionDef)
                            and n.name == "create_deployment"))
    fn.decorator_list = []
    module = ast.Module(body=[ast.ImportFrom(module="__future__",
                                            names=[ast.alias(name="annotations")], level=0),
                              fn], type_ignores=[])
    calls = []
    def scope(t, user):
        calls.append("tenant_auth")
        if not authorize:
            raise Refused(403, {"code": "TENANT_FORBIDDEN"})
        return t
    def mint(*args, **kwargs):
        calls.append("mint")
        raise AssertionError("Token generation MUST NOT be reached")
    class NoDB:
        def __getitem__(self, key):
            calls.append("db")
            raise AssertionError("No database side effect allowed")
    releases = {
        "nvf-connector-windows-0.1.0-x64":
            {"artifact_state": "PUBLISHED", "new_endpoint_eligible": False,
             "eligibility_reason": "retired PowerShell"},
        "nvf-connector-windows-0.2.0-x64":
            {"artifact_state": "PUBLISHED", "new_endpoint_eligible": False,
             "eligibility_reason": "retired PowerShell"},
    }
    ctx = {
        "releases": SimpleNamespace(post=lambda _: lambda fn: fn),
        "Request": object,
        "CreateDeploymentBody": object,
        "get_current_user": lambda: None, "edr_tenant": lambda: None,
        "Depends": lambda x: x,
        "_scoped": scope,
        "catalog": SimpleNamespace(
            get=lambda k: releases.get(k),
            ARTIFACT_PUBLISHED="PUBLISHED"),
        "HTTPException": Refused,
        "_db": NoDB(),
        "enrollment_store": SimpleNamespace(mint_enrollment_token=mint),
    }
    exec(compile(ast.fix_missing_locations(module), str(SOURCE), "exec"), ctx)
    body = SimpleNamespace(release_id=release_id, group_id="g1")
    return ctx["create_deployment"], body, calls


@pytest.mark.parametrize("release_id", [
    "nvf-connector-windows-0.1.0-x64",
    "nvf-connector-windows-0.2.0-x64",
])
def test_ineligible_release_rejected_before_token_or_database(release_id):
    fn, body, calls = _route_for(release_id)
    with pytest.raises(Refused) as ex:
        asyncio.run(fn(body, None, {}, "ten_test"))
    assert ex.value.status_code == 409
    assert ex.value.detail["code"] == "NEW_ENDPOINT_NOT_ELIGIBLE"
    assert calls == ["tenant_auth"]


@pytest.mark.parametrize("release_id", [
    "nvf-connector-windows-0.1.0-x64",
    "nvf-connector-windows-0.2.0-x64",
])
def test_authentication_cannot_be_masked_by_ineligible_release(release_id):
    fn, body, calls = _route_for(release_id, authorize=False)
    with pytest.raises(Refused) as ex:
        asyncio.run(fn(body, None, {}, "ten_wrong"))
    assert ex.value.status_code == 403
    assert calls == ["tenant_auth"]
