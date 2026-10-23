"""Bounded no-network regression checks for deprecated Windows installer publication."""
import ast
import copy
from pathlib import Path
from types import SimpleNamespace

BASE = Path(__file__).resolve().parents[3]
ONBOARD = BASE / "backend/routers/edr_onboarding.py"
CATALOG = BASE / "backend/edr_plane/connector/catalog.py"


def _module(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _dict_entry(node, key):
    assert isinstance(node, ast.Dict)
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    raise AssertionError(f"missing {key}")


def test_windows_ps1_catalog_explicitly_ineligible():
    tree = _module(ONBOARD)
    assignment = next(n for n in tree.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "PACKAGES" for t in n.targets))
    legacy = _dict_entry(assignment.value, "windows-x64")
    assert ast.literal_eval(_dict_entry(legacy, "new_endpoint_eligible")) is False
    assert ast.literal_eval(_dict_entry(legacy, "eligibility_reason"))


def test_both_legacy_connector_releases_ineligible():
    tree = _module(CATALOG)
    assignment = next(n for n in tree.body if isinstance(n, ast.AnnAssign)
                      and isinstance(n.target, ast.Name) and n.target.id == "RELEASES")
    rows = assignment.value.elts
    for release_id in ("nvf-connector-windows-0.1.0-x64",
                       "nvf-connector-windows-0.2.0-x64"):
        row = next(row for row in rows
                   if ast.literal_eval(_dict_entry(row, "release_id")) == release_id)
        assert ast.literal_eval(_dict_entry(row, "new_endpoint_eligible")) is False
        assert ast.literal_eval(_dict_entry(row, "eligibility_reason"))


def _describe_fn():
    node = copy.deepcopy(next(n for n in _module(ONBOARD).body
                              if isinstance(n, ast.FunctionDef) and n.name == "_describe"))
    module = ast.Module(body=[ast.ImportFrom(module="__future__",
                                           names=[ast.alias(name="annotations")],
                                           level=0), node], type_ignores=[])
    ctx = {"_sensor_version": lambda _: None,
           "AGENTS_ROOT": "",
           "os": __import__("os"),
           "hashlib": __import__("hashlib"),
           "_SECRET_SHAPES": (),
           "datetime": __import__("datetime").datetime,
           "timezone": __import__("datetime").timezone}
    exec(compile(module, str(ONBOARD), "exec"), ctx)
    return ctx["_describe"]


def test_disabled_windows_package_never_publishes_install_instruction():
    p = {"directory": "none", "files": [], "silent_install": "powershell -File Install.ps1",
         "new_endpoint_eligible": False, "eligibility_reason": "legacy blocked"}
    out = _describe_fn()(p)
    assert out["new_endpoint_eligible"] is False
    assert out["silent_install"] is None
    assert out["install_instruction_withheld_reason"] == "legacy blocked"


def test_eligible_catalog_keeps_existing_instruction_behavior():
    p = {"directory": "none", "files": [], "silent_install": "test-installer.exe install"}
    out = _describe_fn()(p)
    assert out["silent_install"] == "test-installer.exe install"
    assert out["install_instruction_withheld_reason"] is None
