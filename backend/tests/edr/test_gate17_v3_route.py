"""GATE 17 · the production EDR route must resolve to the EXACT E3 V3 Device Trajectory.

Static source gates. They cannot prove a browser rendered anything — the browser proof is a
separate automated UI gate — but they DO prove the only things a screenshot cannot: that the
route, the flag and the component chain all name the exact handoff implementation, that no
look-alike trajectory has been substituted, and that V3 is enabled for the integration build
WITHOUT touching production environment configuration.
"""
from __future__ import annotations

import re
from pathlib import Path

APP = Path(__file__).resolve().parents[3] / "apps" / "nivxray-xdr"
SRC = APP / "src"
V3 = SRC / "nivxforge" / "trajectory_v3"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def test_the_edr_route_points_at_the_flag_gateway():
    app = _read(SRC / "App.jsx")
    assert re.search(r'path="/edr/device-trajectory"\s+element=\{<Protected><DeviceTrajectoryEntry', app), \
        "the production EDR route must stay on the flag gateway inside nivxforge/"
    assert 'import("@/nivxforge/trajectory_amp/DeviceTrajectoryEntry")' in app


def test_the_gateway_resolves_the_exact_v3_implementation():
    entry = _read(SRC / "nivxforge" / "trajectory_amp" / "DeviceTrajectoryEntry.jsx")
    assert "E3_DT_V3" in entry
    assert "trajectory_v3/DeviceTrajectoryPage" in entry, \
        "V3 must resolve to the handoff page, not to a look-alike"
    page = _read(V3 / "DeviceTrajectoryPage.jsx")
    assert './amp/TrajectoryPage' in page


def test_the_v3_surface_carries_its_own_test_id():
    assert 'data-testid="v3-page"' in _read(V3 / "amp" / "TrajectoryPage.jsx"), \
        "the browser gate asserts this id; it must exist in the V3 source"


def test_v3_is_enabled_for_the_integration_build_only():
    dev = _read(APP / ".env.development")
    assert "VITE_E3_DT_V3=1" in dev
    # Production configuration must NOT be changed by the activation gate.
    assert "VITE_E3_DT_V3" not in _read(APP / ".env")
    prod = APP / ".env.production"
    if prod.exists():
        assert "VITE_E3_DT_V3" not in _read(prod)


def test_the_activation_flag_is_version_controlled():
    """`.gitignore` excludes `.env.*`, so this file had to be force-added.

    Without it the flag lives only on one machine: a fresh clone would build the LEGACY
    trajectory while every gate still reported V3 active. The file carries a build flag and no
    credential, which is why force-adding it is safe — asserted here so it stays that way.
    """
    import subprocess
    tracked = subprocess.run(["git", "ls-files", "--error-unmatch",
                              "apps/nivxray-xdr/.env.development"],
                             cwd="/app", capture_output=True, text=True)
    assert tracked.returncode == 0, (
        "the V3 activation flag must be in version control or the integration build is not "
        "reproducible: " + tracked.stderr)
    body = _read(APP / ".env.development").strip().splitlines()
    assert body == ["VITE_E3_DT_V3=1"], (
        "this file is force-added past .gitignore, so it must never hold anything but the "
        "build flag: " + repr(body))


def test_v3_consumes_the_production_v3_contract_key():
    page = _read(V3 / "amp" / "TrajectoryPage.jsx")
    assert "d.v3 || d" in page, \
        "V3 must read the additive production `v3` presentation contract"


def test_v3_actions_use_the_e1_durable_response_authority():
    page = _read(V3 / "amp" / "TrajectoryPage.jsx")
    assert "/edr/response/actions" in page
    assert "/e3/trajectory/approvals" not in page, \
        "the in-memory E3 preview approval store must never be a production dependency"
    assert "ISOLATE_ENDPOINT" in page and "RELEASE_ISOLATION" in page, \
        "V3's action vocabulary must map onto the actions E1 actually implements"


def test_v3_does_not_label_production_evidence_as_synthetic():
    page = _read(V3 / "amp" / "TrajectoryPage.jsx")
    assert "Production evidence (read-only)" in page
    # A page that read NOTHING must not assert a data source. The preview default claimed
    # "Synthetic data" for an empty/refused read, which is a claim the UI cannot support.
    assert '"No data read"' in page
    assert '"Data source not declared"' in page


def test_no_v3_component_imports_a_preview_or_fixture_module():
    forbidden = ("e1_shape_preview", "kushu_import", "platform_seed", "preview_mount",
                 "e3shell", "e3ui-harness", "/fixtures")
    for f in V3.rglob("*.js*"):
        src = _read(f)
        for token in forbidden:
            assert token not in src, f"{f.name} reaches preview infrastructure via {token}"
