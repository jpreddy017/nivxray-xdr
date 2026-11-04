"""
ICE · Investigation Correlation Engine tests (Rule R21).
"""
from services.ice import correlate, tactic_for


def test_tactic_mapping_covers_execution_and_defense_evasion():
    assert tactic_for("T1059.001") == "execution"
    assert tactic_for("T1059.003") == "execution"
    assert tactic_for("T1564.003") == "defense_evasion"
    assert tactic_for("T1176")     == "persistence"
    assert tactic_for("T1070")     == "defense_evasion"
    # Parent-technique fallback.
    assert tactic_for("T1059.999") == "execution"
    # Unknown → None.
    assert tactic_for("T9999") is None
    assert tactic_for("") is None


def test_correlate_produces_behavior_clusters_and_phases():
    ssot = {
        "mitre": [],
        "document_profile": {"vendor": "eSentire", "title": "Test IR Report"},
        "report_extraction": {
            "commands": [
                {"command": 'cmd /c start /min "" cmd /c timeout 4 & del "x"',
                 "head": "cmd", "purpose": "Self-deletion of stager",
                 "source": "ida.report.command.block[1]"},
                {"command": 'cmd /c start /min "" cmd /c timeout 4 & del "y"',
                 "head": "cmd", "purpose": "Self-deletion of stager",
                 "source": "ida.report.command.block[2]"},
                {"command": "powershell -NoProfile -Command Get-CimInstance Win32_Process",
                 "head": "powershell", "purpose": "PowerShell process enumeration",
                 "source": "ida.report.command.block[3]"},
            ],
            "command_investigations": [
                {"language": "cmd", "lolbins": [{"binary": "cmd.exe"}],
                 "techniques": [{"id": "T1564.003", "name": "Hidden Window"}]},
                {"language": "cmd", "lolbins": [{"binary": "cmd.exe"}],
                 "techniques": [{"id": "T1564.003", "name": "Hidden Window"}]},
                {"language": "powershell", "lolbins": [{"binary": "powershell"}],
                 "techniques": [{"id": "T1057", "name": "Process Discovery"}]},
            ],
            "threat_actors":    [{"name": "UNC6692", "kind": "generic"}],
            "malware_families": [{"name": "Edgecution"}],
            "totals": {"artifacts": 4, "mitre": 0, "cves": 0, "actors": 1,
                        "malware": 1, "commands": 3, "timeline": 0,
                        "yara": 0, "sigma": 0},
        },
    }
    ice = correlate(ssot)

    # Behavior clusters — 2 unique purposes, both with high confidence.
    clusters = ice["behavior_clusters"]
    assert len(clusters) == 2
    self_del = next(c for c in clusters if c["label"] == "Self-deletion of stager")
    assert self_del["command_count"]  == 2
    assert self_del["primary_tactic"] == "defense_evasion"
    assert self_del["confidence"]     == "high"
    assert "cmd.exe" in self_del["lolbins"]

    # Attack phases — kill-chain ordered, defense_evasion + discovery.
    phases = ice["attack_phases"]
    tactics = [p["tactic"] for p in phases]
    assert "defense_evasion" in tactics
    assert "discovery" in tactics
    # defense_evasion must precede discovery in canonical kill-chain.
    assert tactics.index("defense_evasion") < tactics.index("discovery")

    # MITRE matrix
    tids = {m["id"] for m in ice["mitre_matrix"]}
    assert "T1564.003" in tids
    assert "T1057"     in tids
    # Every entry has a tactic + source.
    for m in ice["mitre_matrix"]:
        assert m["tactic"] in {"defense_evasion", "discovery"}
        assert m["source"] == "command"

    # Timeline: 3 execution steps (article_timeline is empty in this fixture)
    tl = ice["timeline"]
    assert len(tl) == 3
    assert tl[0]["kind"] == "execution"
    assert tl[0]["step"] == 1

    # Incident graph — root + actor + malware + 2 clusters + 4 edges.
    graph = ice["incident_graph"]
    node_kinds = [n["kind"] for n in graph["nodes"]]
    assert "incident" in node_kinds
    assert "actor"    in node_kinds
    assert "malware"  in node_kinds
    assert node_kinds.count("behavior") == 2
    assert len(graph["edges"]) >= 4

    # Evidence completeness surface — never crashes on partial data.
    ec = ice["evidence_completeness"]
    dims = {d["dim"]: d["state"] for d in ec["dimensions"]}
    assert dims["Commands"] == "complete"
    assert dims["YARA"]     == "missing"
    assert 0 <= ec["overall_percent"] <= 100

    # ── ICE v2 additions (now nested under incident.summary in v3) ──
    incident = ice["incident"]["summary"]
    assert incident["actor"] == "UNC6692"
    assert "Edgecution" in incident["malware"]
    assert incident["severity"] in ("low", "medium", "high", "critical")
    assert 0 <= incident["confidence_percent"] <= 100
    assert incident["status"] == "under_investigation"

    ready = ice["investigation_readiness"]
    bar_dims = {b["dim"] for b in ready["bars"]}
    assert {"Commands", "IOCs", "Behaviors", "Timeline",
             "Network", "Memory", "EDR", "Report"}.issubset(bar_dims)
    assert 0 <= ready["overall_percent"] <= 100
    assert ready["recommended_next"], "readiness must always recommend a next step"

    assert len(ice["investigation_gaps"]) >= 2
    for gap in ice["investigation_gaps"]:
        assert gap["dim"] and gap["reason"] and gap["action"]

    assert len(ice["recommended_actions"]) >= 1
    prios = {a["priority"] for a in ice["recommended_actions"]}
    assert "P1" in prios, "highest-priority action must exist"

    # ── ICE v3 · Unified Incident SSOT ──
    incident_ssot = ice["incident"]
    assert isinstance(incident_ssot, dict)
    # Every projection-relevant slice must live under `incident`.
    for key in ("summary", "behaviors", "phases", "mitre", "timeline",
                 "graph", "evidence", "completeness", "readiness",
                 "gaps", "recommendations", "provenance"):
        assert key in incident_ssot, f"incident missing `{key}`"
    # Provenance envelope.
    assert set(incident_ssot["provenance"].keys()) >= {
        "source_url", "source_vendor", "source_title"}
    # Evidence Strength on every behavior cluster.
    for b in incident_ssot["behaviors"]:
        assert b["evidence_strength"] in ("strong", "moderate", "weak"), b
        assert isinstance(b["evidence_sources"], list)


def test_correlate_empty_investigation_is_safe():
    """Correlator on a non-URL / plain-text investigation must return
    empty structures without crashing."""
    ice = correlate({"report_extraction": {}})
    assert ice["behavior_clusters"] == []
    assert ice["attack_phases"]     == []
    assert ice["timeline"]          == []
