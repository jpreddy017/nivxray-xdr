"""Phase 4 · Common fixtures for projection tests.

All fixtures return AuthoritativeSSOT instances built purely from
in-memory data — no clock, no random, no I/O (P4-FW1).
"""
from __future__ import annotations

from typing import List

import pytest

from canonical.ssot import (
    AuthoritativeSSOT,
    GraphNode,
    GraphEdge,
    Provenance,
    ReasoningStep,
    ExecutionStep,
    Artifact,
    Source,
)


PROV = Provenance(engine="test.phase4",
                  version="1.0.0-phase4",
                  at="phase4-test")


def _base_ssot(sid: str = "phase4-fixture") -> AuthoritativeSSOT:
    return AuthoritativeSSOT(
        id=sid,
        source=Source(surface="test", endpoint="/test",
                      correlation_id=sid, channel="phase4"),
        input_raw=b"",
        input_profile={"primary_type": "text", "encoding": "utf-8"},
        input_health={"ok": True, "size_bytes": 42},
        provenance=PROV,
    )


# ── SSOT #1 · empty (no evidence at all) ────────────────────────────────
@pytest.fixture
def ssot_empty() -> AuthoritativeSSOT:
    s = _base_ssot("empty")
    s.freeze()
    return s


# ── SSOT #2 · MITRE-rich ────────────────────────────────────────────────
@pytest.fixture
def ssot_mitre() -> AuthoritativeSSOT:
    s = _base_ssot("mitre")
    s.append("evidence_graph.nodes",
             GraphNode(id="ev.health.root", kind="input_health",
                       label="ok", attrs={"ok": True, "size_bytes": 42}),
             PROV)
    for tid, matched in [("T1059.001", ["powershell", "-encodedcommand"]),
                         ("T1218.010", ["regsvr32"])]:
        s.append("evidence_graph.nodes",
                 GraphNode(id=f"ev.mitre.{tid}", kind="mitre_technique",
                           label=f"{tid}: {tid}",
                           attrs={"technique_id": tid, "matched": matched}),
                 PROV)
        s.append("reasoning_steps",
                 ReasoningStep(id=f"rs.mitre.{tid}",
                               rule="mitre.deterministic_needle_match",
                               rationale=f"{tid} matched: {matched}"),
                 PROV)
    s.append("execution_trace",
             ExecutionStep(step_id="exec.mitre_map",
                           capability="MITRE_MAP",
                           engine="canonical.executor.capabilities",
                           status="executed"),
             PROV)
    s.freeze()
    return s


# ── SSOT #3 · IOC-heavy, no MITRE ───────────────────────────────────────
@pytest.fixture
def ssot_iocs_only() -> AuthoritativeSSOT:
    s = _base_ssot("iocs")
    s.append("evidence_graph.nodes",
             GraphNode(id="ev.ioc.url.0000", kind="ioc",
                       label="http://evil.com/x",
                       attrs={"ioc_kind": "url"}), PROV)
    s.append("evidence_graph.nodes",
             GraphNode(id="ev.ioc.url.0001", kind="ioc",
                       label="http://c2.example/beacon",
                       attrs={"ioc_kind": "url"}), PROV)
    s.append("evidence_graph.nodes",
             GraphNode(id="ev.ioc.ip.0000", kind="ioc",
                       label="1.2.3.4", attrs={"ioc_kind": "ip"}), PROV)
    s.append("evidence_graph.nodes",
             GraphNode(id="ev.ioc.md5.0000", kind="ioc",
                       label="44d88612fea8a8f36de82e1278abb02f",
                       attrs={"ioc_kind": "md5"}), PROV)
    s.append("execution_trace",
             ExecutionStep(step_id="exec.ioc_extractor",
                           capability="IOC_EXTRACTOR",
                           engine="canonical.executor.capabilities",
                           status="executed"), PROV)
    s.freeze()
    return s


# ── SSOT #4 · commands + LOLBAS ─────────────────────────────────────────
@pytest.fixture
def ssot_commands() -> AuthoritativeSSOT:
    s = _base_ssot("commands")
    for i, (tool, cmd) in enumerate([
        ("powershell", "powershell -EncodedCommand SGVsbG8="),
        ("cmd",        "cmd /c whoami"),
        ("wmic",       "wmic process where name='foo.exe' delete"),
    ]):
        s.append("evidence_graph.nodes",
                 GraphNode(id=f"ev.cmd.{i:04d}", kind="command",
                           label=cmd, attrs={"tool": tool}), PROV)
    s.append("execution_trace",
             ExecutionStep(step_id="exec.command_detect",
                           capability="COMMAND_DETECT",
                           engine="canonical.executor.capabilities",
                           status="executed"), PROV)
    s.freeze()
    return s


# ── SSOT #5 · rich mixed evidence (MITRE + IOC + commands + artifacts) ──
@pytest.fixture
def ssot_rich() -> AuthoritativeSSOT:
    s = _base_ssot("rich")
    s.append("evidence_graph.nodes",
             GraphNode(id="ev.health.root", kind="input_health",
                       label="ok",
                       attrs={"ok": True, "size_bytes": 4096}),
             PROV)
    # MITRE
    for tid, matched in [("T1059.001", ["powershell"]),
                         ("T1218.010", ["regsvr32"]),
                         ("T1105",     ["certutil -urlcache"])]:
        s.append("evidence_graph.nodes",
                 GraphNode(id=f"ev.mitre.{tid}", kind="mitre_technique",
                           label=f"{tid}: {tid}",
                           attrs={"technique_id": tid, "matched": matched}),
                 PROV)
        s.append("reasoning_steps",
                 ReasoningStep(id=f"rs.mitre.{tid}",
                               rule="mitre.deterministic_needle_match",
                               rationale=f"{tid} matched: {matched}"),
                 PROV)
    # IOCs
    s.append("evidence_graph.nodes",
             GraphNode(id="ev.ioc.url.0000", kind="ioc",
                       label="http://x.example",
                       attrs={"ioc_kind": "url"}), PROV)
    s.append("evidence_graph.nodes",
             GraphNode(id="ev.ioc.sha256.0000", kind="ioc",
                       label="a" * 64, attrs={"ioc_kind": "sha256"}), PROV)
    # Commands
    for i, (tool, cmd) in enumerate([("powershell", "powershell -e SGVsbG8="),
                                     ("certutil",  "certutil -urlcache -f http://x")]):
        s.append("evidence_graph.nodes",
                 GraphNode(id=f"ev.cmd.{i:04d}", kind="command",
                           label=cmd, attrs={"tool": tool}), PROV)
    # Artifacts
    s.append("artifacts",
             Artifact(id="ev.archive.0000", kind="archive_member",
                      label="word/document.xml",
                      attrs={"size_bytes": 512}), PROV)
    # Edge
    s.append("evidence_graph.edges",
             GraphEdge(id="e.0000",
                       from_node_id="ev.mitre.T1059.001",
                       to_node_id="ev.cmd.0000", kind="evidences"),
             PROV)
    # Execution trace
    for cap in ("INPUT_HEALTH", "IOC_EXTRACTOR", "COMMAND_DETECT",
                "MITRE_MAP"):
        s.append("execution_trace",
                 ExecutionStep(step_id=f"exec.{cap.lower()}",
                               capability=cap,
                               engine="canonical.executor.capabilities",
                               status="executed"), PROV)
    s.freeze()
    return s
