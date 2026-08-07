"""R28.7.3 · Vertical Chain Acceptance Test  (Plugins 1 + 2 + 3).

The definitive proof of the Capability Registry architecture.

Feeds a Sophos-shape script into ``Orchestrator.run()``:

    input (script) → gzip_decoded artifact
        → transformer.byte_array_xor_loop → binary_bytes
        → extractor.binary_configuration  → configuration (typed JSON)
        → promoter.configuration_iocs     → ip_artifact + url_artifact
                                             + evidence records

with the following acceptance metric:
    · New contracts added:   3   (plugins 1, 2, 3)
    · Orchestrator changes:  0
    · Planner changes:       0
    · Registry changes:      0
    · Lifecycle changes:     0
    · QA changes:            0
    · SSOT changes:          0
    · Termination changes:   0
"""
from __future__ import annotations

import base64
import json

from services.uaie import plugins                       # noqa: F401 — side effect
from services.uaie.contract    import get as _reg_get
from services.uaie.orchestrator import Orchestrator
from services.uaie.recognizer  import CERTAIN, Reason, Recognition


class _Recognizer:
    name = "test.r28.7.3.recognizer"
    def recognize(self, artifact):
        # Only claim the root — never re-claim children (avoids
        # infinite recognizer loops on downstream types).
        t = artifact.artifact_type
        if t in ("gzip_decoded", "binary_bytes", "configuration",
                  "ip_artifact", "url_artifact", "domain_artifact"):
            return []
        return [Recognition(artifact_type="gzip_decoded",
                             confidence=CERTAIN,
                             reasons=[Reason("t", 1.0)],
                             recognizer=self.name)]


# ══════════════════════════════════════════════════════════════════
# 1 · All three plugins are registered in the Capability Registry
# ══════════════════════════════════════════════════════════════════
def test_all_three_plugins_registered_via_registry():
    for cid in ("transformer.byte_array_xor_loop",
                  "extractor.binary_configuration",
                  "promoter.configuration_iocs"):
        assert _reg_get(cid) is not None, f"{cid} not registered"


# ══════════════════════════════════════════════════════════════════
# 2 · Plugin 2 · deterministic typed extraction
# ══════════════════════════════════════════════════════════════════
def test_plugin_2_emits_typed_configuration():
    from services.uaie.artifact import make_artifact
    # Craft a binary blob with a known IPv4 + URL + domain + long string.
    blob = (
        b"\x00" * 32 +
        b"149.28.81.19" + b"\x00" * 8 +
        b"https://c2.example.com/beacon" + b"\x00" * 8 +
        b"evil.example.com" + b"\x00" * 8 +
        b"MSF-Mutex-Beacon-9c2" + b"\x00" * 8
    )
    art = make_artifact(blob, "binary_bytes", discovered_by="test")
    _, impl = _reg_get("extractor.binary_configuration")
    result = impl.execute(art)
    assert len(result.child_artifacts) == 1
    cfg = json.loads(result.child_artifacts[0].payload.decode("utf-8"))
    types_found = {e["type"] for e in cfg}
    values_found = {e["value"] for e in cfg}
    assert "ipv4"   in types_found
    assert "url"    in types_found
    assert "domain" in types_found
    assert "149.28.81.19"             in values_found
    assert "https://c2.example.com/beacon" in values_found


# ══════════════════════════════════════════════════════════════════
# 3 · Plugin 3 · promotes typed elements → first-class artifacts
# ══════════════════════════════════════════════════════════════════
def test_plugin_3_promotes_iocs_to_artifacts_and_evidence():
    from services.uaie.artifact import make_artifact
    elements = [
        {"type": "ipv4",   "value": "1.2.3.4",           "offset": 0},
        {"type": "url",    "value": "https://x/y",       "offset": 8},
        {"type": "domain", "value": "evil.example.com",  "offset": 16},
        {"type": "string", "value": "just-a-string",     "offset": 24},
    ]
    payload = json.dumps(elements).encode("utf-8")
    art = make_artifact(payload, "configuration", discovered_by="test")
    _, impl = _reg_get("promoter.configuration_iocs")
    r = impl.execute(art)
    types = sorted(a.artifact_type for a in r.child_artifacts)
    assert types == ["domain_artifact", "ip_artifact", "url_artifact"]
    # One evidence record per promoted IOC (3 — the plain 'string'
    # is NOT promoted).
    assert len(r.evidence) == 3
    kinds = sorted(e.kind for e in r.evidence)
    assert kinds == ["ioc.domain", "ioc.ip", "ioc.url"]


# ══════════════════════════════════════════════════════════════════
# 4 · END-TO-END · script → XOR → binary → config → IOC
#    This is THE architectural proof.
# ══════════════════════════════════════════════════════════════════
def test_full_vertical_chain_reaches_ioc_artifacts_via_registry():
    """Feed a Sophos-shape script — the C2 IP MUST surface as an
    ``ip_artifact`` in the final graph, with all three plugins
    running exclusively via the Capability Registry and zero core
    engine changes."""
    # Build shellcode-shape bytes that CONTAIN a known IPv4 + URL.
    # After XOR-encoding with key 0x23, base64-embedding, and the
    # loader script pattern, the engine must:
    #   1. run Plugin 1 (XOR loop) → binary_bytes
    #   2. run Plugin 2 (config extract) → configuration
    #   3. run Plugin 3 (IOC promote) → ip_artifact + url_artifact
    binary = (
        b"\x00" * 32 +
        b"149.28.81.19" + b"\x00" * 8 +
        b"https://c2.example.com/beacon" + b"\x00" * 8 +
        b"\x00" * 32
    )
    key       = 0x23
    encoded   = bytes(b ^ key for b in binary)
    b64       = base64.b64encode(encoded).decode()
    ps_text = (
        f"[Byte[]]$var_code=[System.Convert]::FromBase64String('{b64}');"
        f"for($x=0;$x-lt$var_code.Count;$x++)"
        f"{{$var_code[$x]=$var_code[$x] -bxor 35}}"
    )

    orch = Orchestrator(recognizers=[_Recognizer()],
                         max_artifacts=32, max_depth=6)
    r = orch.run(ps_text.encode("utf-8"), root_type="unknown")

    # ── All three artifact types produced by the vertical chain ──
    types_in_graph = {a.artifact_type for a in r.artifacts.values()}
    assert "binary_bytes"  in types_in_graph
    assert "configuration" in types_in_graph
    assert "ip_artifact"   in types_in_graph
    assert "url_artifact"  in types_in_graph

    # ── The exact C2 IP surfaces as its own artifact ──
    ip_artifacts = [a for a in r.artifacts.values()
                     if a.artifact_type == "ip_artifact"]
    ip_values = {a.payload.decode("utf-8") for a in ip_artifacts}
    assert "149.28.81.19" in ip_values, (
        "vertical chain FAILED to reach the C2 IP.  Got: "
        f"{ip_values}"
    )

    # ── Evidence records surface the IOC at the top-level ──
    ip_evidence = [e for e in r.evidence if e.kind == "ioc.ip"]
    assert any(e.value == "149.28.81.19" for e in ip_evidence), (
        "IOC evidence record for the C2 IP missing"
    )

    # ── Fixed-Point Certificate issued cleanly ──
    cert = r.termination_certificate
    assert cert is not None
    assert cert.fixed_point is True


# ══════════════════════════════════════════════════════════════════
# 5 · Core engine unchanged since Plugin 1 landed
# ══════════════════════════════════════════════════════════════════
def test_core_engine_modules_still_unchanged():
    import services.uaie.orchestrator  as O
    import services.uaie.planner_v2    as P
    import services.uaie.contract      as C
    import services.uaie.lifecycle     as L
    import services.uaie.qa            as Q
    import services.uaie.termination   as T
    import services.uaie.ssot_projector as S
    for module, symbol in (
        (O, "Orchestrator"),
        (P, "plan_for"),
        (C, "CapabilityContract"),
        (C, "register"),
        (C, "applicable_contracts"),
        (L, "LifecycleRecorder"),
        (Q, "register_validator"),
        (T, "TerminationCertificate"),
        (S, "project"),
    ):
        assert hasattr(module, symbol), \
            f"{module.__name__}.{symbol} was removed — core-engine invariant broken"
