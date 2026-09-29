"""R1/R2 · ONE canonical event identifier minting authority.

The defect this pins: two planes derived the canonical id of the SAME raw
event by different rules, so a detection and its evidence disagreed about
the name of one event and the primary join always missed.

What must hold now:

* `canonical_bridge.canonical_event_id()` is the ONLY minting function;
* the replay generation is part of the identity;
* the detection plane CARRIES the authority's value (from the canonical
  evidence, or from the authenticated ingest envelope) and never composes
  its own string;
* the legacy `_pl` form is never minted again — it survives only as a
  READ fallback, which is proven in `test_c2_evidence_resolution.py`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, "/app/backend")

from detection_content.telemetry.nivxforge_sensor_dsm import (  # noqa: E402
    NivXForgeSensorDSM, NivXForgeSensorNormalizer)
from edr_plane import canonical_bridge as cb                    # noqa: E402

RAW = "raw_f58e793a0dd70af63aa55d24"
SENSOR_EVENT = {"activity": "PROCESS", "collection_method": "PROC_POLL",
                "sensor_version": "0.1.0", "observed_at": "2026-06-01T10:00:00Z",
                "pid": 4242, "ppid": 1, "image": "curl",
                "image_path": "/usr/bin/curl", "command_line": "curl http://x",
                "start_ticks": 99}


def _normalized(raw_event: dict, trace_id: str = RAW) -> dict:
    dsm = NivXForgeSensorDSM()
    parsed = dsm.select_parser().parse(raw_event)
    return NivXForgeSensorNormalizer().normalize(
        parsed, trace_id=trace_id, tenant_id="ten_c1")


# ── A · the minting function IS the authority ──────────────────────

def test_authority_strips_the_raw_prefix_and_keeps_the_generation():
    assert cb.canonical_event_id(RAW, 0) == \
        "cev_f58e793a0dd70af63aa55d24_0"
    assert cb.canonical_event_id(RAW, 3) == \
        "cev_f58e793a0dd70af63aa55d24_3"


def test_generation_is_part_of_the_identity():
    # A replayed event is a DIFFERENT canonical event. A reference that
    # dropped the generation could not tell them apart.
    assert cb.canonical_event_id(RAW, 0) != cb.canonical_event_id(RAW, 1)


def test_an_id_without_a_raw_event_is_refused():
    with pytest.raises(ValueError):
        cb.canonical_event_id("", 0)


def test_a_raw_id_without_the_prefix_is_accepted_verbatim():
    assert cb.canonical_event_id("f58e", 2) == "cev_f58e_2"


def test_the_authority_is_named_so_consumers_can_declare_their_source():
    assert cb.CANONICAL_EVENT_ID_AUTHORITY == \
        "edr_plane.canonical_bridge.canonical_event_id"


# ── B · the `_pl` scheme is no longer MINTED anywhere ──────────────

def test_no_plane_composes_a_pl_canonical_id_any_more():
    dsm_source = Path(
        "/app/backend/detection_content/telemetry/nivxforge_sensor_dsm.py"
    ).read_text()
    assert '_pl"' not in dsm_source
    assert "cev_{trace_id}" not in dsm_source


def test_the_bridge_holds_the_only_cev_format_string():
    source = Path("/app/backend/edr_plane/canonical_bridge.py").read_text()
    # Exactly one place composes the identifier: the authority itself.
    assert source.count('f"cev_') == 1


# ── C · the detection plane CARRIES, never re-derives ──────────────

def test_an_id_already_on_the_canonical_evidence_is_carried_unchanged():
    dsm = NivXForgeSensorDSM()
    parsed = dsm.select_parser().parse(dict(SENSOR_EVENT))
    parsed["canonical"]["event_id"] = cb.canonical_event_id(RAW, 7)
    canonical = NivXForgeSensorNormalizer().normalize(
        parsed, trace_id=RAW, tenant_id="ten_c1")
    assert canonical["event_id"] == "cev_f58e793a0dd70af63aa55d24_7"
    assert canonical["provenance"]["canonical_event_id_basis"] == \
        "CARRIED_FROM_CANONICAL_EVIDENCE"


def test_the_authenticated_ingest_envelope_carries_the_authority_id():
    event = {**SENSOR_EVENT,
             "_authenticated_ingest": {
                 "source_kind": "sensor", "trust_state": "AUTHENTICATED",
                 "raw_id": RAW,
                 "canonical_event_id": cb.canonical_event_id(RAW, 2),
                 "replay_generation": 2}}
    canonical = _normalized(event)
    assert canonical["event_id"] == "cev_f58e793a0dd70af63aa55d24_2"
    assert canonical["provenance"]["canonical_event_id_basis"] == \
        "CARRIED_FROM_AUTHENTICATED_INGEST"


def test_without_a_carried_id_the_authority_mints_it_and_says_so():
    canonical = _normalized(dict(SENSOR_EVENT))
    assert canonical["event_id"] == cb.canonical_event_id(RAW, 0)
    basis = canonical["provenance"]["canonical_event_id_basis"]
    assert basis.startswith("MINTED_BY_edr_plane.canonical_bridge")
    assert "GENERATION_ASSUMED_FIRST" in basis


def test_the_carried_id_wins_over_the_trace_id():
    # A pipeline call whose trace_id disagrees with the authenticated
    # envelope must still use the AUTHORITY's id.
    event = {**SENSOR_EVENT,
             "_authenticated_ingest": {
                 "raw_id": RAW, "trust_state": "AUTHENTICATED",
                 "canonical_event_id": cb.canonical_event_id(RAW, 4)}}
    canonical = _normalized(event, trace_id="raw_somethingelse")
    assert canonical["event_id"] == cb.canonical_event_id(RAW, 4)


# ── D · the bridge publishes the id it minted ──────────────────────

def test_the_bridge_publishes_its_canonical_id_on_the_ingest_envelope():
    source = Path("/app/backend/edr_plane/canonical_bridge.py").read_text()
    assert '"canonical_event_id": canonical["event_id"]' in source
    assert '"canonical_event_id_authority": CANONICAL_EVENT_ID_AUTHORITY' \
        in source


def test_parse_then_bridge_identity_is_stable_for_the_same_raw_event():
    payload = json.dumps(SENSOR_EVENT)
    first = cb.parse(payload)
    second = cb.parse(payload)
    first["event_id"] = cb.canonical_event_id(RAW, 0)
    second["event_id"] = cb.canonical_event_id(RAW, 0)
    assert first["event_id"] == second["event_id"]
