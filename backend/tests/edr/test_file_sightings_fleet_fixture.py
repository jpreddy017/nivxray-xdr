"""Two computers, one digest — proved on a DISPOSABLE database.

The preview substrate has exactly one reporting endpoint, so the multi-computer
case cannot be shown there without enrolling a second device into shared data.
This builds its own database, asserts the contract, and drops it. Nothing is
written to the preview dataset and no endpoint is enrolled.

What it must establish:
  * both computers appear as lanes within ONE customer;
  * a TIE for earliest observation keeps both computers, rather than picking
    one and presenting it as the place the file came from;
  * a third endpoint carrying the same digest in ANOTHER customer is absent
    from both reads;
  * seeing the same digest twice is co-observation, never transfer.
"""
import json
import os
import sys
import uuid

import pytest
from pymongo import MongoClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from services.edr import file_sightings as svc  # noqa: E402

DIGEST = "a" * 63 + "1"
OWNER = "fx-owner"
OUTSIDER = "fx-outsider"
EP_A = "ep_fixture_aaaaaaaaaaaa"
EP_B = "ep_fixture_bbbbbbbbbbbb"
EP_C = "ep_fixture_cccccccccccc"
TIE = "2026-09-01T00:00:00.000000+00:00"


def _raw(tenant, endpoint, payload, ingest):
    return {"raw_id": f"raw_{uuid.uuid4().hex[:18]}", "tenant_id": tenant,
            "endpoint_ref": endpoint, "ingest_time": ingest,
            "trust_state": "AUTHENTICATED", "sensor_version": "0.2.0",
            "payload": json.dumps(payload)}


def _process(observed, path="/usr/bin/sleep"):
    return {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
            "observed_at": observed, "image_path": path, "image": "sleep",
            "sha256": DIGEST, "pid": 4242, "ppid": 1, "user": "root",
            "collection_method": "PROC_POLL", "sensor_version": "0.2.0"}


def _create(observed, path="/var/tmp/watch/copy"):
    return {"activity": "FILE", "operation": "CREATE", "observed_at": observed,
            "path": path, "filename": "copy", "size": 68432, "sha256": DIGEST,
            "collection_method": "PROC_POLL", "sensor_version": "0.2.0"}


@pytest.fixture()
def fleet(monkeypatch):
    db_name = f"nivx_filetraj_fixture_{uuid.uuid4().hex[:10]}"
    monkeypatch.setenv("DB_NAME", db_name)
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[db_name]
    db.edr_endpoints.insert_many([
        {"tenant_id": OWNER, "endpoint_id": EP_A, "hostname": "fixture-a",
         "os": "LINUX", "status": "ACTIVE"},
        {"tenant_id": OWNER, "endpoint_id": EP_B, "hostname": "fixture-b",
         "os": "LINUX", "status": "ACTIVE"},
        {"tenant_id": OUTSIDER, "endpoint_id": EP_C, "hostname": "fixture-c",
         "os": "LINUX", "status": "ACTIVE"},
    ])
    db.edr_raw_events.insert_many([
        # Both owner endpoints observed it in the SAME instant.
        _raw(OWNER, EP_A, _process(TIE), TIE),
        _raw(OWNER, EP_B, _process(TIE), TIE),
        # …and each carries later activity of its own.
        _raw(OWNER, EP_A, _process("2026-09-02T10:00:00.000000+00:00"),
             "2026-09-02T10:00:01.000000+00:00"),
        _raw(OWNER, EP_B, _create("2026-09-03T23:50:00.000000+00:00"),
             "2026-09-04T00:10:00.000000+00:00"),   # delivery crosses midnight
        # A third computer in ANOTHER customer holds the same content.
        _raw(OUTSIDER, EP_C, _process("2026-08-01T00:00:00.000000+00:00"),
             "2026-08-01T00:00:01.000000+00:00"),
    ])
    yield db
    client.drop_database(db_name)


def test_the_answer_is_keyed_to_the_digest_that_was_asked_for(fleet):
    # It was not, once: a loop variable shadowed the digest and the response
    # came back keyed "PROCESS/PROCESS_OBSERVED", which the UI then put in the
    # SHA-256 field and in every device-trajectory link.
    out = svc.sightings(DIGEST, tenant_id=OWNER)
    assert out["sha256"] == DIGEST
    assert out["attributes"]["sha256"] == DIGEST


def test_both_computers_appear_as_lanes_in_one_customer(fleet):
    out = svc.sightings(DIGEST, tenant_id=OWNER)
    assert out["ok"] is True
    assert out["endpoint_count"] == 2
    assert {e["endpoint_id"] for e in out["endpoints"]} == {EP_A, EP_B}
    assert {e["hostname"] for e in out["endpoints"]} == {"fixture-a", "fixture-b"}
    assert all(e["identity"] == "registered" for e in out["endpoints"])
    assert out["total_sightings"] == 4


def test_a_tie_for_earliest_keeps_both_computers(fleet):
    out = svc.sightings(DIGEST, tenant_id=OWNER)
    firsts = out["entry_points"]
    # Two endpoints saw it in the same instant. Naming one of them would be a
    # claim about where the file came from that nothing here supports.
    assert len(firsts) == 2
    assert {e["endpoint_id"] for e in firsts} == {EP_A, EP_B}
    assert all(e["first_observed"] == TIE for e in firsts)
    assert "not evidence that the file moved" in out["entry_point_basis"]


def test_another_customers_endpoint_is_absent_from_both_reads(fleet):
    owner = svc.sightings(DIGEST, tenant_id=OWNER)
    assert EP_C not in {e["endpoint_id"] for e in owner["endpoints"]}

    outsider = svc.sightings(DIGEST, tenant_id=OUTSIDER)
    assert outsider["endpoint_count"] == 1
    assert outsider["endpoints"][0]["endpoint_id"] == EP_C
    assert {EP_A, EP_B}.isdisjoint({e["endpoint_id"]
                                    for e in outsider["endpoints"]})


def test_the_path_filter_matches_every_sighting_not_just_the_newest(fleet):
    out = svc.sightings(DIGEST, tenant_id=OWNER, limit=1,
                        path_contains="/var/tmp")
    # limit=1 would hide the creation if the filter ran after the limit: the
    # creation is older than EP_A's newest execution.
    assert out["filter"]["matched_sightings"] == 1
    assert out["filter"]["of_sightings"] == 4
    rows = [s for e in out["endpoints"] for s in e["sightings"]]
    assert len(rows) == 1
    assert rows[0]["activity"] == "CREATE"
    assert rows[0]["path"] == "/var/tmp/watch/copy"
    assert rows[0]["path_field"] == "path"
    assert rows[0]["size"] == 68432
    # Every path the digest was ever seen at stays visible under a filter.
    assert set(out["all_observed_paths"]) == {"/usr/bin/sleep",
                                              "/var/tmp/watch/copy"}


def test_a_filtered_zero_is_a_zero_over_the_whole_history(fleet):
    out = svc.sightings(DIGEST, tenant_id=OWNER, path_contains="/opt/nothing")
    assert out["total_sightings"] == 0
    assert out["endpoints"] == []
    assert out["filter"]["matched_sightings"] == 0
    assert out["filter"]["of_sightings"] == 4


def test_path_provenance_reconciles_counts_with_fields(fleet):
    out = svc.sightings(DIGEST, tenant_id=OWNER)
    prov = out["path_provenance"]
    assert prov["PROCESS/PROCESS_OBSERVED"]["path_field"] == "image_path"
    assert prov["PROCESS/PROCESS_OBSERVED"]["sightings"] == 3
    assert prov["FILE/CREATE"]["path_field"] == "path"
    assert prov["FILE/CREATE"]["sightings"] == 1
    assert "not of launches" in out["process_observation_basis"]


def test_delivery_across_midnight_is_placed_on_the_observed_day(fleet):
    out = svc.sightings(DIGEST, tenant_id=OWNER)
    assert out["day_shifted_sightings"] == 1
    shifted = out["day_shifted_examples"][0]
    assert shifted["observed_day_utc"] == "2026-09-03"
    assert shifted["ingest_day_utc"] == "2026-09-04"
    assert shifted["endpoint_id"] == EP_B


def test_one_exact_sighting_is_readable_regardless_of_the_limit(fleet):
    # The device canvas asks for exactly this when it has no evidence of its
    # own for the day: the sighting has to stay on screen, however old it is.
    whole = svc.sightings(DIGEST, tenant_id=OWNER)
    oldest = sorted((s for e in whole["endpoints"] for s in e["sightings"]),
                    key=lambda s: s["observed_at"])[0]
    out = svc.sightings(DIGEST, tenant_id=OWNER, limit=1,
                        raw_id=oldest["raw_id"])
    rows = [s for e in out["endpoints"] for s in e["sightings"]]
    assert len(rows) == 1
    assert rows[0]["raw_id"] == oldest["raw_id"]
    assert rows[0]["observed_at"] == oldest["observed_at"]


def test_another_customer_cannot_read_a_sighting_by_its_evidence_id(fleet):
    owner_row = [s for e in svc.sightings(DIGEST, tenant_id=OWNER)["endpoints"]
                 for s in e["sightings"]][0]
    out = svc.sightings(DIGEST, tenant_id=OUTSIDER, raw_id=owner_row["raw_id"])
    assert out["total_sightings"] == 0
    assert out["endpoints"] == []
