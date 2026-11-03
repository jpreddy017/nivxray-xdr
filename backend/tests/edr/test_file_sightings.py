"""SHA-256 file sightings · the contract the Files surface depends on.

These run against the live preview substrate, because the whole point of the
feature is that `edr_raw_events.payload.sha256` carries a REAL content digest
on this substrate — a fixture would prove nothing about that claim.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from services.edr import file_sightings as svc  # noqa: E402

# Content executed from /usr/bin/sleep AND from copies under /var/tmp.
MULTI_PATH = "17a623f303e2489770e64a9eab9420c66e576ec5ad215ea7c46ec392a2212f49"
# /usr/bin/dash — carries a sighting observed 2026-09-23 but ingested 09-24.
DAY_SHIFT = "15fc4c72f49c86639a383121eec6fbdbcd32ec9d03db915cb3096928295e1a17"
OWNER = "default"
OTHER = "nivx-live"


def _require_substrate(key=None):
    """These assert against the REAL preview substrate.

    A database without that telemetry (CI's `nivxray_ci_local`, a fresh pod)
    cannot prove or disprove anything here, so the test skips loudly instead of
    passing on an empty read.
    """
    out = svc.sightings(key or MULTI_PATH, tenant_id=OWNER)
    if not out.get("total_sightings"):
        pytest.skip(f"no sightings for {(key or MULTI_PATH)[:12]}… in "
                    f"{os.environ.get('DB_NAME')} — preview substrate absent")
    return out


def test_a_malformed_key_is_refused_without_looking_anything_up():
    for bad in ("notahash", "", "17a623f3", MULTI_PATH[:-1], MULTI_PATH + "a"):
        out = svc.sightings(bad, tenant_id=OWNER)
        assert out["ok"] is False
        assert out["reason"] == "INVALID_SHA256"
        # An empty result and a refused lookup are different answers.
        assert "total_sightings" not in out


def test_a_real_digest_reports_its_sightings_with_time_and_path():
    out = _require_substrate()
    assert out["ok"] is True
    assert out["total_sightings"] > 0
    assert out["endpoint_count"] >= 1
    ep = out["endpoints"][0]
    assert ep["endpoint_id"]
    # The endpoint is a registered one, so its hostname is known.
    assert ep["identity"] == "registered"
    assert ep["hostname"]
    s = ep["sightings"][0]
    for field in ("observed_at", "path", "activity", "endpoint_id"):
        assert s[field], f"{field} missing from a sighting"
    assert s["observed_at"].endswith("+00:00")


def test_the_same_content_is_reported_under_every_path_it_ran_from():
    out = _require_substrate()
    assert len(out["observed_paths"]) > 1, out["observed_paths"]
    assert any(p.startswith("/var/tmp/") for p in out["observed_paths"])
    assert "/usr/bin/sleep" in out["observed_paths"]


def test_a_sighting_is_placed_at_observation_time_not_ingest_time():
    """The regression the owner asked for: delivery crossing midnight.

    A sighting observed on one UTC day and ingested on the next must be
    reported on the day the ENDPOINT saw it, and must say that the two differ.
    """
    out = _require_substrate(DAY_SHIFT)
    assert out["day_shifted_sightings"] >= 1
    shifted = out["day_shifted_examples"]
    assert shifted, "a day-shifted sighting must survive the per-endpoint slice"
    s = shifted[0]
    assert s["ingest_day_differs"] is True
    assert s["observed_day_utc"] != s["ingest_day_utc"]
    assert s["observed_day_utc"] < s["ingest_day_utc"]
    # Every sighting is dated by observation, not by delivery.
    for ep in out["endpoints"]:
        for row in ep["sightings"]:
            assert row["observed_at"]
            assert row["observed_day_utc"] == str(row["observed_at"])[:10]


def test_another_customer_gets_an_honest_zero_not_this_ones_endpoints():
    out = svc.sightings(MULTI_PATH, tenant_id=OTHER)
    assert out["ok"] is True
    assert out["tenant"] == OTHER
    assert out["total_sightings"] == 0
    assert out["endpoints"] == []
    # The owner's endpoint is not named anywhere in another customer's answer.
    assert "ep_2d57cbe6f80152062109" not in str(out)


def test_a_valid_but_unseen_digest_is_a_zero_not_a_failure():
    unseen = "0" * 64
    out = svc.sightings(unseen, tenant_id=OWNER)
    assert out["ok"] is True
    assert out["total_sightings"] == 0
    assert out["endpoint_count"] == 0
    assert out["first_observed"] is None


def test_the_answer_states_what_it_is_and_is_not():
    out = svc.sightings(MULTI_PATH, tenant_id=OWNER)  # notes exist even at zero
    assert "observed_at" in out["time_basis"]
    assert "ingest" in out["time_basis"]
    assert "write" in out["collection_limit"]
    assert out["scope"]["customer"] == OWNER
    assert out["scope"]["authority"] == "server"


def test_a_capped_read_says_it_is_capped():
    """A digest with thousands of sightings must not present a slice as all."""
    busy = "3e83cdfa4cdb93afd114c2b5742d48d653621fbbd7468ecd6e482e5143d1d4c4"
    out = _require_substrate(busy)
    assert out["truncated"] is True
    assert out["scanned"] == svc.SCAN_CAP


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


def test_the_answer_carries_the_sections_the_console_lays_out():
    """Visibility, entry point and attributes — Cisco AMP's File Trajectory
    framing — must come from the read, not be assembled in the browser."""
    out = _require_substrate()
    vis = out["visibility"]
    assert vis["first_observed"] == out["first_observed"]
    assert vis["last_observed"] == out["last_observed"]
    assert vis["endpoints"] == out["endpoint_count"]

    # Entry point is the EARLIEST observation, and every tie is kept.
    eps = out["entry_points"]
    assert eps, "a substrate with sightings must name an entry point"
    earliest = min(e["first_observed"] for e in out["endpoints"]
                   if e["first_observed"])
    assert all(e["first_observed"] == earliest for e in eps)

    assert out["observed_names"], "path leaves are the file's known names"
    assert out["activity_breakdown"], out["activity_breakdown"]
    assert out["attributes"]["sha256"] == out["sha256"]
    # The fields AMP shows and this substrate does not collect are NAMED.
    for gap in ("file size", "signing certificate"):
        assert any(gap in n for n in out["not_collected"]), out["not_collected"]
