"""B3 · FILE CONTENT IDENTITY — positive and negative controls.

The three digests stay apart:

```
PROCESS_IMAGE_SHA256 != FILE_CONTENT_SHA256 != RAW_PAYLOAD_CONTENT_DIGEST
```

A digest is admitted only inside an acquisition record that states when
the bytes were read and whether they moved. UNKNOWN never becomes BENIGN:
every refusal carries its cause.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, "/app/backend")
sys.path.insert(0, "/app/agents/nivxforge-linux")

from edr_plane import canonical_bridge as cb                    # noqa: E402
from edr_plane import file_content_acquisition as fca           # noqa: E402
from edr_plane import file_identity as fi                       # noqa: E402

import nivxforge_content_acquisition as nvx_hash                # noqa: E402

DIGEST = "a" * 64
IMAGE_DIGEST = "b" * 64


def _record(**over):
    base = {"path": r"C:\Users\x\AppData\dropper.exe",
            "acquisition_state": "ACQUIRED",
            "content_version_state": "STABLE_DURING_ACQUISITION",
            "hash_class": fca.FILE_CONTENT_SHA256,
            "hash_algorithm": "SHA-256",
            "sha256": DIGEST,
            "acquired_at": "2026-06-01T10:00:02Z",
            "event_observed_at": "2026-06-01T10:00:00Z",
            "size_bytes": 4096}
    base.update(over)
    return base


# ── A · the digest classes are distinct by name ────────────────────

def test_the_three_digest_classes_are_separate():
    assert len({fca.PROCESS_IMAGE_SHA256, fca.FILE_CONTENT_SHA256,
                fca.RAW_PAYLOAD_CONTENT_DIGEST}) == 3


def test_a_process_image_digest_may_not_identify_a_file(): 
    out = fca.admit(record=_record(hash_class=fca.PROCESS_IMAGE_SHA256))
    assert out["hashes"] == {}
    assert out["acquisition"]["admitted"] is False
    assert "never substituted" in out["acquisition"]["refusal_reason"]


# ── B · POSITIVE CONTROL · a real acquisition is admitted ──────────

def test_an_acquired_record_yields_the_file_content_identity():
    out = fca.admit(record=_record())
    assert out["hashes"] == {"sha256": DIGEST}
    assert out["hash_state"] == "HASH_OBSERVED"
    assert out["hash_class"] == fca.FILE_CONTENT_SHA256
    assert out["field_provenance"]["hashes.sha256"] == \
        "sensor:content_acquisition(SHA-256)"
    assert out["acquisition"]["admitted"] is True


def test_the_canonical_file_block_carries_the_acquisition_record():
    payload = json.dumps({
        "activity": "FILE", "operation": "CREATE",
        "collection_method": "PROC_POLL", "observed_at": "2026-06-01T10:00:00Z",
        "path": "/tmp/dropper", "filename": "dropper", "size": 4096,
        "file_content_acquisition": _record(path="/tmp/dropper")})
    canonical = cb.parse(payload)
    assert canonical["file"]["hashes"] == {"sha256": DIGEST}
    assert canonical["file"]["content_acquisition"]["admitted"] is True
    assert canonical["file"]["hash_class"] == fca.FILE_CONTENT_SHA256
    # B3's existing read model sees it as CONTENT identity.
    obs = fi.from_canonical(canonical, tenant_id="t", endpoint_id="e")
    assert obs.identity_basis == fi.CONTENT_IDENTITY_SHA256


def test_changed_since_event_is_retained_but_labelled():
    out = fca.admit(record=_record(
        content_version_state="CHANGED_SINCE_EVENT"))
    assert out["hashes"] == {"sha256": DIGEST}
    assert "NOT provably the content the event described" in \
        out["hash_reason"]
    assert out["acquisition"]["content_version_state"] == \
        "CHANGED_SINCE_EVENT"


# ── C · NEGATIVE CONTROLS · every refusal states its cause ─────────

@pytest.mark.parametrize("state", ["FILE_ABSENT_AT_ACQUISITION",
                                   "ACCESS_DENIED", "SIZE_LIMIT_EXCEEDED",
                                   "RATE_LIMITED", "TIMEOUT",
                                   "NOT_ELIGIBLE_BY_POLICY",
                                   "CAPABILITY_DISABLED"])
def test_a_non_acquired_state_yields_no_digest_and_names_the_cause(state):
    out = fca.admit(record=_record(acquisition_state=state, sha256=DIGEST))
    assert out["hashes"] == {}
    assert out["hash_state"] == "HASH_NOT_OBSERVED"
    assert state in out["hash_reason"]
    assert "not an absence of the file event" in out["hash_reason"]


def test_a_torn_read_is_discarded_not_presented():
    out = fca.admit(record=_record(
        content_version_state="CHANGED_DURING_ACQUISITION"))
    assert out["hashes"] == {}
    assert "torn read" in out["acquisition"]["refusal_reason"]


def test_an_acquired_record_without_a_content_version_is_refused():
    out = fca.admit(record=_record(content_version_state=""))
    assert out["hashes"] == {}
    assert "content_version_state" in out["acquisition"]["refusal_reason"]


def test_an_acquired_record_without_a_read_time_is_refused():
    out = fca.admit(record=_record(acquired_at=""))
    assert out["hashes"] == {}
    assert "acquired_at" in out["acquisition"]["refusal_reason"]


def test_a_malformed_digest_is_refused():
    out = fca.admit(record=_record(sha256="not-a-digest"))
    assert out["hashes"] == {}
    assert "64-hex" in out["acquisition"]["refusal_reason"]


def test_an_undeclared_acquisition_state_is_refused():
    out = fca.admit(record=_record(acquisition_state="PROBABLY_FINE"))
    assert out["hashes"] == {}
    assert "not a declared acquisition outcome" in \
        out["acquisition"]["refusal_reason"]


def test_absence_of_everything_stays_unknown_and_never_benign():
    out = fca.admit()
    assert out["hashes"] == {}
    assert out["hash_state"] == "HASH_NOT_OBSERVED"
    assert out["acquisition"]["acquisition_state"] == "HASH_NOT_ATTEMPTED"
    assert "never promoted here" in out["hash_reason"]
    assert "BENIGN" not in json.dumps(out)


def test_a_process_image_hash_is_never_promoted_into_the_file(): 
    payload = json.dumps({
        "activity": "FILE", "operation": "CREATE",
        "collection_method": "PROC_POLL", "observed_at": "2026-06-01T10:00:00Z",
        "path": "/tmp/dropped.bin", "filename": "dropped.bin"})
    canonical = cb.parse(payload)
    canonical["process"] = {"name": "curl", "executable_path": "/usr/bin/curl",
                            "hashes": {"sha256": IMAGE_DIGEST}}
    assert canonical["file"]["hashes"] == {}
    image = fi.process_image_identity(canonical)
    assert image["hash_class"] == fi.PROCESS_IMAGE_HASH
    assert image["hashes"]["sha256"] == IMAGE_DIGEST
    obs = fi.from_canonical(canonical, tenant_id="t", endpoint_id="e")
    assert obs.hashes == {}
    assert obs.identity_basis == fi.PATH_IDENTITY_ONLY


# ── D · backward compatibility · a source-stated digest ────────────

def test_a_bare_source_stated_digest_is_admitted_but_version_unknown():
    out = fca.admit(sha256=DIGEST)
    assert out["hashes"] == {"sha256": DIGEST}
    assert out["acquisition"]["acquisition_state"] == fca.SOURCE_STATED
    assert out["acquisition"]["content_version_state"] == "UNKNOWN"
    assert out["field_provenance"]["hashes.sha256"] == \
        "source:file_event.sha256"


# ── E · the SENSOR capability is OFF by default ────────────────────

def test_the_sensor_capability_is_disabled_unless_explicitly_enabled():
    os.environ.pop(nvx_hash.CAPABILITY_FLAG, None)
    assert nvx_hash.enabled() is False
    record = nvx_hash.Acquirer().acquire("/etc/hostname", operation="CREATE")
    assert record["acquisition_state"] == "CAPABILITY_DISABLED"
    assert "sha256" not in record


def test_the_sensor_acquires_real_bytes_when_enabled(tmp_path):
    target = tmp_path / "payload.exe"
    target.write_bytes(b"MZ" + b"\x00" * 64)
    expected = hashlib.sha256(target.read_bytes()).hexdigest()
    os.environ[nvx_hash.CAPABILITY_FLAG] = "1"
    try:
        record = nvx_hash.Acquirer().acquire(
            str(target), operation="CREATE",
            event_observed_at="2026-06-01T10:00:00")
        assert record["acquisition_state"] == "ACQUIRED"
        assert record["sha256"] == expected
        assert record["hash_class"] == fca.FILE_CONTENT_SHA256
        assert record["content_version_state"] in fca.CONTENT_VERSION_STATES
        # And the server admits it through the same contract.
        admitted = fca.admit(record=record)
        assert admitted["hashes"] == {"sha256": expected}
    finally:
        os.environ.pop(nvx_hash.CAPABILITY_FLAG, None)


def test_the_sensor_states_why_a_file_was_not_acquired(tmp_path):
    os.environ[nvx_hash.CAPABILITY_FLAG] = "1"
    try:
        acq = nvx_hash.Acquirer()
        gone = acq.acquire(str(tmp_path / "never.exe"), operation="CREATE")
        assert gone["acquisition_state"] == "FILE_ABSENT_AT_ACQUISITION"

        doc = tmp_path / "notes.txt"
        doc.write_text("private")
        not_allowed = acq.acquire(str(doc), operation="CREATE")
        assert not_allowed["acquisition_state"] == "NOT_ELIGIBLE_BY_POLICY"

        deleted = acq.acquire(str(tmp_path / "x.exe"), operation="DELETE")
        assert deleted["acquisition_state"] == "NOT_ELIGIBLE_BY_POLICY"

        big = tmp_path / "big.bin"
        big.write_bytes(b"\x00" * 2048)
        small_ceiling = nvx_hash.Acquirer(size_ceiling=1024)
        assert small_ceiling.acquire(
            str(big), operation="CREATE")["acquisition_state"] == \
            "SIZE_LIMIT_EXCEEDED"

        budget = nvx_hash.Acquirer(
            budget=nvx_hash.RateBudget(files_per_minute=0))
        assert budget.acquire(
            str(big), operation="CREATE")["acquisition_state"] == \
            "RATE_LIMITED"
    finally:
        os.environ.pop(nvx_hash.CAPABILITY_FLAG, None)


def test_the_sensor_never_reports_file_content_only_the_digest(tmp_path):
    target = tmp_path / "thing.dll"
    target.write_bytes(b"SECRETBYTES")
    os.environ[nvx_hash.CAPABILITY_FLAG] = "1"
    try:
        record = nvx_hash.Acquirer().acquire(str(target), operation="CREATE")
        assert "SECRETBYTES" not in json.dumps(record)
        assert "content" not in {k.lower() for k in record
                                 if k not in ("content_version_state",)}
    finally:
        os.environ.pop(nvx_hash.CAPABILITY_FLAG, None)


def test_the_cache_reuses_a_digest_without_claiming_a_fresh_read(tmp_path):
    target = tmp_path / "cached.exe"
    target.write_bytes(b"MZcached")
    os.environ[nvx_hash.CAPABILITY_FLAG] = "1"
    try:
        acq = nvx_hash.Acquirer()
        first = acq.acquire(str(target), operation="CREATE")
        second = acq.acquire(str(target), operation="CREATE")
        assert first["cache_state"] == "CACHE_MISS"
        assert second["cache_state"] == "CACHE_HIT"
        assert second["acquired_at"] == first["acquired_at"]
        assert acq.stats["cache_hits"] == 1
    finally:
        os.environ.pop(nvx_hash.CAPABILITY_FLAG, None)
