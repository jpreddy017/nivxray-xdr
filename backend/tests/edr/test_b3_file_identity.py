"""B3 · FILE IDENTITY invariants.

`PROCESS IMAGE HASH != FILE-CREATE HASH != FILE CONTENT IDENTITY`.

What this file pins:

* the process-image SHA-256 that ALREADY EXISTS is preserved and stays
  labelled as the image's;
* a created file NEVER inherits the writing process's image hash;
* when the source reported no file hash the state is `HASH_NOT_OBSERVED`
  and the identity is `PATH_IDENTITY_ONLY` — a name match can never be
  presented as a content match;
* when the source DOES report a file hash it is preserved with its
  provenance and the file gains `CONTENT_IDENTITY_SHA256`;
* the writing process is accepted only because the SOURCE stated it on
  the file event itself.
"""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "/app/backend")

from edr_plane import canonical_bridge                          # noqa: E402
from edr_plane import file_identity as fi                       # noqa: E402
from tests.edr import fixtures_windows_eventlog as fx           # noqa: E402
from v2.ingestion.canonical import (HASH_NOT_APPLICABLE,        # noqa: E402
                                    HASH_NOT_OBSERVED,
                                    HASH_OBSERVED)

TENANT = "ten_b3"
ENDPOINT = "ep_b3"
GUID = "{dddddddd-0000-0000-0000-00000000000d}"
IMAGE_SHA256 = ("aaaa1111884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f"
                "00a08")
FILE_SHA256 = ("bbbb2222884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f"
               "00a08")
DROPPED = r"C:\Users\svc-admin\AppData\Local\Temp\payload.dll"


def _canonical(event_id: int, record_id: int, data: dict) -> dict:
    canonical = canonical_bridge.parse(fx.sysmon(event_id, record_id, data))
    canonical_bridge.bind_process_identity(canonical, ENDPOINT)
    canonical["event_id"] = f"cev_b3_{record_id}"
    canonical["additional_fields"]["endpoint_id"] = ENDPOINT
    return canonical


PROCESS_CREATE = {
    "UtcTime": "2026-06-01 10:04:00.123", "ProcessGuid": GUID,
    "ProcessId": "7364", "Image": r"C:\Windows\System32\cmd.exe",
    "OriginalFileName": "Cmd.Exe", "CommandLine": "cmd /c drop",
    "Hashes": f"SHA256={IMAGE_SHA256.upper()}",
}

FILE_CREATE = {
    "UtcTime": "2026-06-01 10:06:00.123", "ProcessGuid": GUID,
    "ProcessId": "7364", "Image": r"C:\Windows\System32\cmd.exe",
    "TargetFilename": DROPPED,
    "CreationUtcTime": "2026-06-01 10:06:00.100",
}


# ── A · the process image hash already exists and stays the image's ──
def test_the_process_image_hash_is_preserved_and_labelled_as_the_images():
    got = fi.process_image_identity(_canonical(1, 8001, PROCESS_CREATE))
    assert got["hash_class"] == fi.PROCESS_IMAGE_HASH
    assert got["hash_state"] == HASH_OBSERVED
    assert got["hashes"]["sha256"] == IMAGE_SHA256
    assert got["original_file_name"] == "Cmd.Exe"
    assert got["hash_provenance"], "the hash lost its provenance"
    assert "sysmon:EventData.Hashes" in json.dumps(got["hash_provenance"])


def test_a_process_create_is_not_a_file_observation():
    assert fi.from_canonical(_canonical(1, 8002, PROCESS_CREATE)) is None, (
        "the process IMAGE was filed as a file observation, which is how a "
        "process-image hash becomes a fake file-content hash")


def test_an_observation_with_no_image_reports_hash_not_applicable():
    got = fi.process_image_identity({"process": {}})
    assert got["hash_state"] == HASH_NOT_APPLICABLE


# ── B · a created file does NOT inherit the writer's image hash ──────
def test_a_created_file_with_no_source_hash_is_hash_not_observed():
    canonical = _canonical(11, 8003, FILE_CREATE)
    # the writer's image hash is NOT on this event at all, and even if it
    # were it would be the IMAGE's
    got = fi.from_canonical(canonical, tenant_id=TENANT,
                            endpoint_id=ENDPOINT)
    assert got is not None
    assert got.path == DROPPED
    assert got.name == "payload.dll"
    assert got.extension == ".dll"
    assert got.hashes == {}
    assert got.hash_state == HASH_NOT_OBSERVED
    assert got.hash_class == fi.FILE_CONTENT_HASH
    assert got.identity_basis == fi.PATH_IDENTITY_ONLY
    assert got.content_identified is False
    assert "not promoted" in got.hash_reason


def test_the_writers_image_hash_is_never_promoted_into_the_file():
    """The file event carries the WRITER's image hash on the same record."""
    canonical = _canonical(11, 8004, {**FILE_CREATE,
                                      "Hashes": ""})
    canonical["process"]["hashes"] = {"sha256": IMAGE_SHA256}
    got = fi.from_canonical(canonical)
    assert got.hashes == {}
    assert got.hash_state == HASH_NOT_OBSERVED
    assert IMAGE_SHA256 not in json.dumps(
        {"hashes": got.hashes, "key": got.file_key})


def test_a_path_only_file_is_not_content_identified():
    a = fi.from_canonical(_canonical(11, 8005, FILE_CREATE))
    # same path, different bytes later — path identity cannot tell them
    # apart, and it says so rather than claiming a content match
    assert a.identity_basis == fi.PATH_IDENTITY_ONLY
    assert a.file_key.startswith("filepath_")


# ── C · when the source DOES report a file hash ──────────────────────
def _hashed_file_canonical() -> dict:
    """A source that genuinely reports the CONTENT hash of a written file.

    Represented as canonical evidence directly: the field and its
    provenance are what matter to the contract, not which vendor produced
    them.
    """
    return {
        "event_id": "cev_b3_hashed",
        "source_vendor": "NivXForge", "source_product": "WindowsSensor",
        "event_time": "2026-06-01T10:06:00+00:00",
        "event_type": "file_create",
        "host": {"host_id": ENDPOINT},
        "process": {"process_guid": GUID, "pid": 7364,
                    "executable_path": r"C:\Windows\System32\cmd.exe",
                    "hashes": {"sha256": IMAGE_SHA256}},
        "file": {"path": DROPPED, "name": "payload.dll", "action": "create",
                 "size_bytes": 20480,
                 "hashes": {"sha256": FILE_SHA256, "md5": "0" * 32},
                 "field_provenance": {
                     "path": "sensor:file_create.target_path",
                     "hashes.sha256": "sensor:content_hash(SHA256)"}},
        "additional_fields": {"endpoint_id": ENDPOINT},
    }


def test_a_source_reported_file_hash_is_preserved_with_its_provenance():
    got = fi.from_canonical(_hashed_file_canonical(), tenant_id=TENANT)
    assert got.hash_state == HASH_OBSERVED
    assert got.hashes["sha256"] == FILE_SHA256
    assert got.identity_basis == fi.CONTENT_IDENTITY_SHA256
    assert got.content_identified is True
    assert got.hash_provenance["hashes.sha256"] == \
        "sensor:content_hash(SHA256)"
    assert got.size == 20480
    assert got.action == "create"


def test_the_file_content_key_is_not_the_process_image_key():
    canonical = _hashed_file_canonical()
    file_obs = fi.from_canonical(canonical)
    image = fi.process_image_identity(canonical)
    assert file_obs.file_key != image["image_content_key"], (
        "the file and the process image resolved to ONE identity — the two "
        "hashes identify different objects")
    assert file_obs.hash_class == fi.FILE_CONTENT_HASH
    assert image["hash_class"] == fi.PROCESS_IMAGE_HASH


def test_a_weak_hash_only_file_is_not_claimed_as_sha256_identity():
    canonical = _hashed_file_canonical()
    canonical["file"]["hashes"] = {"md5": "5d41402abc4b2a76b9719d911017c592"}
    got = fi.from_canonical(canonical)
    assert got.hash_state == HASH_OBSERVED
    assert got.identity_basis == fi.CONTENT_IDENTITY_WEAK_HASH


# ── D · the writing process is SOURCE-STATED or absent ───────────────
def test_the_writer_is_accepted_only_because_the_source_stated_it():
    got = fi.from_canonical(_canonical(11, 8006, FILE_CREATE))
    assert got.writer_basis == fi.WRITER_SOURCE_STATED
    assert got.writer_process_guid == GUID
    assert got.writer_pid == "7364"


def test_a_file_event_with_no_actor_has_no_writer():
    canonical = _hashed_file_canonical()
    canonical["process"] = {}
    got = fi.from_canonical(canonical)
    assert got.writer_basis == fi.WRITER_NOT_OBSERVED
    assert got.writer_process_guid == ""


# ── E · measured coverage, never estimated ───────────────────────────
def test_coverage_measures_what_is_actually_known():
    rows = [fi.from_canonical(_canonical(11, 8100 + i, {
        **FILE_CREATE, "TargetFilename": f"C:\\tmp\\f{i}.dll"}))
        for i in range(3)]
    rows.append(fi.from_canonical(_hashed_file_canonical()))
    got = fi.coverage(rows)
    assert got["file_observations"] == 4
    assert got["with_sha256"] == 1
    assert got["content_identified"] == 1
    assert got["path_identity_only"] == 3
    assert got["hash_states"][HASH_NOT_OBSERVED] == 3
    assert got["with_source_stated_writer"] == 4
    assert "NOT unknown-good" in got["note"]


def test_the_read_model_dialect_resolves_to_the_same_file_facts():
    from v2.ingestion.telemetry_bridge import observation_doc

    canonical = _canonical(11, 8200, FILE_CREATE)
    doc = observation_doc(
        canonical,
        envelope={"connector_id": ENDPOINT, "collector_id": ENDPOINT,
                  "source": "nivxforge-windows-sensor",
                  "collection_method": "WINDOWS_EVENT_LOG",
                  "parser_version": "1.0.0", "source_event_id": "cev_b3",
                  "collection_timestamp": "2026-06-01T10:06:00+00:00"},
        tenant_id=TENANT)
    from_authority = fi.from_canonical(canonical)
    from_read_model = fi.from_observation(doc)
    assert from_read_model is not None
    assert from_read_model.file_key == from_authority.file_key
    assert from_read_model.hash_state == from_authority.hash_state == \
        HASH_NOT_OBSERVED
    assert from_read_model.writer_process_guid == GUID
