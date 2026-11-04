"""B1 · NORMALIZER CONVERGENCE — no security-semantic loss in projection.

```
SOURCE TELEMETRY → SOURCE ADAPTER → CANONICAL NORMALIZATION
        → xdr_canonical_evidence (AUTHORITY)
        → DERIVED READ MODEL / PROJECTION (v2_shadow_observations)
        → Trajectory / Detection / Hunt / Graph / XDR
```

The read model may RESHAPE and INDEX. It may not silently discard a
security-relevant field, and it may not reinterpret or downgrade
evidence.

What this file pins, measured on BOTH canonical dialects the platform
actually holds (the EDR sensor bridge and the XDR DSM plane):

* a `process_create` carrying ProcessGuid + CommandLine + MD5 + SHA-256 +
  ParentProcessGuid + ParentCommandLine + OriginalFileName + field
  provenance reaches the read model with all of it intact;
* the PROCESS-IMAGE hash never arrives in the FILE hash fields;
* a file event with no source hash is `HASH_NOT_OBSERVED` — it does not
  inherit the writing process's image hash;
* `raw.sha256` is the observation's own content digest and is exposed
  under an unambiguous name so it cannot be misread as a file hash.
"""
from __future__ import annotations

import json
import sys

import pytest

sys.path.insert(0, "/app/backend")

from edr_plane import canonical_bridge                          # noqa: E402
from tests.edr import fixtures_windows_eventlog as fx           # noqa: E402
from v2.ingestion.canonical import (HASH_NOT_OBSERVED,          # noqa: E402
                                    HASH_OBSERVED)
from v2.ingestion.telemetry_bridge import observation_doc       # noqa: E402

TENANT = "ten_b1_convergence"
ENDPOINT = "ep_b1_convergence"

GUID = "{a1b2c3d4-1111-2222-0000-000000000042}"
PARENT_GUID = "{a1b2c3d4-9999-8888-0000-000000000001}"
SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
MD5 = "5d41402abc4b2a76b9719d911017c592"
SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
CMDLINE = r'"C:\Windows\System32\cmd.exe" /c whoami'
PARENT_CMDLINE = r'C:\Windows\explorer.exe'
IMAGE = r"C:\Windows\System32\cmd.exe"
ORIGINAL_FILE_NAME = "Cmd.Exe"

#: EXACTLY the Sysmon EID 1 EventData a real endpoint emits.
EID1_DATA = {
    "RuleName": "-",
    "UtcTime": "2026-06-01 10:04:00.123",
    "ProcessGuid": GUID,
    "ProcessId": "7364",
    "Image": IMAGE,
    "FileVersion": "10.0.19041.1",
    "Description": "Windows Command Processor",
    "Product": "Microsoft Windows Operating System",
    "Company": "Microsoft Corporation",
    "OriginalFileName": ORIGINAL_FILE_NAME,
    "CommandLine": CMDLINE,
    "CurrentDirectory": "C:\\Users\\svc-admin\\",
    "User": "NIVX\\svc-admin",
    "LogonGuid": "{a1b2c3d4-0000-0000-0000-000000000009}",
    "LogonId": "0x3e7",
    "TerminalSessionId": "1",
    "IntegrityLevel": "High",
    "Hashes": f"MD5={MD5.upper()},SHA256={SHA256.upper()},SHA1={SHA1.upper()}",
    "ParentProcessGuid": PARENT_GUID,
    "ParentProcessId": "4120",
    "ParentImage": r"C:\Windows\explorer.exe",
    "ParentCommandLine": PARENT_CMDLINE,
    "ParentUser": "NIVX\\svc-admin",
}

ENVELOPE = {"source": "nivxforge-windows-sensor", "connector_id": ENDPOINT,
            "collector_id": ENDPOINT, "collection_method": "WINDOWS_EVENT_LOG",
            "parser_version": "1.0.0", "source_event_id": "cev_b1",
            "collection_timestamp": "2026-06-01T10:04:00+00:00"}


# ── the two canonical dialects ───────────────────────────────────────
@pytest.fixture()
def sensor_canonical() -> dict:
    """The EDR sensor bridge dialect (`WINDOWS_EVENT_LOG` envelope)."""
    payload = fx.sysmon(1, 9001, EID1_DATA)
    canonical = canonical_bridge.parse(payload)
    canonical_bridge.bind_process_identity(canonical, ENDPOINT)
    canonical["event_id"] = "cev_b1_sensor"
    canonical["additional_fields"]["endpoint_id"] = ENDPOINT
    return canonical


@pytest.fixture()
def dsm_canonical() -> dict:
    """The XDR DSM plane dialect (`CanonicalTelemetryEvent`)."""
    from detection_content.telemetry.sysmon_dsm import SysmonDSM

    ev = {"event_id": 1, "provider": fx.SYSMON_PROVIDER,
          "channel": fx.SYSMON_CHANNEL, "record_id": 9001,
          "computer": fx.HOST, **EID1_DATA}
    dsm = SysmonDSM()
    parsed = dsm.select_parser().parse(ev)
    return dsm.select_normalizer().normalize(
        parsed, dsm_id=dsm.id, collector_id=ENDPOINT,
        integration_id="b1-test", trace_id="trace_b1", tenant_id=TENANT)


def _project(canonical: dict) -> dict:
    return observation_doc(canonical, envelope=ENVELOPE, tenant_id=TENANT)


# ── A · the field inventory that must survive projection ─────────────
#: canonical field → how to read it off the projected observation.
def _raw(doc: dict, key: str):
    return (doc["event"]["raw"] or {}).get(key)


REQUIRED = {
    "process.process_guid": lambda d: _raw(d, "process_guid"),
    "process.pid": lambda d: _raw(d, "pid"),
    "process.executable_path": lambda d: _raw(d, "image_path"),
    "process.command_line": lambda d: _raw(d, "command_line"),
    "process.original_file_name": lambda d: _raw(d, "original_file_name"),
    "process.hashes.sha256": lambda d: (
        _raw(d, "process_image_hashes") or {}).get("sha256"),
    "process.hashes.md5": lambda d: (
        _raw(d, "process_image_hashes") or {}).get("md5"),
    "process.parent_process_guid": lambda d: _raw(d, "parent_process_guid"),
    "process.parent_pid": lambda d: _raw(d, "ppid"),
    "process.parent_executable_path": lambda d: _raw(d, "parent_image_path"),
    "process.parent_command_line": lambda d: _raw(d, "parent_command_line"),
    "process.field_provenance": lambda d: _raw(d, "field_provenance"),
    "identity.username": lambda d: _raw(d, "user"),
    "source_event_identity": lambda d: (
        _raw(d, "source_identity") or {}).get("event_id"),
    "observed_at": lambda d: d["event"]["ts"],
    "event_type": lambda d: d["event"]["kind"],
    "tenant_id": lambda d: d["tenant_id"],
    "endpoint_id": lambda d: d["connector_id"],
    "observation_id": lambda d: d["observation_id"],
    "raw_evidence_reference": lambda d: (
        _raw(d, "raw_evidence_ref") or _raw(d, "source_identity")),
}


@pytest.mark.parametrize("dialect", ["sensor", "dsm"])
@pytest.mark.parametrize("field_name", sorted(REQUIRED))
def test_security_relevant_fields_survive_the_projection(
        dialect, field_name, sensor_canonical, dsm_canonical):
    canonical = sensor_canonical if dialect == "sensor" else dsm_canonical
    doc = _project(canonical)
    value = REQUIRED[field_name](doc)
    assert value not in (None, "", {}, []), (
        f"{dialect} dialect: {field_name} exists in canonical evidence but "
        f"is LOST or empty in the read model — projection is lossy. "
        f"raw={json.dumps(doc['event']['raw'], default=str)[:400]}")


@pytest.mark.parametrize("dialect", ["sensor", "dsm"])
def test_the_preserved_values_are_the_source_values_not_placeholders(
        dialect, sensor_canonical, dsm_canonical):
    doc = _project(sensor_canonical if dialect == "sensor" else dsm_canonical)
    raw = doc["event"]["raw"]
    assert raw["process_guid"] == GUID
    assert raw["parent_process_guid"] == PARENT_GUID
    assert raw["command_line"] == CMDLINE
    assert raw["parent_command_line"] == PARENT_CMDLINE
    assert raw["original_file_name"] == ORIGINAL_FILE_NAME
    assert raw["process_image_hashes"]["sha256"] == SHA256
    assert raw["process_image_hashes"]["md5"] == MD5
    assert raw["process_image_hash_state"] == HASH_OBSERVED
    assert raw["pid"] == "7364"
    assert raw["ppid"] == "4120"
    assert raw["parent_image_path"].lower().endswith("explorer.exe")
    # the PE metadata name and the on-disk name stay DIFFERENT facts
    assert raw["original_file_name"].lower() != raw["image_path"].lower()


@pytest.mark.parametrize("dialect", ["sensor", "dsm"])
def test_the_process_block_carries_the_source_identity(
        dialect, sensor_canonical, dsm_canonical):
    doc = _project(sensor_canonical if dialect == "sensor" else dsm_canonical)
    proc = doc["event"]["process"]
    assert proc["guid"] == GUID
    assert proc["parent_guid"] == PARENT_GUID
    assert proc["image_hashes"]["sha256"] == SHA256
    # queryable at the document level, not only buried in the payload
    assert doc["process_guid"] == GUID
    assert doc["parent_process_guid"] == PARENT_GUID


@pytest.mark.parametrize("dialect", ["sensor", "dsm"])
def test_field_provenance_reaches_the_read_model(
        dialect, sensor_canonical, dsm_canonical):
    doc = _project(sensor_canonical if dialect == "sensor" else dsm_canonical)
    prov = doc["event"]["raw"]["field_provenance"]
    assert prov, "field provenance was dropped by the projection"
    assert any("process_guid" in k for k in prov), prov
    # and it cites the SOURCE's own vocabulary
    assert any("ProcessGuid" in str(v) for v in prov.values()), prov


# ── B · PROCESS IMAGE HASH != FILE CONTENT HASH ──────────────────────
@pytest.mark.parametrize("dialect", ["sensor", "dsm"])
def test_a_process_image_hash_never_lands_in_the_file_hash_fields(
        dialect, sensor_canonical, dsm_canonical):
    canonical = sensor_canonical if dialect == "sensor" else dsm_canonical
    assert (canonical["process"]["hashes"] or {}).get("sha256") == SHA256
    doc = _project(canonical)
    raw = doc["event"]["raw"]
    assert raw.get("file") in (None, {}), (
        "a process_create has no file of its own; a file block here means "
        "the process image was filed as a written file")
    for artefact in (doc["event"]["artefacts"].get("file") or ()):
        assert SHA256 not in json.dumps(artefact), (
            "the PROCESS IMAGE hash was promoted into a FILE artefact")


def test_a_file_create_with_no_source_hash_is_hash_not_observed():
    """Sysmon EID 11 states the path and the WRITER, not the content hash.

    The written file must NOT inherit the writing process's image hash.
    """
    payload = fx.sysmon(11, 9002, {
        "RuleName": "-",
        "UtcTime": "2026-06-01 10:06:00.123",
        "ProcessGuid": GUID,
        "ProcessId": "7364",
        "Image": IMAGE,
        "TargetFilename": r"C:\Users\svc-admin\AppData\Local\Temp\payload.dll",
        "CreationUtcTime": "2026-06-01 10:06:00.100",
        "User": "NIVX\\svc-admin",
    })
    canonical = canonical_bridge.parse(payload)
    canonical["event_id"] = "cev_b1_file"
    doc = _project(canonical)
    raw = doc["event"]["raw"]
    assert raw["file"]["path"].endswith("payload.dll")
    assert raw["file"]["hashes"] == {}
    assert raw["file"]["hash_state"] == HASH_NOT_OBSERVED
    assert SHA256 not in json.dumps(raw["file"]), (
        "the created file inherited the writing process's image hash")
    artefact = doc["event"]["artefacts"]["file"][0]
    assert artefact["hash_state"] == HASH_NOT_OBSERVED
    assert artefact["sha256"] == ""


def test_the_observation_content_digest_is_not_presented_as_a_file_hash():
    """`raw.sha256` is the observation's OWN content digest.

    It is neither a file hash nor a process-image hash. The unambiguous
    name must exist so no consumer can read it as one.
    """
    payload = fx.sysmon(1, 9003, EID1_DATA)
    canonical = canonical_bridge.parse(payload)
    canonical["event_id"] = "cev_b1_digest"
    raw = _project(canonical)["event"]["raw"]
    assert raw["content_digest_sha256"] == raw["sha256"]
    assert raw["content_digest_sha256"] != SHA256
    assert raw["process_image_hashes"]["sha256"] == SHA256


# ── C · no value is INVENTED to satisfy the contract ─────────────────
def test_a_source_that_states_nothing_preserves_nothing():
    """A minimal EID 1 must NOT acquire fields the source never stated."""
    payload = fx.sysmon(1, 9004, {
        "UtcTime": "2026-06-01 10:04:00.123",
        "ProcessId": "8000",
        "Image": r"C:\Windows\System32\notepad.exe",
    })
    canonical = canonical_bridge.parse(payload)
    canonical["event_id"] = "cev_b1_sparse"
    raw = _project(canonical)["event"]["raw"]
    assert raw["process_guid"] is None
    assert raw["original_file_name"] is None
    assert raw["parent_process_guid"] is None
    assert raw["parent_command_line"] is None
    assert raw["process_image_hashes"] == {}
    assert raw["process_image_hash_state"] == HASH_NOT_OBSERVED
    assert raw["file"] is None
