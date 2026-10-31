"""GAP-1 · the durable raw-event pointer must survive §d normalization.

Behavior evidence identity is sha(tenant_id, raw_id, sub_key), so a WRONG raw id
would poison replay identity and break traceability back to `edr_raw_events`.
This suite proves the real stored reference is carried, that nothing is ever
substituted for it, and that carrying it changes no existing contract.
"""
import copy

from edr_plane.behavior_evidence_adapter import (REFUSED_NO_RAW_REF,
                                                 to_evidence_record)
from edr_trajectory.providers import (STORE_CANONICAL, STORE_SHADOW,
                                      finalize, from_canonical, from_shadow)

RAW = "raw_9f12c0a3"
OBS = "obs_7731aa90"
CEV = "cev_88ffee11_1"
ACT = "act_4c8e11f2"
TEN = "ten_e759b7288598bd882e3dcac49d"
EP = "ep_a67be48d5b4e01d4d9e8"
TS = "2026-10-03T04:10:07.123456Z"


def shadow_doc(**kw):
    d = {
        "tenant_id": TEN,
        "observation_id": OBS,
        "ingest_job_id": RAW,
        "canonical_event_id": CEV,
        "activity_identity": ACT,
        "collector_id": EP,
        "ingest_time": "2026-10-03T04:10:16.000Z",
        "event": {"device_iid": "dev_d21e1278f914", "activity": "PROCESS",
                  "op": "start", "ts": TS, "computer": EP,
                  "process": {"pid": "7120", "guid": "{a1b2}",
                              "image": "chrome.exe", "cmdline": "chrome.exe",
                              "user": "KUSHU\\jp", "ppid": "640"}},
    }
    d.update(kw)
    return d


def canonical_doc(**kw):
    d = {
        "tenant_id": TEN,
        "event_id": CEV,
        "event_time": TS,
        "ingest_time": "2026-10-03T04:10:16.000Z",
        "provenance": {"collector_id": EP, "trace_id": RAW},
        "raw_ref": {"raw_id": RAW, "collection": "edr_raw_events"},
        "host": {"host_id": EP, "hostname": "KUSHU"},
        "additional_fields": {"activity_type": "PROCESS", "operation": "start",
                              "activity_identity": ACT},
        "process": {"pid": "7120", "process_guid": "{a1b2}",
                    "executable_path": "chrome.exe",
                    "command_line": "chrome.exe", "parent_pid": "640"},
    }
    d.update(kw)
    return d


# ── the reference is carried ──────────────────────────────────────────────

def test_shadow_raw_reference_is_preserved():
    row = from_shadow(shadow_doc())
    assert row["provenance"]["raw_ref"] == RAW


def test_canonical_raw_reference_is_preserved():
    row = from_canonical(canonical_doc())
    assert row["provenance"]["raw_ref"] == RAW


def test_exact_value_is_preserved_not_reformatted():
    odd = "raw_  weird-ID_0001  "
    assert from_shadow(shadow_doc(ingest_job_id=odd))[
        "provenance"]["raw_ref"] == odd.strip()
    assert from_canonical(canonical_doc(
        provenance={"collector_id": EP, "trace_id": odd}))[
            "provenance"]["raw_ref"] == odd.strip()


def test_canonical_falls_back_to_the_explicit_raw_ref_document_field():
    d = canonical_doc(provenance={"collector_id": EP})
    assert from_canonical(d)["provenance"]["raw_ref"] == RAW


def test_shadow_accepts_an_explicit_provenance_trace_id():
    d = shadow_doc(provenance={"trace_id": RAW})
    d.pop("ingest_job_id")
    assert from_shadow(d)["provenance"]["raw_ref"] == RAW


# ── nothing is ever manufactured or substituted ───────────────────────────

def test_missing_shadow_reference_does_not_manufacture_one():
    d = shadow_doc()
    d.pop("ingest_job_id")
    assert from_shadow(d)["provenance"]["raw_ref"] is None


def test_missing_canonical_reference_does_not_manufacture_one():
    d = canonical_doc(provenance={"collector_id": EP})
    d.pop("raw_ref")
    assert from_canonical(d)["provenance"]["raw_ref"] is None


def test_blank_reference_is_absent_not_an_empty_string():
    assert from_shadow(shadow_doc(ingest_job_id="   "))[
        "provenance"]["raw_ref"] is None


def test_observation_id_is_never_substituted_as_the_raw_reference():
    d = shadow_doc()
    d.pop("ingest_job_id")
    row = from_shadow(d)
    assert row["provenance"]["raw_ref"] is None
    assert row["provenance"]["ref"] == OBS          # still the observation id
    assert row["provenance"]["raw_ref"] != OBS


def test_canonical_event_id_is_never_substituted_as_the_raw_reference():
    d = canonical_doc(provenance={"collector_id": EP})
    d.pop("raw_ref")
    row = from_canonical(d)
    assert row["provenance"]["raw_ref"] is None
    assert row["provenance"]["ref"] == CEV
    assert row["provenance"]["raw_ref"] != CEV


def test_endpoint_device_hostname_and_activity_ids_are_never_substituted():
    d = shadow_doc()
    d.pop("ingest_job_id")
    row = from_shadow(d)
    for never in (EP, "dev_d21e1278f914", "KUSHU", ACT, CEV):
        assert row["provenance"]["raw_ref"] != never


# ── the Behavior adapter now receives it ─────────────────────────────────

def _record(row):
    rec, why = to_evidence_record(row, tenant_id=TEN, endpoint_id=EP)
    assert why is None, why
    return rec


def test_behavior_evidence_ref_raw_id_comes_from_the_preserved_reference():
    for row in (finalize(from_shadow(shadow_doc())),
                finalize(from_canonical(canonical_doc()))):
        rec = _record(row)
        assert rec.ref.raw_id == RAW
        assert rec.ref.sub_key == ACT
        assert rec.ref.tenant_id == TEN


def test_adapter_still_fails_closed_when_no_reference_exists():
    d = shadow_doc()
    d.pop("ingest_job_id")
    rec, why = to_evidence_record(finalize(from_shadow(d)), tenant_id=TEN,
                                 endpoint_id=EP)
    assert rec is None and why == REFUSED_NO_RAW_REF


def test_evidence_identity_is_replay_safe_and_store_independent():
    """The SAME activity seen through both stores yields the SAME identity,
    because identity is (tenant, raw_id, activity) — not the store."""
    a = _record(finalize(from_shadow(shadow_doc())))
    b = _record(finalize(from_canonical(canonical_doc())))
    assert a.ref.stable_key() == b.ref.stable_key()
    assert a.ref.store != b.ref.store


def test_caller_override_still_wins_when_supplied():
    rec, why = to_evidence_record(finalize(from_shadow(shadow_doc())),
                                  tenant_id=TEN, endpoint_id=EP,
                                  raw_id="raw_caller_held")
    assert why is None and rec.ref.raw_id == "raw_caller_held"


# ── no existing contract moves ───────────────────────────────────────────

def test_event_identity_is_unchanged():
    assert from_shadow(shadow_doc())["event_id"] == ACT
    assert from_canonical(canonical_doc())["event_id"] == ACT


def test_time_authority_and_ordering_values_are_unchanged():
    s = finalize(from_shadow(shadow_doc()))
    c = finalize(from_canonical(canonical_doc()))
    assert s["observed_ms"] == c["observed_ms"]
    assert s["observed_at"] == c["observed_at"]
    assert s["ingested_ms"] != s["observed_ms"]
    # the new key lives ONLY under provenance; no ordering field gained a value
    assert "raw_ref" not in s or isinstance(s.get("raw_ref"), type(None))


def test_provenance_keeps_every_pre_existing_key():
    p = from_shadow(shadow_doc(event={**shadow_doc()["event"],
                                      "data_label": "windows-sysmon"}))[
        "provenance"]
    assert p["store"] == STORE_SHADOW
    assert p["ref"] == OBS
    assert p["label"] == "windows-sysmon"
    assert set(p) == {"store", "ref", "label", "raw_ref"}
    q = from_canonical(canonical_doc())["provenance"]
    assert q["store"] == STORE_CANONICAL
    assert set(q) == {"store", "ref", "label", "raw_ref"}


def test_row_contract_keys_are_otherwise_identical():
    row = from_shadow(shadow_doc())
    expected = {"schema", "event_id", "tenant_id", "device_id", "kind",
                "observed_ms", "ingested_ms", "severity", "process", "parent",
                "creator", "file", "network", "detection", "boot_id",
                "sources", "provenance", "observed_at", "ingested_at"}
    assert set(row) == expected


def test_source_documents_are_not_mutated():
    for doc, fn in ((shadow_doc(), from_shadow),
                    (canonical_doc(), from_canonical)):
        before = copy.deepcopy(doc)
        fn(doc)
        assert doc == before


def test_normalized_row_is_not_mutated_by_the_adapter():
    row = finalize(from_shadow(shadow_doc()))
    before = copy.deepcopy(row)
    to_evidence_record(row, tenant_id=TEN, endpoint_id=EP)
    assert row == before
