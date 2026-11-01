"""AUTHENTICATION CLASSIFICATION — §d evidence -> V3 presentation, per activity family.

Authentication is the only Windows family whose OUTCOME lives in the source's own class token
(`xdr_canonical_evidence.event_type` / `v2_shadow_observations.event.kind`) and nowhere else:
`additional_fields.activity_type` says only "AUTHENTICATION". §d classified from activity_type
alone, so every sign-in on a real endpoint arrived as `OTHER` and V3 drew it as an unnamed
generic row — evidence the platform HELD but never showed.

These tests pin, family by family, that the classification is taken from the stated class token,
that no outcome is invented when the source states none, and that the existing process / file /
network / registry / DNS / other families are classified exactly as before.
"""
from __future__ import annotations

import asyncio
from typing import Any

from edr_plane import temporal_authority as ta
from edr_plane.trajectory_window import _AUTH_KINDS
from edr_trajectory import production_adapter as pa
from edr_trajectory import production_service as ps
from edr_trajectory import v3_presentation as v3
from edr_trajectory.providers import from_canonical, from_shadow

from test_sd_production_adapter import DEV, T, FakeDB

TS = "2026-10-29T05:31:56.682329+00:00"

#: Shape taken from retained G4 evidence (endpoint ep_024ce6515803f7165a11, Windows 4624).
AUTH_BLOCK = {"outcome": "SUCCESS", "logon_type": "5", "logon_type_name": "SERVICE",
              "logon_type_basis": "winsec:LogonType, mapped from the source value only",
              "target_user": "SYSTEM", "target_domain": "NT AUTHORITY", "target_sid": "S-1-5-18",
              "subject_user": "NIVX-G4-WIN11$", "logon_process": "Advapi",
              "authentication_package": "Negotiate", "workstation_name": "-", "source_ip": "-"}


def canon_auth(event_type: str, *, ts: str = TS, auth: dict[str, Any] | None = AUTH_BLOCK,
               username: str | None = "SYSTEM", pid: str = "0x3b4") -> dict[str, Any]:
    return ta.stamp({"_id": f"cid_{event_type}_{ts}", "tenant_id": T,
                     "event_id": f"cev_{event_type}_{ts}", "event_type": event_type,
                     "event_time": ts, "ingest_time": "2026-10-29T05:32:29+00:00",
                     "host": {}, "provenance": {"collector_id": DEV, "trace_id": "raw_abc"},
                     "additional_fields": {"activity_type": "AUTHENTICATION", "operation": None,
                                           "severity": "NONE"},
                     "identity": {"username": username, "domain": "NT AUTHORITY"},
                     "process": {"pid": pid, "executable_path": "C:\\Windows\\System32\\services.exe"},
                     "authentication": dict(auth) if auth is not None else {}})


def shadow_auth(kind: str, *, ts: str = TS, auth: dict[str, Any] | None = AUTH_BLOCK) -> dict[str, Any]:
    raw: dict[str, Any] = {"user": "SYSTEM", "logon_type": "5", "sid": "S-1-5-18"}
    if auth is not None:
        raw["authentication"] = dict(auth)
    return {"_id": f"oid_{kind}_{ts}", "tenant_id": T, "collector_id": DEV,
            "ingest_time": "2026-10-29T05:32:29+00:00", "activity_identity": f"act_{kind}_{ts}",
            "observation_id": f"obs_{kind}_{ts}", "kind": kind,
            "event": {"ts": ts, "kind": kind, "device_iid": DEV,
                      "process": {"pid": "0x3b0", "image": "C:\\Windows\\System32\\services.exe"},
                      "raw": raw, "provenance": {"ingest_job_id": "raw_abc"}}}


def canon(activity: str, op: str | None, event_type: str, **extra: Any) -> dict[str, Any]:
    doc = ta.stamp({"_id": f"cid_{event_type}", "tenant_id": T, "event_id": f"cev_{event_type}",
                    "event_type": event_type, "event_time": TS,
                    "ingest_time": "2026-10-29T05:32:29+00:00", "host": {},
                    "provenance": {"collector_id": DEV},
                    "additional_fields": {"activity_type": activity, "operation": op,
                                          "severity": "NONE"},
                    "process": {"pid": 4242, "executable_path": "C:\\p.exe"}})
    doc.update(extra)
    return doc


def v3_of(db, **kw) -> dict[str, Any]:
    e3 = asyncio.run(ps.device_trajectory(db, tenant_id=T, refs=[DEV], endpoint_id="ep_1", **kw))
    return v3.build(e3, computer={"hostname": DEV}, identity={"tenant_id": T})


# ── authentication: the class token the source states is the classification ───

def test_every_supported_authentication_kind_is_classified_from_the_canonical_class_token():
    """`activity_type: AUTHENTICATION` names the family; only `event_type` names the outcome."""
    expect = {"logon_success": "AUTH_LOGON_SUCCESS", "logon_failure": "AUTH_LOGON_FAILURE",
              "logon": "AUTH_LOGON", "logoff": "AUTH_LOGOFF",
              "credential_validation": "AUTH_CREDENTIAL_VALIDATION"}
    assert set(expect) == set(_AUTH_KINDS), \
        "§d must support exactly the authentication vocabulary the window projection already does"
    for token, family in expect.items():
        assert from_canonical(canon_auth(token))["kind"] == family
        assert from_shadow(shadow_auth(token))["kind"] == family, "store-independent"


def test_authentication_reaches_v3_as_its_own_event_type_not_as_other():
    out = v3_of(FakeDB(canonical=[canon_auth(t) for t in
                                  ("logon_success", "logon_failure", "logon", "logoff",
                                   "credential_validation")]), page_size=50)
    got = {r["event_type"] for r in out["events"]}
    assert got == {"logon_success", "logon_failure", "logon", "logoff", "credential_validation"}
    assert "other" not in got, "an authentication row rendered as `other` is evidence not shown"
    assert all(r["activity_family"].startswith("AUTH_") for r in out["events"])


def test_v3_event_type_tokens_are_the_tokens_the_v3_renderer_knows():
    """The tokens below are `trajectory_v3/amp/labels.js` KIND keys (commit 6c3a5d88)."""
    for family, token in v3.EVENT_TYPE.items():
        if family.startswith("AUTH_"):
            assert token in ("logon_success", "logon_failure", "logon", "logoff",
                            "credential_validation")


def test_an_authentication_family_is_reported_as_observed():
    e3 = asyncio.run(ps.device_trajectory(FakeDB(canonical=[canon_auth("logon_success")]),
                                          tenant_id=T, refs=[DEV], endpoint_id="ep_1"))
    assert e3["families"]["AUTHENTICATION"]["state"] == "OBSERVED"
    assert e3["families"]["AUTHENTICATION"]["count"] == 1
    assert e3["families"]["PROCESS"]["state"] == "NOT_OBSERVED_IN_THIS_PAGE"


# ── authentication: account, provenance and authentic absence ────────────────

def test_the_account_is_the_account_the_source_named():
    row = v3_of(FakeDB(canonical=[canon_auth("logon_success")]))["events"][0]
    assert row["user"] == "SYSTEM"
    assert row["e3_doc"]["raw"]["logon_type"] == "5"
    assert row["e3_doc"]["raw"]["logon_type_name"] == "SERVICE"
    assert row["e3_doc"]["raw"]["winlog"]["logon_type"] == "5"


def test_the_account_falls_back_to_the_stated_target_user_never_to_a_guess():
    row = v3_of(FakeDB(canonical=[canon_auth("logon_success", username=None)]))["events"][0]
    assert row["user"] == "SYSTEM", "target_user is reported evidence, not an inference"
    row = v3_of(FakeDB(canonical=[canon_auth("logon_success", username=None,
                                             auth={"outcome": "SUCCESS"})]))["events"][0]
    assert "user" not in row, "no account was reported: V3 must say so, not invent one"


def test_a_dash_is_an_absence_and_is_never_rendered_as_a_value():
    """Windows writes `-` for a field absent from THIS record."""
    row = v3_of(FakeDB(canonical=[canon_auth("logon_success")]))["events"][0]
    raw = row["e3_doc"]["raw"]
    assert "source_address" not in raw and "workstation_name" not in raw
    assert "-" not in raw.values()


def test_authentication_without_an_authentication_block_claims_nothing():
    row = v3_of(FakeDB(canonical=[canon_auth("logon_success", auth=None)]))["events"][0]
    assert row["event_type"] == "logon_success", "the stated outcome still classifies the row"
    assert "e3_doc" not in row, "no detail was collected: none is fabricated"


def test_authentication_preserves_identity_timestamp_process_and_provenance():
    out = v3_of(FakeDB(canonical=[canon_auth("logon_success")]))
    row = out["events"][0]
    assert v3.decode_iid(row["event_iid"]), "presentation identity must round-trip"
    assert row["timestamp"].startswith("2026-10-29T05:31:56")
    assert row["timestamp_instant_ms"] is not None
    assert row["pid"] == "0x3b4"
    assert row["image"] == "C:\\Windows\\System32\\services.exe"
    assert row["provenance"]["store"] == pa.STORE_CANONICAL
    assert row["evidence_stores"] == [pa.STORE_CANONICAL]
    assert row["lane_id"], "the server's own lane identity, for Activity Details"


def test_an_unknown_authentication_token_is_not_promoted_to_an_outcome():
    assert from_canonical(canon_auth("mfa_challenge"))["kind"] == "OTHER"


# ── regression: the families that already worked must be untouched ───────────

def test_process_file_network_registry_dns_and_other_are_classified_as_before():
    cases = [(("PROCESS", "create", "process_create"), "PROCESS_START", "process_create"),
             (("PROCESS", "end", "process_end"), "PROCESS_END", "process_end"),
             (("FILE", "CREATE", "file_create"), "FILE_CREATE", "file_create"),
             (("FILE", "write", "file_write"), "FILE_WRITE", "file_write"),
             (("FILE", "delete", "file_delete"), "FILE_DELETE", "file_delete"),
             (("FILE", "rename", "file_rename"), "FILE_MOVE", "file_rename"),
             (("FILE", "execute", "file_execute"), "FILE_EXECUTE", "file_execute"),
             (("NETWORK", None, "network_connect"), "NETWORK_CONNECT", "network_connect"),
             (("DNS", None, "dns_query"), "DNS_QUERY", "dns_query"),
             (("REGISTRY", None, "registry_value_set"), "REGISTRY_SET", "registry_value_set"),
             (("DETECTION", None, "detection"), "DETECTION", "detection"),
             (("SOMETHING_ELSE", None, "sensor_heartbeat"), "OTHER", "other")]
    for (activity, op, event_type), family, token in cases:
        ev = from_canonical(canon(activity, op, event_type))
        assert ev["kind"] == family, f"{activity}/{op} must stay {family}"
        assert v3.EVENT_TYPE[family] == token
    for (activity, op, _), family, _ in cases:
        doc = {"tenant_id": T, "collector_id": DEV, "observation_id": "obs_x",
               "activity_identity": "act_x",
               "event": {"ts": TS, "activity": activity, "op": op, "device_iid": DEV,
                         "process": {"pid": 1, "image": "C:\\p.exe"}}}
        assert from_shadow(doc)["kind"] == family


def test_a_file_execute_flag_is_still_not_a_process_start():
    assert from_canonical(canon("FILE", "execute", "file_execute"))["kind"] == "FILE_EXECUTE"
    assert v3.EVENT_TYPE["FILE_EXECUTE"] == "file_execute"


def test_a_record_with_no_activity_type_pair_is_classified_from_its_class_token():
    """The real Windows shadow observation carries NO `activity`/`op` — only `kind`.

    Before this repair every such record (not only authentication) reached V3 as `other`.
    """
    expect = {"process_create": "PROCESS_START", "process_end": "PROCESS_END",
              "file_create": "FILE_CREATE", "file_write": "FILE_WRITE",
              "file_delete": "FILE_DELETE", "file_rename": "FILE_MOVE",
              "file_execute": "FILE_EXECUTE", "network_connect": "NETWORK_CONNECT",
              "dns_query": "DNS_QUERY", "registry_value_set": "REGISTRY_SET",
              "logon_success": "AUTH_LOGON_SUCCESS", "logoff": "AUTH_LOGOFF"}
    for token, family in expect.items():
        doc = {"tenant_id": T, "collector_id": DEV, "observation_id": f"obs_{token}",
               "activity_identity": f"act_{token}", "kind": token,
               "event": {"ts": TS, "kind": token, "device_iid": DEV,
                         "process": {"pid": 1, "image": "C:\\p.exe"}}}
        assert from_shadow(doc)["kind"] == family, token
        assert from_canonical(canon(None, None, token))["kind"] == family, token
    assert from_shadow({"tenant_id": T, "collector_id": DEV, "observation_id": "o",
                        "event": {"ts": TS, "kind": "sensor_heartbeat",
                                  "device_iid": DEV}})["kind"] == "OTHER"


def test_the_activity_type_pair_still_wins_where_the_writer_populates_it():
    """A writer that states PROCESS/end must not be reclassified by a class token."""
    doc = canon("PROCESS", "end", "process_create")
    assert from_canonical(doc)["kind"] == "PROCESS_END"


def test_a_non_authentication_row_carries_no_authentication_detail():
    out = v3_of(FakeDB(canonical=[canon("PROCESS", "create", "process_create")]))
    assert out["events"][0]["event_type"] == "process_create"
    assert "e3_doc" not in out["events"][0]


def test_mixed_families_on_one_page_each_keep_their_own_classification():
    db = FakeDB(canonical=[canon_auth("logon_success"),
                           canon_auth("logon_failure", ts="2026-10-29T05:31:57.000000+00:00"),
                           canon("PROCESS", "create", "process_create"),
                           canon("FILE", "CREATE", "file_create")])
    out = v3_of(db, page_size=50)
    counts: dict[str, int] = {}
    for r in out["events"]:
        counts[r["event_type"]] = counts.get(r["event_type"], 0) + 1
    assert counts == {"logon_success": 1, "logon_failure": 1, "process_create": 1,
                      "file_create": 1}, counts
