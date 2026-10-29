"""CROSS-STORE ACTIVITY IDENTITY — one real activity, one presentation row.

Real Windows sensor evidence lands in BOTH stores. On the G4 acceptance VM the shadow
observation carries the activity identity the writer stamped (`act_…`) while the canonical
record carries none, so §d fell back to a CONTENT hash for the canonical half — and the hash can
never match, because the two stores name the same machine differently (`ep_…` on canonical,
`dev_…` on the shadow observation). Every activity therefore rendered TWICE and inflated every
investigation count.

The identity both stores provably share is the canonical event id the authenticated ingest
boundary assigned to the delivery: `xdr_canonical_evidence.event_id` ==
`v2_shadow_observations.canonical_event_id`, 1:1 per raw delivery. These tests pin matching on
the STATED identities only — never on timestamp, PID or account — and pin that nothing genuine
is lost: two real logons by the same account in the same second stay two rows, and a store-only
observation stays visible.
"""
from __future__ import annotations

import asyncio
from typing import Any

from edr_plane import temporal_authority as ta
from edr_trajectory import production_adapter as pa
from edr_trajectory import production_service as ps
from edr_trajectory import v3_presentation as v3
from edr_trajectory.identity import dedupe
from edr_trajectory.providers import finalize, from_canonical, from_shadow

from test_sd_production_adapter import DEV, T, FakeDB

#: the shadow store names the machine `dev_…` and the canonical store names it `ep_…`
#: — the same endpoint, proven on retained G4 evidence (ep_024ce6515803f7165a11).
EP = "ep_024ce6515803f7165a11"
IID = "dev_f3f6fbf801f1"
TS = "2026-10-29T05:31:56.682329Z"


def sh(cev: str, *, act: str | None = None, ts: str = TS, kind: str = "logon_success",
       tenant: str = T, device: str = EP, iid: str = IID, pid: str = "0x3b4",
       obs: str | None = None, user: str = "SYSTEM") -> dict[str, Any]:
    """A shadow observation shaped like the retained G4 evidence."""
    return {"_id": f"oid_{obs or cev}", "tenant_id": tenant, "collector_id": device,
            "canonical_event_id": cev, "kind": kind,
            "observation_id": obs or f"obs_{cev}", "ingest_job_id": f"raw_{cev}",
            "ingest_time": "2026-10-29T05:32:29+00:00",
            **({"activity_identity": act} if act is not None else {}),
            "event": {"ts": ts, "kind": kind, "device_iid": iid,
                      "process": {"pid": pid, "image": "C:\\Windows\\System32\\services.exe"},
                      "raw": {"authentication": {"outcome": "SUCCESS", "logon_type": "5",
                                                 "target_user": user}},
                      "provenance": {"ingest_job_id": f"raw_{cev}"}}}


def cn(cev: str, *, act: str | None = None, ts: str = TS, kind: str = "logon_success",
       tenant: str = T, device: str = EP, pid: str = "0x3b4",
       user: str = "SYSTEM") -> dict[str, Any]:
    """The canonical twin of the same delivery (no activity identity, as on the real VM)."""
    return ta.stamp({"_id": f"cid_{cev}", "tenant_id": tenant, "event_id": cev,
                     "event_type": kind, "event_time": ts,
                     "ingest_time": "2026-10-29T05:32:29+00:00", "host": {},
                     "provenance": {"collector_id": device, "trace_id": f"raw_{cev}"},
                     "additional_fields": {"activity_type": "AUTHENTICATION", "operation": None,
                                           **({"activity_identity": act} if act is not None else {})},
                     "identity": {"username": user},
                     "process": {"pid": pid,
                                 "executable_path": "C:\\Windows\\System32\\services.exe"},
                     "authentication": {"outcome": "SUCCESS", "logon_type": "5",
                                        "target_user": user}})


def rows(db, **kw) -> dict[str, Any]:
    kw.setdefault("tenant_id", T)
    kw.setdefault("refs", [EP])
    return asyncio.run(pa.page_device_evidence(db, **kw))


def e3(db, **kw) -> dict[str, Any]:
    kw.setdefault("endpoint_id", EP)
    return asyncio.run(ps.device_trajectory(db, tenant_id=T, refs=[EP], **kw))


def pair(cev: str, *, act: str | None = None, **kw) -> tuple[dict[str, Any], dict[str, Any]]:
    """The retained G4 shape: the activity identity is stated on the shadow side only."""
    return finalize(from_shadow(sh(cev, act=act, **kw))), finalize(from_canonical(cn(cev, **kw)))


# ── 1. one genuine activity represented in two stores ────────────────────────

def test_one_activity_in_two_stores_is_one_row():
    out = rows(FakeDB(shadow=[sh("cev_a_0", act="act_a")], canonical=[cn("cev_a_0")]))
    assert len(out["items"]) == 1
    assert out["suppressed_duplicates"] == 1
    ev = out["items"][0]
    assert sorted(ev["sources"]) == [pa.STORE_SHADOW, pa.STORE_CANONICAL]
    assert out["provenance"]["rows_per_store"] == {pa.STORE_SHADOW: 1, pa.STORE_CANONICAL: 1}, \
        "both reads are still reported: the row is merged, the evidence is not hidden"


def test_the_canonical_event_id_is_what_matches_the_two_stores():
    """It is the ONLY identity the real stores share; the content hash cannot match them."""
    s, c = pair("cev_b_0", act="act_b")
    assert s["event_id"] == "act_b" and c["event_id"] == "cev_b_0", \
        "with no activity identity on the canonical side the rendered ids legitimately differ"
    assert (1, "cev_b_0") in s["identity_keys"] and (1, "cev_b_0") in c["identity_keys"]
    assert s["device_id"] == IID and c["device_id"] == EP, \
        "the stores name the machine differently, which is why device is not part of the key"
    merged, suppressed = dedupe([s, c])
    assert len(merged) == 1 and suppressed == 1


def test_the_stated_activity_identity_is_the_surviving_id():
    """Behavior evidence and deep links already hold `act_…`; merging must not move it."""
    merged, _ = dedupe(list(pair("cev_c_0", act="act_c")))
    assert merged[0]["event_id"] == "act_c"
    assert merged[0]["identity_keys"] == [(0, "act_c"), (1, "cev_c_0")]


def test_merging_is_order_independent():
    s, c = pair("cev_d_0", act="act_d")
    a, _ = dedupe([s, c])
    b, _ = dedupe([c, s])
    assert a[0]["event_id"] == b[0]["event_id"] == "act_d"


def test_both_evidence_references_survive_the_merge():
    out = rows(FakeDB(shadow=[sh("cev_e_0", act="act_e")], canonical=[cn("cev_e_0")]))
    ev = out["items"][0]
    assert ev["provenance"]["store"] == pa.STORE_SHADOW
    assert ev["provenance"]["ref"] == "obs_cev_e_0"
    assert ev["provenance"]["raw_ref"] == "raw_cev_e_0"
    assert sorted(ev["sources"]) == [pa.STORE_SHADOW, pa.STORE_CANONICAL]


# ── 2. legitimate activities are never collapsed ─────────────────────────────

def test_two_real_logons_by_the_same_account_in_the_same_instant_stay_two_rows():
    """Identical account, image, PID and timestamp — only the stated identity differs."""
    db = FakeDB(shadow=[sh("cev_f1_0", act="act_f1"), sh("cev_f2_0", act="act_f2")],
                canonical=[cn("cev_f1_0"), cn("cev_f2_0")])
    out = rows(db, page_size=50)
    assert len(out["items"]) == 2
    assert {e["event_id"] for e in out["items"]} == {"act_f1", "act_f2"}


def test_pid_reuse_does_not_merge_two_activities():
    db = FakeDB(shadow=[sh("cev_g1_0", act="act_g1", pid="0x3b4", ts=TS),
                        sh("cev_g2_0", act="act_g2", pid="0x3b4",
                           ts="2026-10-29T06:00:00.000000Z")])
    out = rows(db, page_size=50)
    assert len(out["items"]) == 2


def test_timestamp_pid_and_account_are_never_the_matching_rule():
    """No stated identity anywhere -> the content fallback must NOT fuse distinct deliveries."""
    a = finalize(from_shadow({"tenant_id": T, "collector_id": EP, "observation_id": "o1",
                              "event": {"ts": TS, "kind": "logon_success", "device_iid": IID}}))
    b = finalize(from_shadow({"tenant_id": T, "collector_id": EP, "observation_id": "o2",
                              "event": {"ts": "2026-10-29T05:31:57.000000Z",
                                        "kind": "logon_success", "device_iid": IID}}))
    merged, _ = dedupe([a, b])
    assert len(merged) == 2


# ── 3. replay and duplicate ingestion ────────────────────────────────────────

def test_the_same_observation_read_twice_is_one_row():
    s = finalize(from_shadow(sh("cev_h_0", act="act_h")))
    merged, suppressed = dedupe([s, dict(s)])
    assert len(merged) == 1 and suppressed == 1


def test_a_replayed_delivery_in_both_stores_twice_is_still_one_row():
    db = FakeDB(shadow=[sh("cev_i_0", act="act_i"), sh("cev_i_0", act="act_i", obs="obs_dup")],
                canonical=[cn("cev_i_0")])
    out = rows(db, page_size=50)
    assert len(out["items"]) == 1
    assert sorted(out["items"][0]["sources"]) == [pa.STORE_SHADOW, pa.STORE_CANONICAL]


# ── 4. missing, blank or partial identity ────────────────────────────────────

def test_a_row_with_no_stated_identity_falls_back_to_content_identity():
    s = finalize(from_shadow({"tenant_id": T, "collector_id": EP, "observation_id": "o3",
                              "event": {"ts": TS, "kind": "logon_success", "device_iid": IID}}))
    assert s["identity_keys"] == []
    assert s["event_id"].startswith("ce_")


def test_a_blank_or_whitespace_identity_is_not_an_identity():
    s = finalize(from_shadow(sh("   ", act="")))
    assert s["identity_keys"] == [] and s["event_id"].startswith("ce_")


def test_a_shadow_row_without_an_activity_identity_still_matches_its_canonical_twin():
    """The real G4 shape in reverse: identity stated on one side only."""
    out = rows(FakeDB(shadow=[sh("cev_j_0")], canonical=[cn("cev_j_0", act="act_j")]))
    assert len(out["items"]) == 1
    assert out["items"][0]["event_id"] == "act_j", "the stated activity identity still wins"


def test_a_malformed_identity_never_merges_unrelated_activities():
    a = finalize(from_shadow(sh("cev_k1_0", act=None)))
    b = finalize(from_shadow(sh("cev_k2_0", act=None)))
    merged, _ = dedupe([a, b])
    assert len(merged) == 2


# ── 5. store-only observations are preserved ─────────────────────────────────

def test_a_canonical_only_activity_is_not_lost():
    out = rows(FakeDB(shadow=[sh("cev_l_0", act="act_l")], canonical=[cn("cev_l_0"), cn("cev_m_0")]))
    assert len(out["items"]) == 2
    only = [e for e in out["items"] if e["event_id"] == "cev_m_0"][0]
    assert only["sources"] == [pa.STORE_CANONICAL]


def test_a_shadow_only_activity_is_not_lost():
    out = rows(FakeDB(shadow=[sh("cev_n_0", act="act_n"), sh("cev_o_0", act="act_o")],
                      canonical=[cn("cev_n_0")]))
    assert len(out["items"]) == 2
    only = [e for e in out["items"] if e["event_id"] == "act_o"][0]
    assert only["sources"] == [pa.STORE_SHADOW]


# ── 6. tenant and endpoint isolation ─────────────────────────────────────────

def test_the_same_canonical_event_id_in_another_tenant_never_merges():
    a = finalize(from_shadow(sh("cev_p_0", act="act_p")))
    b = finalize(from_shadow(sh("cev_p_0", act="act_p", tenant="ten_other")))
    merged, suppressed = dedupe([a, b])
    assert len(merged) == 2 and suppressed == 0
    assert {e["tenant_id"] for e in merged} == {T, "ten_other"}


def test_another_tenants_evidence_is_never_read_into_this_endpoints_page():
    db = FakeDB(shadow=[sh("cev_q_0", act="act_q"),
                        sh("cev_r_0", act="act_r", tenant="ten_other")],
                canonical=[cn("cev_q_0")])
    out = rows(db, page_size=50)
    assert len(out["items"]) == 1 and out["items"][0]["tenant_id"] == T


def test_two_endpoints_with_distinct_deliveries_are_never_fused():
    db = FakeDB(shadow=[sh("cev_s_0", act="act_s"),
                        sh("cev_t_0", act="act_t", device="ep_other", iid="dev_other")])
    out = rows(db, page_size=50, refs=[EP, "ep_other"])
    assert len(out["items"]) == 2
    assert {e["device_id"] for e in out["items"]} == {IID, "dev_other"}


# ── 7. ordering, paging, deep links and selection ────────────────────────────

def test_paging_is_duplicate_free_and_loss_free_after_merging():
    docs_s = [sh(f"cev_u{i}_0", act=f"act_u{i}",
                 ts=f"2026-10-29T05:{i:02d}:00.000000Z") for i in range(10)]
    docs_c = [cn(f"cev_u{i}_0", ts=f"2026-10-29T05:{i:02d}:00.000000Z") for i in range(10)]
    db = FakeDB(shadow=docs_s, canonical=docs_c)
    seen, cursor, guard = [], None, 0
    while guard < 10:
        out = rows(db, page_size=4, cursor=cursor)
        seen.extend(e["event_id"] for e in out["items"])
        cursor, guard = out["next_cursor"], guard + 1
        if not cursor:
            break
    assert len(seen) == 10 == len(set(seen))
    assert seen == sorted(seen, key=lambda i: int(i.split("_")[1][1:]), reverse=True), \
        "newest-first order survives the merge"


def test_the_merged_row_keeps_one_stable_presentation_identity():
    db = FakeDB(shadow=[sh("cev_v_0", act="act_v")], canonical=[cn("cev_v_0")])
    first = v3.build(e3(db), computer={"hostname": EP}, identity={"tenant_id": T})["events"][0]
    second = v3.build(e3(db), computer={"hostname": EP}, identity={"tenant_id": T})["events"][0]
    assert first["event_iid"] == second["event_iid"], "a deep link must not move between reads"
    assert v3.decode_iid(first["event_iid"]) == "act_v"


def test_the_merged_row_resolves_to_one_consistent_activity_detail():
    db = FakeDB(shadow=[sh("cev_w_0", act="act_w")], canonical=[cn("cev_w_0")])
    ev = e3(db)["page"]["items"][0]
    det = ps.activity_details(ev)
    assert det["event_id"] == "act_w"
    assert det["authentication"]["outcome"] == "SUCCESS"
    assert det["authentication"]["target_user"] == "SYSTEM"
    assert det["process"]["pid"] == "0x3b4"


# ── 8. classification and counts after merging ───────────────────────────────

def test_classification_and_family_counts_are_not_changed_by_merging():
    db = FakeDB(shadow=[sh("cev_x1_0", act="act_x1"),
                        sh("cev_x2_0", act="act_x2", kind="process_create")],
                canonical=[cn("cev_x1_0"), cn("cev_x2_0", kind="process_create")])
    out = e3(db)
    fam = {k: v["count"] for k, v in out["families"].items() if v["count"]}
    assert fam == {"AUTHENTICATION": 1, "PROCESS": 1}
    built = v3.build(out, computer={"hostname": EP}, identity={"tenant_id": T})
    assert sorted(e["event_type"] for e in built["events"]) == ["logon_success", "process_create"]


def test_counts_are_not_inflated_by_duplicate_representations():
    n = 25
    db = FakeDB(shadow=[sh(f"cev_y{i}_0", act=f"act_y{i}",
                           ts=f"2026-10-29T05:{i:02d}:00.000000Z") for i in range(n)],
                canonical=[cn(f"cev_y{i}_0", ts=f"2026-10-29T05:{i:02d}:00.000000Z")
                           for i in range(n)])
    out = rows(db, page_size=100)
    assert len(out["items"]) == n
    assert out["provenance"]["rows_per_store"] == {pa.STORE_SHADOW: n, pa.STORE_CANONICAL: n}
    assert out["suppressed_duplicates"] == n
