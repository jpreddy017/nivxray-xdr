"""P0 · Detection Attribution.

A detection is written by the XDR detection fabric as a derivation on the
immutable raw event, NOT onto the canonical observation. The trajectory
projection therefore has to join the two, or an observation that a rule
genuinely fired on renders `UNKNOWN_NOT_ASSESSED` — the console telling
the analyst nothing was assessed when something was.

Nothing here may be inferred: the join is `raw_id == ingest_job_id` and
`derivations[].event_id == canonical_event_id` only.
"""
from __future__ import annotations

import pytest

from edr_plane import trajectory_window as tw


RAW = "raw_attr_test_0001"
CEV = "cev_attr_test_0001_0"
EP = "ep_attr_test"


def _obs(raw_id, cev, *, ts="2026-09-06T10:00:00+00:00", tenant="default"):
    return {"tenant_id": tenant, "kind": "process_create",
            "captured_at": ts, "canonical_event_id": cev,
            "ingest_job_id": raw_id, "collector_id": EP,
            "connector_id": EP,
            "event": {"iid": f"evt_{raw_id}", "ts": ts,
                      "device_iid": "dev_attr_test",
                      "kind": "process_create",
                      "process": {"iid": f"proc_{raw_id}", "name": "bash",
                                  "image": "/usr/bin/bash",
                                  "parent_iid": None},
                      "raw": {"pid": 42, "command_line": "/bin/bash x.sh",
                              "rule_label": "bash · process create"},
                      "provenance": {"ingest_job_id": raw_id,
                                     "origin": "collector-live"}}}


def _deriv(cev, *, outcome="DETECTION_MATCHED", rules="rules: EDR-LNX-002",
           verdict="SUSPICIOUS", at="2026-09-06T10:00:05+00:00",
           incident="inc_attr_test"):
    return {"outcome": outcome, "reason": rules, "event_id": cev,
            "verdict_version": verdict, "derived_at": at,
            "replay_generation": 0,
            "detection_content_version": "nivxray::detection_content::x",
            "evidence_ids": [incident] if incident else []}


class _Coll:
    def __init__(self, docs):
        self._docs = docs

    def find(self, query, _proj=None):
        docs = self._docs
        refs = (query.get("endpoint_ref") or {}).get("$in")
        if refs is not None:
            docs = [d for d in docs if d.get("endpoint_ref") in refs]
        if query.get("derivations.outcome"):
            want = query["derivations.outcome"]
            docs = [d for d in docs
                    if any(x.get("outcome") == want
                           for x in d.get("derivations") or [])]

        async def gen():
            for d in docs:
                yield d
        return gen()


class _DB:
    def __init__(self, raws):
        self._raws = raws

    def __getitem__(self, name):
        assert name == tw.RAW_COLLECTION
        return _Coll(self._raws)


def _raw_event(raw_id, derivations, *, tenant="default", ep=EP):
    return {"raw_id": raw_id, "tenant_id": tenant, "endpoint_ref": ep,
            "trust_state": "AUTHENTICATED", "derivations": derivations}


@pytest.mark.asyncio
async def test_a_detected_observation_is_never_unassessed():
    docs = [_obs(RAW, CEV)]
    db = _DB([_raw_event(RAW, [_deriv(CEV)])])
    attr = await tw._detection_attribution(db, docs)
    a = tw._attr_of(docs[0], tw._ev(docs[0]), attr)
    assert a is not None
    cls = tw.classify(tw._ev(docs[0]), a)
    assert cls["disposition"] != tw.DISPOSITION_UNKNOWN
    assert cls["disposition"] == tw.DISPOSITION_SUSPICIOUS
    assert cls["is_detection"] is True

    cat = tw.build_lane_catalogue(docs, attr)
    row = tw._project(docs[0], cat["lanes"][0], a)
    assert row["assessment_state"] == "ASSESSED_BY_DETECTION_FABRIC"
    assert row["rule_ids"] == ["EDR-LNX-002"]
    assert row["detection"]["outcome"] == "DETECTION_MATCHED"
    assert row["detection"]["raw_event_id"] == RAW
    assert row["detection"]["canonical_event_id"] == CEV
    assert row["detection"]["detection_id"] == ("inc_attr_test::rule::"
                                                "EDR-LNX-002")
    # the authoritative engine is named, so the UI cannot say "no
    # detection engine claimed this observation"
    assert row["detected_by"][0]["authoritative"] is True
    assert all(not d.get("telemetry_only") for d in row["detected_by"][:1])
    assert cat["lanes"][0]["detection_count"] == 1


@pytest.mark.asyncio
async def test_a_rule_match_with_no_severe_verdict_is_still_assessed():
    docs = [_obs(RAW, CEV)]
    db = _DB([_raw_event(RAW, [_deriv(CEV, verdict="LIKELY_BENIGN")])])
    attr = await tw._detection_attribution(db, docs)
    a = tw._attr_of(docs[0], tw._ev(docs[0]), attr)
    cls = tw.classify(tw._ev(docs[0]), a)
    assert cls["disposition"] == tw.DISPOSITION_DETECTED
    assert cls["disposition"] != tw.DISPOSITION_UNKNOWN
    assert a["verdict"] == "LIKELY_BENIGN"        # carried verbatim


@pytest.mark.asyncio
async def test_multiple_rules_are_deterministic_and_most_severe_wins():
    docs = [_obs(RAW, CEV)]
    db = _DB([_raw_event(RAW, [
        _deriv(CEV, rules="rules: EDR-LNX-004", verdict="SUSPICIOUS",
               at="2026-09-06T10:00:09+00:00"),
        _deriv(CEV, rules="rules: EDR-LNX-002, EDR-LNX-001",
               verdict="MALICIOUS", at="2026-09-06T10:00:05+00:00")])])
    a = (await tw._detection_attribution(db, docs))[RAW]
    assert a["rule_ids"] == ["EDR-LNX-001", "EDR-LNX-002", "EDR-LNX-004"]
    assert a["verdict"] == "MALICIOUS"
    assert a["detected_at"] == "2026-09-06T10:00:05+00:00"   # first
    cls = tw.classify(tw._ev(docs[0]), a)
    assert cls["disposition"] == tw.DISPOSITION_MALICIOUS


@pytest.mark.asyncio
async def test_a_non_detected_observation_keeps_its_previous_behaviour():
    docs = [_obs(RAW, CEV)]
    db = _DB([_raw_event(RAW, [_deriv(CEV,
                                      outcome="DETECTION_EVALUATED_NO_MATCH",
                                      rules=None, verdict=None)])])
    attr = await tw._detection_attribution(db, docs)
    assert attr == {}
    row = tw._project(docs[0], tw.build_lane_catalogue(docs)["lanes"][0],
                      None)
    assert row["disposition"] == tw.DISPOSITION_UNKNOWN
    assert row["is_detection"] is False
    assert row["detection"] is None
    assert row["assessment_state"] == "NO_DETECTION_CLAIMED_THIS_OBSERVATION"
    assert row["detected_by"][0]["telemetry_only"] is True
    assert row["rule_ids"] == []


@pytest.mark.asyncio
async def test_attribution_never_crosses_a_customer_boundary():
    docs = [_obs(RAW, CEV, tenant="default")]
    db = _DB([_raw_event(RAW, [_deriv(CEV)], tenant="nivx-live")])
    assert await tw._detection_attribution(db, docs) == {}


@pytest.mark.asyncio
async def test_a_forged_identifier_cannot_manufacture_attribution():
    docs = [_obs(RAW, CEV)]
    # the raw event names a DIFFERENT canonical event and a different
    # raw id — nothing about this observation may be claimed from it
    db = _DB([_raw_event("raw_someone_else",
                         [_deriv("cev_someone_else_0")])])
    attr = await tw._detection_attribution(db, docs)
    assert tw._attr_of(docs[0], tw._ev(docs[0]), attr) is None


@pytest.mark.asyncio
async def test_attribution_is_not_derived_from_time_or_process_name():
    """Same endpoint, same process name, one second apart — only the
    observation that OWNS the raw id may be attributed."""
    other_raw, other_cev = "raw_attr_test_0002", "cev_attr_test_0002_0"
    docs = [_obs(RAW, CEV, ts="2026-09-06T10:00:00+00:00"),
            _obs(other_raw, other_cev, ts="2026-09-06T10:00:01+00:00")]
    db = _DB([_raw_event(RAW, [_deriv(CEV)])])
    attr = await tw._detection_attribution(db, docs)
    assert tw._attr_of(docs[0], tw._ev(docs[0]), attr) is not None
    assert tw._attr_of(docs[1], tw._ev(docs[1]), attr) is None
