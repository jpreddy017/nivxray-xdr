"""B4 · REPUTATION invariants.

```
CANONICAL EVIDENCE → OBSERVABLE → ADAPTER → PROVIDER(S) → RESULT
```

What this file pins:

* observable extraction keeps the SUBJECT: a process-image SHA-256 and a
  written-file SHA-256 are different facts about different objects;
* `UNKNOWN` never means benign, and `LOOKUP_FAILED` never means
  `UNKNOWN`;
* an unsupported observable type is not an answer about the observable;
* provider disagreement stays visible;
* the local IOC provider is REAL — positive and negative controls — and
  needs no network, no API key and no third party;
* a tenant's IOC never judges another tenant's evidence, cache included.
"""
from __future__ import annotations

import sys

import pytest

sys.path.insert(0, "/app/backend")

from edr_plane import canonical_bridge                          # noqa: E402
from edr_plane.reputation import (AGG_GOOD_ASSERTED,            # noqa: E402
                                  AGG_MALICIOUS_ASSERTED,
                                  AGG_NO_INTELLIGENCE,
                                  AGG_NO_LOOKUP_COMPLETED,
                                  AGG_NOT_SUPPORTED, KNOWN_GOOD,
                                  KNOWN_MALICIOUS, LOOKUP_FAILED,
                                  NOT_SUPPORTED, OBS_DOMAIN, OBS_IP,
                                  OBS_SHA256, SUBJECT_DNS_QUESTION,
                                  SUBJECT_FILE_CONTENT, SUBJECT_NETWORK_PEER,
                                  SUBJECT_PROCESS_IMAGE, UNKNOWN, Observable,
                                  ReputationService, extract)
from edr_plane.reputation.contract import (ReputationProvider,  # noqa: E402
                                           ReputationResult)
from edr_plane.reputation.providers import LocalIOCProvider     # noqa: E402
from tests.edr import fixtures_windows_eventlog as fx           # noqa: E402

TENANT = "ten_b4"
OTHER_TENANT = "ten_b4_other"
ENDPOINT = "ep_b4"
BAD_SHA = "dead" + "a" * 60
GOOD_SHA = "beef" + "b" * 60
IMAGE_SHA = "cafe" + "c" * 60


# ── a fake async Mongo, scoped to this file ──────────────────────────
class _Coll:
    def __init__(self, docs, *, fail=False):
        self.docs, self.fail = docs, fail

    async def find_one(self, query, projection=None):
        if self.fail:
            raise RuntimeError("intelligence store unreachable")
        for d in self.docs:
            if all(d.get(k) == v for k, v in query.items()):
                return {k: v for k, v in d.items() if k != "_id"}
        return None


class _DB:
    def __init__(self, docs, *, fail=False):
        self._coll = _Coll(docs, fail=fail)

    def __getitem__(self, _name):
        return self._coll


IOCS = [
    {"kind": "sha256", "value": BAD_SHA, "source": "customer-intel",
     "severity": "high", "confidence": 0.9, "tags": ["ransomware"],
     "updated_at": "2026-05-01T00:00:00+00:00",
     "intelligence_version": "local-2026-05-01"},
    {"kind": "sha256", "value": GOOD_SHA, "disposition": "KNOWN_GOOD",
     "source": "golden-image-allowlist"},
    {"kind": "domain", "value": "evil.example.com", "source": "customer-intel",
     "tenant_id": TENANT},
    {"kind": "ip", "value": "203.0.113.9", "source": "customer-intel"},
    {"kind": "sha256", "value": "f" * 64, "disposition": "PROBABLY_FINE"},
]


def _service(db) -> ReputationService:
    svc = ReputationService()
    svc.register(LocalIOCProvider(db))
    return svc


def _obs(otype, value, subject=SUBJECT_FILE_CONTENT) -> Observable:
    return Observable(type=otype, value=value, subject=subject,
                      source_field="test", tenant_id=TENANT,
                      evidence_refs=("cev_b4",))


# ── A · observable extraction keeps the subject ──────────────────────
def test_extraction_separates_a_process_image_hash_from_a_file_hash():
    canonical = {
        "event_id": "cev_b4_1", "event_time": "2026-06-01T10:00:00+00:00",
        "process": {"hashes": {"sha256": IMAGE_SHA}},
        "file": {"path": r"C:\tmp\x.dll", "hashes": {"sha256": BAD_SHA}},
        "additional_fields": {"endpoint_id": ENDPOINT},
    }
    got = extract(canonical, tenant_id=TENANT)
    by_subject = {(o.subject, o.value) for o in got}
    assert (SUBJECT_PROCESS_IMAGE, IMAGE_SHA) in by_subject
    assert (SUBJECT_FILE_CONTENT, BAD_SHA) in by_subject
    assert all(o.evidence_refs == ("cev_b4_1",) for o in got)


def test_extraction_reads_a_real_canonical_sysmon_event():
    payload = fx.sysmon(22, 4001, {
        "UtcTime": "2026-06-01 10:04:00.123",
        "ProcessGuid": "{eeeeeeee-0000-0000-0000-00000000000e}",
        "ProcessId": "7364", "Image": r"C:\Windows\System32\cmd.exe",
        "QueryName": "evil.example.com",
        "QueryResults": "203.0.113.9;",
    })
    canonical = canonical_bridge.parse(payload)
    canonical["event_id"] = "cev_b4_dns"
    got = {(o.type, o.value, o.subject) for o in extract(
        canonical, tenant_id=TENANT, endpoint_id=ENDPOINT)}
    assert (OBS_DOMAIN, "evil.example.com", SUBJECT_DNS_QUESTION) in got
    assert (OBS_IP, "203.0.113.9", SUBJECT_DNS_QUESTION) in got


def test_extraction_invents_nothing():
    got = extract({"event_id": "cev_b4_2", "process": {}, "file": {},
                   "network": {}}, tenant_id=TENANT)
    assert got == []


def test_a_malformed_digest_is_not_extracted_as_a_hash():
    got = extract({"event_id": "cev_b4_3",
                   "process": {"hashes": {"sha256": "not-a-hash"}}},
                  tenant_id=TENANT)
    assert got == []


# ── B · the local provider is real ───────────────────────────────────
@pytest.mark.asyncio
async def test_positive_control_a_known_malicious_hash_matches():
    out = await _service(_DB(IOCS)).evaluate([_obs(OBS_SHA256, BAD_SHA)],
                                             tenant_id=TENANT)
    row = out[0]
    assert row["aggregate_state"] == AGG_MALICIOUS_ASSERTED
    result = row["results"][0]
    assert result["verdict"] == KNOWN_MALICIOUS
    assert result["matched"] is True
    assert result["confidence"] == 0.9
    assert result["severity"] == "high"
    assert result["intelligence_timestamp"] == "2026-05-01T00:00:00+00:00"
    assert result["intelligence_version"] == "local-2026-05-01"
    assert result["match_basis"].startswith("iocs:kind=sha256")
    assert result["tenant_scope"] == "platform"
    assert result["queried_at"]


@pytest.mark.asyncio
async def test_negative_control_an_unlisted_hash_is_unknown_not_benign():
    out = await _service(_DB(IOCS)).evaluate([_obs(OBS_SHA256, "1" * 64)],
                                             tenant_id=TENANT)
    row = out[0]
    assert row["aggregate_state"] == AGG_NO_INTELLIGENCE
    assert row["results"][0]["verdict"] == UNKNOWN
    assert row["results"][0]["matched"] is False
    assert "NOT benign" in row["aggregate_meaning"]
    assert "not benign" in row["results"][0]["verdict_meaning"]


@pytest.mark.asyncio
async def test_an_explicit_allowlist_entry_is_known_good():
    out = await _service(_DB(IOCS)).evaluate([_obs(OBS_SHA256, GOOD_SHA)],
                                             tenant_id=TENANT)
    assert out[0]["aggregate_state"] == AGG_GOOD_ASSERTED
    assert out[0]["results"][0]["verdict"] == KNOWN_GOOD


@pytest.mark.asyncio
async def test_an_unreadable_disposition_is_refused_not_guessed():
    out = await _service(_DB(IOCS)).evaluate([_obs(OBS_SHA256, "f" * 64)],
                                             tenant_id=TENANT)
    assert out[0]["results"][0]["verdict"] == LOOKUP_FAILED
    assert out[0]["aggregate_state"] == AGG_NO_LOOKUP_COMPLETED


@pytest.mark.asyncio
async def test_a_domain_and_an_ip_are_both_supported():
    svc = _service(_DB(IOCS))
    out = await svc.evaluate(
        [_obs(OBS_DOMAIN, "evil.example.com", SUBJECT_DNS_QUESTION),
         _obs(OBS_IP, "203.0.113.9", SUBJECT_NETWORK_PEER)],
        tenant_id=TENANT)
    assert [r["aggregate_state"] for r in out] == [AGG_MALICIOUS_ASSERTED,
                                                   AGG_MALICIOUS_ASSERTED]


@pytest.mark.asyncio
async def test_the_local_provider_needs_no_network_or_secret():
    provider = LocalIOCProvider(_DB(IOCS))
    assert provider.offline is True
    assert isinstance(provider, ReputationProvider)
    svc = _service(_DB(IOCS))
    assert svc.providers[0]["offline"] is True


# ── C · failure is never intelligence ────────────────────────────────
@pytest.mark.asyncio
async def test_a_lookup_failure_is_not_unknown():
    out = await _service(_DB(IOCS, fail=True)).evaluate(
        [_obs(OBS_SHA256, BAD_SHA)], tenant_id=TENANT)
    row = out[0]
    assert row["results"][0]["verdict"] == LOOKUP_FAILED
    assert row["aggregate_state"] == AGG_NO_LOOKUP_COMPLETED
    assert row["lookup_failures"][0]["reason"]
    assert "NOT" in row["aggregate_meaning"]


@pytest.mark.asyncio
async def test_a_failed_lookup_is_never_cached_as_an_answer():
    svc = _service(_DB(IOCS, fail=True))
    await svc.evaluate([_obs(OBS_SHA256, BAD_SHA)], tenant_id=TENANT)
    assert svc.cache_size() == 0


def test_a_non_judgement_can_never_be_a_match():
    for verdict in (UNKNOWN, LOOKUP_FAILED, NOT_SUPPORTED):
        with pytest.raises(ValueError):
            ReputationResult(observable=BAD_SHA, observable_type=OBS_SHA256,
                             subject=SUBJECT_FILE_CONTENT,
                             provider_id="p", verdict=verdict, matched=True)


@pytest.mark.asyncio
async def test_an_unsupported_observable_type_is_not_an_answer():
    class NarrowProvider:
        provider_id = "test.sha256_only"
        provider_version = "1.0.0"
        supported_types = (OBS_SHA256,)
        offline = True

        async def lookup(self, observables, *, tenant_id):
            raise AssertionError("must not be asked about an unsupported "
                                 "type")

    svc = ReputationService()
    svc.register(NarrowProvider())
    out = await svc.evaluate(
        [_obs(OBS_DOMAIN, "example.com", SUBJECT_DNS_QUESTION)],
        tenant_id=TENANT)
    assert out[0]["aggregate_state"] == AGG_NOT_SUPPORTED
    assert out[0]["results"][0]["verdict"] == NOT_SUPPORTED


# ── D · disagreement stays visible ───────────────────────────────────
@pytest.mark.asyncio
async def test_provider_disagreement_is_not_silently_collapsed():
    class GoodSayer:
        provider_id = "test.says_good"
        provider_version = "1.0.0"
        supported_types = (OBS_SHA256,)
        offline = True

        async def lookup(self, observables, *, tenant_id):
            return [ReputationResult(
                observable=o.value, observable_type=o.type, subject=o.subject,
                provider_id=self.provider_id, verdict=KNOWN_GOOD,
                matched=True, match_basis="test:allowlist")
                for o in observables]

    svc = _service(_DB(IOCS))
    svc.register(GoodSayer())
    row = (await svc.evaluate([_obs(OBS_SHA256, BAD_SHA)],
                              tenant_id=TENANT))[0]
    assert row["provider_disagreement"] is True
    assert len(row["results"]) == 2
    verdicts = {r["provider_id"]: r["verdict"] for r in row["results"]}
    assert verdicts["nivxforge.local_ioc"] == KNOWN_MALICIOUS
    assert verdicts["test.says_good"] == KNOWN_GOOD
    # a malicious assertion is never erased by a good one
    assert row["aggregate_state"] == AGG_MALICIOUS_ASSERTED


# ── E · tenant scope, cache included ─────────────────────────────────
@pytest.mark.asyncio
async def test_a_tenant_scoped_ioc_never_judges_another_tenant():
    svc = _service(_DB(IOCS))
    mine = await svc.evaluate(
        [_obs(OBS_DOMAIN, "evil.example.com", SUBJECT_DNS_QUESTION)],
        tenant_id=TENANT)
    theirs = await svc.evaluate(
        [Observable(type=OBS_DOMAIN, value="evil.example.com",
                    subject=SUBJECT_DNS_QUESTION, source_field="test",
                    tenant_id=OTHER_TENANT)],
        tenant_id=OTHER_TENANT)
    assert mine[0]["aggregate_state"] == AGG_MALICIOUS_ASSERTED
    assert theirs[0]["aggregate_state"] == AGG_NO_INTELLIGENCE, (
        "a tenant-scoped IOC answered for a tenant that does not own it")


@pytest.mark.asyncio
async def test_the_cache_records_its_own_provenance_and_freshness():
    svc = _service(_DB(IOCS))
    first = await svc.evaluate([_obs(OBS_SHA256, BAD_SHA)], tenant_id=TENANT)
    second = await svc.evaluate([_obs(OBS_SHA256, BAD_SHA)], tenant_id=TENANT)
    assert first[0]["results"][0]["cache_state"] == "CACHE_MISS"
    hit = second[0]["results"][0]
    assert hit["cache_state"] == "CACHE_HIT_FRESH"
    assert hit["provenance"]["cache_queried_at"]
    assert hit["provenance"]["cache_read_at"]
    assert hit["provenance"]["cache_ttl_seconds"] == 3600
    assert hit["verdict"] == KNOWN_MALICIOUS


@pytest.mark.asyncio
async def test_an_expired_entry_is_served_as_stale_not_as_fresh():
    docs = [{"kind": "sha256", "value": BAD_SHA, "source": "customer-intel",
             "valid_until": "2020-01-01T00:00:00+00:00"}]
    svc = _service(_DB(docs))
    await svc.evaluate([_obs(OBS_SHA256, BAD_SHA)], tenant_id=TENANT)
    again = await svc.evaluate([_obs(OBS_SHA256, BAD_SHA)], tenant_id=TENANT)
    assert again[0]["results"][0]["cache_state"] == "CACHE_HIT_STALE"
