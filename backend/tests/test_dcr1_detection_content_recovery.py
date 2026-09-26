"""DCR-1 · detection content recovery, under the product-neutral allowlist.

What must be proven is not "a binding was added" but that the recovered
detections evaluate REAL observed values and refuse everything else:

* a Zeek DNS observation can satisfy an allowlisted DNS predicate authored
  for `product: windows`, WITHOUT the evidence being represented as Windows;
* the allowlist is a closed contract — a rule that also inspects a
  product-specific field is not eligible, and a canonical field being
  mapped never makes a category neutral;
* absent field, wrong evidence semantics, missing provenance and another
  tenant's watchlist entry all produce NO match;
* every match cites predicate → observed value → canonical evidence_ref.
"""
from __future__ import annotations

import copy
import uuid

import pytest

from detection_content import ioc_watchlist as iw
from detection_content import rule_store_binding as rsb
from detection_content.dcr1_product_neutral import (CATEGORY_CONTRACT,
                                                    PRODUCT_NEUTRAL_CATEGORIES,
                                                    evidence_admissible,
                                                    neutral_eligibility)
from detection_content.detection_estate import estate
from detection_content.rule_store_binding import (_Binding,
                                                  evaluate_store_rules,
                                                  flatten_with_paths)

STAMP = uuid.uuid4().hex[:10]
TEN = "default"
OTHER = f"dcr1-other-{STAMP}"
PROOF_SOURCE = f"dcr1-test-{STAMP}"

_DNS_RULE = {"selection": {"QueryName|endswith": [".top", ".xyz"]},
             "condition": "selection"}


def _doc(**over):
    d = {"id": f"det_dns_{STAMP}", "upstream_id": f"net_dns_{STAMP}",
         "title": "Suspicious DNS Query to Uncommon TLDs",
         "license_policy_state": "PERMITTED", "state": "VALIDATED",
         "enabled": "True", "level": "low",
         "logsource": {"category": "dns", "product": "windows"},
         "attack_techniques": "['T1071.004']", "rule_type": "field_match",
         "detection": _DNS_RULE}
    d.update(over)
    return d


def _ioc_doc(field, namespace, **over):
    d = {"id": f"det_ioc_{STAMP}", "upstream_id": f"ioc_{field}_{STAMP}",
         "title": "IOC Watchlist Match", "license_policy_state": "PERMITTED",
         "state": "VALIDATED", "enabled": "True", "level": "informational",
         "logsource": {}, "rule_type": "ioc", "attack_techniques": "['T1071']",
         "detection": {"selection": {f"{field}|watchlist": namespace},
                       "condition": "selection"}}
    d.update(over)
    return d


def _zeek_dns(query="evil.xyz", tenant=TEN, answer="198.51.100.9"):
    return {"event_id": f"zeek-dns-{STAMP}", "tenant_id": tenant,
            "source_vendor": "Zeek",
            "source_product": "Zeek / Corelight network sensor",
            "event_type": "dns_query",
            "network": {"src_ip": "10.77.0.31", "src_port": 53211,
                        "dest_ip": "10.77.0.1", "dest_port": 53,
                        "protocol": "udp", "dns_query": query,
                        "dns_response_ips": [answer]},
            "provenance": {"dsm_id": "zeek-json", "collector_id": "col-1",
                           "trace_id": f"tr-{STAMP}"}}


def _zeek_conn(dest_ip="198.51.100.9", tenant=TEN):
    return {"event_id": f"zeek-conn-{STAMP}", "tenant_id": tenant,
            "source_vendor": "Zeek",
            "source_product": "Zeek / Corelight network sensor",
            "event_type": "network_connect",
            "network": {"src_ip": "10.77.0.31", "dest_ip": dest_ip,
                        "dest_port": 443, "protocol": "tcp",
                        "dns_query": ""},
            "provenance": {"dsm_id": "zeek-json", "collector_id": "col-1",
                           "trace_id": f"tr-{STAMP}"}}


def _edr_hash(sha256, tenant=TEN):
    return {"event_id": f"leef-{STAMP}", "tenant_id": tenant,
            "source_vendor": "IBM", "source_product": "QRadar EDR",
            "event_type": "leef_event",
            "process": {"name": "certutil.exe", "hashes": {"sha256": sha256}},
            "provenance": {"dsm_id": "cef-leef", "collector_id": "col-2",
                           "trace_id": f"tr-{STAMP}"}}


@pytest.fixture()
def only(monkeypatch):
    def _install(*bindings):
        monkeypatch.setattr(rsb, "load_bindings",
                            lambda force=False: list(bindings))
    return _install


@pytest.fixture()
def watchlist():
    from deps import sync_collection
    col = sync_collection(iw.WATCHLIST_COLLECTION)
    seeded = []

    def _add(kind, value, tenant_id=None):
        doc = {"kind": kind, "value": value, "source": PROOF_SOURCE,
               "severity": "high", "tags": ["dcr1-test"]}
        if tenant_id:
            doc["tenant_id"] = tenant_id
        col.insert_one(dict(doc))
        seeded.append((kind, value))
        return value

    yield _add
    for kind, value in seeded:
        col.delete_many({"kind": kind, "value": value,
                         "source": PROOF_SOURCE})


# ── the allowlist contract itself ───────────────────────────────────

def test_the_allowlist_is_closed_and_excludes_execution_behaviour():
    assert PRODUCT_NEUTRAL_CATEGORIES == {"dns", "network"}
    for excluded in ("process_creation", "registry_set", "file", "proxy",
                     "ids", "image_load"):
        ok, why = neutral_eligibility(excluded, {"CommandLine"})
        assert not ok and "allowlist" in why


def test_a_canonical_field_is_not_automatically_product_neutral():
    # `sha256` IS canonical and IS mapped — and still gives no rule the
    # right to evaluate cross-product.
    assert "sha256" in rsb._FIELD_MAP
    for cat, contract in CATEGORY_CONTRACT.items():
        assert not (contract["fields"] & {"sha256", "CommandLine", "Image"}), cat
    ok, why = neutral_eligibility("dns", {"QueryName", "CommandLine"})
    assert not ok and "does not own" in why


def test_a_dns_rule_that_also_reads_a_process_field_stays_product_gated():
    mixed = dict(_DNS_RULE)
    mixed["selection"] = {**_DNS_RULE["selection"],
                          "CommandLine|contains": "curl"}
    b = _Binding(_doc(detection=mixed))
    assert b.state == "NO_TELEMETRY"
    assert not b.product_neutral
    assert "does not own" in b.reason


def test_evidence_semantics_are_required_not_merely_the_field():
    # A Sysmon EID3 record can carry a destination hostname in
    # `network.dns_query`; it is NOT a DNS observation.
    conn = _zeek_conn()
    conn["network"]["dns_query"] = "198.51.100.9"
    ok, why = evidence_admissible("dns", conn)
    assert not ok and "not a 'dns' observation" in why


def test_provenance_is_required_for_neutral_evaluation():
    ev = _zeek_dns()
    ev["provenance"] = {}
    assert not evidence_admissible("dns", ev)[0]
    ev2 = _zeek_dns()
    ev2.pop("tenant_id")
    assert not evidence_admissible("dns", ev2)[0]


# ── the recovered DNS detection ─────────────────────────────────────

def test_zeek_dns_satisfies_a_windows_authored_dns_predicate(only):
    b = _Binding(_doc())
    assert b.state == "BOUND" and b.product_neutral and b.product == "windows"
    only(b)
    ev = _zeek_dns(query=f"dcr1-{STAMP}.xyz")
    hits = evaluate_store_rules(ev)
    assert [h["rule_id"] for h in hits] == [f"det_dns_{STAMP}"]
    hit = hits[0]
    # …and the evidence is NOT represented as Windows anywhere.
    assert hit["product_neutral"] is True
    assert rsb._event_product(ev) != "windows"
    assert ev["source_vendor"] == "Zeek"
    # predicate → observed value → canonical evidence_ref → detection
    cond = hit["citation"]["matched_conditions"][0]
    assert cond["predicate"] == "QueryName|endswith"
    assert cond["canonical_field"] == "network.dns_query"
    assert cond["observed_value"] == f"dcr1-{STAMP}.xyz"
    assert cond["evidence_ref"] == f"xdr_canonical_evidence/{ev['event_id']}"
    assert hit["citation"]["citation_completeness"] == "CITED"


def test_the_benign_and_absent_and_wrong_type_cases_produce_no_match(only):
    only(_Binding(_doc()))
    assert evaluate_store_rules(_zeek_dns(query=f"dcr1-{STAMP}.com")) == []
    absent = _zeek_dns()
    absent["network"]["dns_query"] = ""
    assert evaluate_store_rules(absent) == []
    assert "QueryName" not in flatten_with_paths(absent)[0]
    wrong = _zeek_dns(query=f"dcr1-{STAMP}.xyz")
    wrong["event_type"] = "network_connect"
    assert evaluate_store_rules(wrong) == []
    no_prov = _zeek_dns(query=f"dcr1-{STAMP}.xyz")
    no_prov["provenance"] = {}
    assert evaluate_store_rules(no_prov) == []


def test_a_product_gated_rule_is_unaffected_by_dcr1(only):
    linux = _doc(id="det_lin", logsource={"category": "process_creation",
                                          "product": "linux"},
                 detection={"selection": {"CommandLine|contains": "/dev/tcp/"},
                            "condition": "selection"})
    b = _Binding(linux)
    assert b.state == "BOUND" and not b.product_neutral
    only(b)
    win_ev = {"event_id": "w1", "tenant_id": TEN, "source_product": "Windows",
              "process": {"command_line": "x /dev/tcp/1.2.3.4/4444"},
              "provenance": {"dsm_id": "microsoft-sysmon",
                             "collector_id": "c", "trace_id": "t"}}
    assert evaluate_store_rules(win_ev) == []


# ── the IOC watchlist contract ──────────────────────────────────────

def test_the_ioc_contract_refuses_anything_it_did_not_declare():
    for detection, expect in [
        ({"selection": {"dst_ip|contains": "ioc.network.ip"},
          "condition": "selection"}, "modifier"),
        ({"selection": {"src_ip|watchlist": "ioc.network.ip"},
          "condition": "selection"}, "not in the IOC contract"),
        ({"selection": {"dst_ip|watchlist": "ioc.anything.else"},
          "condition": "selection"}, "contract binds it to"),
        ({"condition": "selection"}, "declares no watchlist predicate"),
    ]:
        b = _Binding(_ioc_doc("x", "y", detection=detection))
        assert b.state == "UNSUPPORTED_BY_IOC_CONTRACT", detection
        assert expect in b.reason, b.reason


def test_hash_watchlist_matches_only_a_genuinely_observed_hash(only,
                                                               watchlist):
    b = _Binding(_ioc_doc("hash.sha256", "ioc.file.sha256"))
    assert b.state == "BOUND" and b.contract == "ioc"
    only(b)
    bad = watchlist("sha256", f"{STAMP}{'a' * (64 - len(STAMP))}")
    hits = evaluate_store_rules(_edr_hash(bad))
    assert len(hits) == 1
    cond = hits[0]["citation"]["matched_conditions"][0]
    assert cond["canonical_field"] == "process.hashes.sha256"
    assert cond["observed_value"] == bad
    assert cond["watchlist_entry"]["source"] == PROOF_SOURCE
    assert hits[0]["citation"]["declared_semantics"] == "ANY_OF"
    # a different hash, and evidence with no hash observed
    assert evaluate_store_rules(_edr_hash("b" * 64)) == []
    none_observed = _edr_hash(bad)
    none_observed["process"]["hashes"] = {}
    assert evaluate_store_rules(none_observed) == []


def test_network_watchlist_never_fabricates_a_resolution(only, watchlist):
    b = _Binding(_ioc_doc("dst_domain", "ioc.network.domain",
                          detection={"selection": {
                              "dst_ip|watchlist": "ioc.network.ip",
                              "dst_domain|watchlist": "ioc.network.domain"},
                              "condition": "selection"}))
    assert b.state == "BOUND"
    only(b)
    bad_domain = watchlist("domain", f"dcr1-c2-{STAMP}.example-c2.net")
    bad_ip = watchlist("ip", "203.0.113.77")

    dns_hit = evaluate_store_rules(_zeek_dns(query=bad_domain))
    assert len(dns_hit) == 1
    matched = dns_hit[0]["citation"]["matched_conditions"]
    assert [m["canonical_field"] for m in matched] == ["network.dns_query"]
    # the IP predicate on DNS evidence is refused, not silently evaluated:
    # the resolver address is not a C2 peer.
    refused = [c for c in dns_hit[0]["citation"]["evaluated_conditions"]
               if c["predicate"] == "dst_ip|watchlist"]
    assert refused[0]["result"] == "EVIDENCE_TYPE_NOT_ADMISSIBLE"

    assert len(evaluate_store_rules(_zeek_conn(dest_ip=bad_ip))) == 1
    # A flow to the address a listed domain once answered is NOT a domain
    # match: no resolution is reconstructed.
    stale = evaluate_store_rules(_zeek_conn(dest_ip="198.51.100.9"))
    assert stale == []
    assert evaluate_store_rules(_zeek_dns(query="benign.example.com")) == []


def test_a_tenant_scoped_watchlist_entry_never_judges_another_tenant(
        only, watchlist):
    only(_Binding(_ioc_doc("dst_domain", "ioc.network.domain")))
    scoped = watchlist("domain", f"dcr1-tenant-{STAMP}.example-c2.net",
                       tenant_id=OTHER)
    assert evaluate_store_rules(_zeek_dns(query=scoped, tenant=TEN)) == []
    assert len(evaluate_store_rules(_zeek_dns(query=scoped,
                                              tenant=OTHER))) == 1


def test_evaluation_is_deterministic_on_replay(only, watchlist):
    only(_Binding(_doc()))
    ev = _zeek_dns(query=f"dcr1-{STAMP}.xyz")
    first = evaluate_store_rules(copy.deepcopy(ev))
    second = evaluate_store_rules(copy.deepcopy(ev))
    assert first == second and len(first) == 1


# ── estate accounting ───────────────────────────────────────────────

def test_the_estate_separates_detections_from_fixtures_and_references():
    docs = [{"title": "real one", "source": "SigmaHQ"},
            {"title": "real one", "source": "SigmaHQ"},
            {"title": "T1059", "source": "MITRE ATT&CK",
             "upstream_id": "attack_T1059.001"},
            {"title": "chain", "source": "NivXRay-correlation",
             "upstream_id": "cor_1", "lane": "correlation"},
            {"title": "proprietary demo", "source": "TestVendor"},
            {"title": "lifecycle test", "source": "NivXRay-native"}]
    e = estate(docs)
    assert e["store_rules_counted"] == 6
    assert e["authored_detections_distinct"] == 1
    assert e["authored_detection_duplicate_copies"] == 1
    assert e["mitre_reference_entries"] == 1
    assert e["correlation_mirrors"] == 1
    assert e["test_fixtures"] == 2


def test_the_live_report_never_counts_fixtures_as_detections():
    rep = rsb.binding_report()
    e = rep["detection_estate"]
    assert e["store_rules_counted"] == rep["authored_rules"]
    assert (e["authored_detections_distinct"]
            + e["authored_detection_duplicate_copies"]
            + e["mitre_reference_entries"] + e["correlation_mirrors"]
            + e["test_fixtures"]) == e["store_rules_counted"]
    assert rep["product_neutral_contract"]["product_neutral_categories"] \
        == ["dns", "network"]
    assert rep["ioc_contract"]["declared_semantics"] == "ANY_OF"


def test_the_store_rules_dcr1_recovered_are_bound_in_the_live_store():
    rep = rsb.binding_report()
    dns = next((r for r in rep["rules"]
                if r["upstream_id"] == "net_dns_susp_tld"), None)
    if dns is None or dns["binding_state"] == "LICENSE_BLOCKED":
        pytest.skip("this database's copy of the authored store is absent or "
                    "licence-blocked; the live-store proof runs in "
                    "scripts/p0_dcr1_detection_recovery_proof.py")
    bound = {r["upstream_id"]: r for r in rep["rules"]
             if r["binding_state"] == "BOUND"}
    assert "net_dns_susp_tld" in bound
    assert bound["net_dns_susp_tld"]["product_neutral"] is True
    assert "ioc_file_hash_watchlist" in bound
    assert "ioc_network_watchlist" in bound
    assert bound["ioc_file_hash_watchlist"]["evaluation_contract"] == "ioc"
