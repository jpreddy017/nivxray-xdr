"""ADR-0014 · Phase 2 · Evidence Priority weight table tests (§1.1.17).

Locks the weight-table contract so a future engine cannot silently
elevate low-signal metadata into a verdict driver.
"""
from __future__ import annotations

from nivxforge.investigation.evidence_priority import (
    WEIGHTS,
    weight_for,
    is_high_signal,
    is_dominant,
)


class TestWeightBoundaries:
    def test_all_weights_in_range(self):
        for kind, w in WEIGHTS.items():
            assert 0 <= w <= 10, f"{kind!r} weight out of range: {w}"

    def test_high_signal_kinds(self):
        high_signal = [
            "child_process_execution", "malware_disposition",
            "quarantine_action", "network_beacon", "persistence",
            "credential_access", "lateral_movement", "lsass_access",
            "sha_matched_family",
        ]
        for kind in high_signal:
            assert weight_for(kind) >= 9, f"{kind} should be dominant"
            assert is_dominant(weight_for(kind))

    def test_vendor_and_ca_infra_zero(self):
        # Non-negotiable: vendor + CA infra must NEVER drive verdicts.
        assert weight_for("vendor_infrastructure") == 0
        assert weight_for("certificate_infrastructure") == 0
        assert weight_for("vendor_metadata") == 0
        assert weight_for("schema_url") == 0

    def test_unknown_kind_returns_zero(self):
        assert weight_for("not-a-real-kind") == 0


class TestClassificationDownWeights:
    def test_vendor_infra_downweights_external_ioc(self):
        # An IOC URL that would normally score 6 gets down-weighted to 0
        # when classified as vendor infrastructure.
        assert weight_for("external_ioc_url",
                          category="vendor_infrastructure") == 0

    def test_ca_infra_downweights_external_ioc(self):
        assert weight_for("external_ioc_domain",
                          category="certificate_infrastructure") == 0

    def test_classification_never_upweights(self):
        # A hash matching a family gets 10 — but if it's mistakenly
        # tagged as vendor_metadata, it's down-weighted to 0. Category
        # can never up-weight a lower base kind.
        assert weight_for("hash_ioc", category="vendor_metadata") == 0

    def test_no_category_returns_base_weight(self):
        assert weight_for("external_ioc_ip") == WEIGHTS["external_ioc_ip"]


class TestConvenienceHelpers:
    def test_is_high_signal_boundary(self):
        assert not is_high_signal(6)
        assert is_high_signal(7)
        assert is_high_signal(10)

    def test_is_dominant_boundary(self):
        assert not is_dominant(8)
        assert is_dominant(9)
