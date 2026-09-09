"""Tests for the Semantic Alias Registry (v1).

Governance contracts (see NIVXRAY_ARCHITECTURE_VISION.md):
  · Registry is versioned
  · Registry contains zero vendor knowledge
  · Every alias declares a confidence score
  · Unknown fields return an empty list (supported state)
  · Registry contains no ambiguous aliases
"""
from __future__ import annotations

import re

import pytest

from nivxforge.investigation.pipeline import semantic_alias_registry as reg


class TestRegistryContract:

    def test_version_constant_present(self):
        assert reg.SEMANTIC_ALIAS_REGISTRY_VERSION == "semantic_alias_registry_v1"

    def test_foundational_concepts_declared(self):
        # Every concept the owner mandated must be present.
        mandated = {
            "Host", "User", "Process", "Command", "File", "Directory",
            "Hash", "IP", "Domain", "URL", "Email", "Registry",
            "Service", "ScheduledTask", "Certificate",
            "NetworkConnection", "Port", "Protocol", "NamedPipe",
            "Mutex", "Detection", "Alert", "MITRE",
        }
        assert mandated.issubset(set(reg.CONCEPTS))

    def test_registry_snapshot_returns_all_concepts(self):
        snap = reg.registry_snapshot()
        assert set(snap.keys()) == set(reg.CONCEPTS)
        # Every concept has at least one alias
        for concept, aliases in snap.items():
            assert len(aliases) >= 1, f"{concept} has no aliases"

    def test_every_alias_carries_confidence(self):
        for concept in reg.CONCEPTS:
            for a in reg.aliases_for(concept):
                assert 0.0 < a.confidence <= 1.0
                assert a.concept == concept
                assert a.surface  # non-empty

    def test_registry_has_no_vendor_knowledge(self):
        # Aliases must be canonical concept surfaces, not vendor
        # product / brand names. Sample a curated blocklist that
        # would appear only in a vendor-aware registry.
        VENDOR_TOKENS = {
            "crowdstrike", "falcon", "mde", "defender", "microsoft",
            "cisco", "sentinelone", "carbonblack", "cortex", "xdr",
            "sysmon", "windowsevent", "elastic", "splunk", "qradar",
            "arcsight", "zeek", "suricata", "sophos", "mandiant",
            "tanium", "wazuh",
        }
        for concept in reg.CONCEPTS:
            for a in reg.aliases_for(concept):
                assert a.surface.lower() not in VENDOR_TOKENS, (
                    f"vendor-branded alias detected: {a.surface} "
                    f"under {concept}"
                )

    def test_registry_creates_no_ambiguity(self):
        # No normalized surface maps to two different concepts.
        seen: dict = {}
        for concept in reg.CONCEPTS:
            for a in reg.aliases_for(concept):
                if a.surface in seen:
                    assert seen[a.surface] == concept, (
                        f"ambiguous alias {a.surface!r} maps to "
                        f"{seen[a.surface]} and {concept}"
                    )
                seen[a.surface] = concept


class TestLookup:

    def test_direct_hostname_resolves_to_host(self):
        matches = reg.lookup("hostname")
        assert len(matches) == 1
        assert matches[0].concept == "Host"
        assert matches[0].confidence == 1.0
        assert matches[0].registry_version == \
            reg.SEMANTIC_ALIAS_REGISTRY_VERSION

    def test_device_name_normalizes_to_host(self):
        # DeviceName should normalize (lowercase, drop separators) and hit
        matches = reg.lookup("DeviceName")
        assert len(matches) == 1
        assert matches[0].concept == "Host"

    def test_underscore_case_normalizes(self):
        # sha_256 → sha256 → Hash
        matches = reg.lookup("SHA_256")
        assert len(matches) == 1
        assert matches[0].concept == "Hash"

    def test_dot_case_normalizes(self):
        # host.name → hostname → Host
        matches = reg.lookup("host.name")
        assert len(matches) == 1
        assert matches[0].concept == "Host"

    def test_unknown_field_returns_empty_list(self):
        # This is the supported success state, not an error.
        assert reg.lookup("some_completely_unseen_field_xyz") == []

    def test_none_and_empty_string(self):
        assert reg.lookup(None) == []  # type: ignore[arg-type]
        assert reg.lookup("") == []

    def test_lookup_returns_registry_version_provenance(self):
        for f in ("hostname", "username", "sha256", "processname"):
            matches = reg.lookup(f)
            assert matches, f"expected match for {f}"
            assert matches[0].registry_version == \
                reg.SEMANTIC_ALIAS_REGISTRY_VERSION


class TestOwnerExampleParity:
    """The owner explicitly listed these aliases per concept — verify."""

    @pytest.mark.parametrize("surface,concept", [
        ("hostname", "Host"),
        ("computer", "Host"),
        ("device", "Host"),
        ("machine", "Host"),
        ("endpoint", "Host"),
        ("user", "User"),
        ("username", "User"),
        ("process", "Process"),
        ("commandline", "Command"),
        ("filename", "File"),
        ("directory", "Directory"),
        ("md5", "Hash"),
        ("sha256", "Hash"),
        ("ipaddress", "IP"),
        ("domain", "Domain"),
        ("url", "URL"),
        ("email", "Email"),
        ("registrykey", "Registry"),
        ("servicename", "Service"),
        ("scheduledtask", "ScheduledTask"),
        ("thumbprint", "Certificate"),
        ("networkconnection", "NetworkConnection"),
        ("port", "Port"),
        ("protocol", "Protocol"),
        ("namedpipe", "NamedPipe"),
        ("mutex", "Mutex"),
        ("detectionname", "Detection"),
        ("alertname", "Alert"),
        ("mitreattack", "MITRE"),
    ])
    def test_concept_alias(self, surface, concept):
        m = reg.lookup(surface)
        assert m, f"{surface} not resolved"
        assert m[0].concept == concept
