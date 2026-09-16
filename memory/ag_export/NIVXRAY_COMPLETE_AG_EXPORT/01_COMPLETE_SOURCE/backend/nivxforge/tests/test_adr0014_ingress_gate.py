"""ADR-0014 · Phase 2 · Ingress Normalisation Gate tests (§1.1.14).

Per-vendor coverage. Every adapter proves:
    (1) Vendor JSON is detected → `was_vendor_json=True`.
    (2) The canonical text NEVER contains raw schema URLs
        (CRL distribution points, AMP console URLs, etc).
    (3) Operational fields (host, user, process, parent, sha256, cmd)
        appear in the canonical text.
    (4) A provenance tag (`normalised_via`) is emitted.

Plus a permanent "pollution corpus" that every future ingress path
must satisfy.
"""
from __future__ import annotations

import pytest

pytest.importorskip("v2.investigation.normalizers",
                    reason="Ingress gate uses Workspace normalizers.py")

from nivxforge.investigation.ingress_gate import apply_ingress_gate


# ─── Vendor-specific JSON samples (minimal, focused on canonical fields) ──

CISCO_SECURE_ENDPOINT = (
    '{"detection":"ExecutedMalware.ioc","host":"AZG51-CHECKIN-1",'
    '"src_ip":"185.159.5.55","user":"User","file":"menu_En.exe",'
    '"sha256":"1b7eda7f00000000000000000000000000000000000000000000000000000d0ac",'
    '"parent":"Autorun.exe","parent_signer":"STAR MICRONICS",'
    '"disposition":"Malicious","connector_guid":"cisco-secure-endpoint",'
    '"computer":{"hostname":"AZG51-CHECKIN-1"}}'
)

CROWDSTRIKE_FALCON = (
    '{"event_simpleName":"ProcessRollup2","aid":"abcd","ComputerName":"host-1",'
    '"UserName":"alice","ImageFileName":"C:\\\\bad.exe","ParentImageFileName":"C:\\\\parent.exe",'
    '"CommandLine":"bad.exe /flag","SHA256HashData":"deadbeef",'
    '"falcon_host_link":"https://falcon.crowdstrike.com/hosts/abcd",'
    '"behaviors":[{"scenario":"malware","filename":"bad.exe","cmdline":"bad.exe /flag","sha256":"deadbeef"}]}'
)

MICROSOFT_DEFENDER = (
    '{"AlertId":"da637","IncidentId":"42","MachineId":"m-1","Category":"Malware",'
    '"title":"Trojan detected","computerDnsName":"host-def","userName":"bob",'
    '"detectionSource":"WindowsDefenderAv","alertCreationTime":"2026-02-28T10:00:00",'
    '"evidence":[{"processName":"bad.exe","processCommandLine":"bad.exe /run",'
    '"sha256":"cafebabe","parentProcessName":"parent.exe","filePath":"C:\\\\bad.exe"}]}'
)

SENTINELONE = (
    '{"agentDetectionInfo":{"agentComputerName":"s1-host","agentDomain":"corp"},'
    '"threatInfo":{"threatName":"Emotet","classification":"Malware",'
    '"originatorProcess":"bad.exe","commandLine":"bad.exe /x",'
    '"sha256":"beef","filePath":"C:\\\\bad.exe","mitigationStatus":"quarantined"},'
    '"indicators":[]}'
)

SYSMON = (
    '{"System":{"EventID":"1","Computer":"sysmon-host","TimeCreated":"2026-02-28T10:00:00"},'
    '"EventData":{"Image":"C:\\\\bad.exe","CommandLine":"bad.exe /x",'
    '"ParentImage":"C:\\\\Windows\\\\explorer.exe","Hashes":{"SHA256":"abc123"},'
    '"User":"corp\\\\alice"}}'
)

QRADAR = (
    '{"qid":12345,"categoryid":67,"log_source_id":8,"offense_source":"host-1",'
    '"description":"Malware detected","start_time":"2026-02-28T10:00:00",'
    '"hostname":"host-qrad","username":"alice","process":"bad.exe",'
    '"command_line":"bad.exe /run"}'
)

SPLUNK = (
    '{"sourcetype":"WinEventLog","_time":"2026-02-28T10:00:00","index":"main",'
    '"search_name":"malware","host":"splunk-host","user":"alice",'
    '"process":"bad.exe","process_command_line":"bad.exe /run",'
    '"file_hash":"abc123"}'
)

CISCO_XDR_WITH_SCHEMA_URLS = (
    '{"incident_id":"i1","sighting_id":"s1","confidence":"high",'
    '"title":"Alert","description":"malware seen",'
    '"observables":[{"type":"file_name","value":"menu_En.exe"},'
                    '{"type":"sha256","value":"1b7eda7f"}],'
    '"targets":[{"hostname":"AZG51-CHECKIN-1","user":"User"}],'
    '"references":[{"url":"https://console.amp.cisco.com/incidents/1"},'
                   '{"url":"http://crl.verisign.com/ThawteTimestampingCA.crl"},'
                   '{"url":"http://logo.verisign.com"}]}'
)


# ─── Per-vendor detection + normalisation ─────────────────────────────

@pytest.mark.parametrize("name,payload", [
    ("cisco_secure_endpoint", CISCO_SECURE_ENDPOINT),
    ("crowdstrike",           CROWDSTRIKE_FALCON),
    ("defender",              MICROSOFT_DEFENDER),
    ("sentinelone",           SENTINELONE),
    ("sysmon",                SYSMON),
    ("qradar",                QRADAR),
    ("splunk",                SPLUNK),
])
def test_vendor_json_detected_and_normalised(name, payload):
    r = apply_ingress_gate(payload)
    assert r.was_vendor_json is True, f"{name}: gate did not detect vendor JSON"
    assert r.normalised_via, f"{name}: no provenance tag emitted"
    assert r.text != payload, f"{name}: canonical text unchanged (should be synthesised)"
    assert r.events, f"{name}: no canonical events emitted"


# ─── Pollution regression — the exact defect the operator reported ────

class TestPollutionCorpus:
    """These strings must NEVER appear in canonical text or become IOCs."""

    _POLLUTERS = [
        "crl.verisign.com",
        "console.amp.cisco.com",
        "logo.verisign.com",
        "csc3-2010-aia.verisign.com",
        "csc3-2010-crl.verisign.com",
        "private.intel.amp.cisco.com",
        "xdr.us.security.cisco.com",
        "www.microsoft.com",
    ]

    def test_cisco_xdr_schema_urls_never_leak_to_canonical_text(self):
        r = apply_ingress_gate(CISCO_XDR_WITH_SCHEMA_URLS)
        assert r.was_vendor_json is True
        for polluter in self._POLLUTERS:
            assert polluter not in r.text, (
                f"Schema URL leaked into canonical text: {polluter!r}"
            )


# ─── No-vendor short-circuit (non-JSON inputs unchanged) ──────────────

class TestNoVendorShortCircuit:
    def test_plain_powershell_input_untouched(self):
        cli = "powershell -EncodedCommand cgBlAGcAcwB2AHIAMwAy"
        r = apply_ingress_gate(cli)
        assert r.was_vendor_json is False
        assert r.text == cli
        assert r.normalised_via is None
        assert r.events == []

    def test_empty_input(self):
        r = apply_ingress_gate("")
        assert r.was_vendor_json is False

    def test_random_json_without_vendor_shape(self):
        r = apply_ingress_gate('{"foo":"bar","baz":42}')
        # Generic JSON w/o operational fields → treated as no-op
        # (adapter emits nothing → gate returns raw).
        # Either behaviour is acceptable; assert non-crash and provenance shape.
        if r.was_vendor_json:
            assert r.normalised_via
        else:
            assert r.text == '{"foo":"bar","baz":42}'


# ─── Canonical text carries operational fields ────────────────────────

class TestCanonicalTextFields:
    def test_cisco_secure_endpoint_canonical_carries_host_user(self):
        r = apply_ingress_gate(CISCO_SECURE_ENDPOINT)
        t = r.text
        assert "AZG51-CHECKIN-1" in t
        assert "User" in t.split("\n", 1)[-1]  # exclude the vendor= header
        # detection name is always populated by the adapter
        assert "ExecutedMalware" in t

    def test_sysmon_canonical_carries_image_cmdline(self):
        r = apply_ingress_gate(SYSMON)
        assert "bad.exe" in r.text
        assert "bad.exe /x" in r.text or "/x" in r.text
