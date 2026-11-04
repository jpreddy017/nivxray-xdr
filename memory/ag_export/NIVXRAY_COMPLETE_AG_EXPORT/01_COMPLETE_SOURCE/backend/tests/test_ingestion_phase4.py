"""Unit tests · v2/ingestion · Investigation Ingestion Engine (Phase 4.1).

These are pure-function tests. No Mongo, no HTTP. They exercise:
  * Format detection
  * Source detection
  * Every normalizer (Sysmon XML · Windows Security XML · JSON · CSV)
  * ZIP dispatch
  * CES → CEM v1 bridge
  * The Golden Investigation Corpus (round-trip against build_investigation)
  * Determinism (byte-identical output for identical input)
"""
from __future__ import annotations
import sys
import io
import json
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # /app/backend

from v2.ingestion.format_detector import detect_format
from v2.ingestion.source_detector import (
    detect_source, SOURCE_SYSMON, SOURCE_WINDOWS_SECURITY,
    SOURCE_CANONICAL_JSON, SOURCE_GENERIC_CSV,
)
from v2.ingestion.canonical import (
    CanonicalEventRecord, IngestionProvenance, ces_to_cem_dict, CES_FIELDS,
)
from v2.ingestion.metrics import IngestionMetrics
from v2.ingestion.pipeline import normalize_bytes
from v2.ingestion.golden_corpus import GOLDEN_CORPUS, list_datasets, get_dataset
from v2.ingestion.normalizers import (
    normalize_sysmon_xml, normalize_winsec_xml,
    normalize_json, normalize_csv,
)
from v2.investigation import build_investigation


# ─── Fixtures ────────────────────────────────────────────────────────
SYSMON_XML = """<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-...}"/>
      <EventID>1</EventID>
      <TimeCreated SystemTime="2026-02-25T14:00:00.000Z"/>
      <Computer>WKS-01</Computer>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -EncodedCommand SQBFAFgAKABJAG4A</Data>
      <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="ParentCommandLine">cmd.exe /c start powershell</Data>
      <Data Name="ProcessGuid">{aaaa-bbbb}</Data>
      <Data Name="ProcessId">1000</Data>
      <Data Name="ParentProcessId">500</Data>
      <Data Name="User">CORP\\alice</Data>
      <Data Name="Hashes">SHA256=abcdef1234</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon"/>
      <EventID>3</EventID>
      <TimeCreated SystemTime="2026-02-25T14:00:05.000Z"/>
      <Computer>WKS-01</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="DestinationIp">185.234.219.5</Data>
      <Data Name="DestinationPort">443</Data>
      <Data Name="Protocol">tcp</Data>
    </EventData>
  </Event>
</Events>
""".encode("utf-8")

WINSEC_XML = """<?xml version="1.0"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625}"/>
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-02-25T14:01:00Z"/>
      <Computer>DC-01</Computer>
    </System>
    <EventData>
      <Data Name="NewProcessName">C:\\Windows\\System32\\net.exe</Data>
      <Data Name="CommandLine">net user administrator /active:yes</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="TargetUserName">admin</Data>
      <Data Name="NewProcessId">1234</Data>
      <Data Name="ProcessId">500</Data>
    </EventData>
  </Event>
</Events>
""".encode("utf-8")

CANONICAL_JSON = json.dumps({
    "events": [
        {"timestamp": "2026-02-25T14:00:00Z",
         "provider": "Microsoft-Windows-Sysmon", "event_id": 1,
         "computer": "WKS-01", "image": "C:\\Windows\\explorer.exe",
         "command_line": "explorer.exe", "parent_image": "userinit.exe"},
        {"timestamp": "2026-02-25T14:00:02Z",
         "provider": "Microsoft-Windows-Sysmon", "event_id": 3,
         "computer": "WKS-01", "image": "chrome.exe",
         "dst_ip": "1.1.1.1", "dst_port": "443"},
    ]
}).encode("utf-8")

GENERIC_CSV = """timestamp,provider,event_id,computer,image,command_line,parent_image
2026-02-25T14:00:00Z,Microsoft-Windows-Sysmon,1,HR-11,resume.exe,resume.exe,explorer.exe
2026-02-25T14:00:01Z,Microsoft-Windows-Sysmon,11,HR-11,resume.exe,,
""".encode("utf-8")


# ─── Format detection ────────────────────────────────────────────────
def test_format_detects_xml():
    assert detect_format(SYSMON_XML) == "xml"
    assert detect_format(WINSEC_XML) == "xml"


def test_format_detects_json():
    assert detect_format(CANONICAL_JSON) == "json"


def test_format_detects_csv():
    assert detect_format(GENERIC_CSV) == "csv"


def test_format_detects_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("s.xml", SYSMON_XML)
    assert detect_format(buf.getvalue(), filename="bundle.zip") == "zip"


def test_format_unknown_on_empty():
    assert detect_format(b"") == "unknown"


# ─── Source detection ────────────────────────────────────────────────
def test_source_sysmon_from_xml():
    assert detect_source(SYSMON_XML, fmt="xml") == SOURCE_SYSMON


def test_source_windows_security_from_xml():
    assert detect_source(WINSEC_XML, fmt="xml") == SOURCE_WINDOWS_SECURITY


def test_source_canonical_from_json():
    assert detect_source(CANONICAL_JSON, fmt="json") == SOURCE_CANONICAL_JSON


def test_source_generic_from_csv():
    assert detect_source(GENERIC_CSV, fmt="csv") == SOURCE_GENERIC_CSV


# ─── Sysmon normalizer ───────────────────────────────────────────────
def test_sysmon_normalizer_extracts_all_fields():
    prov = IngestionProvenance(origin="test", format="sysmon_xml", source="sysmon")
    records = list(normalize_sysmon_xml(SYSMON_XML, provenance=prov))
    assert len(records) == 2
    r0 = records[0]
    assert r0.event_id == 1
    assert r0.image.endswith("powershell.exe")
    assert "EncodedCommand" in r0.command_line
    assert r0.parent_image.endswith("cmd.exe")
    assert r0.computer == "WKS-01"
    assert r0.user == "CORP\\alice"
    assert r0.file_hash_sha256 == "abcdef1234"
    r1 = records[1]
    assert r1.event_id == 3
    assert r1.dst_ip == "185.234.219.5"


# ─── Windows Security normalizer ─────────────────────────────────────
def test_winsec_normalizer_process_creation():
    prov = IngestionProvenance(origin="test", format="windows_security_xml", source="windows_security")
    records = list(normalize_winsec_xml(WINSEC_XML, provenance=prov))
    assert len(records) == 1
    r = records[0]
    assert r.event_id == 4688
    assert r.image.endswith("net.exe")
    assert r.command_line.startswith("net user")


# ─── JSON normalizer ─────────────────────────────────────────────────
def test_json_normalizer_wrapper_shape():
    prov = IngestionProvenance(origin="test", format="json", source="canonical")
    records = list(normalize_json(CANONICAL_JSON, provenance=prov))
    assert len(records) == 2
    assert records[0].command_line == "explorer.exe"
    assert records[1].dst_ip == "1.1.1.1"


# ─── CSV normalizer ──────────────────────────────────────────────────
def test_csv_normalizer():
    prov = IngestionProvenance(origin="test", format="csv", source="generic_csv")
    records = list(normalize_csv(GENERIC_CSV, provenance=prov))
    assert len(records) == 2
    assert records[0].computer == "HR-11"
    assert records[0].image == "resume.exe"


# ─── ZIP dispatch ────────────────────────────────────────────────────
def test_zip_dispatches_to_multiple_normalizers():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sysmon.xml", SYSMON_XML)
        zf.writestr("winsec.xml", WINSEC_XML)
        zf.writestr("canonical.json", CANONICAL_JSON)
    m = IngestionMetrics(ingest_job_id="t", case_id="c")
    records = normalize_bytes(buf.getvalue(), "bundle.zip",
                               metrics=m, ingest_job_id="t")
    # 2 (sysmon) + 1 (winsec) + 2 (json) = 5
    assert len(records) == 5, [r.provenance.source for r in records]
    sources = {r.provenance.source for r in records}
    assert {"sysmon", "windows_security"}.issubset(sources)


# ─── CES → CEM v1 bridge ─────────────────────────────────────────────
def test_ces_to_cem_kind_resolution():
    r = CanonicalEventRecord(
        timestamp="2026-02-25T14:00:00Z",
        provider="Microsoft-Windows-Sysmon", event_id=1,
        image="powershell.exe",
        command_line="powershell -EncodedCommand SQBFAFgAKABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQA",
        provenance=IngestionProvenance(),
    )
    d = ces_to_cem_dict(r, case_id="c1", sequence=0)
    assert d["kind"] == "process_create"
    assert d["adapter"]                        # any non-empty adapter
    assert d["ts"] == "2026-02-25T14:00:00Z"
    # MITRE tagging should identify encoded PS + PowerShell execution
    assert any(t.startswith("T1059") for t in d["mitre"]), d["mitre"]
    assert "T1027" in d["mitre"]


def test_ces_to_cem_network_kind():
    r = CanonicalEventRecord(
        timestamp="2026-02-25T14:00:00Z",
        provider="Microsoft-Windows-Sysmon", event_id=3,
        image="chrome.exe", dst_ip="1.2.3.4", dst_port="443",
        provenance=IngestionProvenance(),
    )
    d = ces_to_cem_dict(r, case_id="c1")
    assert d["kind"] == "network_connect"
    assert "T1071.001" in d["mitre"]


def test_ces_to_cem_deterministic():
    r = CanonicalEventRecord(
        timestamp="2026-02-25T14:00:00Z", provider="Microsoft-Windows-Sysmon",
        event_id=1, image="cmd.exe", command_line="cmd /c whoami",
        provenance=IngestionProvenance(),
    )
    a = ces_to_cem_dict(r, case_id="det", sequence=0)
    b = ces_to_cem_dict(r, case_id="det", sequence=0)
    assert a == b


# ─── CES schema is stable ────────────────────────────────────────────
def test_ces_fields_locked():
    """Guardrail: CES fields must not silently change — this is a contract."""
    # 32 core fields per the operator's canonical schema spec (v1)
    assert len(CES_FIELDS) >= 32, CES_FIELDS
    assert "timestamp" in CES_FIELDS
    assert "provider" in CES_FIELDS
    assert "event_id" in CES_FIELDS
    assert "command_line" in CES_FIELDS
    assert "file_path" in CES_FIELDS
    assert "registry_key" in CES_FIELDS
    assert "dst_ip" in CES_FIELDS
    assert "dns_query" in CES_FIELDS


# ─── Golden Corpus round-trip ────────────────────────────────────────
def test_golden_corpus_lists_six_datasets():
    ds = list_datasets()
    ids = {d["id"] for d in ds}
    # Phase 4.2 expanded the corpus to 34 datasets; the original 6 must
    # remain present.
    assert {"clean_workstation", "office_phishing", "cobalt_strike",
            "enterprise_admin", "ransomware", "info_stealer"} <= ids
    assert len(ids) >= 30


def test_golden_dataset_investigation_roundtrip():
    """Every dataset must build a non-empty IKG when fed through build_investigation."""
    for dsid, ds in GOLDEN_CORPUS.items():
        records = ds.records()
        assert records, dsid
        # CES → CEM → build_investigation-input shape
        frames = []
        for i, rec in enumerate(records):
            ev = ces_to_cem_dict(rec, case_id=dsid, sequence=i)
            frame = {
                "frame_iid": ev["iid"],
                "ts":        ev["ts"],
                "lane":      _lane_from_kind(ev["kind"]),
                "action":    ev["kind"],
                "label":     (ev.get("raw") or {}).get("rule_label") or ev["kind"],
                "cmdline":   (ev.get("raw") or {}).get("command_line") or "",
                "target":    (ev.get("raw") or {}).get("target") or "",
                "mitre":     list(ev.get("mitre") or []),
                "parent":    {"iid": (ev.get("process") or {}).get("parent_iid"),
                              "name":(ev.get("process") or {}).get("parent_name"),
                              "type":"process"},
                "entity":    {"iid": ev.get("process_iid"),
                              "name":(ev.get("process") or {}).get("name"),
                              "type":"process"},
            }
            frames.append(frame)
        inv = build_investigation(frames, case_id=dsid)
        assert inv.header["event_count"] == len(records), dsid
        assert inv.ikg["stats"]["nodes"] > 0, dsid


def test_golden_verdict_expectations():
    """Verdicts should broadly align with the corpus expectations."""
    def _score(dsid):
        records = get_dataset(dsid).records()
        frames = []
        for i, rec in enumerate(records):
            ev = ces_to_cem_dict(rec, case_id=dsid, sequence=i)
            frames.append({
                "frame_iid": ev["iid"],
                "ts":        ev["ts"],
                "lane":      _lane_from_kind(ev["kind"]),
                "action":    ev["kind"],
                "label":     (ev.get("raw") or {}).get("rule_label") or ev["kind"],
                "cmdline":   (ev.get("raw") or {}).get("command_line") or "",
                "target":    (ev.get("raw") or {}).get("target") or "",
                "mitre":     list(ev.get("mitre") or []),
                "parent":    {"iid": (ev.get("process") or {}).get("parent_iid"),
                              "name":(ev.get("process") or {}).get("parent_name"),
                              "type":"process"},
                "entity":    {"iid": ev.get("process_iid"),
                              "name":(ev.get("process") or {}).get("name"),
                              "type":"process"},
            })
        return build_investigation(frames, case_id=dsid).header["device_score"]

    # Clean workstation stays clearly below the malicious threshold.
    clean = _score("clean_workstation")
    assert clean <= 30, f"clean_workstation scored {clean}"
    # Cobalt Strike scenario climbs well above the malicious threshold.
    cs = _score("cobalt_strike")
    assert cs >= 60, f"cobalt_strike scored {cs}"
    # Enterprise admin activity remains clearly benign.
    admin = _score("enterprise_admin")
    assert admin <= 30, f"enterprise_admin scored {admin}"


# ─── Helpers ─────────────────────────────────────────────────────────
def _lane_from_kind(kind: str) -> str:
    if kind in ("process_create", "process_exit", "process_access",
                "image_load", "remote_thread_create"):
        return "process"
    if kind in ("file_create", "file_write", "file_delete", "file_rename"):
        return "file"
    if kind in ("network_connect", "network_listen", "dns_query", "http_request"):
        return "network"
    if kind in ("registry_create", "registry_value_set", "registry_delete"):
        return "registry"
    return "system"


if __name__ == "__main__":
    import traceback
    tests = [(n, f) for n, f in list(globals().items())
             if n.startswith("test_") and callable(f)]
    ok, fail = 0, 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✓ {name}")
            ok += 1
        except AssertionError as e:
            print(f"  ✗ {name} · AssertionError · {e}")
            fail += 1
        except Exception as e:
            print(f"  ✗ {name} · {type(e).__name__}: {e}")
            traceback.print_exc()
            fail += 1
    print(f"\n{ok}/{ok+fail} passed")
    sys.exit(0 if fail == 0 else 1)
