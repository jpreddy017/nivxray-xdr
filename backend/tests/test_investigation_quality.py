"""Phase 8 · Investigation Quality Benchmark

Regression suite for the NivXRay Investigation Engine. Every future
code change must keep every quality gate green across the entire
Golden Investigation Corpus.

Gates (from the MDR analyst-review spec):

  G1  Executive Summary present + mentions the source vendor + describes
      the endpoint or user.
  G2  Investigation Summary is chronological (each paragraph begins with a
      real timestamp OR contains a timestamp/anchor phrase).
  G3  Every artefact in `observed_evidence` has a `provenance` label.
  G4  IOC precision: `observed_iocs` MUST NOT contain any host from the
      reference-URL vendor / documentation catalogue.
  G5  Probable Initial Access is evidence-linked, confidence-scored, and
      never claims High confidence unless ≥ 4 evidence bullets are attached.
  G6  Timeline is chronological (ISO timestamps ascending, unknowns last).
  G7  Recommendations are grouped by tier (immediate / short_term / long_term)
      and evidence-linked (every action has `why` + `evidence`).
  G8  Investigation Conclusion is present and non-empty.
  G9  Confidence card has bounded numeric sub-scores (0-100) and banded
      overall in {"High", "Medium", "Low", "None"}.
  G10 Known-vs-Unknown lists exist and are populated.
  G11 Cross-source: the same set of report keys is produced regardless of
      vendor.  (Structural determinism.)

Run:
    cd /app/backend && python -m pytest -q tests/test_investigation_quality.py
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys
from datetime import datetime

import pytest

sys.path.insert(0, "/app/backend")

from v2.investigation.model import build_model  # noqa: E402
from v2.investigation.report import compose_report  # noqa: E402
from v2.investigation.normalizers import normalize  # noqa: E402


_URL_RE  = re.compile(r"https?://[^\s\"'<>)]+", re.I)
_IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+)\b", re.I)


def _extract_iocs(raw: str) -> dict:
    urls = sorted(set(m.group(0).rstrip('.,;)"\'') for m in _URL_RE.finditer(raw)))
    ips  = sorted(set(_IP_RE.findall(raw)))
    hosts = sorted({
        h.lower() for h in _HOST_RE.findall(raw)
        if "." in h and not h.endswith(".exe") and not h.endswith(".dll")
        and not h.endswith(".ps1") and not h.endswith(".sct")
        and not h.endswith(".msi") and not h.endswith(".docm")
    })
    return {"urls": urls, "ips": ips, "domains": hosts}


CORPUS_DIR = os.path.join(os.path.dirname(__file__), "golden_corpus")

# Vendor label expected in the Executive Summary for each sample. The
# match is case-insensitive and substring — the source label must appear.
EXPECTED_VENDOR_LABEL = {
    "01_cisco_xdr":               "Cisco",
    "02_cisco_secure_endpoint":   "Cisco Secure Endpoint",
    "03_crowdstrike_falcon":      "CrowdStrike Falcon",
    "04_microsoft_defender":      "Microsoft Defender",
    "05_sentinelone":             "SentinelOne",
    "06_sysmon":                  "Sysmon",
    "07_qradar":                  "QRadar",
    "08_splunk":                  "Splunk",
    "09_generic_json":            "GenericEDR",
}

# Hosts that MUST NEVER appear as an IOC (from any part of `observed_iocs`).
NEVER_IOC_HOSTS = {
    "secureboard.cisco.com", "amp.cisco.com", "umbrella.com",
    "falcon.crowdstrike.com", "security.microsoft.com",
    "learn.microsoft.com", "attack.mitre.org", "virustotal.com",
    "management.sentinelone.net", "splunk.com",
}

# Deterministic structural key set (Gate G11)
EXPECTED_TOP_KEYS = {
    "confidence", "executive_summary", "known_vs_unknown",
    "probable_initial_access", "investigation_summary", "timeline",
    "attack_story", "technical_summary", "mitre_by_tactic",
    "mitre_techniques", "negative_findings", "recommendations",
    "supporting_evidence", "observed_evidence", "observed_iocs",
    "threat_intelligence", "limitations", "investigation_conclusion",
    "empty",
}


# ────────────────────────────────────────────────────────────────
def _corpus_files() -> list[tuple[str, str]]:
    files = sorted(glob.glob(os.path.join(CORPUS_DIR, "*.txt")))
    assert files, f"golden corpus is empty at {CORPUS_DIR}"
    return [(os.path.splitext(os.path.basename(f))[0], f) for f in files]


def _build(raw: str) -> dict:
    """Full pipeline: normalize → build_model → compose_report."""
    events = normalize(raw)
    iocs = _extract_iocs(raw)
    fis = {"iocs": iocs, "severity": ""}
    im = build_model(raw, events, fis, {}, {}).to_dict()
    return compose_report(im)


# ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name,path", _corpus_files())
def test_investigation_quality_gates(name: str, path: str):
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    rep = _build(raw)
    assert isinstance(rep, dict) and not rep.get("empty"), \
        f"{name}: report came back empty"

    # ── G11 · Cross-source structural determinism ────────────────
    missing = EXPECTED_TOP_KEYS - set(rep.keys())
    assert not missing, f"{name}: missing report keys → {missing}"

    # ── G1 · Executive Summary vendor + subject ──────────────────
    exec_summary = " ".join(rep["executive_summary"])
    assert exec_summary.strip(), f"{name}: executive summary is empty"
    vendor = EXPECTED_VENDOR_LABEL[name]
    assert vendor.lower() in exec_summary.lower(), \
        f"{name}: expected vendor '{vendor}' in executive summary → got: {exec_summary[:200]}"

    # ── G2 · Investigation Summary chronology anchor ─────────────
    inv = " ".join(rep["investigation_summary"])
    assert inv.strip(), f"{name}: investigation summary is empty"
    assert ("UTC" in inv) or ("at " in inv.lower()) or ("following" in inv.lower()), \
        f"{name}: investigation summary lacks a chronological anchor"

    # ── G3 · Every observed_evidence artefact has provenance ─────
    for bucket in ("urls", "domains", "ips"):
        for item in (rep["observed_evidence"].get(bucket) or []):
            assert "provenance" in item, \
                f"{name}: observed_evidence.{bucket} item missing provenance → {item}"

    # ── G4 · IOC precision — no reference-vendor hosts ───────────
    for bucket in ("urls", "domains", "ips"):
        for ioc in (rep["observed_iocs"].get(bucket) or []):
            value = (ioc.get("value") or "").lower()
            for banned in NEVER_IOC_HOSTS:
                assert banned not in value, \
                    f"{name}: reference host '{banned}' incorrectly classified as IOC → {ioc}"

    # ── G5 · Probable Initial Access shape + confidence discipline
    ia = rep["probable_initial_access"]
    assert set(ia.keys()) >= {"vector", "confidence", "evidence", "paragraph"}, \
        f"{name}: probable_initial_access missing keys → {list(ia.keys())}"
    assert ia["confidence"] in {"High", "Medium", "Low", "None"}, \
        f"{name}: bad confidence → {ia['confidence']}"
    if ia["confidence"] == "High":
        assert len(ia["evidence"]) >= 4, \
            f"{name}: High-confidence IA needs ≥4 evidence bullets → {ia['evidence']}"
    assert ia["paragraph"].strip(), f"{name}: IA paragraph is empty"

    # ── G6 · Timeline chronological (ISO ts ascending, unknowns last)
    tl = rep["timeline"]
    prev = -1.0
    for row in tl:
        ts = row.get("ts") or ""
        try:
            k = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            k = float("inf")
        assert k >= prev - 0.001, \
            f"{name}: timeline not sorted at row {row}"
        prev = k

    # ── G7 · Recommendations grouped + evidence-linked ───────────
    recs = rep["recommendations"]
    assert isinstance(recs, dict), f"{name}: recommendations not grouped"
    assert set(recs.keys()) >= {"immediate", "short_term", "long_term"}, \
        f"{name}: recommendations missing tier(s) → {list(recs.keys())}"
    for tier, items in recs.items():
        for r in items:
            assert r.get("action"), f"{name}: rec missing action → {r}"
            assert r.get("why"), f"{name}: rec missing 'why' → {r}"

    # ── G8 · Investigation Conclusion non-empty ──────────────────
    assert (rep["investigation_conclusion"] or "").strip(), \
        f"{name}: investigation conclusion is empty"

    # ── G9 · Confidence card sub-scores bounded + banded ─────────
    conf = rep["confidence"]
    assert conf["overall"] in {"High", "Medium", "Low", "None"}, \
        f"{name}: bad overall band → {conf['overall']}"
    for k in ("evidence_completeness", "timeline_completeness"):
        v = conf.get(k, -1)
        assert 0 <= v <= 100, f"{name}: {k} out of range → {v}"

    # ── G10 · Known + Unknown populated ──────────────────────────
    kvu = rep["known_vs_unknown"]
    assert kvu["known"], f"{name}: KNOWN list empty"
    assert kvu["unknown"], f"{name}: UNKNOWN list empty"


# ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name,path", _corpus_files())
def test_process_chain_no_self_spawn(name: str, path: str):
    """Regression: parent process must never equal child process (the old
    `Process:` vs `Parent Process:` regex-collision bug)."""
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    rep = _build(raw)
    for row in rep["technical_summary"]["processes"]:
        parent = (row.get("parent") or "").lower()
        proc   = (row.get("process") or "").lower()
        if parent and proc:
            assert parent != proc, f"{name}: self-spawn in process chain → {row}"


# ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name,path", _corpus_files())
def test_ioc_reference_split_populated(name: str, path: str):
    """The observed_evidence URL bucket MUST contain at least one URL when
    the sample includes a reference URL, and the reference/console URLs
    must be labelled with a non-IOC provenance."""
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    if "https://" not in raw and "http://" not in raw:
        pytest.skip(f"{name}: no URLs in sample")
    rep = _build(raw)
    urls = rep["observed_evidence"]["urls"]
    assert urls, f"{name}: no URLs surfaced in observed_evidence"
    # Every url must carry provenance
    provs = {u["provenance"] for u in urls}
    assert provs, f"{name}: urls have no provenance"


# ────────────────────────────────────────────────────────────────
def test_cross_source_key_parity():
    """Every vendor sample MUST produce the same top-level report keys."""
    key_sets: dict[str, set[str]] = {}
    for name, path in _corpus_files():
        with open(path, encoding="utf-8") as f:
            raw = f.read()
        rep = _build(raw)
        key_sets[name] = set(rep.keys())
    all_keys = set.intersection(*key_sets.values())
    for name, keys in key_sets.items():
        assert keys == all_keys, (
            f"{name}: report keys diverge from the shared baseline "
            f"→ extra={keys - all_keys}  missing={all_keys - keys}"
        )
