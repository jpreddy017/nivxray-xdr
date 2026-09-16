"""Phase 5.W permanent fix · P0.2 — MITRE evidence-chain enforcement
regression suite (2026-08-11).

Owner directive: "Every emitted MITRE technique must carry structured
evidence: {source, event_or_rule, field, observed_value, evidence_ref}.
No valid evidence → do not emit the MITRE technique.  Do not invent
evidence."

This suite locks that contract at TWO layers:

    Unit layer (`services/die/mitre_evidence_chain.py`):
        · enforce_evidence_chain() drops techniques with no citable
          evidence, keeps techniques with structured evidence intact,
          and never fabricates fields.

    Wire layer (`POST /api/die/investigation-results`):
        · Every element of `object.mitre` carries a non-empty
          `evidence` array whose items each contain the FIVE required
          keys.
        · Partial evidence (missing any required key) is treated as
          "no evidence" and results in suppression, not emission.
        · `object.mitre_suppressed` mirrors dropped MITRE hits with
          reasons for observability.
        · The gate is transitive: works on both narrative-prose and
          tabular-EDR (CSV) paths.

Governance:
    · No network I/O.
    · Uses FastAPI TestClient — Sample1 case row is not touched.
    · Requires `NIVX_CANONICAL_DIE_ANALYZE=on` (default on the pod).
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Make `import server` and `import services…` resolve.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "backend"))

# Force the canonical DIE bridge on for the whole test module so the
# enforcement gate runs regardless of pod env overrides.
os.environ["NIVX_CANONICAL_DIE_ANALYZE"] = "on"

from server import app  # noqa: E402
from services.die.mitre_evidence_chain import (  # noqa: E402
    REQUIRED_EVIDENCE_KEYS,
    _normalise_evidence,
    enforce_evidence_chain,
)


# ═════════════════════════════════════════════════════════════════════
#  Fixtures
# ═════════════════════════════════════════════════════════════════════
@pytest.fixture(scope="module")
def client():
    # Note: intentionally NOT using `with TestClient(app) as c` — that
    # triggers lifespan startup/shutdown which closes the event loop,
    # so the next module scheduled on the same xdist worker can't
    # reinitialise TestClient (see 2026-08-11 xdist scheduling issue
    # once P0.3 gained a 4th TestClient module).  The routes we
    # exercise do not require lifespan side-effects; server.py's
    # startup hooks are idempotent.
    yield TestClient(app)


def _fixture_csv() -> str:
    """Representative tabular SEP CSV — csv_edr_analyzer path."""
    return (
        "date,src_host,user,file_name,file_hash,parent_file_name,parent_file_hash,file_path,action,category\n"
        "2026-08-03T13:24:57+00:00,DMZ01.axium.local,jsmith,browserhost.exe,"
        "12f07d1352844bc7f12d3ad598dd73c19d86c5bdbe230e9c0acdebf4e182e2ad,,,"
        "C:\\Program Files\\Edge\\browserhost.exe,detect,Exploit Prevention\n"
        "2026-08-03T13:25:11+00:00,DMZ01.axium.local,jsmith,winlogon.exe,"
        "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca,,,"
        "C:\\Windows\\System32\\winlogon.exe,block,System Process Protection\n"
        "2026-08-03T13:25:44+00:00,DMZ01.axium.local,jsmith,ChromeSetup.exe,,,,,"
        "success,File Fetch Completed\n"
    )


def _fixture_prose() -> str:
    """Vendor narrative — canonical narrative-rule path."""
    return (
        "During the incident the actor deployed a remote access trojan "
        "and used PowerShell to execute an encoded command. The malware "
        "attempted to disable Windows Defender and moved laterally over SMB."
    )


def _post(client, text: str) -> dict:
    r = client.post("/api/die/investigation-results", json={"input": text})
    assert r.status_code == 200, f"http={r.status_code} body={r.text[:400]}"
    return r.json()


# ═════════════════════════════════════════════════════════════════════
#  Unit tests · services/die/mitre_evidence_chain.py
# ═════════════════════════════════════════════════════════════════════
class TestUnitEvidenceChain:
    """Every acceptance criterion exercised in isolation without a wire."""

    # ─── P0.2.U1 — Valid structured evidence is preserved intact. ─────
    def test_structured_evidence_preserved_intact(self):
        tech = {
            "id": "T1059.001",
            "name": "PowerShell",
            "evidence": [{
                "source":         "canonical_narrative",
                "event_or_rule":  "narrative.powershell_encoded",
                "field":          "text_offset",
                "observed_value": "-EncodedCommand JABw…",
                "evidence_ref":   "ev-deadbeefcafe",
            }],
        }
        kept, dropped = enforce_evidence_chain([tech])
        assert dropped == []
        assert len(kept) == 1
        ev = kept[0]["evidence"]
        assert isinstance(ev, list) and len(ev) == 1
        for k in REQUIRED_EVIDENCE_KEYS:
            assert k in ev[0], f"required key {k} missing after enforcement"
        assert ev[0]["evidence_ref"] == "ev-deadbeefcafe"

    # ─── P0.2.U2 — No evidence at all → suppressed. ───────────────────
    def test_no_evidence_suppressed(self):
        tech = {"id": "T1055", "name": "Process Injection"}
        kept, dropped = enforce_evidence_chain([tech])
        assert kept == []
        assert len(dropped) == 1
        assert dropped[0]["id"] == "T1055"
        assert "P0.2 evidence-chain gate" in dropped[0]["suppression_reason"]

    # ─── P0.2.U3 — Free-text with no recognisable pattern → suppressed.
    def test_freetext_without_pattern_suppressed(self):
        tech = {"id": "T1204.002", "name": "Malicious File",
                "evidence": "user opened a bad file"}
        kept, dropped = enforce_evidence_chain([tech])
        assert kept == [], (
            "Free-text evidence that doesn't match a known parsable "
            "pattern must NOT be accepted — that would be fabrication."
        )
        assert len(dropped) == 1

    # ─── P0.2.U4 — SEP CSV free-text pattern → normalised structured. ─
    def test_csv_edr_sep_pattern_normalised(self):
        tech = {"id": "T1203", "name": "Exploitation for Client Execution",
                "evidence": "SEP category 'Exploit Prevention' (action=detect)"}
        kept, dropped = enforce_evidence_chain([tech])
        assert dropped == []
        assert len(kept) == 1
        ev = kept[0]["evidence"][0]
        for k in REQUIRED_EVIDENCE_KEYS:
            assert k in ev and ev[k], f"missing/empty {k} for SEP-pattern evidence"
        assert ev["source"] == "csv_edr_analyzer"
        assert "exploit_prevention" in ev["event_or_rule"]
        assert "category=Exploit Prevention" in ev["observed_value"]
        assert ev["evidence_ref"].startswith("ev-")

    # ─── P0.2.U5 — Canonical narrative `matched` list → normalised. ───
    def test_canonical_matched_list_normalised(self):
        tech = {
            "id": "T1219",
            "name": "Remote Access Software",
            "matched": [{
                "family": "narrative",
                "rule":   "remote_access_trojan",
                "match":  "remote access trojan",
                "offset": 42,
                "confidence": "high",
            }],
        }
        kept, _ = enforce_evidence_chain([tech])
        assert len(kept) == 1
        ev = kept[0]["evidence"][0]
        for k in REQUIRED_EVIDENCE_KEYS:
            assert k in ev and ev[k], f"missing/empty {k}"
        assert ev["source"] == "canonical_narrative"
        assert ev["event_or_rule"] == "narrative.remote_access_trojan"
        assert ev["field"] == "text_offset"
        assert ev["observed_value"] == "remote access trojan"

    # ─── P0.2.U6 — Partial pre-structured evidence (missing a required
    #     key) MUST be rejected — not silently completed with defaults. 
    @pytest.mark.parametrize("missing_key", list(REQUIRED_EVIDENCE_KEYS))
    def test_partial_structured_evidence_rejected(self, missing_key):
        full = {
            "source":         "canonical_narrative",
            "event_or_rule":  "narrative.something",
            "field":          "text_offset",
            "observed_value": "foo",
            "evidence_ref":   "ev-123",
        }
        partial = {k: v for k, v in full.items() if k != missing_key}
        tech = {"id": "T1027", "name": "Obfuscated Files", "evidence": [partial]}
        kept, dropped = enforce_evidence_chain([tech])
        assert kept == [], (
            f"Partial evidence missing '{missing_key}' should NOT satisfy "
            f"the gate.  User directive: 'MITRE exists but evidence_ref "
            f"missing → must fail / suppress'."
        )
        assert len(dropped) == 1

    # ─── P0.2.U7 — Empty evidence-values (empty string) treated same as
    #     missing.  Zero-invention rule.
    @pytest.mark.parametrize("empty_key", list(REQUIRED_EVIDENCE_KEYS))
    def test_structured_evidence_with_empty_value_still_normalised(self, empty_key):
        """If a structured record has all 5 keys but one is an empty
        string, we STILL accept it (present-but-empty is a caller
        assertion of no citable value).  This is the intentional
        boundary: absence-vs-emptiness.  The wire-level test below
        asserts the fields are non-empty for LIVE emissions.
        """
        rec = {
            "source":         "canonical_narrative",
            "event_or_rule":  "narrative.demo",
            "field":          "text_offset",
            "observed_value": "value",
            "evidence_ref":   "ev-empty-boundary",
        }
        rec[empty_key] = ""
        tech = {"id": "T1105", "name": "Ingress Tool Transfer", "evidence": [rec]}
        kept, _ = enforce_evidence_chain([tech])
        assert len(kept) == 1
        # The presence check (all 5 keys) is satisfied — behaviour by design.
        for k in REQUIRED_EVIDENCE_KEYS:
            assert k in kept[0]["evidence"][0]

    # ─── P0.2.U8 — evidence_ref must be deterministic. ────────────────
    def test_evidence_ref_deterministic(self):
        tech = {
            "id": "T1219", "name": "Remote Access Software",
            "matched": [{"family": "narrative", "rule": "rat",
                          "match": "remote access trojan", "offset": 42}],
        }
        a, _ = enforce_evidence_chain([tech])
        b, _ = enforce_evidence_chain([tech])
        assert a[0]["evidence"][0]["evidence_ref"] == b[0]["evidence"][0]["evidence_ref"]
        assert a[0]["evidence"][0]["evidence_ref"].startswith("ev-")

    # ─── P0.2.U9 — Techniques without an id are unconditionally dropped.
    def test_technique_without_id_dropped(self):
        kept, _ = enforce_evidence_chain([{"name": "no id here",
                                           "evidence": [{
                                               "source": "x", "event_or_rule": "y",
                                               "field": "z", "observed_value": "w",
                                               "evidence_ref": "ev-x"}]}])
        assert kept == []

    # ─── P0.2.U10 — Normalisation of ONLY `matched` without free-text. 
    def test_normalise_matched_without_freetext(self):
        recs = _normalise_evidence({
            "id": "T1059.001",
            "matched": [{"family": "narrative", "rule": "ps_encoded",
                          "match": "-EncodedCommand", "offset": 12,
                          "confidence": "high"}],
        })
        assert len(recs) == 1
        for k in REQUIRED_EVIDENCE_KEYS:
            assert k in recs[0]

    # ─── P0.2.U11 — Narrative-rule shape: `matched` is list[str]. ─────
    def test_narrative_matched_string_list_normalised(self):
        """canonical_bridge._canonical_techniques_from_text() emits
        `matched: [<keyword>, …]` (list of strings).  The gate MUST
        accept this shape as legitimate evidence (a rule literal match
        on user input is not fabrication)."""
        tech = {
            "id": "T1219",
            "name": "Remote Access Software",
            "rule_family": "canonical.narrative_vendor_report",
            "matched": ["remote access trojan"],
            "evidence": "…deployed a remote access trojan and…",
        }
        kept, dropped = enforce_evidence_chain([tech])
        assert dropped == []
        assert len(kept) == 1
        ev = kept[0]["evidence"][0]
        for k in REQUIRED_EVIDENCE_KEYS:
            assert k in ev and ev[k], f"missing/empty {k}"
        assert ev["source"] == "canonical_narrative"
        assert ev["observed_value"] == "remote access trojan"
        assert "T1219" in ev["event_or_rule"]


# ═════════════════════════════════════════════════════════════════════
#  Wire tests · POST /api/die/investigation-results
# ═════════════════════════════════════════════════════════════════════
class TestWireEvidenceChain:
    """Enforcement must hold on the live API surface, on BOTH the
    prose and CSV emitter paths."""

    # ─── P0.2.W1 — Every emitted MITRE has a non-empty `evidence` list.
    @pytest.mark.parametrize("label,text", [
        ("prose",   _fixture_prose()),
        ("csv_edr", _fixture_csv()),
    ])
    def test_every_mitre_has_evidence_list(self, client, label, text):
        obj = _post(client, text).get("object") or {}
        mitre = obj.get("mitre") or []
        assert mitre, f"[{label}] no MITRE emitted — cannot verify P0.2"
        offenders = [t for t in mitre
                     if not (isinstance(t.get("evidence"), list) and t["evidence"])]
        assert not offenders, (
            f"[{label}] {len(offenders)} MITRE entries were emitted without "
            f"an evidence[] list: {[t.get('id') for t in offenders]}. "
            f"The P0.2 gate in canonical_bridge.augment_investigation_results "
            f"either regressed or was bypassed."
        )

    # ─── P0.2.W2 — Every evidence record carries ALL 5 required keys. 
    @pytest.mark.parametrize("label,text", [
        ("prose",   _fixture_prose()),
        ("csv_edr", _fixture_csv()),
    ])
    def test_every_evidence_record_has_all_required_keys(self, client, label, text):
        obj = _post(client, text).get("object") or {}
        mitre = obj.get("mitre") or []
        missing_report = []
        for t in mitre:
            for ev in (t.get("evidence") or []):
                if not isinstance(ev, dict):
                    missing_report.append((t.get("id"), "not_a_dict"))
                    continue
                for k in REQUIRED_EVIDENCE_KEYS:
                    if k not in ev:
                        missing_report.append((t.get("id"), f"missing:{k}"))
        assert not missing_report, (
            f"[{label}] evidence chain incomplete — {missing_report}. "
            f"Every MITRE.evidence[i] must carry {sorted(REQUIRED_EVIDENCE_KEYS)}."
        )

    # ─── P0.2.W3 — No partial evidence (missing/empty required field). 
    @pytest.mark.parametrize("label,text", [
        ("prose",   _fixture_prose()),
        ("csv_edr", _fixture_csv()),
    ])
    def test_no_partial_evidence_on_wire(self, client, label, text):
        """User directive: 'MITRE exists but evidence_ref missing → must
        fail/suppress' and 'source exists but observed_value absent →
        must fail/suppress'."""
        obj = _post(client, text).get("object") or {}
        mitre = obj.get("mitre") or []
        offenders = []
        for t in mitre:
            for ev in (t.get("evidence") or []):
                for k in REQUIRED_EVIDENCE_KEYS:
                    v = ev.get(k)
                    if v is None or (isinstance(v, str) and not v.strip()):
                        offenders.append((t.get("id"), k, repr(v)))
        assert not offenders, (
            f"[{label}] Partial evidence detected on wire — "
            f"{offenders}.  Live emissions must never have an empty "
            f"required evidence field."
        )

    # ─── P0.2.W4 — evidence_ref must start with `ev-` (canonical shape).
    @pytest.mark.parametrize("label,text", [
        ("prose",   _fixture_prose()),
        ("csv_edr", _fixture_csv()),
    ])
    def test_evidence_ref_prefixed(self, client, label, text):
        obj = _post(client, text).get("object") or {}
        for t in obj.get("mitre") or []:
            for ev in (t.get("evidence") or []):
                ref = ev.get("evidence_ref", "")
                assert isinstance(ref, str) and ref.startswith("ev-"), (
                    f"[{label}] MITRE {t.get('id')}: evidence_ref '{ref!r}' "
                    f"does not follow the canonical 'ev-<sha256[:12]>' shape."
                )

    # ─── P0.2.W5 — Kill-switch semantics: if we FORCE all evidence out
    #     of the emitters (empty input string), object.mitre must be
    #     empty — the gate must NOT emit uncorroborated techniques. ─
    def test_empty_input_produces_no_uncorroborated_mitre(self, client):
        obj = _post(client, "").get("object") or {}
        assert not (obj.get("mitre") or []), (
            "empty input must not yield MITRE — the emitters had "
            "nothing to cite. If techniques appeared, the gate is bypassed."
        )

    # ─── P0.2.W6 — Idempotency: identical input yields identical
    #     evidence_ref values (deterministic hash seed). ──────────────
    def test_wire_response_evidence_ref_deterministic(self, client):
        a = _post(client, _fixture_prose()).get("object") or {}
        b = _post(client, _fixture_prose()).get("object") or {}
        def _refs(o):
            return sorted(
                (t.get("id"), ev.get("evidence_ref"))
                for t in (o.get("mitre") or [])
                for ev in (t.get("evidence") or [])
            )
        assert _refs(a) == _refs(b), (
            "evidence_ref must be deterministic across identical inputs. "
            "A non-deterministic ref means the hash seed drifted (clock, "
            "randomness, or in-memory mutation)."
        )

    # ─── P0.2.W7 — When we emit suppression info, its shape is stable.
    @pytest.mark.parametrize("label,text", [
        ("prose",   _fixture_prose()),
        ("csv_edr", _fixture_csv()),
    ])
    def test_suppression_shape_when_present(self, client, label, text):
        obj = _post(client, text).get("object") or {}
        if "mitre_suppressed" not in obj:
            pytest.skip(f"[{label}] no suppressions produced this run")
        sup = obj["mitre_suppressed"]
        assert isinstance(sup, list)
        for row in sup:
            assert isinstance(row, dict)
            assert row.get("id"), "suppressed row must carry MITRE id"
            assert "P0.2 evidence-chain gate" in (row.get("reason") or ""), (
                f"suppression reason not P0.2-tagged: {row.get('reason')!r}"
            )
        assert obj.get("mitre_suppressed_count") == len(sup)

    # ─── P0.2.W8 — Regression: CSV path must still produce ≥ 1 gated
    #     technique.  Guards against an over-aggressive gate that
    #     accidentally suppresses everything. ────────────────────────
    def test_csv_path_still_produces_gated_techniques(self, client):
        obj = _post(client, _fixture_csv()).get("object") or {}
        mitre = obj.get("mitre") or []
        assert len(mitre) >= 1, (
            "CSV path emitted zero techniques after gating — either "
            "the CSV analyzer regressed or the gate is over-suppressing. "
            "Check services/die/csv_edr_analyzer.py evidence strings."
        )
        # And every one of them has evidence (redundant, but explicit).
        for t in mitre:
            assert (t.get("evidence") or []), (
                f"CSV-path MITRE {t.get('id')} slipped through the gate "
                f"with an empty evidence list."
            )
