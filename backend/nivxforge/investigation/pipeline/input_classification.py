"""Stage 1 · Input Classification.

First discriminator in the locked pipeline. Given a raw string,
classify what SHAPE of input this is so the Parser (Stage 2) knows
what strategy to apply.

Classifications:
    - json           single JSON object / array
    - ndjson         newline-delimited JSON
    - csv            comma / tab separated table
    - xml            XML / Windows EVTX-style XML
    - encoded_cmd    PowerShell -EncodedCommand blob
    - plain_command  raw command line (powershell / cmd / bash / lolbin)
    - key_value      key=value log lines (Suricata, Zeek, Syslog KV)
    - plain_text     everything else (still investigable)

Never raises. Deterministic. Cheap regex-based sniffing only —
NO parsing here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


class InputClass:
    JSON = "json"
    NDJSON = "ndjson"
    CSV = "csv"
    XML = "xml"
    ENCODED_CMD = "encoded_cmd"
    PLAIN_COMMAND = "plain_command"
    KEY_VALUE = "key_value"
    PLAIN_TEXT = "plain_text"
    EMPTY = "empty"


@dataclass(frozen=True)
class InputClassification:
    kind: str
    confidence: float
    hint: Optional[str] = None


_JSON_START = re.compile(r"^\s*[\{\[]")
_XML_START = re.compile(r"^\s*<\??[A-Za-z]")
_ENCODED_CMD = re.compile(
    r"(?:powershell(?:\.exe)?|pwsh)\s+(?:[^\s]+\s+)*-e(?:nc(?:od(?:ed(?:command)?)?)?)?"
    r"\s+[A-Za-z0-9+/=]{4,}",
    re.IGNORECASE,
)
_STANDALONE_B64 = re.compile(r"^[A-Za-z0-9+/=\s]{40,}$")
_PLAIN_CMD = re.compile(
    r"^\s*(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?|bash|sh|zsh|"
    r"wmic|reg|schtasks|bitsadmin|certutil|rundll32|regsvr32|mshta|"
    r"msiexec|curl|wget|nslookup|netsh|vssadmin|net\s+(?:user|group|localgroup))\b",
    re.IGNORECASE,
)
_KV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,40}=[^\s]")


def classify_input(raw: str) -> InputClassification:
    """Deterministic input classification. Never raises."""
    if raw is None:
        return InputClassification(InputClass.EMPTY, 1.0)
    if not isinstance(raw, str):
        raw = str(raw)
    stripped = raw.strip()
    if not stripped:
        return InputClassification(InputClass.EMPTY, 1.0)

    # 1. Encoded PowerShell — highest specificity.
    if _ENCODED_CMD.search(stripped):
        return InputClassification(InputClass.ENCODED_CMD, 0.98,
                                   hint="powershell_encoded_command")

    # 2. JSON / NDJSON — structural.
    if _JSON_START.match(stripped):
        # ndjson if multiple top-level JSON objects one per line
        first_line = stripped.split("\n", 1)[0].rstrip()
        if first_line.endswith("}") and stripped.count("\n{") >= 1:
            return InputClassification(InputClass.NDJSON, 0.9)
        return InputClassification(InputClass.JSON, 0.95)

    # 3. XML.
    if _XML_START.match(stripped):
        return InputClassification(InputClass.XML, 0.9)

    # 4. Standalone base64 blob (analyst pasted just the payload).
    #    Check BEFORE the plain-command test.
    if _STANDALONE_B64.match(stripped) and len(stripped) >= 40:
        return InputClassification(InputClass.ENCODED_CMD, 0.75,
                                   hint="standalone_base64_blob")

    # 5. Plain command line (any LOLBIN / shell).
    if _PLAIN_CMD.match(stripped):
        return InputClassification(InputClass.PLAIN_COMMAND, 0.9)

    # 6. CSV — heuristic: first line has >=3 commas AND all lines have
    #    consistent comma counts. Tabs treated as CSV variant.
    lines = stripped.split("\n")[:5]
    if len(lines) >= 2:
        commas = [ln.count(",") for ln in lines if ln.strip()]
        tabs = [ln.count("\t") for ln in lines if ln.strip()]
        if commas and commas[0] >= 2 and len(set(commas)) == 1:
            return InputClassification(InputClass.CSV, 0.85, hint="comma")
        if tabs and tabs[0] >= 2 and len(set(tabs)) == 1:
            return InputClassification(InputClass.CSV, 0.8, hint="tab")

    # 7. Key=value log lines (Suricata, Zeek, Syslog KV).
    kv_hits = sum(1 for ln in lines if _KV_LINE.match(ln.strip()))
    if kv_hits >= 2:
        return InputClassification(InputClass.KEY_VALUE, 0.8)

    # 8. Fallthrough — still investigable.
    return InputClassification(InputClass.PLAIN_TEXT, 0.5)


__all__ = ["InputClass", "InputClassification", "classify_input"]
