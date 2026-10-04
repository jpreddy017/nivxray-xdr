#!/usr/bin/env python3
"""RCA reproduction for the Command Intelligence decoder defect (report only).

Reconstructed to the SHAPE the owner disclosed (obfuscated PowerShell whose
payload variable is built from string literals interleaved with non-string
operands, then Base64-decoded and executed via a ScriptBlock). The exact
original sample must replace this fixture before it is pinned as a permanent
regression case.

Run:  cd /app/backend && python3 ../scripts/ci_decoder_rca_repro.py
"""
import base64
import json
import sys

sys.path.insert(0, "/app/backend")

from command_analyzer import analyze_command, tokenize          # noqa: E402
from powershell_ast import deobfuscate_ps                       # noqa: E402

INNER = (
    "\r\ntry{\r\n;$rck-MS = 'x';\r\n"
    "ipconfig /release\r\nipconfig /renew\r\n"
    "netsh winsock reset\r\nnetsh int ip reset\r\n"
    "Start-Sleep -Seconds 5\r\n"
    "[System.Net.ServicePointManager]::SecurityProtocol = 3072\r\n"
    "$d = [Convert]::FromBase64String('SGVsbG8gZnJvbSBsYXllciAy')\r\n"
    "Set-Content -Path 'C:\\Users\\Public\\stage2.ps1' -Value $d\r\n"
    "}catch{}\r\n"
)
B64 = base64.b64encode(INNER.encode()).decode()

# Interleave the base64 with NON-STRING operands, the disclosed shape:
#   'lit' + 9 + 'lit' + 'A' + ...
def _obfuscated_expr(b64: str) -> str:
    parts, i, n = [], 0, 0
    while i < len(b64):
        chunk = b64[i:i + 11]
        i += 11
        parts.append("'" + chunk + "'")
        if i < len(b64):
            # every other joint is a bare numeric literal, which PowerShell
            # coerces to a string, i.e. it IS part of the payload
            parts.append("9" if n % 2 == 0 else "'A'")
            n += 1
    return " + ".join(parts)


CMD = (
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
    "-ExecutionPolicy bypass -c \"$EbaYA; $BnWKB; "
    f"$BnWKB = {_obfuscated_expr(B64)}; "
    "$EbaYA = [System.Text.Encoding]::UTF8.GetString("
    "[Convert]::FromBase64String($BnWKB)); "
    "Invoke-Command -ScriptBlock ([ScriptBlock]::Create($EbaYA))\""
)


def main() -> int:
    print("=" * 78)
    print("STAGE 0 · tokenizer")
    print("=" * 78)
    toks = tokenize(CMD)
    print("token_count   :", len(toks))
    print("executable    :", toks[0] if toks else "")
    print("backslashes ok:", "\\" in (toks[0] if toks else ""))

    print()
    print("=" * 78)
    print("STAGE 1 · powershell_ast.deobfuscate_ps (the reported transforms)")
    print("=" * 78)
    d = deobfuscate_ps(CMD)
    for t in d["transformations"]:
        print(f"  - {t['kind']}: {t['detail']}")
    print("bindings      :", list(d["bindings"].keys()))
    out = d["output"]
    print("survives ' + 9 + ':", "+ 9 +" in out or "' + 9 + '" in out)
    print("survives \"+ 'A' +\":", "+ 'A' +" in out)
    print("output excerpt:", out[180:420].replace("\n", "\\n"))

    print()
    print("=" * 78)
    print("STAGE 2 · analyze_command (the API surface)")
    print("=" * 78)
    r = analyze_command(CMD)
    ps = r["parsed_structure"]
    print("parsed.executable      :", ps.get("executable"))
    print("parsed.token_count     :", ps.get("token_count"))
    print("ast.applied            :", r["ast_deobfuscation"]["applied"])
    print("decode_chains          :", len(r["decode_chains"]))
    payloads = r["identified_payloads"]
    print("identified_payloads    :", len(payloads))
    roles = {}
    for p in payloads:
        roles[p["role"]] = roles.get(p["role"], 0) + 1
    print("  roles                :", roles)
    print("mitre                  :", r["mitre"])
    print("execution_flow         :", r["execution_flow"])
    print("behavior_summary       :", r["behavior_summary"])
    print("iocs.urls/files        :",
          r["iocs"].get("urls"), r["iocs"].get("files"))
    fin = r["final_decoded_inline"] or ""
    print("final == original      :", fin.strip() == CMD.strip())
    print("inner payload recovered:", "netsh winsock reset" in fin)
    print("inner recovered in ast :",
          "netsh winsock reset" in (r["ast_deobfuscation"].get("final") or ""))

    print()
    print("=" * 78)
    print("VERDICT")
    print("=" * 78)
    findings = {
        "F1_posix_shlex_eats_backslashes":
            "\\" not in (toks[0] if toks else "\\"),
        "F2_non_string_operand_breaks_folding":
            ("+ 9 +" in out or "+ 'A' +" in out),
        "F3_variable_never_bound":
            "$BnWKB" not in d["bindings"],
        "F4_applied_true_without_recovery":
            bool(r["ast_deobfuscation"]["applied"])
            and "netsh winsock reset" not in
                (r["ast_deobfuscation"].get("final") or ""),
        "F5_fragments_as_standalone_base64":
            roles.get("standalone base64", 0) > 0,
        "F6_canonical_artifact_is_the_wrapper":
            "netsh winsock reset" not in fin,
        "F7_security_analysis_empty":
            (not r["mitre"]) and (not r["execution_flow"]),
    }
    for k, v in findings.items():
        print(("REPRODUCED  " if v else "not present ") + k)
    print()
    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
