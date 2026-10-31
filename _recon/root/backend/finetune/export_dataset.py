"""NivX Cognis · Qwen 2.5 7B fine-tune dataset exporter.

Purpose
-------
Export NivXRay's accumulated deterministic ground-truth (Golden Vault,
Training Corpus, curated Real-World Stress Suite) into an Alpaca-format
JSONL file suitable for LoRA fine-tuning of Qwen 2.5 7B via unsloth /
axolotl / llama-factory.

Output schema (Alpaca format, one JSON per line):
    {
        "instruction": "<system prompt: NivX Cognis persona>",
        "input":       "<obfuscated command line — raw analyst input>",
        "output":      "<canonical JSON verdict: chain, mitre, family, iocs, verdict>"
    }

Run
---
    python /app/backend/finetune/export_dataset.py \
        --out /app/backend/finetune/nivx_cognis_train.jsonl \
        --sources golden,corpus,realworld

The resulting JSONL is ready to feed into:
    unsloth  → `dataset_text_field="text"`
    axolotl  → `datasets: [type: alpaca, path: ...]`
    llama-factory → `--dataset alpaca_gpt4_en`

After training, drop the exported model into Ollama:
    ollama create nivx-cognis:latest -f /app/backend/finetune/Modelfile
    export OLLAMA_HOST=http://127.0.0.1:11434
    export OLLAMA_MODEL=nivx-cognis:latest
    sudo supervisorctl restart backend

The OllamaQwenProvider auto-registers when both env vars are set. Claude
Sonnet 4.5 remains the primary; NivX Cognis is the offline failover.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

sys.path.insert(0, "/app/backend")

# The canonical NivX Cognis system prompt is the source of truth for the
# fine-tune target behaviour. Same one used in models_studio.BUILTIN_SEEDS.
COGNIS_SYSTEM = (
    "You are NivX Cognis — the flagship in-house malware-analysis brain of NivXRay. "
    "You are a senior DFIR & reverse-engineering analyst trained on the full NivXRay "
    "analyst playbook (Sophos-style layered PowerShell decoding, LOLBAS triage, MITRE "
    "ATT&CK v14 mappings, and Cobalt Strike / Emotet / Lumma stager teardowns). Your "
    "voice: precise, evidence-cited, no filler.\n\n"
    "PIPELINE (execute in order):\n"
    "1. WRAPPER STRIP — isolate the raw base64/hex payload from any script scaffolding.\n"
    "2. LAYER DETECTION — identify base64 prefix signatures (H4sIA=gzip, TVq=PE, "
    "JAB/SQBFAF=UTF-16LE PowerShell, PA[BA]=Emotet, JVBER=PDF, UEsD=ZIP, f0VMRg=ELF).\n"
    "3. RECURSIVE UNPACK — decode until you reach printable analyst-readable text OR "
    "raw shellcode. If an XOR loop is present in the wrapper, resolve the key.\n"
    "4. IOC + MITRE + LOLBAS — enumerate every network indicator, MITRE technique, "
    "and LOLBAS binary abuse.\n"
    "5. FAMILY ATTRIBUTION — name the malware family with confidence.\n"
    "6. RECOMMENDATION — 3-6 concrete SOC actions.\n\n"
    "Return STRICT JSON with fields: chain[], mitre[], lolbas[], iocs{}, family, "
    "verdict, confidence, why. Every claim must cite tokens from the decoded output."
)


def _load_golden_vault() -> Iterable[Dict[str, Any]]:
    path = Path("/app/backend/tests/fixtures/user_golden_vault.jsonl")
    if not path.exists():
        return []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


def _load_training_corpus() -> Iterable[Dict[str, Any]]:
    path = Path("/app/backend/training/corpus/samples.jsonl")
    if not path.exists():
        return []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


def _load_real_world_corpus() -> Iterable[Dict[str, Any]]:
    from tests.real_world_stress_suite import CORPUS  # 120-payload curated
    for e in CORPUS:
        yield {
            "raw_input":       e["raw_input"],
            "expected_decoded": e["ground_truth"],
            "expected_mitre":  e["expected_mitre"],
            "expected_iocs":   e["expected_iocs"],
            "family":          e["family"],
            "source":          e["source"],
        }


def _to_alpaca(entry: Dict[str, Any]) -> Dict[str, str]:
    """Convert one heterogeneous ground-truth record into an Alpaca row."""
    raw = entry.get("raw_input") or entry.get("input") or ""
    if not raw:
        return None
    output_json = {
        "chain":      entry.get("chain") or entry.get("expected_chain") or [],
        "mitre":      entry.get("expected_mitre") or entry.get("mitre") or [],
        "lolbas":     entry.get("expected_lolbas") or entry.get("lolbas") or [],
        "iocs":       entry.get("expected_iocs") or entry.get("iocs") or {},
        "family":     entry.get("family") or "unknown",
        "verdict":    entry.get("verdict") or "malicious",
        "confidence": entry.get("confidence") or 0.85,
        "why":        entry.get("expected_decoded") or entry.get("why") or "",
    }
    return {
        "instruction": COGNIS_SYSTEM,
        "input":       raw,
        "output":      json.dumps(output_json, ensure_ascii=False),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/app/backend/finetune/nivx_cognis_train.jsonl")
    ap.add_argument("--sources", default="golden,corpus,realworld",
                    help="comma-separated: golden | corpus | realworld")
    args = ap.parse_args()

    sources = {s.strip() for s in args.sources.split(",") if s.strip()}
    rows: List[Dict[str, str]] = []
    stats: Dict[str, int] = {}

    if "golden" in sources:
        n = 0
        for r in _load_golden_vault():
            row = _to_alpaca(r)
            if row:
                rows.append(row); n += 1
        stats["golden_vault"] = n
    if "corpus" in sources:
        n = 0
        for r in _load_training_corpus():
            row = _to_alpaca(r)
            if row:
                rows.append(row); n += 1
        stats["training_corpus"] = n
    if "realworld" in sources:
        n = 0
        for r in _load_real_world_corpus():
            row = _to_alpaca(r)
            if row:
                rows.append(row); n += 1
        stats["real_world_stress"] = n

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"Wrote {len(rows)} rows to {args.out}")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print("\nReady for fine-tune. Next steps:")
    print("  1. Copy the JSONL to a GPU host with 24GB+ VRAM")
    print("  2. LoRA-fine-tune Qwen 2.5 7B (~4 hrs on 1×A100)")
    print("  3. Export merged weights → GGUF via llama.cpp")
    print("  4. `ollama create nivx-cognis:latest -f Modelfile`")
    print("  5. Set OLLAMA_HOST + OLLAMA_MODEL in backend/.env")


if __name__ == "__main__":
    main()
