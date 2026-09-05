# NivX Cognis — Fine-tune Activation Guide

**Status:** Scaffolded. Dataset exporter + Modelfile shipped. Actual training + Ollama deployment is **manual** — the ed preview environment has no GPU.

## What's here now

| File | Purpose |
|------|---------|
| `export_dataset.py` | Exports Golden Vault + Training Corpus + Real-World Stress Suite → Alpaca-format JSONL |
| `Modelfile` | Ollama Modelfile scaffold (GGUF path + Qwen2.5 chat template + NivX Cognis system prompt) |
| `README.md` | This guide |

## Step-by-step activation

### 1. Export the training set (runs in preview)

```bash
cd /app/backend
python finetune/export_dataset.py --out finetune/nivx_cognis_train.jsonl
```

Expected: ~700 rows (Golden Vault + curated corpus + 120 real-world entries), each with `{instruction, input, output}` in strict Alpaca format.

### 2. Fine-tune on a GPU host (external — needs 24GB+ VRAM)

Recommended tooling (unsloth is fastest):

```bash
# On a GPU host — Vast.ai / RunPod / Lambda / your own workstation
pip install unsloth transformers datasets

python <<'EOF'
from unsloth import FastLanguageModel
from datasets import load_dataset
model, tok = FastLanguageModel.from_pretrained(
    "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
    max_seq_length=8192, load_in_4bit=True,
)
model = FastLanguageModel.get_peft_model(
    model, r=32, target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
    lora_alpha=32, use_gradient_checkpointing="unsloth",
)
ds = load_dataset("json", data_files="nivx_cognis_train.jsonl", split="train")
def fmt(x):
    return {"text": f"<|im_start|>system\n{x['instruction']}<|im_end|>\n<|im_start|>user\n{x['input']}<|im_end|>\n<|im_start|>assistant\n{x['output']}<|im_end|>"}
ds = ds.map(fmt)
from trl import SFTTrainer, SFTConfig
tr = SFTTrainer(model=model, tokenizer=tok, train_dataset=ds,
                args=SFTConfig(output_dir="./nivx-cognis-lora",
                               num_train_epochs=3, per_device_train_batch_size=2,
                               learning_rate=2e-4, logging_steps=20, save_steps=200))
tr.train()
model.save_pretrained_merged("./nivx-cognis-merged", tok, save_method="merged_16bit")
EOF
```

Runtime: ~3-4 hours on 1×A100 40GB, ~8 hours on 1×RTX 4090.

### 3. Convert to GGUF (llama.cpp)

```bash
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp && make -j
python convert_hf_to_gguf.py /path/to/nivx-cognis-merged \
    --outfile nivx-cognis.q5_k_m.gguf --outtype q5_K_M
```

Q5_K_M is the recommended quantization — ~5GB, retains ~97% of full-precision quality.

### 4. Build the Ollama image

Copy the GGUF next to the `Modelfile`:

```bash
cp nivx-cognis.q5_k_m.gguf /app/backend/finetune/
cd /app/backend/finetune
ollama create nivx-cognis:latest -f Modelfile
ollama list        # should show nivx-cognis:latest
ollama run nivx-cognis:latest "test"
```

### 5. Wire NivXRay to the local Ollama

Add to `backend/.env`:

```
OLLAMA_HOST=http://127.0.0.1:11434
OLLAMA_MODEL=nivx-cognis:latest
```

```bash
sudo supervisorctl restart backend
```

**On boot, `llm_provider.OllamaQwenProvider` auto-registers.** Claude Sonnet 4.5 remains the primary online provider; NivX Cognis becomes the **offline failover** — used automatically if the Emergent LLM key exhausts or the network drops.

### 6. Verify

```bash
curl -s http://127.0.0.1:11434/api/generate \
  -d '{"model":"nivx-cognis:latest","prompt":"decode: powershell -Enc SQBFAFgA","stream":false,"format":"json"}' | jq
```

Should return a JSON verdict matching the NivX Cognis schema (chain, mitre, lolbas, iocs, family, verdict, confidence, why).

## Cost estimate

| Item | Cost |
|------|------|
| GPU rental (Vast.ai A100 40GB × 4h) | ~$4 |
| Storage (GGUF ~5GB) | negligible |
| Ollama inference (self-hosted, no per-call cost) | $0 |
| **Total one-time** | **~$4** |

Compared to per-call Claude Sonnet 4.5 (~$3 per 1M input tokens), the Qwen fallback breaks even after ~1.3M input tokens processed — trivial for any active production analyst team.

## When to activate

Trigger the fine-tune when **any** of these happen:
- Emergent LLM key credit burn exceeds acceptable OPEX
- Air-gapped / offline analyst deployment required (SOC in classified environment)
- You want to advertise "runs 100% self-hosted, no data leaves your infra"
- You want deterministic reproducibility (same input → same output, always)
