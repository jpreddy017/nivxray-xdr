# NivX Cognis — Offline LLM Deployment Guide (Qwen 2.5 7B via Ollama)

**Goal**: Turn NivXRay into an air-gapped tool. All AI-driven reasoning
(process-tree prediction, KB synthesis, verdict narration, troubleshoot) runs
locally on your hardware, with the same strict JSON contract + anti-hallucination
validators as the online path.

**Failover behaviour**: `llm_provider.llm_json` tries the online provider
(Emergent Claude Sonnet 4.5) first. If it's unreachable, it automatically falls
through to `OllamaQwenProvider`. Same JSON schema, same validators — no change
at the call-site.

---

## Step 1 · Export the training dataset (already possible today)

From the running NivXRay backend, download the training corpus in
OpenAI-fine-tune format:

```bash
curl -H "Authorization: Bearer $ADMIN_JWT" \
     "$API_URL/api/training/dataset?format=openai" \
     > nivxray_training.jsonl

# 101 seed archetypes across Windows (70) · Linux (27) · macOS (2) · container (2)
wc -l nivxray_training.jsonl
```

Every row is a proper `{"messages":[system,user,assistant]}` triplet with the
strict citation-based system prompt already embedded.

---

## Step 2 · Fine-tune Qwen 2.5 7B with QLoRA (needs GPU)

Runs on a single 24GB card (RTX 3090 / 4090 / A5000 / Colab-A100). Not on
this preview container.

```bash
# One-time
pip install torch transformers datasets peft trl bitsandbytes accelerate

# Fine-tune (Axolotl or trl SFTTrainer — pick your poison)
python -m axolotl.cli.train qwen25_7b_qlora.yaml
```

Recommended axolotl config skeleton (`qwen25_7b_qlora.yaml`):

```yaml
base_model: Qwen/Qwen2.5-7B-Instruct
model_type: Qwen2ForCausalLM
tokenizer_type: AutoTokenizer

load_in_4bit: true
adapter: qlora
lora_r: 32
lora_alpha: 64
lora_dropout: 0.05
lora_target_modules:
  - q_proj
  - k_proj
  - v_proj
  - o_proj
  - gate_proj
  - up_proj
  - down_proj

datasets:
  - path: ./nivxray_training.jsonl
    type: sharegpt.load_openai        # reads OpenAI-format messages array

sequence_len: 4096
sample_packing: true
pad_to_sequence_len: true

gradient_checkpointing: true
micro_batch_size: 2
gradient_accumulation_steps: 8
num_epochs: 3
optimizer: adamw_bnb_8bit
lr_scheduler: cosine
learning_rate: 2e-4
warmup_ratio: 0.03

output_dir: ./nivx-cognis-qlora
```

After training, merge the adapter and export to GGUF (Ollama's format):

```bash
# Merge adapter into base weights
python merge_adapter.py --base Qwen/Qwen2.5-7B-Instruct \
                       --adapter ./nivx-cognis-qlora \
                       --out ./nivx-cognis-merged

# Convert to GGUF (Q4_K_M is a good quality/size trade-off for a 24GB box)
python convert_hf_to_gguf.py ./nivx-cognis-merged --outtype q4_k_m
```

---

## Step 3 · Load into Ollama

Save this as `Modelfile.nivx-cognis` next to your GGUF:

```dockerfile
FROM ./nivx-cognis-merged-q4_k_m.gguf

TEMPLATE """{{ if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ if .Prompt }}<|im_start|>user
{{ .Prompt }}<|im_end|>
{{ end }}<|im_start|>assistant
"""

PARAMETER temperature 0.2
PARAMETER num_predict 4096
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|im_start|>"
```

Load and tag:

```bash
ollama create nivx-cognis -f Modelfile.nivx-cognis
ollama list      # verify nivx-cognis:latest appears
ollama run nivx-cognis "ping"        # sanity test
```

---

## Step 4 · Enable failover in NivXRay backend

Add two env vars to `backend/.env`:

```
OLLAMA_HOST=http://YOUR_OLLAMA_HOST:11434
OLLAMA_MODEL=nivx-cognis:latest
```

Restart the backend:

```bash
sudo supervisorctl restart backend
```

Verify the chain:

```bash
curl -H "Authorization: Bearer $ADMIN_JWT" \
     "$API_URL/api/system/llm-providers"
```

You should now see:

```json
{
  "chain": [
    {"name": "emergent-claude-sonnet-4-5",  "kind": "online",  "priority": 10},
    {"name": "ollama:nivx-cognis:latest",   "kind": "offline", "priority": 100}
  ]
}
```

That's it. Every AI call — `POST /api/ai/*`, `POST /api/analyze/process-tree`,
`POST /api/kb/rebuild` with synth — will automatically fall through to
NivX Cognis whenever the online provider is unreachable.

---

## Step 5 · Air-gapped test

Simulate loss of internet:

```bash
# Firewall the Emergent LLM endpoint
sudo iptables -A OUTPUT -d api.emergent.sh -j DROP

# Trigger any AI action — process-tree, KB rebuild, etc.
curl -H "Authorization: Bearer $ADMIN_JWT" \
     -H "Content-Type: application/json" \
     -X POST "$API_URL/api/analyze/process-tree" \
     -d '{"raw":"powershell -c IEX(...)","decoded":"powershell -c IEX(...)"}'
```

Backend logs should show:

```
llm_provider: emergent-claude-sonnet-4-5 failed (connection refused) — trying next
```

And the response still succeeds — served by NivX Cognis.

---

## What the JSON schema contract guarantees

Both providers speak the SAME contract because the SYSTEM prompt is identical
across them. The strict validators (`training.validator.validate_and_prune`,
`knowledge_base.synthesizer._verify_citations`) run AFTER either provider
returns — they don't care who generated the JSON, they just enforce:

- every process node has an evidence citation traceable to the decoded payload
- every IOC in `rationale.iocs` is a verbatim substring of the decoded/raw text
- uncited fields are pruned + warning appended

Result: **swapping Claude ↔ Qwen changes speed and cost, never correctness.**

---

## Cost & performance envelope (recommendation)

| Path              | Latency          | Cost/req            | Where data goes         |
|-------------------|------------------|---------------------|-------------------------|
| Claude Sonnet 4.5 | 2–8 s            | ~$0.003–$0.015      | Emergent → Anthropic    |
| NivX Cognis (Q4)  | 4–12 s (24GB GPU) | 0                  | Never leaves your box   |

For high-volume triage or DFIR customers, the offline path pays for itself
within a few thousand requests. For rare / hard cases, Claude still wins on
quality — hence the hybrid design.
