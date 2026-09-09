#!/usr/bin/env bash
# NivXRay — Offline LLM fine-tuning recipe (Feb-2026 #8)
#
# End-to-end walkthrough for training a small local model on the NivXRay
# decoder task using the JSONL you export from /api/admin/finetune/dataset.
#
# Steps:
#   1. Export training data as ChatML JSONL
#   2. Fine-tune a Qwen 2.5 base model with LoRA via llama-factory
#   3. Merge LoRA into a GGUF checkpoint
#   4. Import into Ollama and set NivXRay's env vars to use it
#
# This script is DOCUMENTATION-ONLY — run each block on a workstation
# with a GPU. The NivXRay container itself does NOT train.
# ---------------------------------------------------------------------
set -euo pipefail

: "${API_URL:?Set API_URL to your NivXRay base URL (no trailing slash)}"
: "${TOKEN:?Set TOKEN to an admin bearer token}"
: "${OLLAMA_HOST:=http://localhost:11434}"
: "${BASE_MODEL:=Qwen/Qwen2.5-7B-Instruct}"
: "${LORA_OUT:=./nivxray-lora}"
: "${MERGED_OUT:=./nivxray-merged}"
: "${GGUF_OUT:=./nivxray.gguf}"

# ── 1. Export training data ──────────────────────────────────────────
echo "→ Exporting ChatML JSONL from $API_URL"
curl -fsSL -H "Authorization: Bearer $TOKEN" \
     "$API_URL/api/admin/finetune/dataset?fmt=chatml&limit=20000" \
     -o nivxray-train.jsonl
wc -l nivxray-train.jsonl

# ── 2. Fine-tune with LoRA (llama-factory) ───────────────────────────
# Prereq: pip install llama-factory[torch,metrics] transformers accelerate peft
echo "→ Fine-tuning $BASE_MODEL with LoRA"
llamafactory-cli train \
    --stage sft \
    --do_train \
    --model_name_or_path "$BASE_MODEL" \
    --dataset_dir . \
    --dataset nivxray-train \
    --template qwen \
    --finetuning_type lora \
    --lora_target q_proj,v_proj \
    --output_dir "$LORA_OUT" \
    --per_device_train_batch_size 2 \
    --gradient_accumulation_steps 8 \
    --lr_scheduler_type cosine \
    --logging_steps 10 \
    --save_steps 200 \
    --learning_rate 5e-5 \
    --num_train_epochs 3 \
    --bf16 True \
    --plot_loss True

# ── 3. Merge LoRA + convert to GGUF for Ollama ───────────────────────
echo "→ Merging LoRA into base weights"
llamafactory-cli export \
    --model_name_or_path "$BASE_MODEL" \
    --adapter_name_or_path "$LORA_OUT" \
    --template qwen \
    --finetuning_type lora \
    --export_dir "$MERGED_OUT" \
    --export_size 2 \
    --export_legacy_format False

echo "→ Converting to GGUF"
# Prereq: git clone https://github.com/ggerganov/llama.cpp && make
python llama.cpp/convert.py "$MERGED_OUT" --outfile "$GGUF_OUT" \
    --outtype q4_K_M

# ── 4. Import into Ollama ────────────────────────────────────────────
echo "→ Creating Ollama model 'nivxray'"
cat > Modelfile <<EOF
FROM $GGUF_OUT
TEMPLATE """{{ if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ if .Prompt }}<|im_start|>user
{{ .Prompt }}<|im_end|>
{{ end }}<|im_start|>assistant
"""
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|im_start|>"
PARAMETER temperature 0.1
SYSTEM """You are NivXRay, a CyberChef-style decoder. Reply with JSON only."""
EOF
ollama create nivxray -f Modelfile

# ── 5. Configure NivXRay to use it ───────────────────────────────────
cat <<EOF
✅ Fine-tuning complete. To make NivXRay use the offline model, set on
   the backend server:

     LLM_TIEBREAKER_PROVIDER=ollama    # or "auto" to prefer Claude when available
     OFFLINE_LLM_URL=$OLLAMA_HOST
     OFFLINE_LLM_MODEL=nivxray

   Then verify from /admin:
     curl -H "Authorization: Bearer \$TOKEN" \\
          -X POST "\$API_URL/api/admin/finetune/test-offline-llm"

   The tiebreaker will now route to your local Qwen LoRA in "deep" mode
   whenever the top two deterministic candidates score within TIE_THRESHOLD.
EOF
