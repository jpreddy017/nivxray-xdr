#!/usr/bin/env bash
# NivX Cognis · Qwen 2.5 7B one-shot fine-tune bootstrap
#
# Run on a GPU host (Vast.ai / RunPod / Lambda / your own workstation with 24GB+ VRAM).
# Assumes an Ubuntu 22.04 CUDA 12.x AMI.
#
# Usage:
#   # (on preview / your Emergent host)
#   python /app/backend/finetune/export_dataset.py --out /tmp/nivx_cognis_train.jsonl
#   scp /tmp/nivx_cognis_train.jsonl user@gpu-host:~/
#
#   # (on the GPU host)
#   curl -o run_finetune.sh https://<preview-host>/app/backend/finetune/run_finetune.sh
#   chmod +x run_finetune.sh
#   ./run_finetune.sh
#
# Output:
#   ~/nivx-cognis-merged/     — merged HF weights (fp16)
#   ~/nivx-cognis.q5_k_m.gguf — quantized GGUF ready for Ollama
#
# Deploy back to NivXRay:
#   scp nivx-cognis.q5_k_m.gguf user@preview-host:/app/backend/finetune/
#   ssh user@preview-host 'cd /app/backend/finetune && ollama create nivx-cognis:latest -f Modelfile'
#   # then set OLLAMA_HOST + OLLAMA_MODEL in backend/.env and restart supervisor.
set -euo pipefail

echo "== NivX Cognis · Qwen 2.5 7B fine-tune bootstrap =="
if [ ! -f "nivx_cognis_train.jsonl" ]; then
    echo "ERROR: nivx_cognis_train.jsonl not found in \$(pwd)"
    echo "Copy it from your preview host first:"
    echo "  scp <preview>:/app/backend/finetune/nivx_cognis_train.jsonl ."
    exit 1
fi

echo "== 1/5 · Install unsloth + llama.cpp =="
pip install -q --upgrade pip
pip install -q "unsloth[cu121-torch230] @ git+https://github.com/unslothai/unsloth.git" \
                 transformers datasets trl accelerate peft bitsandbytes sentencepiece protobuf

if [ ! -d "llama.cpp" ]; then
    git clone --depth 1 https://github.com/ggerganov/llama.cpp
    (cd llama.cpp && make -j$(nproc) LLAMA_CUDA=1)
fi

echo "== 2/5 · LoRA fine-tune Qwen 2.5 7B (3 epochs, batch=2) =="
python - <<'PY'
from unsloth import FastLanguageModel
from datasets import load_dataset
from trl import SFTTrainer, SFTConfig

model, tok = FastLanguageModel.from_pretrained(
    "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
    max_seq_length=8192, load_in_4bit=True,
)
model = FastLanguageModel.get_peft_model(
    model, r=32,
    target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
    lora_alpha=32, use_gradient_checkpointing="unsloth",
)
ds = load_dataset("json", data_files="nivx_cognis_train.jsonl", split="train")
def fmt(x):
    return {"text":
        f"<|im_start|>system\n{x['instruction']}<|im_end|>\n"
        f"<|im_start|>user\n{x['input']}<|im_end|>\n"
        f"<|im_start|>assistant\n{x['output']}<|im_end|>"}
ds = ds.map(fmt, remove_columns=[c for c in ds.column_names if c != 'text'])
tr = SFTTrainer(
    model=model, tokenizer=tok, train_dataset=ds,
    dataset_text_field="text", max_seq_length=8192,
    args=SFTConfig(
        output_dir="./nivx-cognis-lora",
        num_train_epochs=3, per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        learning_rate=2e-4, warmup_steps=20,
        logging_steps=20, save_steps=200,
        optim="paged_adamw_8bit",
        report_to="none",
    ),
)
tr.train()
model.save_pretrained_merged("./nivx-cognis-merged", tok, save_method="merged_16bit")
print("== LoRA merged into ./nivx-cognis-merged ==")
PY

echo "== 3/5 · Convert to GGUF =="
python llama.cpp/convert_hf_to_gguf.py ./nivx-cognis-merged \
    --outfile ./nivx-cognis.f16.gguf --outtype f16

echo "== 4/5 · Quantize to Q5_K_M (~5GB) =="
./llama.cpp/llama-quantize ./nivx-cognis.f16.gguf ./nivx-cognis.q5_k_m.gguf Q5_K_M

echo "== 5/5 · Cleanup + summary =="
rm -f ./nivx-cognis.f16.gguf
du -h ./nivx-cognis.q5_k_m.gguf
echo ""
echo "DONE. Now copy nivx-cognis.q5_k_m.gguf back to your NivXRay host:"
echo "  scp nivx-cognis.q5_k_m.gguf <preview>:/app/backend/finetune/"
echo "  ssh <preview> 'cd /app/backend/finetune && ollama create nivx-cognis:latest -f Modelfile'"
echo "  ssh <preview> 'echo OLLAMA_HOST=http://127.0.0.1:11434 >> /app/backend/.env'"
echo "  ssh <preview> 'echo OLLAMA_MODEL=nivx-cognis:latest >> /app/backend/.env'"
echo "  ssh <preview> 'sudo supervisorctl restart backend'"
