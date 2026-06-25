#!/usr/bin/env bash
# SovereignSec-AI — local vLLM serving, offline (IMPL_SPEC §4). Run in its OWN venv
# (a stray vLLM install can pull torch cu126 and break sm_120).
#
# Verified corrections baked in:
#   - Model ID needs the -2512 suffix (part of the ID).
#   - Structured-output backend is a SERVER-START flag now: --structured-outputs-config.backend
#     (per-request guided_json/guided_decoding_backend were REMOVED in v0.12).
#   - --max-model-len is a VRAM BUDGET choice (model is natively 256K).
#   - LoRA from Unsloth is HF-format -> if serving a BF16 base + HF LoRA, switch to
#     --tokenizer_mode hf --config_format hf --load_format hf + a jinja template.
#   - Pin cu128 wheels; verify torch.cuda.get_device_capability()==(12,0).
#   - [RUNTIME CHECK] FP8 kernel coverage on sm_120 (consumer Blackwell) has lagged
#     sm_100 — smoke-test the FP8 path + KV headroom at the chosen ctx.
set -euo pipefail
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1

MODEL="${MODEL:-mistralai/Devstral-Small-2-24B-Instruct-2512}"   # local path in air-gap
LORA="${LORA:-/models/loras/audit-cal}"

VLLM_ALLOW_RUNTIME_LORA_UPDATING=1 vllm serve "$MODEL" \
  --served-model-name devstral \
  --tokenizer_mode mistral --config_format mistral --load_format mistral \
  --enable-lora --max-lora-rank 32 --lora-modules "audit-cal=${LORA}" \
  --enable-auto-tool-choice --tool-call-parser mistral \
  --structured-outputs-config.backend xgrammar \
  --max-model-len 65536 --gpu-memory-utilization 0.92 --port 8000
