#!/usr/bin/env python3
"""SovereignSec-AI — rung-5 QLoRA SFT (+ optional ORPO) on Blackwell (IMPL_SPEC §3).

Stage A = QLoRA SFT for all 3 objectives in one conversational dataset.
Stage B = optional ORPO preference pass — this is what actually moves
precision/calibration (plain SFT never penalizes a confident-wrong finding).

VERIFIED gotchas baked in (these OVERRIDE the original draft):
  - SFTConfig.max_length DEFAULTS TO 1024 — you MUST set it or sequences silently
    truncate. (NOT max_seq_length on SFTConfig.)
  - SFTTrainer takes processing_class=tok, NOT tokenizer=.
  - assistant_only_loss=True needs {% generation %} tags in the chat template.
    Qwen-2.5 has them; stock Mistral/[INST] generally does NOT -> fall back to
    train_on_responses_only — which is KNOWN-FLAKY for Mistral (can mask all
    tokens -> zero loss). [RUNTIME CHECK] decode one batch's labels: assistant
    JSON unmasked, prompt masked.
  - FP8 checkpoint is NOT a QLoRA base. Load BF16 source weights + load_in_4bit=True.
    [RUNTIME CHECK] does an unsloth/...-bnb-4bit repo exist for your build?
  - Blackwell = cu128 EVERYWHERE; keep training and vLLM in SEPARATE venvs.
  - GGUF export shells out to llama.cpp (Unsloth builds it on first call) ->
    PRE-BUILD llama.cpp during setup or it fails air-gapped. push_to_hub_* is online.
"""
from __future__ import annotations

import argparse
import os

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="/models/Devstral-Small-2505-bf16",
                    help="BF16 SOURCE weights (NOT an FP8 checkpoint)")
    ap.add_argument("--chat-template", default="mistral", help='"mistral" | "qwen-2.5"')
    ap.add_argument("--sft-data", required=True, help="conversational JSONL (messages)")
    ap.add_argument("--pref-data", default=None, help="ORPO JSONL {prompt,chosen,rejected}")
    ap.add_argument("--max-len", type=int, default=8192)
    ap.add_argument("--rank", type=int, default=32)
    ap.add_argument("--out", default="/out")
    args = ap.parse_args()

    from unsloth import FastLanguageModel               # import unsloth FIRST
    from unsloth.chat_templates import get_chat_template
    from datasets import load_dataset
    from trl import SFTTrainer, SFTConfig

    model, tok = FastLanguageModel.from_pretrained(
        model_name=args.model, max_seq_length=args.max_len,
        dtype=None, load_in_4bit=True, full_finetuning=False)   # dtype=None -> bf16 on Blackwell
    model = FastLanguageModel.get_peft_model(
        model, r=args.rank, lora_alpha=args.rank, lora_dropout=0.0, bias="none",
        target_modules=LORA_TARGETS, use_gradient_checkpointing="unsloth", random_state=3407)
    tok = get_chat_template(tok, chat_template=args.chat_template)

    ds = load_dataset("json", data_files=args.sft_data, split="train")

    sft = SFTConfig(
        output_dir=f"{args.out}/sft",
        max_length=args.max_len,            # << critical: default is 1024
        packing=False,                       # keep False with response-masking
        assistant_only_loss=True,            # needs {% generation %} tags (see header)
        per_device_train_batch_size=1, gradient_accumulation_steps=16,
        learning_rate=2e-4, num_train_epochs=2, warmup_ratio=0.03,
        lr_scheduler_type="cosine", optim="adamw_8bit", bf16=True, report_to="none")
    SFTTrainer(model=model, processing_class=tok, train_dataset=ds, args=sft).train()
    model.save_pretrained_merged(f"{args.out}/sft_merged", tok, save_method="merged_16bit")

    if args.pref_data:                       # Stage B — calibration / FP-suppression
        from trl import ORPOTrainer, ORPOConfig
        pref = load_dataset("json", data_files=args.pref_data, split="train")
        orpo = ORPOConfig(
            output_dir=f"{args.out}/orpo", beta=0.1,
            max_length=args.max_len, max_prompt_length=4096,
            per_device_train_batch_size=1, gradient_accumulation_steps=16,
            learning_rate=5e-6, num_train_epochs=1, optim="adamw_8bit",
            bf16=True, report_to="none")
        ORPOTrainer(model=model, args=orpo, processing_class=tok, train_dataset=pref).train()

    # GGUF for local serving (PRE-BUILD llama.cpp during setup; this shells out to it)
    model.save_pretrained_gguf(f"{args.out}/final_gguf", tok, quantization_method="q4_k_m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
