#!/usr/bin/env python3
"""Measured QLoRA smoke-train on Blackwell (M3) — captures VRAM, tokens/sec, time, loss.

This is the "Blackwell optimization story" portfolio metric. It's a SMOKE run on a
small model + tiny dataset to prove the rig + capture real numbers; the production
run uses the 24-27B base on the 20k moat dataset (ft-rig/train/rung5_train.py).

Run (train venv):
  TMPDIR="$PWD/.tmp" HF_HOME="$PWD/.tmp/hf" PYTHONPATH=ft-rig \
    .venv-train/bin/python bench/bench_train.py --model Qwen/Qwen2.5-Coder-1.5B-Instruct \
    --data ft-rig/data/out/smoke_sft.jsonl --max-steps 30
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-1.5B-Instruct")
    ap.add_argument("--data", default="ft-rig/data/out/smoke_sft.jsonl")
    ap.add_argument("--max-seq-len", type=int, default=2048)
    ap.add_argument("--max-steps", type=int, default=30)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--out", default="out/smoke_adapter")
    ap.add_argument("--chat-template", default="qwen-2.5")
    args = ap.parse_args()

    import torch
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import get_chat_template
    from datasets import load_dataset
    from trl import SFTTrainer, SFTConfig

    t_load0 = time.perf_counter()
    model, tok = FastLanguageModel.from_pretrained(
        model_name=args.model, max_seq_length=args.max_seq_len,
        dtype=None, load_in_4bit=True)
    model = FastLanguageModel.get_peft_model(
        model, r=args.rank, lora_alpha=args.rank, lora_dropout=0.0, bias="none",
        target_modules=LORA_TARGETS, use_gradient_checkpointing="unsloth", random_state=3407)
    tok = get_chat_template(tok, chat_template=args.chat_template)
    load_s = time.perf_counter() - t_load0
    weight_vram_gib = torch.cuda.memory_allocated() / 1024**3

    ds = load_dataset("json", data_files=args.data, split="train")
    ds = ds.map(lambda r: {"text": tok.apply_chat_template(r["messages"], tokenize=False)})

    torch.cuda.reset_peak_memory_stats()
    cfg = SFTConfig(
        output_dir=args.out, dataset_text_field="text", max_length=args.max_seq_len,
        packing=False, per_device_train_batch_size=1, gradient_accumulation_steps=4,
        warmup_steps=2, max_steps=args.max_steps, learning_rate=2e-4,
        logging_steps=5, optim="adamw_8bit", bf16=True, report_to="none", seed=3407)
    trainer = SFTTrainer(model=model, processing_class=tok, train_dataset=ds, args=cfg)

    t0 = time.perf_counter()
    out = trainer.train()
    train_s = time.perf_counter() - t0
    peak_vram_gib = torch.cuda.max_memory_allocated() / 1024**3

    model.save_pretrained(args.out)
    tok.save_pretrained(args.out)

    m = out.metrics
    result = {
        "model": args.model, "dataset": args.data, "rows": len(ds),
        "max_seq_len": args.max_seq_len, "max_steps": args.max_steps, "lora_rank": args.rank,
        "gpu": torch.cuda.get_device_name(0),
        "compute_capability": list(torch.cuda.get_device_capability(0)),
        "torch": torch.__version__, "torch_cuda": torch.version.cuda,
        "load_time_s": round(load_s, 2),
        "weights_vram_gib_4bit": round(weight_vram_gib, 2),
        "peak_vram_gib_training": round(peak_vram_gib, 2),
        "train_time_s": round(train_s, 2),
        "train_samples_per_s": round(m.get("train_samples_per_second", 0), 3),
        "train_steps_per_s": round(m.get("train_steps_per_second", 0), 3),
        "final_loss": round(m.get("train_loss", 0), 4),
        "adapter": args.out,
    }
    Path("bench/results").mkdir(parents=True, exist_ok=True)
    Path("bench/results/train_benchmark.json").write_text(json.dumps(result, indent=2))
    print("\n=== M3 smoke-train benchmark ===")
    for k, v in result.items():
        print(f"  {k}: {v}")
    print("wrote bench/results/train_benchmark.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
