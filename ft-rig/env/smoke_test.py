#!/usr/bin/env python3
"""SovereignSec-AI — 4-bit QLoRA smoke test on the fast proxy.

Proves the *whole* gradient path works on this Blackwell box before we scale to
24-27B in Phase 1: load a model in 4-bit, attach a LoRA, run one forward + one
optimizer step. If this passes and `nvidia-smi` shows sane VRAM, the rig is good.

PHASE0_CHECKLIST.md step 4. Maps to PLAN.md §2.3 (VRAM) and §6 (rig).

Usage:
    python smoke_test.py                         # default proxy
    python smoke_test.py --model <hf_repo>       # any QLoRA-able base
"""
from __future__ import annotations

import argparse

PROXY = "Qwen/Qwen2.5-Coder-7B-Instruct"  # ~5-8 GB QLoRA; trains in minutes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=PROXY)
    ap.add_argument("--max-seq-len", type=int, default=2048)
    args = ap.parse_args()

    import torch
    from unsloth import FastLanguageModel

    print(f"Loading {args.model} in 4-bit …")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.max_seq_len,
        dtype=None,            # auto (bf16 on Blackwell)
        load_in_4bit=True,
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_alpha=32,
        lora_dropout=0.0,
        bias="none",
        use_gradient_checkpointing="unsloth",
    )

    # One forward + backward + optimizer step on a trivial batch.
    text = "def add(a, b):\n    return a + b\n"
    batch = tokenizer(text, return_tensors="pt").to(model.device)
    batch["labels"] = batch["input_ids"].clone()

    opt = torch.optim.AdamW(
        (p for p in model.parameters() if p.requires_grad), lr=1e-4
    )
    model.train()
    out = model(**batch)
    out.loss.backward()
    opt.step()
    opt.zero_grad()

    peak = torch.cuda.max_memory_allocated() / 1024**3
    print(f"\nOK — forward+backward+step ran. loss={out.loss.item():.4f}")
    print(f"Peak VRAM (allocated): {peak:.2f} GiB  (log this in RUN_LOG.md)")
    print("Rig works. Safe to scale to the 24-27B base in Phase 1.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
