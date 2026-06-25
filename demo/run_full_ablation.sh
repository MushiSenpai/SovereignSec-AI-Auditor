#!/usr/bin/env bash
# Orchestrate the complete rungs-0->5 ablation (deterministic + base vs FT LLM).
# Usage: BASE=<hf_id> FT=<adapter_dir> MAXEVAL=40 bash demo/run_full_ablation.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export TMPDIR="$PWD/.tmp" HF_HOME="$PWD/.tmp/hf"
BASE="${BASE:-Qwen/Qwen2.5-Coder-7B-Instruct}"
FT="${FT:-out/real_adapter_7b}"
MAXEVAL="${MAXEVAL:-40}"

echo "== deterministic system rungs (seeded) =="
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=. .venv/bin/python demo/run_full_ablation.py --mode deterministic
echo "== LLM rung: base ($BASE) on real held-out =="
PYTHONPATH=. .venv-train/bin/python demo/run_full_ablation.py --mode llm --model-dir "$BASE" --label base --max-eval "$MAXEVAL"
echo "== LLM rung: fine-tuned ($FT) on real held-out =="
PYTHONPATH=. .venv-train/bin/python demo/run_full_ablation.py --mode llm --model-dir "$FT" --label ft --max-eval "$MAXEVAL"
echo "== merge =="
PYTHONPATH=. .venv/bin/python demo/run_full_ablation.py --mode merge
