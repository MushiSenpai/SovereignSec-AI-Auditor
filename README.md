# SovereignSec-AI

> A fully local, agentic AI security reviewer for proprietary codebases.
> Understands a whole repo, explains its reasoning, **validates its own findings**, and never sends a byte off the machine.

A deterministic **cross-file taint engine** + SAST + an optional local LLM, combined in a **hybrid**
that returns *proof-carrying* findings — fully air-gapped.

## Quick start (the MVP)
```bash
# one-command, air-gapped (no GPU, no model, zero egress)
docker build -t sovereignsec .
docker run --rm --network=none -v "$PWD:/target:ro" sovereignsec audit /target
# or locally:
pip install tree-sitter tree-sitter-python jedi networkx semgrep bandit pyyaml
PYTHONPATH=. python -m sscai audit demo/seeded_repo
```
```
[HIGH  ] CWE-89   db.py::find_user   ✔ PROVEN (taint)
          evidence: user -> user_lookup() [arg 0] -> find_user() [arg 0] -> find_user
```
The `✔ PROVEN` findings carry a deterministic source→sink taint path — not an LLM guess.

## Honest results (all measured — see `bench/results/`)
- **Hybrid (LLM + system) 0.97** on a hard 29-module benchmark, beating LLM-alone (0.90).
- **Cross-file taint** traces vulns across files with **zero false positives on safe-but-suspicious decoys** (where a per-file LLM false-positives).
- **The fine-tune adds ~0 detection** over the base — its honest value is output schema/calibration. Capability lives in the *system*. (See [`INSIGHTS.md`](INSIGHTS.md).)

## Models (HuggingFace)
Two QLoRA adapters (Qwen2.5-Coder), trained locally on a single RTX 5090 on 879 real mined CVE→patch pairs:
- [SovereignSec-Auditor-LoRA-Qwen2.5-Coder-7B](https://huggingface.co/MushiSenpai/SovereignSec-Auditor-LoRA-Qwen2.5-Coder-7B) — train loss 0.686
- [SovereignSec-Auditor-LoRA-Qwen2.5-Coder-32B](https://huggingface.co/MushiSenpai/SovereignSec-Auditor-LoRA-Qwen2.5-Coder-32B) — train loss 0.562

> **Honest note:** on a post-cutoff (leak-resistant) eval these adapters add **~0 detection capability** over the base model — their value is **output schema/calibration**, not "smarter" detection. Detection lives in the *system*. Each model card spells out exactly what the adapter does and does not do.

## Start here
- 🟢 [`EXPLAIN_LIKE_IM_10.md`](EXPLAIN_LIKE_IM_10.md) — **the whole project in plain English** (no jargon hidden). Start here if you're new.
- ⭐ [`INSIGHTS.md`](INSIGHTS.md) — **what building this actually taught me**. The honest field report: why the fine-tune adds zero detection, the measurement bugs, toy-eval 1.0 vs real-file 0.07, and the hybrid that wins.
- ❓ [`docs/FAQ.md`](docs/FAQ.md) — the two honest questions: *"did the fine-tuning fail?"* and *"how would you spot a zero-day?"*
- [`BLOG_QUEUE.md`](BLOG_QUEUE.md) — every failure and fix, as blog-ready entries (the raw log behind the insights).
- [`bench/results/`](bench/results/) — all measured results (train metrics, ablations, post-cutoff, haystack, cross-file — with raw model outputs saved).

## Layout
```
sovereign-code-auditor/
├── README.md
├── EXPLAIN_LIKE_IM_10.md   # the whole project in plain English (start here)
├── INSIGHTS.md             # honest field report — what building this taught me
├── docs/FAQ.md             # "did the fine-tune fail?" · "how would you spot a zero-day?"
├── BLOG_QUEUE.md           # every failure + fix, blog-ready
├── IMPL_SPEC.md            # grounded design spec (all components)
├── Dockerfile              # air-gapped one-command MVP
├── LICENSE                 # Apache-2.0 + third-party notices
├── sscai/                  # the product
│   ├── graph/              # tree-sitter + call graph + cross-file taint engine
│   ├── sast/               # Semgrep-OSS + Bandit + own rules
│   ├── agent/              # agentic audit loop + hybrid merge
│   ├── validation/         # proof / validation oracle (scorecard)
│   └── cli.py              # `python -m sscai audit <repo>`
├── demo/                   # seeded_repo fixture + ablation/haystack runners + recordings
├── bench/results/          # all measured results (with raw model outputs saved)
├── tests/                  # M2 acceptance suite (12 tests)
└── ft-rig/                 # reusable fine-tuning rig (project-agnostic)
    ├── env/                # pinned Blackwell (sm_120) toolchain + HARD verification gate
    ├── data/               # GHSA→fix-commit miner + dataset generators (the moat)
    ├── train/              # QLoRA training (Unsloth + TRL)
    ├── serve/              # local vLLM serving
    └── eval/               # ablation-ladder harness
```

## Status — shipped & measured
- **Core auditor** ✅ runs fully air-gapped today: cross-file taint + SAST → *proof-carrying* findings (`python -m sscai audit`).
- **L1–L5 system** ✅ implemented, **12 tests green** against `demo/seeded_repo/`.
- **Data moat** ✅ GHSA→fix-commit miner validated on real OSV data; **879 real vuln→patch pairs** mined (see [`BLOG_QUEUE.md`](BLOG_QUEUE.md) F1).
- **Fine-tune** ✅ LoRA adapters trained on 1.5B / 7B / 32B Qwen2.5-Coder (losses 0.856 / 0.686 / 0.562); **post-cutoff detection delta +0.0** — value is output schema/calibration, not detection. [Adapters on HuggingFace](https://huggingface.co/MushiSenpai/SovereignSec-Auditor-LoRA-Qwen2.5-Coder-7B).
- **Hybrid** ✅ **0.97** on the 29-module benchmark (beats LLM-alone 0.90). All numbers in [`bench/results/`](bench/results/).
- **Learnings:** every failure + fix is in [`BLOG_QUEUE.md`](BLOG_QUEUE.md).

## Dev setup & tests
```bash
python3 -m venv .venv && .venv/bin/pip install -U pip
.venv/bin/pip install tree-sitter tree-sitter-python jedi networkx flask pytest semgrep bandit datasketch pydriller pyyaml
# run the M2 acceptance suite + eval metrics
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=.:ft-rig/eval .venv/bin/python -m pytest tests/ ft-rig/eval/tests/ -q
# see the ablation (Semgrep-CE-only R=0.5 -> +taint P=R=1.0)
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=. .venv/bin/python demo/run_ablation.py
```
QLoRA training ([`ft-rig/train/`](ft-rig/train)) and vLLM serving ([`ft-rig/serve/`](ft-rig/serve)) run on the GPU — see [`IMPL_SPEC.md`](IMPL_SPEC.md) and [`bench/results/M3_REPORT.md`](bench/results/M3_REPORT.md).
