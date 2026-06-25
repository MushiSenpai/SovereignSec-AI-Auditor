# `sscai_eval` — SovereignSec-AI evaluation harness

The spine of the case study (see [`../../INSIGHTS.md`](../../INSIGHTS.md)). It exists to answer one question honestly:
**how much does each layer of the system actually add, and how much does the fine-tune add?**

## Modules
| Module | Role | Phase-0 status |
|---|---|---|
| `schema.py` | `Finding` / `Severity` / `ValidationStatus` — the structured report contract | ✅ defined |
| `rungs.py` | the 6-rung ablation ladder (base → +retrieval → +SAST → +agent → +validation → +finetune) | ✅ defined |
| `metrics.py` | precision/recall/F1, pass@k, patch-validation rate, delta-vs-baseline | ✅ implemented + tested |
| `pipeline.py` | `Auditor` protocol + per-rung pipeline factory; layer stubs | 🟡 contracts only — layers land in Phase 1 |
| `contamination.py` | gold-patch reproduction probe (excludes findings the base model memorized) | 🟡 stub — implement when a model backend exists |
| `datasets.py` | `EvalItem` + held-out / canaried set loaders | 🟡 stub — wire in Phase-0 step 6 |

## Phase-0 vs Phase-1
- **Phase 0:** harness installs, metrics tested, the held-out set is built and contamination-filtered, and the two *no-scaffolding* baselines are implemented to get first numbers: **rung 0** (bare LLM) and the **SAST-only** baseline (Semgrep, no LLM).
- **Phase 1:** the retrieval / agent / validation layers (`pipeline.py` stubs) are implemented one at a time — each lights up its rung — and **rung 5 (the fine-tuned model)** completes the ladder.

## Run
```bash
pip install -e .
pytest -q                       # metrics are real + tested
python ../run_baseline.py --model Qwen/Qwen2.5-Coder-7B-Instruct --rungs 0,2 --set owasp_benchmark
```
`run_baseline.py` never crashes on unimplemented rungs — it prints them as `pending (Phase 1)` so you can see the ladder fill in over time.

## Non-negotiables
- Always report the **delta vs the SAST-tool-alone baseline** — robust to "the model already knew the CVE."
- Evaluate on **post-cutoff CVEs *and* closed-source code**; run the **contamination probe**; keep a **private canaried** set.
- "Tests pass" ≠ fixed: validate patches with the **full** suite + differential tests + multiple payloads.
