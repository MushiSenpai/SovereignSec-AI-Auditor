# SovereignSec-AI — cross-file PRECISION (the headline)

5 multi-file apps, each a real cross-file vuln + 10 SAFE decoys (same sink, constant/local input). Per-file LLM pattern-matches the sink; cross-file taint follows actual user input. Deterministic scoring (function sets).

| config | recall | precision | decoy false-positives |
|---|---|---|---|
| PER-FILE LLM | 0.60 | 0.25 | 0/10 |
| **SYSTEM (cross-file taint)** | **1.00** | **1.00** | **0/10** |

**Precision: per-file LLM 0.25 → cross-file taint 1.00.** The LLM false-positives on 0/10 safe decoys; the taint engine on 0/10 — it only flags paths user input reaches.

Per-app (real flagged? / decoy FPs):
- app0_fetch [CWE-918]: per-file real=N decoyFP=none | system real=Y decoyFP=none
- app1_storage [CWE-22]: per-file real=N decoyFP=none | system real=Y decoyFP=none
- app2_cache [CWE-502]: per-file real=Y decoyFP=none | system real=Y decoyFP=none
- app3_db [CWE-89]: per-file real=Y decoyFP=none | system real=Y decoyFP=none
- app4_ops [CWE-78]: per-file real=Y decoyFP=none | system real=Y decoyFP=none