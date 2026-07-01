# SovereignSec-AI — cross-file PRECISION (the headline)

5 multi-file apps, each a real cross-file vuln + 10 SAFE decoys (same sink, constant/local input). Per-file LLM pattern-matches the sink; cross-file taint follows actual user input. Deterministic scoring (function sets).

| config | recall | precision | decoy false-positives |
|---|---|---|---|
| PER-FILE LLM | 0.60 | 0.25 | 0/10 |
| **SYSTEM (cross-file taint)** | **1.00** | **1.00** | **0/10** |

**Precision: per-file LLM 0.25 → cross-file taint 1.00.** Neither config flags the safe decoys (0/10 each). The LLM's failure mode is elsewhere: it misses 2/5 real vulns (recall 0.60) and raises 9 false positives on *other* functions (precision 0.25). The taint engine flags only proven source→sink paths — 5/5 real vulns, 0 false positives anywhere.

Per-app (real flagged? / decoy FPs):
- app0_fetch [CWE-918]: per-file real=N decoyFP=none | system real=Y decoyFP=none
- app1_storage [CWE-22]: per-file real=N decoyFP=none | system real=Y decoyFP=none
- app2_cache [CWE-502]: per-file real=Y decoyFP=none | system real=Y decoyFP=none
- app3_db [CWE-89]: per-file real=Y decoyFP=none | system real=Y decoyFP=none
- app4_ops [CWE-78]: per-file real=Y decoyFP=none | system real=Y decoyFP=none