# SovereignSec-AI — complete rungs-0->5 ablation

LLM rungs: bare audit on the REAL held-out mined set (base vs fine-tuned 7B).
System rungs: deterministic on the seeded cross-file fixture.

| rung | P | R | F1 | note |
|---|---|---|---|---|
| R0  base LLM, bare (held-out real CVEs) | 1.0 | 0.95 | 0.974 | LLM-only floor |
| R2  SAST tool-only (seeded) | 1.0 | 1.0 | 1.0 | deterministic baseline |
| R4  system: SAST + cross-file taint (seeded) | 1.0 | 1.0 | 1.0 | 1 taint path(s) |
| R5  fine-tuned LLM, bare (held-out real CVEs) | 1.0 | 1.0 | 1.0 | FT delta vs R0 |

**Fine-tune delta on real held-out CVEs (R5 vs R0): recall 0.95→1.0 (+0.05), precision 1.0→1.0 (+0.0)**

_Honest scope: held-out split is by CWE-family from the same repos (not post-cutoff); seeded fixture saturates the deterministic system, so the FT delta shows on the LLM rungs. Next: 24-27B base + agentic loop on harder evals._