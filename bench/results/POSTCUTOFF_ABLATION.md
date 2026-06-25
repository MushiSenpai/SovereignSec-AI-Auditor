# SovereignSec-AI — POST-CUTOFF ablation (leak-resistant)

Eval: real CVEs published 2025+ / fix commits 2024-07+ (30 vuln + 30 safe), unmemorizable by the base. Model: 32B base vs fine-tuned.

| model | P | R | F1 | accuracy |
|---|---|---|---|---|
| base 32B | 1.0 | 1.0 | 1.0 | 1.0 |
| fine-tuned 32B | 1.0 | 1.0 | 1.0 | 1.0 |

**FT delta on post-cutoff CVEs: recall 1.0→1.0 (+0.0), precision 1.0→1.0 (+0.0).**

This is the honest detection number: the eval is genuinely post-training-cutoff, so no memorization. Compare against the same-distribution held-out (FULL_ABLATION.md) to see how much of that near-perfect score was leakage.