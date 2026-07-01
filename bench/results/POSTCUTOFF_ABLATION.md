# SovereignSec-AI — POST-CUTOFF ablation (leak-resistant)

Eval: real CVEs published 2025+ / fix commits 2024-07+ (30 vuln + 30 safe), unmemorizable by the base. Model: 32B base vs fine-tuned.

| model | P | R | F1 | accuracy |
|---|---|---|---|---|
| base 32B | 1.0 | 1.0 | 1.0 | 1.0 |
| fine-tuned 32B | 1.0 | 1.0 | 1.0 | 1.0 |

**FT delta on post-cutoff CVEs: recall 1.0→1.0 (+0.0), precision 1.0→1.0 (+0.0).**

This is the honest detection number: the eval is genuinely post-training-cutoff, so no memorization. Compare against the same-distribution held-out (FULL_ABLATION.md) to see how much of that near-perfect score was leakage.

**Ceiling-effect caveat:** the base 32B already scores P=R=1.0 on this eval, so there is no headroom for a fine-tune to show a detection gain — the "+0.0 delta" is partly saturation of an eval the base model already aces. The honest claim is "no measurable detection gain on this eval", not "proven zero gain in general". A harder post-cutoff eval (subtler vulns, longer cross-file contexts) that pulls the base off the ceiling is future work.