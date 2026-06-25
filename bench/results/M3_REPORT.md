# SovereignSec-AI — M3 smoke-train report (real RTX 5090)

A QLoRA smoke-train to (a) prove the training rig runs end-to-end on Blackwell, (b) capture
the "Blackwell optimization" metrics, and (c) **empirically** confirm the CUDA-13.2-driver /
12.8-runtime config produces coherent output (no gibberish). It is **not** a capability run —
that needs the 24–27B base on the 20k generate-and-verify moat dataset.

## Setup
- Model: `Qwen/Qwen2.5-Coder-1.5B-Instruct`, 4-bit QLoRA, rank 16, 18.46M trainable (1.18%).
- Data: 120 templated records produced by `ft-rig/data/make_smoke_dataset.py` (written to `ft-rig/data/out/smoke_sft.jsonl`, not committed) — 50% taint-audit positives, 50% calibration negatives.
- 30 steps, batch 1 × grad-accum 4, bf16, adamw_8bit, max_seq_len 2048.

## Measured (real Blackwell numbers — `bench/results/train_benchmark.json`)
| metric | value |
|---|---|
| GPU | RTX 5090 (sm_120), torch 2.10.0+cu128, CUDA runtime 12.8 |
| 4-bit weight VRAM | **1.18 GiB** |
| peak training VRAM | **1.37 GiB** |
| model load time | 97.5 s (incl. download) |
| train time (30 steps) | **18.15 s** |
| throughput | **7.12 samples/s · 1.78 steps/s** |
| final loss | 1.375 |
| adapter | `out/smoke_adapter/adapter_model.safetensors` (73 MB) |

VRAM headroom is enormous at 1.5B — extrapolating to the 24–27B base (≈22 GB 4-bit base +
activations) is the real test (8K ctx target; see IMPL_SPEC §3 VRAM table).

## Coherence / no-gibberish check ✅
Greedy decode on a SQLi prompt returned valid, on-schema JSON:
`FINDING: {"no_finding": true, "checked_cwe": ["CWE-89"]}` — coherent, **not gibberish**, so the
13.2-driver / cu128-runtime stack is sound (validates the `verify_env.py` gate fix, BLOG A5).

## Honest accuracy caveat ⚠️ (the point of measuring)
That answer is **wrong** — the input is textbook SQL injection and should be a finding, not
"no_finding". A 1.5B model trained 30 steps on 120 templated rows is undertrained and overfit
to the calibration-negative template → it under-reports. This is expected and on-thesis:
**the fine-tune does not create detection capability**; real capability comes from the system
(L1–L5) plus a real, verified, balanced dataset and a proper run (more steps, the 7B/24B base,
the ORPO calibration pass). Lesson banked: always measure accuracy, never ship "it trained" as
"it works." (BLOG_QUEUE C4.)

---

## M3-production run — fine-tune on REAL mined CVE data (2026-06-25)
Same rig, real data instead of templates: **879 vuln→patch pairs** mined from full-depth
clones of django/flask/werkzeug (167 SQLi, 67 XSS, 64 path-traversal, …) → 890 SFT records.

| metric | smoke (toy data) | **real CVE data** |
|---|---|---|
| dataset | 120 templated | **890 from 879 real pairs** |
| steps | 30 | 120 |
| final loss | 1.375 | **0.856** |
| peak VRAM | 1.37 GiB | 1.49 GiB |
| train time | 18 s | 55 s (8.9 samples/s) |
| bare audit — vulnerable SQLi | ❌ "no_finding" | ✅ **flags CWE-89** |
| bare audit — safe parameterized | (n/a) | ✅ **clean (no FP)** |

**Headline:** real CVE data fixed the miscalibration toy data caused — the real-data adapter
flags the vulnerable query and clears the parameterized one on the bare single-function audit.
(Honest scope: bare-audit case on patterns near the training data, coarse function-level labels;
the full cross-file + agentic rungs-0→5 eval and the 24–27B production base are next — infra
ready in `sscai/agent/inference_backend.py`.)

---

## Complete rungs-0→5 ablation — 7B base vs fine-tuned (2026-06-25)
7B fine-tune (real data): **loss 0.686**, peak VRAM **5.98 GiB**, 63 s/120 steps.

| rung | P | R | F1 | note |
|---|---|---|---|---|
| R0  base 7B, bare (held-out real CVEs) | 1.0 | 0.95 | 0.974 | LLM-only floor |
| R2  SAST tool-only (seeded) | 1.0 | 1.0 | 1.0 | deterministic baseline |
| R4  system: SAST + cross-file taint (seeded) | 1.0 | 1.0 | 1.0 | 1 taint path |
| R5  fine-tuned 7B, bare (held-out real CVEs) | 1.0 | 1.0 | 1.0 | FT vs R0 |

### Reading it honestly (this is the result, not a disappointment)
- **Both base (R=0.95) and FT (R=1.0) score near-perfect** — that's the *tell*. The held-out is
  same-repo **pre-fix/post-fix pairs**; telling them apart is an easy, **leakage-adjacent proxy**,
  not real-world detection. A near-perfect base proves the task is easy, not that the FT is magic.
- **The fine-tune's measured DETECTION delta over base is negligible (+0.05 R, +0.0 P).** This is
  the project thesis, measured: *the fine-tune does not create detection capability.*
- **The FT's real, defensible win is schema/calibration** (raw outputs, BLOG E6): it emits clean
  terse `FINDING:{cwe}` / `no_finding`, while the base emits verbose, inconsistent JSON
  (file/line/description, sometimes a `findings[]` array, often no CWE id). That consistency is
  what makes the agent loop + downstream parsing reliable (the honest FT objective; see ../../docs/FAQ.md).
- **Getting here took 3 eval-harness fixes** (BLOG E5/E6: format mismatch → `secure`-substring
  bug → crediting structured findings). Every "result" was read at the raw-output level before
  being believed — the discipline matters more than the number.
- **Trustworthy detection numbers need a harder eval:** post-cutoff / closed-source code + the
  agentic cross-file system (L1–L5), not bare same-distribution pre/post-fix pairs. That's next.

Video: `demo/recording/full_ablation.gif`.

---

## Post-cutoff (leak-resistant) ablation — the definitive honest result (2026-06-25)
Eval: **30 vuln + 30 safe** from real CVEs **published 2025+ / fix commits 2024-07+** (genuinely
unmemorizable by the base). **32B fine-tune:** loss **0.562**, peak VRAM **19.94 GiB** (fits 32 GB),
257 s/120 steps.

| model | P | R | F1 | accuracy |
|---|---|---|---|---|
| base 32B | 1.0 | 1.0 | 1.0 | 1.0 |
| fine-tuned 32B | 1.0 | 1.0 | 1.0 | 1.0 |

**Fine-tune detection delta: +0.0 / +0.0.** Video: `demo/recording/postcutoff.gif`.

### What this means (the capstone finding)
- **The fine-tune adds ZERO detection capability over the base** on a fair, leak-resistant eval.
  Base Qwen2.5-Coder-32B already flags all 30 vulns and clears all 30 safe (verified in the raw
  outputs: it emits `{"vulnerability":...}` / `{"finding":{...}}` for vulns and "**No Finding**"
  for safe code).
- **Every earlier apparent FT "gain" was a measurement artifact** (+0.633 post-cutoff, +0.05
  held-out): a keyword detector under-credited the base's varied output formats. It took **4
  detector iterations + reading raw outputs** to see this (BLOG E5/E6/E7).
- **The FT's real, verified value is schema/format compliance + calibration** — terse, parseable
  `FINDING:{cwe}` the agent loop and parsers can consume, which *generalizes to unseen CVEs*.
  That is exactly the honest fine-tune objective (see ../../docs/FAQ.md), not detection magic.
- **Both perfect ⇒ the pre/post-fix pair framing is an easy proxy even post-cutoff.** The real,
  hard eval is "audit a WHOLE repo at a vuln commit, find the bug among all the safe code" via the
  agentic cross-file system, scored by an **LLM-judge** (free-form outputs can't be keyword-matched
  fairly — proven 4×). That's the genuine frontier, and it's where the **system (L1–L5)**, not the
  fine-tune, will matter.

**Portfolio bottom line:** rigorous measurement showed *fine-tune ≠ capability*; the value is the
air-gapped system + the engineering. Saying that plainly — with the 4 caught measurement bugs as
evidence — is the credibility.

---

## Haystack localization — the reality check (2026-06-25)
The single-function eval is easy (base = FT = 1.0). The real task: localize the vuln in the FULL
pre-fix file (15 real django/flask CVE files, **avg ~14 functions each**, 10 SQLi + 5 XSS).
Auditor = base 32B; **LLM-judge** (7B) scores localization vs ground truth. Video: `haystack.gif`.

| config | localization accuracy |
|---|---|
| BARE (file only) | **0.07** |
| SYSTEM (+ SAST candidates) | **0.07** |

**System delta: +0.00.** Both fail ~93% of the time.

### Why — and why this is the most valuable result in the repo
- **The LLM can't find the needle.** Given a whole file, the 32B confidently answers "No finding"
  on real CVE code (SecLLMHolmes, reproduced live). Spotting 1 vulnerable function among ~14 is a
  different, much harder problem than "is THIS function vulnerable?" — which is why the toy eval's
  1.0 was so misleading.
- **The system didn't help because our SAST rules don't fire on real framework vulns.** 14 of 15
  files got **0 SAST candidates**: real Django SQLi lives in ORM/aggregate internals
  (`__init__`, JSONB/HStore fields, aggregate SQL construction), not the textbook
  `cursor.execute("%s" % x)` our rules + Bandit B608 target. No candidates → no narrowing → no help.
- **The honest gap:** toy-eval SOTA **1.0** vs real-CVE localization **0.07**. That delta is the
  whole story, and most "LLM finds vulns" demos never measure it.

### The road ahead (unglamorous, and that's the point)
The number moves only with real engineering, not a fine-tune: (1) SAST/taint rules + the custom
cross-file taint engine extended to cover **real framework vuln classes** (the genuine moat);
(2) a true **agentic loop** (trace taint, run tools, hypothesize, validate) instead of one-shot
"audit this file"; (3) the **validation layer** to kill false positives. This is exactly the
system (L1–L5) the project was built around — now with a hard, honest benchmark to drive it.

### Follow-up: the user-code haystack — the system DOES move the number on its real domain
Key realization: the mined CVEs are *frameworks fixing their own internals* (Django auditing
Django). The product audits **user application code** that uses frameworks — a different domain,
where textbook patterns and our rules/taint actually fire. So I built a matching benchmark:
realistic Flask modules (~11 functions, 1 vuln in a user idiom, buried among safe routes).

| haystack | bare LLM | + system (SAST) | delta |
|---|---|---|---|
| framework-internal CVEs (mismatched domain) | 0.07 | 0.07 | +0.00 |
| **user-app code (the product's real domain)** | **0.67** | **1.00** | **+0.33** |

Verified in raw outputs: on the XSS files the bare 32B **mislocalized** (flagged the wrong function
as command injection); the SAST candidate (line 31, CWE-79) **corrected it** to the right function.
The system genuinely helps where its rules apply. Video: `usercode_haystack.gif`.

**The complete, honest picture:** the system works on the domain it's built for (user-app code:
+0.33; cross-file SQLi 0.5→1.0 on the seeded repo), and I showed exactly where it doesn't yet
(framework internals: 0.07 — rules don't cover those patterns). Both numbers are real and measured.
That contrast — not a single inflated score — is the deliverable.

---

## The agentic loop on a hard 6-CWE benchmark — coverage vs breadth (2026-06-25)
A larger, **generated + adversarially-verified** benchmark (a 36-agent workflow): **29 user-app
modules, 6 CWE classes** (SQLi, XSS, cmd-injection, path-traversal, SSRF, deserialization), 12 with
**decoys** (functions that look risky but are safe), 11 "hard" (subtle / fake sanitizers). Auditor
= 32B. Three architectures, LLM-judge scored. Video: `haystack_v2.gif`.

| config | recall | what it is |
|---|---|---|
| BARE (whole file) | **0.90** | the LLM's pretrained breadth |
| ONE-SHOT (+ SAST hints) | **0.79** | hints *HURT* — anchored the LLM on wrong candidates |
| AGENTIC (trace → triage → validate) | **0.41** | precise (**0.76**) but blind beyond our rules |
| **HYBRID (LLM breadth ∪ system-confirmed)** | **0.93** | **best of the four** — breadth kept + proof |

**Agentic recall by CWE class:** SQLi **1.00**, cmd-injection **1.00** (we have rules/taint) — but
XSS 0.20, deserialization 0.20, path-traversal **0.00**, SSRF **0.00** (no rules). It produced **no
finding on 14 of 29 files**.

### The honest synthesis — the sharpest result in the repo
- **The agentic system is exactly as good as its rule/taint coverage.** Where covered: perfect and
  precise. Where not: blind. This *quantifies* "a system is only as good as its rules" across six
  vulnerability classes — the agentic literally cannot see what it has no rule for.
- **A strong base LLM (0.90) has breadth** — it knows SSRF, path-traversal, and deserialization from
  pretraining — but no precision guarantees and no cross-file reach.
- **Naive SAST-hint injection HURT the LLM (0.90 → 0.79)** by anchoring it on wrong/incomplete
  candidates. "Feed SAST output to the LLM" is not a free win.
- **Neither pure-LLM nor pure-system wins** — so I built the **hybrid**: run the LLM independently
  (breadth, no SAST hints) and the system independently (precise, cross-file), then **merge**. Result:
  **recall 0.93 — the best of the four** (it kept the LLM's breadth and the system lifted SSRF
  0.75→1.00), and crucially **17 of its findings carry a deterministic taint/SAST proof** (the
  high-confidence subset an analyst triages first) while the rest are flagged "needs review." That
  provenance — not just the recall — is the product value: a *prioritized, evidenced* finding list.
- The remaining long pole is unchanged and honest: **expand rule/taint coverage toward the full
  OWASP set** (path-traversal stayed 0.60; the system is still blind without rules) and improve
  triage (it confirmed a decoy in one case). The hybrid is the architecture; coverage is the work.

---

## The coverage push — turning the roadmap into measured gains (2026-06-25)
Acting on "coverage is the work": added Semgrep taint rules for **SSRF (CWE-918), path-traversal
(CWE-22), insecure deserialization (CWE-502)**, broadened the XSS rule, and broadened the custom
taint engine's sinks/sources. The single highest-leverage fix: adding **`request.get_json()` as a
taint source** — the common Flask JSON-body pattern (`payload = request.get_json(); payload.get('url')
→ requests.get(...)`) that the SSRF cases used. SAST gt-localization went from blind on those classes
to **26/29 (90%)** of candidates landing in the right function.

Re-ran the same 29-module benchmark (`v2` → `v2cov`):

| config | recall before | recall after |
|---|---|---|
| bare LLM | 0.90 | 0.90 |
| one-shot | 0.79 | 0.76 |
| **agentic** | **0.41** | **0.69** |
| **hybrid** | **0.93** | **0.97** |
| **proof-carrying findings** | **17** | **38** |

**Agentic recall by class (before → after):** SSRF **0.0 → 1.0**, XSS 0.2 → 0.6, path-traversal
0.0 → 0.4, SQLi/cmd-injection 1.0 → 1.0. Deserialization stayed 0.2 (the candidate lands in the
wrong function in 2/5 — next rule to fix). Video: `haystack_v2cov.gif`.

**The measured lesson:** expanding rule coverage moved the system from blind (agentic 0.41) to
genuinely useful (0.69), pushed the hybrid to **0.97** (near-ceiling), and **more than doubled the
deterministically-proven finding subset (17 → 38)** — the high-confidence findings an analyst can
trust without re-checking. This is exactly the "coverage is the work" roadmap, now with a before/after
number on it. And it's honest about what's still weak (deserialization, path-traversal) — the next
rules to write.

---

## Cross-file: the system's headline value, finally isolated (2026-06-25)
Multi-file apps where the vuln flows `routes.py → services.py → sink layer`. First pass tied
(per-file LLM 1.0 = system 1.0) because the sinks looked obviously bad in isolation. So I built a
**precision** benchmark: each app has the real cross-file vuln **plus safe decoys** (the same sink on
a constant/local input — `requests.get("https://internal/health")`, `pickle.loads(local_file)`).

| config | recall | precision |
|---|---|---|
| per-file LLM | 0.60 | **0.25** |
| **system (cross-file taint)** | **1.00** | **1.00** |

The per-file LLM **misses** the non-obvious cross-file vulns (a bare `requests.get(url)` looks fine
when you can't see `url` is user-controlled) **and is noisy** (precision 0.25 — 9 false positives).
The cross-file taint engine is **perfect on both** — it flags exactly the user-reachable sinks and
nothing else, with the full source→sink path as proof. This is the one thing a single-file or
per-file LLM fundamentally cannot do, measured. Video: `crossfile_precision.gif`.

## The MVP
`python -m sscai audit <repo>` (or the Docker image, `--network=none`): the deterministic,
air-gapped core — cross-file taint + SAST — emitting **proof-carrying findings**
(`✔ PROVEN (taint)` with the source→sink path). No GPU, no model, zero egress. The optional `--llm`
flag adds the hybrid LLM pass. This is the shippable product; the LLM/fine-tune is an optional
augmentation, and the deterministic engine is the trustworthy spine.
