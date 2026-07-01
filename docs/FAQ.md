# SovereignSec-AI — the two honest questions

The two questions that matter most about this project, answered without spin. If you only read one
file besides [`INSIGHTS.md`](../INSIGHTS.md), read this one.

---

## 1. "The fine-tune adds ~0 detection. Did the fine-tuning fail? Did you even really fine-tune?"

**Short answer: the training is real and the project is a success. "Zero detection delta" is a
rigorous *finding*, not a failure — and it's the most valuable result here.** Two separate things:

### Did we actually fine-tune the model? Yes — unambiguously.
We trained real LoRA adapters on three model sizes (1.5B, 7B, 32B). On the real 890-record training set (built from 879 mined vuln→patch pairs)
the training loss dropped with scale every time (1.5B → 7B → 32B: **0.856 → 0.686 → 0.562**), the
adapter files exist and load, and when you feed the fine-tuned
model vulnerable code it emits a clean `FINDING: {"cwe":"CWE-89",...}`. That is a real, working
fine-tune. Nothing fake or broken about the training itself.

### What does "0 detection delta" mean — and why isn't it a failure?
It means: on a **fair test** (real CVEs published *after* the model's training cutoff, so it
couldn't have memorized them), the fine-tuned model is **not better at *finding* bugs** than the
base model. That sounds bad. It isn't, for three reasons:

1. **It's expected, and it was the thesis from day one.** Fine-tuning on a few hundred examples
   teaches a model *how to respond* — format, tone, calibration. It does **not** install new
   reasoning the base model didn't already have. The base `Qwen2.5-Coder` already "knows" SQL
   injection, SSRF, etc. from its massive pretraining; a small adapter can't make it *know more
   about vulnerabilities*, only *say findings more consistently*. The very first expert review at
   the project's start said exactly this: *"LoRA steers format and behaviour, not new capability
   like spotting vulnerabilities."*

2. **Measuring "0 delta" is the scientific success.** We had a hypothesis ("a small fine-tune won't
   add detection capability"), we built a fair, leak-resistant test, and we got a clear, honest
   answer. That's the method working — not the project failing.

3. **When *would* it be a failure?** If we had **claimed** "I fine-tuned a state-of-the-art
   vulnerability detector" and shipped a model that wasn't. That is what a lot of projects quietly
   do. We did the opposite: measured honestly, found the fine-tune isn't the lever, and **built the
   thing that is.**

### So where's the actual success? The system, not the adapter.
- The **hybrid** (LLM + cross-file taint + SAST) scored **0.97 recall** on a hard benchmark —
  beating the LLM alone (0.90) and everything else. The breadth costs finding-precision (0.51 vs
  the agentic config's 0.61), which is why **38 of its findings carry deterministic proof** — the
  high-confidence subset an analyst triages first.
- The **cross-file taint engine** deterministically traces vulnerabilities across files (recall and
  precision **1.0**, zero false positives) — something an LLM fundamentally can't do reliably: on
  the same test a per-file LLM missed 2/5 real vulns and raised 9 false positives on other
  functions (recall 0.60, precision 0.25), while the taint engine flags only proven source→sink
  paths.
- It's **fully air-gapped** — no code ever leaves the machine.

The fine-tune is one honest cog: it makes the LLM's output clean and parseable so the system can
*merge* it with the deterministic findings. Useful — just not the engine. **The model is genuinely
fine-tuned; "0 detection delta" is the rigorous proof that the *system* is where capability lives;
and that's exactly what was built.** For a portfolio, "I measured honestly and built the right
architecture" is a far stronger signal than a fake SOTA claim.

---

## 2. "How would you train a model to spot a *zero-day* (a bug with no CVE, no rule, no pattern)?"

This is the deepest question in the field. *(It's also the seed of a future project — see the note
at the end.)*

**Short answer: you don't train detection *into* a model — not even a future frontier model.** This
project measured why: fine-tuning teaches format and behaviour, not new reasoning, and even frontier
models are unreliable at finding bugs cold (they hallucinate; they flip their verdict when you rename
a variable). A more powerful base helps the *reasoning*, but "a bigger model will just find
zero-days" is mostly hope. Zero-day discovery is a **search-and-verify problem**, not a
classification problem — so the answer is a **system**, the same shape this project is built on.

**The five things that actually find zero-days (what the best systems do):**

1. **Hypothesis + execution, not a verdict.** The model proposes *where* a bug could be (tainted
   data reaching a sink, a missing bounds check); the system **verifies by running it** — a fuzzer,
   a sanitizer (ASan), the test suite, an actual exploit. Google's "Big Sleep" found a real zero-day
   this way (an LLM + a debugger). The model generates hypotheses; *execution* is ground truth.

2. **Variant analysis — the most productive real technique.** Take a *known* bug (a CVE, a patch)
   and hunt for **unfixed siblings of the same flaw** elsewhere. Most real zero-days are found by
   generalizing a known flaw class to new code — not by divining the totally unknown.

3. **Fuzzing + sanitizers — the workhorse.** Tools like AFL/libFuzzer + AddressSanitizer find memory
   bugs by *execution*, no model needed. The frontier is LLMs **writing smarter fuzz harnesses and
   mutating inputs intelligently**. The model makes the fuzzer smarter; the fuzzer finds the bug.

4. **Whole-program semantic reasoning.** Zero-days hide in the *interaction* between components — a
   taint source five files from the sink, a config that makes a sink reachable. A model + a precise
   cross-program graph (exactly what this project's taint engine does, scaled up) reasons about
   reachability like a human auditor.

5. **Differential / "missing-check" reasoning.** "This handler validates input; the sibling handler
   doesn't — *why?*" The model spots the **inconsistency** (a missing auth or bounds check) by
   comparing to the norm. This catches logic and auth bugs that have **no signature** — the closest
   thing to "novel."

**If you wanted to "train" for it:** you'd distill **reasoning traces of how experts find bugs**
(source→sink→exploit reasoning, variant-analysis reasoning) so the model generates *better
hypotheses*. That *sharpens* a strong base — it doesn't install capability it lacks (the same lesson
this project proves) — and you pair it with the tools above.

**The honest frontier truth:** even the best systems find *few* zero-days, and Google itself noted
"a target-specific fuzzer is often at least as effective." No model today "spots any zero-day," and
it won't come from fine-tuning — it'll come from better **model + tool + execution** systems.

### Why this project is the right foundation
SovereignSec-AI is the *shape* zero-day discovery needs: a strong model as orchestrator + cross-file
taint + SAST + a validation oracle + the hybrid merge + a benchmark harness. To push toward
zero-days you'd bolt three things onto this exact infrastructure:
- **Variant analysis** (mine a CVE → hunt unfixed siblings) — the data-mining + taint engine already
  do half of this.
- **An execution / fuzzing layer** (extend the validation oracle to actually *run* and fuzz) — the
  L5 oracle is the hook.
- **Differential reasoning** (missing-check detection) — a new agent pass over the call graph.

> **Future project idea — "Zero-Day Tuning."** A dedicated build on top of this infrastructure:
> variant-analysis + execution-grounded verification + differential reasoning, evaluated on a
> held-out set of *real, recent* CVEs treated as "unknown." The whole point of building this
> intricate base — the taint engine, the agentic loop, the validation oracle, the benchmark
> harness — is that the next capability is an *addition*, not a from-scratch rebuild.
