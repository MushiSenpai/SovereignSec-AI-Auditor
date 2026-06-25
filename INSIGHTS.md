# What building a local AI code auditor actually taught me

> A field report from building **SovereignSec-AI** — a fully local, air-gapped agentic
> code-security auditor on a single RTX 5090. Written for anyone building LLM systems for
> real work, not demos. The short version: **the model was never the hard part. Measuring
> honestly was.** Every "win" in this project turned out to be a measurement artifact until
> proven otherwise, and the most valuable result is a number that looks like a failure.

If you only read one section, read **#3** and **#7**.

---

## 1. Chatbots are confidently wrong — in both directions
I had five frontier models (Gemini, Claude, Grok, Kimi, ChatGPT) each design this project.
The *strategy* they agreed on was trustworthy. The *facts* were a minefield:
- One invented model version numbers. Two of us then "corrected" it by calling them
  hallucinations — and a primary-source check showed the models were **real**. So the
  confident invention *and* the confident skepticism were both wrong.
- A specific, scary claim ("CUDA 13.2 produces gibberish") was stated with fake precision —
  and turned out **true**, but for the runtime, not the driver (more in #5).

**Lesson:** neither a model's confidence nor your own skepticism substitutes for checking a
primary source. I built a 15-agent research workflow whose entire value was the *adversarial
verification* pass, not the research pass.

---

## 2. The fine-tune does not create capability — and I proved it on myself
The seductive pitch is "fine-tune an LLM into a security expert." It doesn't work that way,
and I have the receipts:
- On an *easy* eval (is THIS single function vulnerable?), base and fine-tuned models both
  scored a perfect **1.0**. Looks like SOTA.
- On the *fair, leak-resistant* eval (real CVEs published after the model's training cutoff),
  the **32B** fine-tune's detection advantage over the base was **exactly 0.0** — the base
  Qwen2.5-Coder-32B already nailed it. (The same-distribution held-out ablation, a **7B** run,
  showed a delta of **+0.05 recall** — still negligible. Both point the same way.)

The fine-tune's real, honest value is **output discipline** — clean, parseable, calibrated
findings the rest of the pipeline can consume — not detection skill. Detection capability,
where it exists at all, comes from the *system*, not the adapter.

---

## 3. Measurement is the hard part. Read the raw outputs. Every time.
This is the spine of the whole project. Getting a single trustworthy number took **four**
eval-harness fixes, each discovered by reading the model's actual outputs instead of trusting
the score:
1. The eval prompted for one JSON shape; the fine-tune emitted the shape it was *trained* on →
   the parser silently scored every real detection as a miss (fine-tune looked like 0% recall).
2. My "no vulnerability" keyword list contained `secure` — and **`insecure` contains `secure`**,
   so "this code is insecure (CWE-89)" was read as *clean*.
3. The base model reported findings with `file`/`line`/`description` but no CWE id; my
   CWE-only detector scored those real detections as misses.
4. The base used yet another shape (`{"vulnerability": "..."}`); credited that, and the
   "+0.63 fine-tune win" collapsed to **0.0**.

**Lesson:** a keyword/regex scorer cannot fairly compare a schema-compliant model against a
free-form one — it systematically under-credits the verbose one and makes the terse one look
brilliant. The way you measure can lie louder than the model. Use an LLM-judge for free-form
outputs, and **never believe an ablation number you haven't read the raw outputs behind.**
A result that's suspiciously perfect (1.0/1.0, or a huge clean delta) is a measurement bug
until proven otherwise.

---

## 4. Toy evals lie. Build the hard one.
The single-function eval said 1.0. So I built the real task: localize the vulnerability in a
*whole file* (~14 functions, the bug is one needle in the haystack), scored by an LLM-judge.

| eval | accuracy |
|---|---|
| single function: "is this vulnerable?" | **1.0** |
| localize the vuln in a real file | **0.07** |

Both the bare LLM and the SAST-assisted system fail ~93% of the time on real code. Given a
whole file, a strong 32B model confidently says "No finding." The gap between **1.0 on the toy
eval and 0.07 on the real one** is the entire story — and almost no "LLM finds vulnerabilities"
demo ever measures it.

---

## 5. The boring details are load-bearing
A sampler of things that silently break real builds, none of which any plan mentioned:
- **"CUDA version" is three different numbers** (driver max / runtime / toolkit). The
  gibberish warning targets the *runtime*; a cu128 build under a 13.2 *driver* is fine — but
  my env-gate conflated them and failed a valid box. Gate the number that matters; back it
  with an empirical smoke test.
- **`/tmp` was 804 MB** on a box with 1.2 TB free, so `pip install torch` died with ENOSPC.
  Point `TMPDIR` at the big partition.
- **Bandit rates SQL injection at LOW confidence**, so a "medium-confidence" filter silently
  drops the most important vulnerability class.
- **GitHub tags fix commits as `WEB`, not `FIX`** — on 157 real advisories, *every* fix-commit
  reference was `WEB`. The intuitive `type == "FIX"` miner would have mined **zero** pairs.
- **An FP8 checkpoint can't be a QLoRA base**, and a BF16 24B won't fit 32 GB — so training and
  serving need *different* precisions of the same model.

---

## 6. Licensing is an architecture constraint, not a footnote
For a product whose whole pitch is "scan your *private* code locally":
- **CodeQL's license forbids** generating a database for non-open-source code without a paid
  seat — illegal on use #1. Excluded by design.
- **Semgrep's free engine is fine, but its curated rules can't be shipped, and its cross-file
  taint is a paid, cloud-only feature** — which is precisely why building our own cross-file
  taint engine became the most interesting component, not a nice-to-have.

You cannot pick your tools after designing the system; the licenses *are* part of the design.

---

## 7. The honest moat — and the domain mismatch I almost missed
The data is the moat, not the model. There is no off-the-shelf, label-verified Python-web vuln
dataset; the public ones are so mislabeled that a model scoring 68% F1 on one scores 3% on the
cleaned version. Curating real, verified data is the defensible work.

But the deepest realization came last: **the CVEs I mined are frameworks fixing their own
internal bugs** (Django auditing Django's ORM internals). The product's actual job is auditing
**user application code** that *uses* those frameworks — where textbook patterns (raw SQL with
request input, unescaped output) actually appear and where our rules and taint engine actually
fire. On framework internals, our SAST fired on 1 of 15 files; on user-app code (the seeded
benchmark), the cross-file taint engine takes recall from 0.5 to 1.0 with zero false positives.

**Same system, opposite results — because the eval domain and the product domain weren't the
same thing.** Always check that your benchmark is testing the job your product actually does.

---

## 8. Neither the model nor the rules win alone — you need both, merged
The last experiment built a real agentic loop (trace → triage → validate) and tested three
architectures on a hard, generated-and-verified benchmark (29 modules, 6 CWE classes, with decoys):
- **Bare LLM: 0.90** — broadly capable; it knows SSRF, path traversal, and deserialization from
  pretraining, with no rules at all.
- **One-shot SAST hints: 0.79 — *worse*.** Feeding the model a scanner's candidate lines *anchored*
  it on wrong/incomplete locations. Bad hints actively mislead a capable model.
- **Agentic system: 0.41 recall / 0.76 precision** — perfect on the classes we wrote rules for
  (SQL injection, command injection: 1.00) and **completely blind on the ones we didn't** (path
  traversal, SSRF: 0.00). It produced no finding on 14 of 29 files.

This is the cleanest statement of the whole project: **a deterministic system is exactly as good as
its coverage — precise but blind beyond it; an LLM has breadth but no precision or cross-file reach;
and naively gluing them (SAST → LLM) can be worse than either.** The architecture that wins is a
*hybrid* that merges them — LLM breadth plus system precision and cross-file reach on covered classes
— and the unglamorous long pole is expanding rule coverage toward the full OWASP set. There is no
shortcut, and measuring three architectures on a hard benchmark is the only way to know which
trade-offs are real.

So I built the hybrid — LLM independently for breadth, the system independently for
precision/cross-file reach, then *merged* (not SAST-fed-into-LLM, which hurt). *Before the coverage
push*, it won: **recall 0.93, the best of all four configs**, keeping the LLM's breadth while the
system lifted the classes it covers (SSRF 0.75 → 1.00). And it returns something neither alone can: a
**prioritized, evidenced** finding list — **17 findings carrying a deterministic taint/SAST proof**
(triage these first) and the rest flagged "needs human review." For a security tool, that provenance
matters more than the recall point.

Then I did the unglamorous work the result pointed at — **expanded the rule/taint coverage** (added
SSRF, path-traversal, and deserialization taint rules; the single biggest fix was adding
`request.get_json()` as a taint source) and re-ran the same 29-module benchmark. The coverage push
moved the numbers it was supposed to: **agentic recall 0.41 → 0.69, hybrid 0.93 → 0.97** (near
ceiling), **SSRF coverage → 1.00**, and the deterministically-proven finding subset **more than
doubled, 17 → 38** — the high-confidence findings an analyst can trust without re-checking. Honestly,
**path traversal is still the weak spot (~0.40)** and deserialization lags — the next rules to write.
The hybrid is the architecture; coverage is the job, and now it has a before/after number on it.

## What works, what doesn't, and the road ahead

**Works (today, measured):**
- A fully local, zero-egress pipeline: tree-sitter + Jedi call graph, a custom cross-file taint
  engine (the headline — Semgrep CE can't follow cross-file flows), Semgrep+Bandit, an agent
  loop, and a dynamic patch oracle that proves a fix by flipping a real exploit.
- On user-app code (the product's real domain), the system finds the cross-file SQL injection
  scanners miss (recall 0.5→1.0, no false positives on safe parameterized queries), and on a
  **haystack** (1 vuln among ~11 functions) it lifts the LLM's localization from **0.67 → 1.00** —
  by *correcting* the model when it mislocalized (the SAST candidate pointed it to the right
  function). That +0.33 is the system earning its keep where its rules apply.
- 4-bit QLoRA of a 32B model trains in ~4 minutes at ~20 GB on a single RTX 5090.

**Doesn't (yet, and I measured it):**
- Localizing a vulnerability in *framework-internal* code (Django auditing Django): **0.07**, and
  the system doesn't help there (+0.00) because our rules cover textbook user-code patterns, not
  framework internals. The honest contrast — user-code +0.33 vs framework-internal +0.00 — is the
  point: **a system is only as good as the match between its rules and the code it's pointed at.**

**The road ahead — real engineering, not a fine-tune:**
1. SAST/taint rules and the custom engine extended to **real framework vuln classes**, evaluated
   on **user-application code** (the product's actual domain).
2. A true **agentic loop** — trace taint, run tools, hypothesize, validate — not one-shot
   "audit this file."
3. The **validation layer** to kill false positives, with the haystack benchmark as the honest
   yardstick to drive all of it.

---

*The thread through all of it: the credibility of an AI system is the rigor of its evaluation.
Anyone can get 1.0 on a toy. The engineering — and the honesty — is in showing where the real
number is, and building toward moving it. The full, unsexy log of every failure and fix lives
in [`BLOG_QUEUE.md`](BLOG_QUEUE.md); the measured results in [`bench/results/`](bench/results/).*
