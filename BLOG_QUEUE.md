# SovereignSec-AI — Blog Queue

> Every failure and fix from building SovereignSec-AI, written up as blog-ready entries.
> Each is a real thing that went wrong (or a non-obvious truth that cost research to
> establish) — the kind of detail that makes a portfolio piece credible. Newest work last.
> Status legend: 🟢 verified on this machine · 🔵 verified against primary sources · ⚪ to-write.

The throughline for the whole series: **in security-AI, the confident-sounding default is
usually wrong, and only empirical/primary-source verification settles it.** Every entry below
is an instance of that.

---

## Series A — "The chatbots were confidently wrong" (model/toolchain)

### A1. Five frontier models planned my project — here's what they got wrong 🔵
**TL;DR.** I had Gemini, Claude, Grok, Kimi, and ChatGPT each design the same project. The
*strategic* consensus was trustworthy; the *factual* details were a minefield.
- Gemini invented version numbers ("Qwen 3.6", "DeepSeek-V4-Flash", "MiniMax-M3"). Claude (and I) flagged them as hallucinations. **A live check proved them real** — so the skeptics were *also* wrong. Lesson: neither confident invention nor confident skepticism substitutes for a primary-source check (HF cards, leaderboards).
- Kimi stated "CUDA 13.2 produces gibberish" with fake-precise detail. It *was* true (Unsloth's own docs). Right answer, untrustworthy reasoning.
**Why it matters.** A portfolio piece built on a hallucinated model name is a credibility landmine. The fix is a verification discipline, not a smarter model.

### A2. FP8 weights are not a QLoRA base (and BF16-24B won't fit your 5090) 🔵
**TL;DR.** Devstral-Small-2-24B ships as an FP8 checkpoint. You cannot `load_in_4bit` an
FP8 checkpoint (double-quant FP8→NF4 is unsupported) — QLoRA needs BF16/FP16 source weights.
And full BF16-24B (~48 GB) doesn't fit 32 GB, so **serving** must be FP8/quantized while
**training** must start from BF16. Two different precisions for two different phases on the
same model. The exact HF id matters too: `mistralai/Devstral-Small-2-24B-Instruct-2512` — the
`-2512` is part of the id; without it, offline pre-download targets nothing.

### A3. The CUDA-13.2 gibberish trap, and pinning a Blackwell toolchain 🔵
**TL;DR.** RTX 5090 (sm_120) needs CUDA 12.8 / a cu128 torch build / triton ≥3.3.1; **CUDA
13.2 silently produces gibberish with Qwen3.6** (Unsloth docs). The defense is a hard
`verify_env.py` gate that fails loudly if torch isn't cu128, the GPU isn't sm_120, or the
driver reports 13.2 — because a bad Blackwell stack produces *wrong output, not errors*.

### A4. vLLM quietly changed its structured-output API 🔵
**TL;DR.** Every "constrain the JSON" snippet online uses `extra_body={"guided_json": ...}`.
That was **removed in vLLM v0.12** → it's now `extra_body={"structured_outputs": {"json": ...}}`
and the backend (`xgrammar`) is a **server-start flag**, not per-request. Also: Qwen2.5-Coder's
native tool-calling silently fails with `--tool-call-parser hermes` (it emits ```json fences,
not `<tool_call>` tags). Robust path: guided decoding for every model.

### A5. "CUDA 13.2 gives gibberish" is about the runtime, not the driver — my gate flagged the wrong thing 🟢🔵
**TL;DR.** On the real box, my `verify_env.py` **hard-failed**: `nvidia-smi` reports **CUDA 13.2**,
the exact version Unsloth warns produces gibberish. But that's the **driver's max-supported
CUDA**, not the runtime in use — torch is a **cu128** build (`torch.version.cuda == 12.8`) that
bundles its own 12.8 runtime, and a newer driver happily runs an older runtime. Unsloth's
warning targets the **toolkit/runtime**, not the driver. So the gate was a false alarm on a
valid config. Fix: check `torch.version.cuda` (the runtime) as the hard guard; treat a 13.2
driver-with-safe-runtime as a pass-with-note — then **prove it empirically** with a smoke-train
(loss decreased, output coherent → no gibberish). Lesson: "CUDA version" is three different
numbers (driver max / runtime / toolkit); gate the one that matters and back it with a smoke-test.

---

## Series B — "Licensing is an architecture constraint, not a footnote"

### B1. CodeQL's license forbids the one thing this product does 🔵
**TL;DR.** The obvious engine for deep code analysis is CodeQL. Its license **forbids
generating a database for any codebase that isn't open-source** without a paid GitHub
Advanced Security seat. A privacy-first auditor whose entire pitch is "scan your *private*
code locally" would be in violation on use #1. → Default to Semgrep's LGPL engine + our own
rules, and **build our own cross-file taint** (which became the project's most interesting
component — see C-series).

### B2. Semgrep's free tier can't do the thing security people think it does 🔵
**TL;DR.** Semgrep CE (LGPL engine) is fine to embed and run offline — but (a) its **curated
registry rules are restrictively licensed** (can't ship/serve them → ship only your own), and
(b) **cross-file/inter-procedural taint and framework-native Django/Flask dataflow are paid
Pro Engine**, cloud-tied, not air-gappable. So "use Semgrep for taint" quietly means
"single-file taint only" on the free tier. This directly forced the custom L1 taint engine.

---

## Series C — Building cross-file taint (the moat)

### C1. Semgrep CE literally cannot see the bug — measured 🟢
**TL;DR.** On the seeded repo (a textbook 3-file SQLi: `app.user → services.user_lookup →
db.find_user`), Semgrep-CE-with-our-rules scores **recall 0.5** — it finds the in-file XSS but
**misses the cross-file SQLi entirely**, because the source and sink live in different files.
Adding our L1 taint recovers it at P=R=1.0. This isn't a strawman; it's the exact gap that
justifies building the taint engine, with a number attached.

| rung | P | R | F1 | finds the cross-file SQLi? |
|---|---|---|---|---|
| Semgrep-CE only | 1.0 | 0.5 | 0.67 | ❌ |
| + Bandit | 1.0 | 1.0 | 1.0 | ✅ (sink only, low-confidence) |
| + L1 cross-file taint | 1.0 | 1.0 | 1.0 | ✅ (full source→sink path) |

### C2. Tree-sitter ≠ a call graph (you need Jedi too) 🟢🔵
**TL;DR.** Tree-sitter gives you syntax, fast and error-tolerant — but it **cannot resolve
imports, aliases, or `self.method()` dispatch**, so you can't build a real call graph from its
captures. The working stack is tree-sitter for parsing + **Jedi** for semantic resolution
(`goto(follow_imports=True)`) + a custom summary worklist for taint. Also a 2025 API trap:
`Language(tspython.language())` + `QueryCursor(Query(...))` — the old `lang.query()` path is
removed in tree-sitter 0.25, and the `tree-sitter-language-pack` convenience package **fetches
grammars on first use** (an air-gap killer) — use the per-language wheel.

### C5. Real CVE data fixed what toy data broke 🟢
**TL;DR.** After the toy smoke-train miscalibrated (C4), I mined **879 real vuln→patch pairs**
from full-depth django/flask/werkzeug clones (167 SQLi, 67 XSS, 64 path-traversal, …) and
re-trained the *same* 1.5B proxy on them (loss 1.375 → **0.856**). On the bare single-function
audit the real-data adapter now **correctly flags the SQLi (CWE-89) and clears the parameterized
query** — the exact case the toy model got wrong. Same model, same rig, same VRAM; the only
change was real, balanced data. The lesson the whole project keeps proving: **data quality is
the lever, not the adapter** — which is exactly why the mining pipeline (and its FIX/WEB bug, F1)
is the moat.

### C4. My first fine-tuned model confidently cleared textbook SQL injection 🟢
**TL;DR.** The M3 smoke-train ran end-to-end on the 5090 (1.18 GiB 4-bit weights, 1.37 GiB peak,
18 s for 30 steps, coherent output). Then I asked the fine-tuned model to audit a textbook SQLi
and it answered `{"no_finding": true}`. **Wrong** — but exactly the right lesson: a 1.5B model
trained 30 steps on 120 templated rows is undertrained and overfit to the "safe" template, so it
under-reports. The fine-tune did **not** create detection capability (the whole project thesis).
The value of the smoke-train was proving the rig + capturing Blackwell metrics + confirming no
gibberish — *and* catching the miscalibration, because we measured accuracy instead of shipping
"it trained" as "it works." Real capability needs the system (L1–L5) + the verified moat dataset
+ a proper run (more steps, 7B/24B base, the ORPO calibration pass).

### C3. The one-line trick that makes taint precise: focus arg0 🟢
**TL;DR.** A naive "any tainted arg into `cursor.execute` = SQLi" flags both the vulnerable
`execute(tainted_query)` **and** the safe `execute("... ?", (user,))` — a false positive on
every parameterized query. The fix is to **focus the sink on its first positional argument**
(the query string): in the parameterized call the tainted value is arg1, while arg0 is a
constant literal → correctly **not** flagged. On the seeded repo this is the difference between
1 precise finding and a wall of false positives on safe code. (Same idea as Semgrep's
`focus-metavariable`, implemented in our worklist.)

---

## Series D — SAST tuning (where the defaults bite)

### D1. Bandit's "medium-confidence" filter silently drops SQL injection 🟢
**TL;DR.** The grounded spec said run `bandit -ll -ii` (medium+ severity **and** confidence).
On the seeded repo that returned **zero findings** — because Bandit rates SQL injection (B608)
at **LOW confidence**, so the `-ii` floor drops the single most important vuln class. A security
auditor that requires medium-confidence misses real SQLi. Fix: filter on **severity only**
(`-ll`), keep all confidences, and feed Bandit's confidence to the triage layer as a prior.
**Evidence:** raw Bandit flags `B608 MEDIUM LOW db.py:36`; with `-ii` it vanished.

### D2. My XSS rule "found" XSS in JSON endpoints — high recall, low precision in miniature 🟢
**TL;DR.** A first-pass XSS rule with sink `return $SINK` fired on **3** routes; only **1** was
real. The other two were `return {"id": ...}` dict responses — which Flask auto-encodes as JSON
(not HTML), so they're not XSS. This is the literature's "LLM/SAST finds plausible-but-wrong
bugs" failure mode, reproduced in a hand-written rule. Fix: narrow the sink to **string
concatenation / f-strings** (the actual HTML-injection shape), which dropped the rule to exactly
the one real finding. Lesson: a sink is a *type/shape* claim, not just a function name.

---

## Series E — Measuring without fooling yourself

### E1. Most "code vuln detection" benchmarks are measuring label noise 🔵
**TL;DR.** PrimeVul (ICSE 2025): a model scored **68% F1 on BigVul but 3% on the cleaned
dataset** once labels were corrected, duplicates removed, and splits made chronological. The
"every function in a CVE-fix commit is vulnerable" heuristic is wrong because fix commits bundle
refactors and tests (tangled commits). Mandatory hygiene: untangle, dedup, **chronological
split (never random)**, manual spot-check.

### E2. The benchmark everyone quotes got retired for contamination 🔵
**TL;DR.** OpenAI **stopped reporting SWE-bench Verified (Feb 2026)**: frontier models could
reproduce the *verbatim gold patch* from just a task id, and 59.4% of "hard" tasks had flawed
tests. So "the model detected the CVE" can mean "the model memorized the public fix." Defenses:
evaluate on **post-cutoff AND closed-source** code, run a **gold-patch-reproduction probe** to
exclude memorized items, keep a private canaried eval set, and always report the delta **vs the
deterministic-tool-only baseline** (robust to memorization).

### E3. "The tests pass" is not proof the bug is fixed 🔵🟢
**TL;DR.** ICSE-2026: ~30% of plausible patches that pass the visible tests diverge from
ground truth; ~8% even fail the *full* suite. So our L5 oracle uses a **negative exploit oracle**
(the exploit must now *fail*) **plus** the full suite **plus** differential tests, run N times,
**unanimous-or-reject** (averaging hides a non-proof). Demonstrated end-to-end: applying the
parameterized fix to the seeded SQLi flips `check_sqli` from success→failure while pytest stays
green → verdict `FIXED`, 3/3 runs.

### E4. Coarse matching conflates a true finding with a false positive 🟢
**TL;DR.** My first ablation scorer flagged a "leaked false positive" on a rung that was
actually correct. The cause: it matched findings at **(file, CWE)** granularity — but the real
SQLi (`find_user`) and the *planted* false positive (`find_user_safe`) live in the **same file
with the same CWE**. Only line/function-scoped matching can tell "found the real bug" from
"flagged the safe lookalike." If your eval can't distinguish those two, your precision number is
fiction.

---

### E5. The eval said my fine-tune detected zero vulns — the harness was wrong, not the model 🟢
**TL;DR.** The first complete-ablation run scored the fine-tuned 7B at **0% recall** — it
"detected nothing." The model wasn't broken: it was trained to emit `FINDING: {"cwe":..}` /
`{"no_finding":true}`, but the eval prompted for and parsed a *different* `{"findings":[..]}`
shape, so the parser silently discarded every real detection. Two lessons: (1) **evaluate a
fine-tune with the exact I/O contract it was trained on** — a mismatched prompt/parser yields a
confident, false zero; (2) a format-agnostic detector (regex for a CWE id minus negative
phrases) keeps base-vs-FT comparisons fair across output shapes. Same family as E2/E3: *how you
measure can lie louder than the model*.

### E6. A "perfect" fine-tune score that wasn't detection at all 🟢
**TL;DR.** My complete ablation first showed the fine-tuned 7B at **1.0/1.0** and the base at
**0.0** — too good to be true, so I refused to ship it without reading the raw outputs. Three
things were true at once: (1) the parser only credited a CWE id, but the **base model reported
real findings with file/line/description and no CWE id**, so its detections scored as misses;
(2) the FT model emitted the exact terse `FINDING:{cwe}` contract it was trained on, so it
*looked* perfect — but that's **schema compliance**, an intended FT objective, not proof of
detection skill; (3) the held-out split is **same-repo pre-fix/post-fix pairs**, so a high score
partly measures "can this tell a pre-fix function from its patched version" — a leakage-adjacent
proxy. Lesson: **read the raw model outputs before believing any ablation number**; separate
format compliance from capability; test on post-cutoff/closed-source code before claiming
detection gains. The fine-tune's honest, verified win is calibration + schema — detection
capability still lives in the system (L1–L5) and needs a harder eval. **Final fair numbers
(after 3 harness fixes): base R=0.95/P=1.0 vs FT R=1.0/P=1.0 — a +0.05 recall delta. The
fine-tune adds ~nothing to *detection* here; both score near-perfect because the eval is
easy/leaky. The FT's real win is schema compliance. That honesty is the portfolio.**

### E7. The leak-resistant eval that proved the fine-tune adds zero detection 🟢
**TL;DR.** To kill the leakage doubt from E6, I built a **post-cutoff** eval — real CVEs published
**2025–2026** with fix commits after the model's training data, so the base literally could not
have memorized them. First pass: the FT looked **+0.633 recall** ahead. But reading the raw
outputs (again) showed the **base WAS detecting** the vulns — in `{"vulnerability":...}` /
`{"finding":{...}}` shapes my CWE-keyed detector didn't credit. After a **4th** detector fix
(credit every affirmative shape; treat negated values + "**No Finding**" as clean) and saving
*every* output for audit: **base 32B = FT 32B = P/R/F1 = 1.0** on the post-cutoff set — the
fine-tune's detection delta is **exactly 0**. The base Qwen2.5-Coder-32B already nails it.
Capstone lessons: (1) the fine-tune's honest win is **output-schema compliance, not capability**;
(2) the apparent gains were **measurement artifacts every single time**; (3) even post-cutoff,
**pre/post-fix pairs are an easy proxy** — the real test is repo-level agentic audit judged by an
**LLM-judge**, not keyword-matched. *Measure ruthlessly, read the raw outputs, never ship the artifact.*

### E8. The haystack reality check: 1.0 on toy evals, 0.07 on real files 🟢
**TL;DR.** Single-function eval: base = FT = **1.0** — looks SOTA. Then I built the real task:
localize the vuln in the FULL pre-fix file (~14 functions, real django/flask CVEs), scored by an
LLM-judge. Result: **bare LLM 0.07, system (+SAST) 0.07** — both fail ~93% of the time. Two honest
causes: (1) given a whole file the 32B confidently says "No finding" — it can't spot the needle
(SecLLMHolmes, live); (2) our SAST rules fired on **1 of 15 files** — real Django SQLi lives in ORM/
aggregate internals (`__init__`, JSONB/HStore fields), not the textbook `cursor.execute("%s"%x)`
our rules target, so the system gave 0 candidates and couldn't help. The gap between toy-eval SOTA
(1.0) and real-CVE localization (0.07) is the entire story — and almost no "LLM finds vulns" demo
measures it. The road ahead is real engineering, not a fine-tune: SAST/taint rules for real
framework vuln classes, an agentic (not one-shot) loop, and validation. **The honesty is the moat.**
**Follow-up (the other half): the mined CVEs are frameworks fixing their OWN internals — but the
product audits USER-app code. On a matching user-code haystack (realistic Flask modules, 1 vuln in
a user idiom among ~11 functions), the same system lifts localization 0.67 → 1.00 (+0.33), correcting
the LLM when it mislocalized an XSS. So the 0.07 was a domain mismatch, not a dead end: the system
works where its rules apply. Always check your benchmark tests the job your product actually does.**

### E9. Three architectures on a hard benchmark: the model, the rules, and the trap of gluing them 🟢
**TL;DR.** Built a 29-module, 6-CWE generated+verified benchmark (with decoys, via a 36-agent
workflow) and a real agentic loop (trace→triage→validate), then measured three architectures with an
LLM-judge. The result surprised me: **bare LLM 0.90 > one-shot SAST-hints 0.79 > agentic 0.41.** The
agentic was *precise* (0.76) but blind beyond our rules — SQLi/cmd-injection 1.00, but SSRF/path-
traversal 0.00, no finding on 14/29 files. Two hard lessons: (1) **feeding a capable LLM static-
analysis hints can HURT it** (0.90→0.79) by anchoring it on wrong candidates — "SAST → LLM" is not a
free win; (2) **a rule-based system is exactly as good as its coverage**, quantified across six
classes. Neither pure-LLM nor pure-system wins; the answer is a **hybrid** (LLM breadth + system
precision/reach on covered classes, *merged*), and the long pole is rule coverage. The only way I
learned this was building all three and measuring on a hard set. **Then I built the hybrid and it
won: recall 0.93 (best of the four), keeping the LLM's breadth while the system lifted its covered
classes (SSRF 0.75→1.00) — and it returns a prioritized list where 17 findings carry a deterministic
taint/SAST proof (triage first) and the rest are flagged "needs review." For a security tool, that
provenance beats the recall point. Architecture solved; coverage is the remaining work.**

### E10. The coverage push: blind → useful, and the proof-carrying subset doubled 🟢
**TL;DR.** E9 said "coverage is the work." So I wrote the missing rules — SSRF, path-traversal,
deserialization, broadened XSS — and re-measured. The single biggest fix was a *one-line source*:
real Flask code reads the JSON body via `request.get_json()`, not `request.args.get`, so the SSRF
flow `payload=request.get_json(); payload.get('url') → requests.get(...)` never matched until I added
`get_json` as a taint source. SSRF SAST-localization went 0/4 → 4/4. On the 29-module benchmark the
agentic config climbed **0.41 → 0.69** (SSRF 0.0→1.0, XSS 0.2→0.6), the hybrid hit **0.97**, and the
**proof-carrying (deterministically-confirmed) finding subset more than doubled, 17 → 38.** The
lesson: for a rules+LLM system, coverage isn't a detail — it's the product. One missing source
keyword made an entire vulnerability class invisible. Measure per-class, and the gaps tell you exactly
what to build next (deserialization is still 0.2 — that's the next rule).

### E11. Cross-file precision: the one thing the LLM can't do, and the MVP that ships it 🟢
**TL;DR.** To isolate the cross-file taint engine's value I built a precision benchmark: real
cross-file vulns + safe decoys (the *same* sink on constant/local input — `requests.get("internal")`,
`pickle.loads(local_file)`). Result: **system 1.00/1.00 (recall/precision), per-file LLM 0.60/0.25.**
The per-file LLM misses the non-obvious cross-file cases (a bare `requests.get(url)` looks fine
without seeing `url` is user-controlled) and is noisy (9 false positives); the taint engine flags
exactly the user-reachable sinks with the full source→sink path as proof. That deterministic,
proof-carrying, cross-file capability is the product's spine — so the MVP ships it: `python -m sscai
audit <repo>` (or a `--network=none` Docker image) returns `✔ PROVEN (taint)` findings with no GPU,
no model, zero egress. The LLM/fine-tune is an optional augmentation on top, not the engine — which
is the whole project's thesis, now packaged.

## Series F — Data mining (the moat)

### F1. GitHub Security Advisories tag fix commits as "WEB", not "FIX" — and it's not close 🟢🔵
**TL;DR.** The intuitive way to mine vuln→patch pairs is "pull `references[]` where
`type == FIX`." On **157 real Django/Flask advisories**, the breakdown of GitHub fix-commit
references by type was **355 `WEB`, 0 `FIX`**. The FIX-only miner finds **0** advisories with
fix commits; harvesting **both FIX and WEB** finds **134** (incl. a real CWE-89 Django SQLi,
CVE-2022-28347). My first miner had the FIX-only bug; a grounding-research pass caught it; this
real-data test proved it would have mined *literally nothing*. **The single most expensive
one-line bug in the project — caught before it cost weeks.**

### F2. CVEfixes is SQLite, MoreFixes is PostgreSQL (don't `sqlite3.connect` the wrong one) 🔵
**TL;DR.** Two CC-BY-4.0 vuln corpora that look interchangeable aren't: CVEfixes ships as a
SQLite DB (just `sqlite3.connect`), MoreFixes ships as a ~16 GB **PostgreSQL** dump (needs a
local PG + psycopg). And a subtle portability bug: `before_change` is the text `'True'`/`'False'`
in CVEfixes-SQLite but a **native bool** in MoreFixes-PG — string-matching it breaks silently on
one of them.

### F3. PyDriller needs full-depth clones or it mines empty pairs 🔵
**TL;DR.** PyDriller computes a commit's diff against its **parent**. If you `git clone --depth 1`
the framework repos you mine (to save space/time), every fix commit has no parent in the clone →
empty/incorrect before-after pairs. The advisory-database repo itself is fine shallow (it's just
JSON); the *target* repos must be full-depth.

---

## Series G — Process / orchestration

### G1. A 14-agent research workflow that fact-checks itself 🟢
**TL;DR.** Instead of trusting one model's plan, I ran a workflow: one research agent per
component → an **adversarial verification agent** per component (prompted to refute against
primary sources) → a synthesizer that folds corrections in as overrides. It caught the FIX/WEB
bug, the FP8/QLoRA trap, the vLLM API change, and more. The verification pass, not the research
pass, is where the value was.

### G2. Surviving a mid-run session limit with resumable workflows 🟢
**TL;DR.** The first grounding run hit a session limit; 3 of 15 agents died (including the
data-mining one). Because the workflow is resumable by run-id, the re-run returned the 12
successful agents **from cache instantly** and only re-ran the 3 failures — turning a total
re-run into a near-free top-up. Design background work to be resumable.

### G3. Build the eval harness and the verification gate *before* the model 🔵
**TL;DR.** The order that prevents self-deception: pinned-toolchain gate → eval harness →
baselines → *then* the system → *then* the fine-tune as one ablation rung. You cannot claim
"better" without a baseline, and you cannot trust a baseline on a toolchain that silently
mis-runs.

---

## Series H — Running on a real Blackwell box (infra/ops)

### H1. ENOSPC during install — plenty of disk free, but /tmp was the trap 🟢
**TL;DR.** `pip install torch (cu128)` died with `OSError: [Errno 28] No space left on device`
even with plenty of free disk overall. The catch: `/tmp` is its own small partition, and pip
extracts multi-GB wheels there by default. Fix: point `TMPDIR` (and the pip cache) at a
partition with room (e.g. a dir on the big `/home` partition). Bonus lesson: the background job reported "exit code 0" because the
trailing `tail` in the compound command succeeded — grep the log for `ERROR`, don't trust the
exit code of a `{ a; b; tail; }` block.

### H2. Measuring the Blackwell training run 🟢
**TL;DR.** `bench/bench_train.py` captures the numbers that make the "I drove frontier hardware"
claim concrete: 4-bit weight VRAM, peak training VRAM, load time, train time, tokens/sec, and
final loss — written to `bench/results/train_benchmark.json`. (See that file for the smoke-run
figures; the production run uses the 24-27B base on the 20k moat dataset.)

## Backlog / to-write as the build continues ⚪
- ORPO vs plain SFT for false-positive calibration (does the preference pass actually move precision?).
- The generate-and-verify synthetic pipeline: what % of teacher-generated vulns survive the triple-lock gate (the spec's 40–70% discard is a guess — measure it).
- vLLM + LoRA serving on consumer Blackwell (sm_120): does the FP8 path hold up vs sm_100?
- The full split-screen demo: autonomous scan beside a zero-egress network monitor.
- Honest write-up of where the fine-tune helped vs didn't (the rung-5 delta).
