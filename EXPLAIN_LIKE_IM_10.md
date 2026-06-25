# SovereignSec-AI, explained simply

*For anyone — including the person who built it — who wants to really understand what this is, why
it's built the way it is, and how to explain it to a client or an interviewer. No jargon is hidden;
every technical word is expanded the first time it appears.*

---

## 1. The problem, in one breath

Companies write **source code** (the instructions that make their apps work). That code often has
**security vulnerabilities** — mistakes that let an attacker steal data or take over the system.
Think of a vulnerability as *a door someone forgot to lock.*

AI is great at reading code and spotting some of these doors. But here's the catch: the popular AI
tools send your code **to their servers in the cloud** to analyze it. Banks, hospitals, defense
contractors, and anyone with secret code **legally cannot** do that. So they get no AI help at all.

**SovereignSec-AI** is an AI security checker that runs **entirely on your own computer**. Your code
never leaves the building — "**air-gapped**" (a machine with no connection to the outside world).
That's the whole pitch: *AI code security for people whose code can't leave.*

---

## 2. The surprise at the heart of the project

The obvious idea was: *"Take an AI model and **fine-tune** it to be a security expert."*

> **Fine-tuning** = taking an existing AI model and training it a bit more on your special examples,
> so it gets better at your specific task. A **LoRA** is a small, cheap way to do that — instead of
> retraining the whole giant model, you train a tiny "adapter" patch that rides on top.

We did exactly that — trained real adapters on three model sizes. And then we **measured it
honestly**, and found something most projects never admit:

> **Fine-tuning did NOT make the AI better at finding bugs. It only made it talk more neatly.**

Why? Because a big AI model already "knows" about security holes from reading the whole internet
during its original training. A few hundred extra examples can't teach it to *find more* — it can
only teach it to *report findings in a tidy format*. (This isn't a failure; it's a known truth about
how fine-tuning works. The detailed version is in [`docs/FAQ.md`](docs/FAQ.md).)

So if the AI alone isn't the answer, what is? **A system of tools working together, with the AI as
one helper.** That realization is the whole project.

---

## 3. The pieces of the system (the toolbox)

Picture a security audit as a team, not a single genius:

- **The AI model** — *the brilliant but unreliable intern.* Knows a huge amount, but guesses, gets
  distracted, and sometimes confidently says something wrong. Great for breadth, bad for certainty.

- **The taint engine** (our headline tool) — *following the breadcrumb.*
  > **Taint analysis** = tracking dangerous, user-controlled input as it travels through the code,
  > to see if it reaches a dangerous spot without being cleaned up first. "**Cross-file**" means it
  > follows that trail *across multiple files* — like following a marble through a marble run that
  > goes from room to room.
  This is the thing the AI *can't* do reliably. If a hacker's input enters in `routes.py`, passes
  through `services.py`, and ends up in a database query in `db.py`, the taint engine follows the
  whole path and says "this is a real **SQL injection**" — and it shows you the exact path as proof.
  > **SQL injection** = tricking the app's question to its database so the attacker can read or
  > change data they shouldn't.

- **SAST scanners** — *the spell-checkers for security.*
  > **SAST** = "Static Application Security Testing" — tools that scan code for known dangerous
  > patterns without running it. We use two free ones (Semgrep and Bandit) plus our own rules.
  They're fast and reliable at spotting *known patterns*, but they can't follow a trail across files,
  and they raise false alarms.

- **The validator** — *actually trying the lock.* Instead of trusting "I think this is a bug," it
  applies the fix and re-runs a real attack to confirm the door is now locked.

- **The hybrid** — *the team working together.* Run the AI (broad) and the tools (precise)
  **separately**, then **merge** their findings. The AI catches a wide range; the tools confirm with
  proof and kill false alarms. We measured: the team beats any member alone.

---

## 4. The numbers (and why we trust them)

We tested everything on benchmarks (collections of test cases with known right answers). The honest
results:

- **The AI alone**, audited a whole file: decent (caught ~90% of obvious bugs) but **noisy** (lots
  of false alarms) and **blind to cross-file trails**.
- **The taint engine** on cross-file bugs: **perfect** — found every one, raised *zero* false
  alarms, even when we planted "decoy" functions that *look* dangerous but are actually safe. The AI
  flagged the decoys; the taint engine didn't, because it checks whether real user input actually
  reaches them.
- **The hybrid**: the best of all — **0.97 out of 1.0** on a hard test.

And here's the part we're proudest of: **we didn't trust our own scores.** We *read the AI's actual
answers* and caught **four separate bugs in our grading code** — bugs that had made the fine-tuned
model look amazing (or terrible) for the wrong reasons. The lesson, repeated all over this project:
*the way you measure can lie louder than the thing you're measuring.* Being this careful is what
separates a real result from a demo. (The whole saga is in [`BLOG_QUEUE.md`](BLOG_QUEUE.md).)

---

## 5. Why we built so much "intricate infrastructure"

This is the most important part for understanding the *value*.

We didn't just build one tool. We built a **reusable workshop**: a training rig (to fine-tune any
model), a data pipeline (to mine real vulnerability examples from public records), a test harness
(to grade fairly with an "**LLM-judge**" — using a second AI to score free-form answers), and the
taint engine. Like a workshop with every tool laid out, so you can build *many* things, not just
one.

Because of that, the next capabilities are **add-ons, not rebuilds**:
- Want to cover more vulnerability types (the **OWASP Top 10** — the industry's list of the ten most
  common web security risks)? Add a few rules; the system already knows how to use them. We proved
  it: adding rules moved one score from 0.41 to 0.69.
- Want to chase **zero-days** (brand-new bugs nobody has reported yet)? That's a future project, and
  it plugs into this exact base — see [`docs/FAQ.md`](docs/FAQ.md).

That's the real asset: **the infrastructure and the flow.** The first capability (this auditor) is
proof the workshop works.

---

## 6. The honest scorecard

**Works today:** a fully local, no-internet auditor that follows vulnerabilities across files and
returns *proof* (not guesses); a hybrid that beats the AI alone; trains a 32-billion-parameter model
on a single graphics card in minutes.

**Doesn't (yet):** it only covers the vulnerability types we've written rules for so far (it's
"blind" to types it has no rule for — we measured exactly that); a couple of categories are still
weak; finding truly novel zero-days is a future build.

**The fine-tune:** real and working, but its honest job is *clean output*, not *better detection*.

---

## 7. How to explain it in one or two sentences

> *"It's an AI code-security auditor that runs **entirely on your own machine**, so your private code
> never leaves — built as a **system** where deterministic tools do the precise, provable work (like
> tracing a vulnerability across files) and the AI helps with breadth. We measured everything
> honestly, and proved the **system** beats the AI alone — which is the real engineering."*

And if they push on the fine-tuning: *"We fine-tuned the model and measured that it adds reliable
output formatting, not new detection skill — capability lives in the system. Knowing that, and
proving it, is the point."*
