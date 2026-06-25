# `ft-rig/data` — the data moat (M1)

Builds the labeled Python-web security corpus that no one ships off-the-shelf
(IMPL_SPEC §0 + §6). **The curated output is the private moat** (see [`../../INSIGHTS.md`](../../INSIGHTS.md));
only the *generators* in this dir are public.

## Pipeline order
```
            ┌─ mine_ghsa.py     GHSA(OSV) → fix commits → before/after methods (PyDriller)
  MINE  ────┤
            └─ cvefixes.py      CVEfixes/MoreFixes SQLite → Python method pairs
                                          │
  GENERATE ─ synth_generate.py  teacher(≠student) → (framework×CWE×idiom) vuln+secure+exploit cells
                                          │
  VERIFY ─── synth_verify.py    TRIPLE-LOCK gate: semgrep(our rules)+bandit+RUNNABLE EXPLOIT
             verify_labels.py   untangle tangled commits · MinHashLSH dedup · chronological split
                                          │
  ASSEMBLE ─ assemble.py        → canonical records (records.py) · split by CWE-seed FAMILY
                                  · enforce MIX (45/25/20/10) · write sft_train.jsonl + heldout.jsonl
```

## Non-negotiables (verified, IMPL_SPEC §6/§0)
- **The runnable exploit is authoritative ground truth.** Semgrep/Bandit only corroborate.
- **Teacher ≠ student** in generation (else you bake in the student's blind spots).
- **Run every generated exploit in a sandbox** (`bwrap`/nsjail `--net=none`, rlimits, timeout) — PoCs literally execute attacker code. `synth_verify.run_exploit_sandboxed` does this; **never** run on the host namespace.
- **Hygiene is mandatory** (the BigVul 68% → PrimeVul 3% F1 lesson): untangle, dedup, **chronological** (never random) split; positives + their calibration negatives stay in the same train/eval side (`assemble.split_by_family`).
- **Nemotron-SFT-SWE-v2 is mixed-license** → `assemble.filter_nemotron_ccby` keeps only CC-BY-4.0 rows; attribute; never embed in the shipped product.

## Status
Pure-Python logic (hygiene, record builders, mix split/report) is implemented + smoke-tested.
The I/O-heavy seams run on the M1 box: PyDriller (cloned repos), sqlite (CVEfixes DB),
vLLM teacher endpoint, semgrep/bandit, the sandbox. `§0` mining pins are **VERIFY-PENDING**
until the data-mining grounding re-run reconciles `IMPL_SPEC.md`.

## Import note (packaging wart)
`ft-rig` has a hyphen, so these modules import as the top-level package `data` with
relative imports. Run them with both the repo root (for `sscai`) and `ft-rig` on the
path, e.g. `PYTHONPATH=.:ft-rig python -m data.assemble`. Do **not** `python ft-rig/data/assemble.py`
directly (breaks the relative imports). A small `pyproject` for the rig (like `ft-rig/eval`)
is the clean long-term fix.
