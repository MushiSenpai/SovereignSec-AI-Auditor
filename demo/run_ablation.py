#!/usr/bin/env python3
"""Mini ablation on the seeded repo (PLAN §8.1, IMPL_SPEC) — the case-study spine.

Shows what each layer adds, scored against GROUND_TRUTH.json. Candidate-stage
matching is on (file, CWE) — lines differ across tools (Bandit flags the SQL-build
line, our taint flags the execute sink), so the agent/finding stage pins exact lines.

Run:  PYTHONPATH=. .venv/bin/python demo/run_ablation.py
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = "demo/seeded_repo"
GT = json.loads((Path(REPO) / "GROUND_TRUTH.json").read_text())
TRUTH = {(f["file"], f["cwe"]) for f in GT["findings"]}
# The planted FP shares (file, CWE) with the real SQLi — so FP-leak detection MUST be
# LINE-scoped (the FP is find_user_safe's body; the real bug is find_user's). Coarse
# (file, CWE) matching conflates them (a real measurement learning — see BLOG_QUEUE).
_FP = GT["planted_false_positives"][0]
FP_FILE, FP_LO, FP_HI = _FP["file"], _FP["line"], _FP["line"] + 8


def cwe_of(c) -> str:
    raw = c.cwe[0] if c.cwe else ""
    return raw.split(":")[0] if raw else ""


def leaks_fp(cands) -> bool:
    return any(Path(c.path).name == FP_FILE and FP_LO <= c.line <= FP_HI for c in cands)


def score(pred: set, label: str, fp_leak: bool) -> dict:
    tp = len(pred & TRUTH)
    fp = len(pred - TRUTH) + (1 if fp_leak else 0)
    fn = len(TRUTH - pred)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"rung": label, "P": round(prec, 2), "R": round(rec, 2), "F1": round(f1, 2),
            "found": sorted(pred), "fp_leak": fp_leak}


def main():
    from sscai.sast.runner import run_semgrep, run_bandit
    from sscai.sast.normalize import from_semgrep, from_bandit
    from sscai.graph.taint import analyze_repo

    # Rung A — Semgrep CE (our rules) ONLY. Single-file taint => misses cross-file SQLi.
    sg = [from_semgrep(r) for r in run_semgrep(REPO).get("results", [])]
    sg = [c for c in sg if "/tests/" not in c.path and "/exploits/" not in c.path]
    pred_a = {(Path(c.path).name, cwe_of(c)) for c in sg}

    # Rung B — + Bandit (intra-file, no taint). Recovers the SQLi SINK location.
    bd = [from_bandit(r) for r in run_bandit(REPO).get("results", [])]
    bd = [c for c in bd if "/tests/" not in c.path and "/exploits/" not in c.path]
    pred_b = pred_a | {(Path(c.path).name, cwe_of(c)) for c in bd}

    # Rung C — + L1 cross-file taint. Confirms the SQLi as an exploitable source->sink
    # path across 3 files (high confidence), which neither tool alone can prove.
    tp = analyze_repo(REPO)
    pred_c = pred_b | {(Path(s.split("::")[0]).name, p.cwe)
                       for p in tp for s in [p.sink]}

    rows = [score(pred_a, "A: Semgrep-CE only", leaks_fp(sg)),
            score(pred_b, "B: + Bandit", leaks_fp(sg + bd)),
            score(pred_c, "C: + L1 cross-file taint", leaks_fp(sg + bd))]

    print(f"\nGround truth: {sorted(TRUTH)}")
    print(f"Planted FP (line-scoped): {FP_FILE}:{FP_LO}-{FP_HI} (find_user_safe) must NOT be flagged\n")
    print(f"{'rung':28} {'P':>4} {'R':>4} {'F1':>4}  FP-leak  findings")
    print("-" * 78)
    for r in rows:
        print(f"{r['rung']:28} {r['P']:>4} {r['R']:>4} {r['F1']:>4}  {str(r['fp_leak']):>5}    {r['found']}")
    print(f"\nCross-file taint paths (L1): {len(tp)}")
    for p in tp:
        print("  " + " -> ".join(s.split('::')[-1] if '::' in s else s for s in p.steps))


if __name__ == "__main__":
    main()
