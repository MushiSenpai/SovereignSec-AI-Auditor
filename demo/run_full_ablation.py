#!/usr/bin/env python3
"""Complete rungs-0->5 ablation (PLAN §8.1, M4).

Two evidence sources, both real:
  - DETERMINISTIC system rungs on the seeded repo (Semgrep -> +Bandit -> +taint).
  - LLM rungs on the REAL held-out mined set (base vs fine-tuned bare audit).

Modes (run separately so we never double-load a model in one process):
  --mode deterministic
  --mode llm --model-dir <hf_id_or_adapter> --label base|ft [--max-eval 40]
  --mode merge

Writes bench/results/full_ablation*.json and prints the final table.
Run via demo/run_full_ablation.sh (orchestrates all modes).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

# Negatives first (word-bounded; 'insecure' != 'secure'), incl. negated vuln VALUES
# like {"vulnerability":"none"} so the base's "no vuln" outputs read as clean.
_NEG = re.compile(
    r'("no_finding"\s*:\s*true|\bno[_ ]?finding\b|\bnot vulnerable\b'
    r'|\bno (?:obvious )?(?:vulnerab\w*|security (?:issue|vulnerab)\w*|issues?|findings?)\b'
    r'|"findings"\s*:\s*\[\s*\]'
    r'|"vulnerabilit(?:y|ies)"\s*:\s*"?(?:none|no\b|n/?a|not\b|null)'
    r'|"finding"\s*:\s*(?:null|"none"|\[\s*\]))', re.I)
# Affirmative finding markers across ALL shapes we've seen base + FT emit.
_POS = re.compile(
    r'(cwe[-_ ]?\d+|"cwe"|"vulnerabilit(?:y|ies)"|"finding"\b|"issue"|"tainted'
    r'|"findings"\s*:\s*\[\s*\{|"file"\s*:)', re.I)


def detects_vuln(text: str) -> bool:
    """Format-agnostic + FAIR across output shapes (BLOG E6/E7). The FT emits the terse
    trained `FINDING:{cwe}`; the BASE emits varied JSON — `{"file","line","description"}`,
    `{"vulnerability":"..."}`, `{"finding":{"issue":...}}`. We credit any affirmative
    finding shape, and treat negated values (`"vulnerability":"none"`) / empty arrays /
    'no finding' as clean. Negatives win over positives. (Still not a substitute for an
    LLM-judge — see E7 — but materially fairer than a CWE-only detector.)"""
    low = text or ""
    if _NEG.search(low):
        return False
    return bool(_POS.search(low))

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RES = ROOT / "bench" / "results"
REPO = str(ROOT / "demo" / "seeded_repo")


# ---------- deterministic system rungs (seeded repo) ----------
def deterministic():
    from sscai.sast.runner import run_semgrep, run_bandit
    from sscai.sast.normalize import from_semgrep, from_bandit
    from sscai.graph.taint import analyze_repo
    gt = json.loads((Path(REPO) / "GROUND_TRUTH.json").read_text())
    truth = {(f["file"], f["cwe"]) for f in gt["findings"]}
    fp = gt["planted_false_positives"][0]
    fpfile, lo, hi = fp["file"], fp["line"], fp["line"] + 8

    def cwe(c): return c.cwe[0].split(":")[0] if c.cwe else ""
    def names(cs): return {(Path(c.path).name, cwe(c)) for c in cs}
    def leak(cs): return any(Path(c.path).name == fpfile and lo <= c.line <= hi for c in cs)

    def prf(pred, fpl):
        tp = len(pred & truth); fpc = len(pred - truth) + (1 if fpl else 0); fn = len(truth - pred)
        p = tp / (tp + fpc) if tp + fpc else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        return {"P": round(p, 3), "R": round(r, 3),
                "F1": round(2 * p * r / (p + r), 3) if p + r else 0.0}

    sg = [c for c in (from_semgrep(r) for r in run_semgrep(REPO).get("results", []))
          if "/tests/" not in c.path and "/exploits/" not in c.path]
    bd = [c for c in (from_bandit(r) for r in run_bandit(REPO).get("results", []))
          if "/tests/" not in c.path and "/exploits/" not in c.path]
    taint = analyze_repo(REPO)
    pa = names(sg); pb = pa | names(bd)
    pc = pb | {(Path(p.sink.split("::")[0]).name, p.cwe) for p in taint}
    out = {"semgrep_only": prf(pa, leak(sg)), "plus_bandit": prf(pb, leak(sg + bd)),
           "plus_taint": prf(pc, leak(sg + bd)), "taint_paths": len(taint)}
    (RES / "full_ablation_det.json").write_text(json.dumps(out, indent=2))
    print("deterministic:", json.dumps(out))


# ---------- LLM bare-audit eval on the real held-out set ----------
def llm(model_dir: str, label: str, max_eval: int, eval_file: str = "ft-rig/data/out/real_heldout.jsonl"):
    from sscai.agent.inference_backend import LocalInferenceBackend
    records = [json.loads(l) for l in open(ROOT / eval_file)]
    pos = [r for r in records if r["objective"] == "taint_trace_audit"][: max_eval // 2]
    neg = [r for r in records if r["objective"] == "calibration_negative"][: max_eval // 2]
    b = LocalInferenceBackend(model_dir, max_seq_len=2048)

    # Use each record's OWN system+user (the training I/O contract) for a fair
    # comparison; detect a finding format-agnostically from the generated text.
    samples = []

    def judge(r, is_pos) -> bool:
        out = b.complete(r["messages"][:2], 200)
        fl = detects_vuln(out)
        samples.append({"is_pos": is_pos, "flagged": fl, "out": out[:300]})  # save ALL for transparency
        return fl

    t0 = time.perf_counter()
    tp = sum(judge(r, True) for r in pos)
    fn = len(pos) - tp
    fp = sum(judge(r, False) for r in neg)
    tn = len(neg) - fp
    dt = time.perf_counter() - t0
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    out = {"label": label, "model_dir": model_dir, "n_pos": len(pos), "n_neg": len(neg),
           "TP": tp, "FN": fn, "FP": fp, "TN": tn,
           "precision": round(prec, 3), "recall": round(rec, 3),
           "f1": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0.0,
           "accuracy": round((tp + tn) / (len(pos) + len(neg)), 3) if (pos or neg) else 0.0,
           "eval_file": eval_file,
           "eval_time_s": round(dt, 1), "sec_per_audit": round(dt / max(1, len(pos) + len(neg)), 2),
           "samples": samples}
    (RES / f"full_ablation_llm_{label}.json").write_text(json.dumps(out, indent=2))
    print(f"llm[{label}]:", json.dumps(out))


# ---------- merge into the complete rungs 0->5 table ----------
def merge():
    det = json.loads((RES / "full_ablation_det.json").read_text())
    base = json.loads((RES / "full_ablation_llm_base.json").read_text())
    ft = json.loads((RES / "full_ablation_llm_ft.json").read_text())
    rows = [
        ("R0  base LLM, bare (held-out real CVEs)", base["precision"], base["recall"], base["f1"], "LLM-only floor"),
        ("R2  SAST tool-only (seeded)", det["plus_bandit"]["P"], det["plus_bandit"]["R"], det["plus_bandit"]["F1"], "deterministic baseline"),
        ("R4  system: SAST + cross-file taint (seeded)", det["plus_taint"]["P"], det["plus_taint"]["R"], det["plus_taint"]["F1"], f"{det['taint_paths']} taint path(s)"),
        ("R5  fine-tuned LLM, bare (held-out real CVEs)", ft["precision"], ft["recall"], ft["f1"], "FT delta vs R0"),
    ]
    lines = ["# SovereignSec-AI — complete rungs-0->5 ablation", "",
             "LLM rungs: bare audit on the REAL held-out mined set (base vs fine-tuned 7B).",
             "System rungs: deterministic on the seeded cross-file fixture.", "",
             "| rung | P | R | F1 | note |", "|---|---|---|---|---|"]
    for name, p, r, f1, note in rows:
        lines.append(f"| {name} | {p} | {r} | {f1} | {note} |")
    delta_r = round(ft["recall"] - base["recall"], 3)
    delta_p = round(ft["precision"] - base["precision"], 3)
    lines += ["", f"**Fine-tune delta on real held-out CVEs (R5 vs R0): "
              f"recall {base['recall']}→{ft['recall']} ({delta_r:+}), "
              f"precision {base['precision']}→{ft['precision']} ({delta_p:+})**",
              "", "_Honest scope: held-out split is by CWE-family from the same repos "
              "(not post-cutoff); seeded fixture saturates the deterministic system, so the "
              "FT delta shows on the LLM rungs. Next: 24-27B base + agentic loop on harder evals._"]
    body = "\n".join(lines)
    (RES / "FULL_ABLATION.md").write_text(body)
    (RES / "full_ablation.json").write_text(json.dumps(
        {"deterministic": det, "llm_base": base, "llm_ft": ft,
         "ft_delta": {"recall": delta_r, "precision": delta_p}}, indent=2))
    print(body)


def postcutoff():
    """Compare base vs FT on the POST-CUTOFF (leak-resistant) eval — the trustworthy number."""
    base = json.loads((RES / "full_ablation_llm_base_pc.json").read_text())
    ft = json.loads((RES / "full_ablation_llm_ft_pc.json").read_text())
    dr = round(ft["recall"] - base["recall"], 3)
    dp = round(ft["precision"] - base["precision"], 3)
    lines = ["# SovereignSec-AI — POST-CUTOFF ablation (leak-resistant)", "",
             f"Eval: real CVEs published 2025+ / fix commits 2024-07+ ({base['n_pos']} vuln + "
             f"{base['n_neg']} safe), unmemorizable by the base. Model: 32B base vs fine-tuned.", "",
             "| model | P | R | F1 | accuracy |", "|---|---|---|---|---|",
             f"| base 32B | {base['precision']} | {base['recall']} | {base['f1']} | {base['accuracy']} |",
             f"| fine-tuned 32B | {ft['precision']} | {ft['recall']} | {ft['f1']} | {ft['accuracy']} |",
             "", f"**FT delta on post-cutoff CVEs: recall {base['recall']}→{ft['recall']} ({dr:+}), "
             f"precision {base['precision']}→{ft['precision']} ({dp:+}).**",
             "", "This is the honest detection number: the eval is genuinely post-training-cutoff, so "
             "no memorization. Compare against the same-distribution held-out (FULL_ABLATION.md) to see "
             "how much of that near-perfect score was leakage."]
    (RES / "POSTCUTOFF_ABLATION.md").write_text("\n".join(lines))
    (RES / "postcutoff_ablation.json").write_text(json.dumps(
        {"base": base, "ft": ft, "delta": {"recall": dr, "precision": dp}}, indent=2))
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["deterministic", "llm", "merge", "postcutoff"])
    ap.add_argument("--model-dir"); ap.add_argument("--label", default="base")
    ap.add_argument("--max-eval", type=int, default=40)
    ap.add_argument("--eval-file", default="ft-rig/data/out/real_heldout.jsonl")
    a = ap.parse_args()
    if a.mode == "deterministic":
        deterministic()
    elif a.mode == "llm":
        llm(a.model_dir, a.label, a.max_eval, a.eval_file)
    elif a.mode == "postcutoff":
        postcutoff()
    else:
        merge()


if __name__ == "__main__":
    main()
