#!/usr/bin/env python3
"""Haystack localization eval — does the SYSTEM help the LLM find the needle? (BLOG E7+)

Task: given a full pre-fix file (vuln buried among ~14 functions), localize the vulnerability.
Two configs, same auditor model:
  - BARE   : the file alone.
  - SYSTEM : the file + SAST candidate lines (Semgrep our-rules + Bandit) to narrow the search.
Scored by an LLM-JUDGE (free-form outputs can't be keyword-matched — proven 4x; E5/E6/E7).

Modes (separate processes -> never double-load):
  --mode audit  --model-dir <auditor> --label <l>     # generates bare + system outputs
  --mode judge  --model-dir <judge> --audits <label>  # judges localization vs ground truth
  --mode report --audits <label>
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RES = ROOT / "bench" / "results"
EVAL = ROOT / "ft-rig/data/out/haystack_eval.jsonl"


def _sast_candidates(code: str) -> list:
    from sscai.sast import scan
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "mod.py").write_text(code)
        try:
            cs = scan(d)
        except Exception:
            return []
    out = []
    for c in cs:
        out.append({"line": c.line, "cwe": (c.cwe[0].split(":")[0] if c.cwe else ""), "rule": c.rule_id})
    return out[:12]


def audit(model_dir: str, label: str, eval_file: str = str(EVAL)):
    from sscai.agent.inference_backend import LocalInferenceBackend
    items = [json.loads(l) for l in open(eval_file)]
    b = LocalInferenceBackend(model_dir, max_seq_len=8192)
    SYS = ("You are a security auditor. Find the security vulnerability in this file and report "
           "the VULNERABLE FUNCTION name, the line, and the CWE. If none, say 'No finding'.")
    results = []
    for it in items:
        code = it["file_content"]
        bare = b.complete([{"role": "system", "content": SYS},
                           {"role": "user", "content": f"File `{it['file_path']}`:\n```python\n{code}\n```"}], 256)
        cands = _sast_candidates(code)
        hint = ("A static scanner flagged these candidate lines: "
                + ", ".join(f"L{c['line']}({c['cwe']})" for c in cands) if cands
                else "A static scanner flagged no lines; analyze manually.")
        system = b.complete([{"role": "system", "content": SYS},
                             {"role": "user", "content":
                              f"File `{it['file_path']}`:\n```python\n{code}\n```\n\n{hint}\n"
                              "Confirm the real vulnerability and name the vulnerable function."}], 256)
        # AGENTIC: trace (taint+SAST) -> hypothesize+validate per candidate -> confirmed findings
        from sscai.agent.agentic import agentic_audit, format_findings, hybrid_audit
        ag = agentic_audit(b, code)
        # HYBRID: LLM breadth (independent) MERGED with system-confirmed (reuses ag)
        hy = hybrid_audit(b, code, agentic_result=ag)
        results.append({"cve": it["cve"], "cwe": it["cwe"], "file_path": it["file_path"],
                        "n_functions": it["n_functions"], "gt_functions": it["gt_functions"],
                        "n_candidates": len(cands), "bare_out": bare[:500], "system_out": system[:500],
                        "agentic_out": format_findings(ag)[:500], "agentic_confirmed": ag["confirmed"],
                        "hybrid_out": format_findings(hy)[:500], "hybrid_confirmed": hy["confirmed"],
                        "hybrid_provenance": hy["provenance"]})
    (RES / f"haystack_audits_{label}.json").write_text(json.dumps(results, indent=2))
    print(f"audited {len(results)} haystacks ({label}); avg SAST candidates/file="
          f"{sum(r['n_candidates'] for r in results)/max(1,len(results)):.1f}")


def _judge_one(jb, output: str, gt: list, cwe: str) -> bool:
    p = [{"role": "user", "content":
          f"A {cwe} vulnerability exists in this file, located in function(s): {', '.join(gt)}.\n"
          f"An auditor reported:\n---\n{output}\n---\n"
          f"Did the auditor correctly identify a vulnerability located in one of those functions? "
          f"Answer with only YES or NO."}]
    return "yes" in jb.complete(p, 8).strip().lower()[:6]


def judge(model_dir: str, label: str):
    from sscai.agent.inference_backend import LocalInferenceBackend
    audits = json.loads((RES / f"haystack_audits_{label}.json").read_text())
    jb = LocalInferenceBackend(model_dir, max_seq_len=4096)
    for r in audits:
        r["bare_correct"] = _judge_one(jb, r["bare_out"], r["gt_functions"], r["cwe"])
        r["system_correct"] = _judge_one(jb, r["system_out"], r["gt_functions"], r["cwe"])
        r["agentic_correct"] = _judge_one(jb, r.get("agentic_out", ""), r["gt_functions"], r["cwe"])
        r["hybrid_correct"] = _judge_one(jb, r.get("hybrid_out", ""), r["gt_functions"], r["cwe"])
    (RES / f"haystack_judged_{label}.json").write_text(json.dumps(audits, indent=2))
    print(f"judged {len(audits)} haystacks")


def report(label: str):
    from collections import Counter
    j = json.loads((RES / f"haystack_judged_{label}.json").read_text())
    n = len(j)
    bare = sum(r["bare_correct"] for r in j) / n
    syst = sum(r["system_correct"] for r in j) / n
    agent = sum(r.get("agentic_correct", False) for r in j) / n
    hyb = sum(r.get("hybrid_correct", False) for r in j) / n
    comp = ", ".join(f"{v}×{k}" for k, v in sorted(Counter(r["cwe"] for r in j).items()))
    avg_fns = sum(r["n_functions"] for r in j) / n

    def precision(field):
        tp = fp = 0
        for r in j:
            for fn in (r.get(field) or {}):
                tp += 1 if fn in r["gt_functions"] else 0
                fp += 0 if fn in r["gt_functions"] else 1
        return (tp / (tp + fp) if (tp + fp) else 0.0), tp, fp

    aprec, atp, afp = precision("agentic_confirmed")
    hprec, htp, hfp = precision("hybrid_confirmed")
    sys_conf = sum(1 for r in j for v in (r.get("hybrid_provenance") or {}).values() if v == "system-confirmed")
    lines = ["# SovereignSec-AI — haystack localization (bare vs one-shot vs agentic vs HYBRID)", "",
             f"Label: **{label}**. Localize the vuln in a full file (~{avg_fns:.0f} functions each, "
             f"{n} files; {comp}). Auditor = 32B; LLM-judge scores localization vs ground truth.", "",
             "| config | recall | finding precision |", "|---|---|---|",
             f"| BARE (file only) | {bare:.2f} | — |",
             f"| ONE-SHOT (+ SAST hints) | {syst:.2f} | — |",
             f"| AGENTIC (trace→triage→validate) | {agent:.2f} | {aprec:.2f} ({atp}/{atp+afp}) |",
             f"| **HYBRID (LLM breadth ∪ system-confirmed)** | **{hyb:.2f}** | {hprec:.2f} ({htp}/{htp+hfp}) |", "",
             f"**bare {bare:.2f} · one-shot {syst:.2f} · agentic {agent:.2f} · hybrid {hyb:.2f}.** "
             f"Of the hybrid's findings, **{sys_conf}** carry deterministic system proof "
             "(taint path / SAST) — the high-confidence subset an analyst triages first.", "",
             "Per-file (bare / one-shot / agentic / hybrid):"]
    for r in j:
        lines.append(f"- {r['file_path']} [{r['cwe']}, {r['n_functions']} fns]: "
                     f"{'Y' if r['bare_correct'] else 'N'} / "
                     f"{'Y' if r['system_correct'] else 'N'} / "
                     f"{'Y' if r.get('agentic_correct') else 'N'} / "
                     f"{'Y' if r.get('hybrid_correct') else 'N'}")
    (RES / f"HAYSTACK_REPORT_{label}.md").write_text("\n".join(lines))
    (RES / f"haystack_report_{label}.json").write_text(json.dumps(
        {"label": label, "n": n, "composition": comp, "bare_acc": round(bare, 3),
         "oneshot_acc": round(syst, 3), "agentic_acc": round(agent, 3), "hybrid_acc": round(hyb, 3),
         "agentic_precision": round(aprec, 3), "hybrid_precision": round(hprec, 3),
         "hybrid_system_confirmed": sys_conf}, indent=2))
    print("\n".join(lines[:13]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["audit", "judge", "report"])
    ap.add_argument("--model-dir"); ap.add_argument("--label", default="32b"); ap.add_argument("--audits", default="32b")
    ap.add_argument("--eval-file", default=str(EVAL))
    a = ap.parse_args()
    if a.mode == "audit":
        audit(a.model_dir, a.label, a.eval_file)
    elif a.mode == "judge":
        judge(a.model_dir, a.audits)
    else:
        report(a.audits)


if __name__ == "__main__":
    main()
