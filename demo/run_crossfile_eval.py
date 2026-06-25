#!/usr/bin/env python3
"""Cross-file eval — the one thing single-file benchmarks can't show.

Each app's vuln flows routes.py -> services.py -> sink_layer. Compares:
  - SYSTEM   : cross-file taint over the whole app (deterministic, sees the call graph).
  - PER-FILE : the LLM audits each file ALONE (scalable scanner view; blind to cross-file flow).
  - HYBRID   : system OR per-file.
A per-file LLM can flag an obvious in-file smell (string-formatted SQL) but cannot know a bare
`requests.get(url)` / `open(path)` / `pickle.loads(x)` is user-controlled when the source is in
another file — which is exactly where cross-file taint wins.

Modes: audit --model-dir <m> | judge --model-dir <judge> | report
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RES = ROOT / "bench" / "results"
MAN = ROOT / "ft-rig/data/out/crossfile_manifest.jsonl"


def audit(model_dir: str):
    from sscai.agent.inference_backend import LocalInferenceBackend
    from sscai.graph.taint import analyze_repo
    apps = [json.loads(l) for l in open(MAN)]
    b = LocalInferenceBackend(model_dir, max_seq_len=4096)
    SYS = ("You are a security auditor reviewing ONE file of a larger application. Find any "
           "security vulnerability and name the vulnerable function + CWE, or say 'No finding'.")
    out = []
    for m in apps:
        # SYSTEM: deterministic cross-file taint over the whole app
        paths = analyze_repo(m["app_dir"])
        sys_found = any(m["gt_function"] in p.sink and p.cwe == m["cwe"] for p in paths)
        sys_path = next((" -> ".join(s.split("::")[-1].split(":")[0] if "::" in s else s
                                     for s in p.steps) for p in paths if m["gt_function"] in p.sink), "")
        # PER-FILE: LLM audits each file independently
        per_file = {}
        for fname, content in m["files"].items():
            per_file[fname] = b.complete(
                [{"role": "system", "content": SYS},
                 {"role": "user", "content": f"File `{fname}`:\n```python\n{content}\n```"}], 200)[:350]
        out.append({"app": m["app"], "cwe": m["cwe"], "gt_file": m["gt_file"],
                    "gt_function": m["gt_function"], "system_found": sys_found,
                    "system_path": sys_path, "per_file": per_file})
    (RES / "crossfile_audits.json").write_text(json.dumps(out, indent=2))
    print(f"audited {len(out)} cross-file apps; system found {sum(r['system_found'] for r in out)}/{len(out)}")


def judge(model_dir: str):
    from sscai.agent.inference_backend import LocalInferenceBackend
    a = json.loads((RES / "crossfile_audits.json").read_text())
    jb = LocalInferenceBackend(model_dir, max_seq_len=4096)
    for r in a:
        combined = "\n".join(f"{f}: {o}" for f, o in r["per_file"].items())
        v = jb.complete([{"role": "user", "content":
                          f"The real vulnerability is a {r['cwe']} in `{r['gt_file']}::{r['gt_function']}`.\n"
                          f"A per-file auditor reported:\n---\n{combined}\n---\n"
                          f"Did the auditor identify a vulnerability in `{r['gt_function']}`? Answer only YES or NO."}], 8)
        r["perfile_correct"] = "yes" in v.strip().lower()[:6]
    (RES / "crossfile_judged.json").write_text(json.dumps(a, indent=2))
    print(f"judged {len(a)} apps")


def report():
    j = json.loads((RES / "crossfile_judged.json").read_text())
    n = len(j)
    sysr = sum(r["system_found"] for r in j) / n
    pf = sum(r.get("perfile_correct", False) for r in j) / n
    hyb = sum(r["system_found"] or r.get("perfile_correct", False) for r in j) / n
    lines = ["# SovereignSec-AI — cross-file localization (the headline)", "",
             f"{n} multi-file apps; vuln flows routes.py → services.py → sink layer. "
             "SYSTEM = cross-file taint (whole call graph); PER-FILE = LLM audits each file alone.", "",
             "| config | localization recall |", "|---|---|",
             f"| PER-FILE LLM (blind to cross-file) | {pf:.2f} |",
             f"| **SYSTEM (cross-file taint)** | **{sysr:.2f}** |",
             f"| HYBRID (system ∪ per-file) | {hyb:.2f} |", "",
             f"**per-file {pf:.2f} → cross-file taint {sysr:.2f} ({sysr-pf:+.2f}).** "
             "The cross-file taint is deterministic and carries the full source→sink path.", "",
             "Per-app (per-file LLM / system):"]
    for r in j:
        lines.append(f"- {r['app']} [{r['cwe']}] {r['gt_file']}::{r['gt_function']}: "
                     f"{'Y' if r.get('perfile_correct') else 'N'} / "
                     f"{'Y' if r['system_found'] else 'N'}"
                     + (f"  [{r['system_path']}]" if r['system_found'] else ""))
    (RES / "CROSSFILE_REPORT.md").write_text("\n".join(lines))
    (RES / "crossfile_report.json").write_text(json.dumps(
        {"n": n, "perfile": round(pf, 3), "system": round(sysr, 3), "hybrid": round(hyb, 3)}, indent=2))
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["audit", "judge", "report"])
    ap.add_argument("--model-dir")
    a = ap.parse_args()
    {"audit": lambda: audit(a.model_dir), "judge": lambda: judge(a.model_dir), "report": report}[a.mode]()


if __name__ == "__main__":
    main()
