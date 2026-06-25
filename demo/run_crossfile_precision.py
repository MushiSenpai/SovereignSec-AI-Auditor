#!/usr/bin/env python3
"""Cross-file PRECISION eval — the system's headline value, measured.

Each app: a REAL cross-file vuln (user input reaches a sink) + SAFE DECOYS (same sink, constant/
local input). A per-file LLM pattern-matches the sink and flags the decoys (false positives); the
cross-file taint engine only flags the path user input actually reaches. Scoring is deterministic
(function-name sets) — no judge needed.

Modes: audit --model-dir <m> | report
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RES = ROOT / "bench" / "results"
MAN = ROOT / "ft-rig/data/out/crossfile_prec_manifest.jsonl"


def audit(model_dir: str):
    from sscai.agent.inference_backend import LocalInferenceBackend
    from sscai.agent.agentic import structured_llm_findings
    from sscai.graph.taint import analyze_repo
    apps = [json.loads(l) for l in open(MAN)]
    b = LocalInferenceBackend(model_dir, max_seq_len=4096)
    out = []
    for m in apps:
        sys_funcs = sorted({p.sink.split("::")[1].split(":")[0]
                            for p in analyze_repo(m["app_dir"]) if "::" in p.sink})
        perfile = set()
        for fname, content in m["files"].items():
            for fn, _cwe in structured_llm_findings(b, content):
                if fn:
                    perfile.add(fn)
        out.append({"app": m["app"], "cwe": m["cwe"], "gt_function": m["gt_function"],
                    "decoy_functions": m["decoy_functions"],
                    "system_flagged": sys_funcs, "perfile_flagged": sorted(perfile)})
    (RES / "crossfile_prec_audits.json").write_text(json.dumps(out, indent=2))
    print(f"audited {len(out)} precision apps")


def _score(flagged_key, j):
    tp = fp = fn = decoy_fp = 0
    for r in j:
        flagged = set(r[flagged_key])
        gt = r["gt_function"]
        decoys = set(r["decoy_functions"])
        if gt in flagged:
            tp += 1
        else:
            fn += 1
        wrong = flagged - {gt}
        fp += len(wrong)
        decoy_fp += len(wrong & decoys)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return {"recall": round(rec, 2), "precision": round(prec, 2),
            "decoy_false_positives": decoy_fp, "total_false_positives": fp}


def report():
    j = json.loads((RES / "crossfile_prec_audits.json").read_text())
    n = len(j)
    sysm = _score("system_flagged", j)
    pfm = _score("perfile_flagged", j)
    ndecoys = sum(len(r["decoy_functions"]) for r in j)
    lines = ["# SovereignSec-AI — cross-file PRECISION (the headline)", "",
             f"{n} multi-file apps, each a real cross-file vuln + {ndecoys} SAFE decoys (same sink, "
             "constant/local input). Per-file LLM pattern-matches the sink; cross-file taint follows "
             "actual user input. Deterministic scoring (function sets).", "",
             "| config | recall | precision | decoy false-positives |", "|---|---|---|---|",
             f"| PER-FILE LLM | {pfm['recall']:.2f} | {pfm['precision']:.2f} | "
             f"{pfm['decoy_false_positives']}/{ndecoys} |",
             f"| **SYSTEM (cross-file taint)** | **{sysm['recall']:.2f}** | **{sysm['precision']:.2f}** | "
             f"**{sysm['decoy_false_positives']}/{ndecoys}** |", "",
             f"**Precision: per-file LLM {pfm['precision']:.2f} → cross-file taint {sysm['precision']:.2f}.** "
             f"The LLM false-positives on {pfm['decoy_false_positives']}/{ndecoys} safe decoys; the taint "
             f"engine on {sysm['decoy_false_positives']}/{ndecoys} — it only flags paths user input reaches.", "",
             "Per-app (real flagged? / decoy FPs):"]
    for r in j:
        sysd = set(r["system_flagged"]) & set(r["decoy_functions"])
        pfd = set(r["perfile_flagged"]) & set(r["decoy_functions"])
        lines.append(f"- {r['app']} [{r['cwe']}]: per-file real={'Y' if r['gt_function'] in r['perfile_flagged'] else 'N'} "
                     f"decoyFP={sorted(pfd) or 'none'} | system real={'Y' if r['gt_function'] in r['system_flagged'] else 'N'} "
                     f"decoyFP={sorted(sysd) or 'none'}")
    (RES / "CROSSFILE_PRECISION_REPORT.md").write_text("\n".join(lines))
    (RES / "crossfile_prec_report.json").write_text(json.dumps({"n": n, "per_file": pfm, "system": sysm}, indent=2))
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["audit", "report"])
    ap.add_argument("--model-dir")
    a = ap.parse_args()
    audit(a.model_dir) if a.mode == "audit" else report()


if __name__ == "__main__":
    main()
