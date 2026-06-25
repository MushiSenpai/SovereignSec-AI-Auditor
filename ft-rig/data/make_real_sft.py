#!/usr/bin/env python3
"""Build an SFT dataset from the REAL mined pairs (M3-production, IMPL_SPEC §0/§6).

Each mined (vulnerable -> patched) pair becomes a positive (vulnerable code -> FINDING)
and a calibration negative (patched code -> no_finding). Balanced per CWE, length-capped
to fit the context, split into train + held-out.

Caveat (honest): the CWE label is the advisory's (function-level, not line-precise), and
the held-out split here is random not chronological — production uses chronological splits
(BLOG E1). This is a real-data step up from the templated smoke set, not the final corpus.

Run: PYTHONPATH=ft-rig .venv/bin/python -m data.make_real_sft
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, "ft-rig")
from data.records import calibration_negative, taint_trace_audit  # noqa: E402

CAP_PER_CWE = 50
MAX_CODE_CHARS = 1400   # keep both sides within the smoke context window


def main() -> int:
    rows = [json.loads(l) for l in open("ft-rig/data/out/mined_pairs.jsonl")]
    by_cwe = defaultdict(list)
    for r in rows:
        if (r.get("cwe") and len(r["vulnerable"]) < MAX_CODE_CHARS
                and len(r["patched"]) < MAX_CODE_CHARS):
            by_cwe[r["cwe"]].append(r)

    selected = [r for rs in by_cwe.values() for r in rs[:CAP_PER_CWE]]
    recs = []
    for r in selected:
        cwe = r["cwe"]
        meta = {"cwe_seed_id": f"{r['repo']}:{cwe}:{r['fix_sha'][:8]}", "cve": r["cve"],
                "source": "mined", "license": "CC-BY-4.0"}
        recs.append(taint_trace_audit(
            f"# {r['repo']}/{r['file']} :: {r['func']}\n{r['vulnerable']}",
            "This pre-fix function contains the vulnerability the CVE patched.",
            {"cwe": cwe, "severity": "high", "confidence": 0.85}, dict(meta)))
        recs.append(calibration_negative(
            f"# {r['repo']}/{r['file']} :: {r['func']}\n{r['patched']}",
            "This is the patched version; the vulnerability is fixed.", [cwe], dict(meta)))

    # deterministic split by cwe_seed_id family (positives + negatives stay together)
    fams = sorted({rec.metadata["cwe_seed_id"] for rec in recs})
    holdout = set(fams[:: max(1, len(fams) // 12)][:max(1, len(fams) // 12)])  # ~8% families
    train = [r for r in recs if r.metadata["cwe_seed_id"] not in holdout]
    held = [r for r in recs if r.metadata["cwe_seed_id"] in holdout]

    out = Path("ft-rig/data/out")
    for name, data in [("real_sft.jsonl", train), ("real_heldout.jsonl", held)]:
        with open(out / name, "w") as f:
            for rec in data:
                f.write(json.dumps({"messages": rec.messages, "objective": rec.objective,
                                    "metadata": rec.metadata}) + "\n")
    print(f"selected pairs={len(selected)} | records={len(recs)} "
          f"(train={len(train)}, heldout={len(held)}) | CWEs={len(by_cwe)}")
    print("per-CWE (capped):", {k: min(len(v), CAP_PER_CWE) for k, v in
                                sorted(by_cwe.items(), key=lambda x: -len(x[1]))[:8]})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
