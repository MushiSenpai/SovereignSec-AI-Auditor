#!/usr/bin/env python3
"""Make a tiny SMOKE SFT dataset to exercise the training rig + capture Blackwell
metrics (NOT the real moat — that comes from the generate-and-verify pipeline).

Templated positives (vulnerable -> finding JSON) + calibration negatives (safe ->
no-finding), across a few CWEs, in the canonical conversational `messages` shape.

Run: PYTHONPATH=ft-rig .venv-train/bin/python -m data.make_smoke_dataset --out ft-rig/data/out/smoke_sft.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SYS = "You are a security auditor. Trace taint (source -> sink) and report findings as JSON, or say no finding when code is safe."

# (cwe, vulnerable snippet, safe snippet, sink desc)
CASES = [
    ("CWE-89", "q = \"SELECT * FROM u WHERE n='%s'\" % name\ncur.execute(q)",
     "cur.execute(\"SELECT * FROM u WHERE n=?\", (name,))", "cur.execute"),
    ("CWE-79", "return \"<h1>\" + name + \"</h1>\"",
     "return render_template('p.html', name=name)", "html response"),
    ("CWE-78", "os.system(\"ping \" + host)",
     "subprocess.run(['ping', host])", "os.system"),
    ("CWE-502", "obj = pickle.loads(data)",
     "obj = json.loads(data)", "pickle.loads"),
    ("CWE-22", "open(base + user_path).read()",
     "open(safe_join(base, user_path)).read()", "open"),
]
FRAMEWORKS = ["flask", "django", "fastapi"]


def records():
    for fw in FRAMEWORKS:
        for cwe, vuln, safe, sink in CASES:
            ctx = f"# {fw} view\nname = request.args.get('name')\n{vuln}"
            finding = {"cwe": cwe, "severity": "high", "confidence": 0.9, "sink": sink}
            yield {"objective": "taint_trace_audit", "messages": [
                {"role": "system", "content": SYS},
                {"role": "user", "content": f"Audit:\n```python\n{ctx}\n```"},
                {"role": "assistant", "content":
                 f"Tainted source `request.args.get` reaches `{sink}` unsanitized.\n"
                 f"FINDING: {json.dumps(finding)}"}]}
            safe_ctx = f"# {fw} view\nname = request.args.get('name')\n{safe}"
            yield {"objective": "calibration_negative", "messages": [
                {"role": "system", "content": SYS},
                {"role": "user", "content": f"Audit:\n```python\n{safe_ctx}\n```"},
                {"role": "assistant", "content":
                 f"Input is parameterized/escaped before `{sink}`; no taint reaches a sink.\n"
                 f"FINDING: {json.dumps({'no_finding': True, 'checked_cwe': [cwe]})}"}]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="ft-rig/data/out/smoke_sft.jsonl")
    ap.add_argument("--repeat", type=int, default=4, help="duplicate set N times for a longer smoke run")
    args = ap.parse_args()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    rows = list(records()) * args.repeat
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows)} smoke records -> {args.out}")


if __name__ == "__main__":
    main()
