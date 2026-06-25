#!/usr/bin/env python3
"""Build the HAYSTACK eval (the real frontier, BLOG E7 follow-up).

The single-function eval is an easy proxy (both base & FT score 1.0). The hard,
real-world task: given a WHOLE pre-fix file (the vulnerable function buried among many
safe ones), LOCALIZE the vulnerability. This is where the system (SAST/taint narrowing)
should help the LLM — the project's core claim.

OSV(django/flask/werkzeug) -> fix commits -> for each modified .py file capture the FULL
pre-fix file (haystack) + the changed function (ground-truth location) + CWE. Filtered to
CWEs our system covers (SQLi/XSS) and to multi-function files that fit context.

Run: PYTHONPATH=ft-rig .venv/bin/python -m data.make_haystack_eval
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, "ft-rig")
from data.mine_ghsa import iter_pypi_advisories  # noqa: E402

CLONES = {"django": ".tmp/repos/django", "flask": ".tmp/repos/flask", "werkzeug": ".tmp/repos/werkzeug"}
COVERED_CWE = {"CWE-89", "CWE-79"}      # our SAST rules + taint cover these
MIN_CHARS, MAX_CHARS = 1500, 11000      # a real multi-function haystack that fits ctx
MIN_FUNCS = 3                            # must be a haystack, not a 1-function file
TARGET = 15


def osv_dir(pkgs):
    root = Path(tempfile.mkdtemp()) / "advdb" / "x"
    root.mkdir(parents=True)
    for pkg in pkgs:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps({"package": {"ecosystem": "PyPI", "name": pkg}}).encode(),
            headers={"Content-Type": "application/json"})
        for v in json.loads(urllib.request.urlopen(req, timeout=30).read()).get("vulns", []):
            if v.get("id", "").startswith("GHSA"):
                (root / f"{v['id']}.json").write_bytes(json.dumps(v).encode())
    return str(root.parent)


def main() -> int:
    from pydriller import Repository
    t0 = time.time()
    advs = [a for a in iter_pypi_advisories(osv_dir(["Django", "Flask", "Werkzeug"]))
            if a.cwes and a.cwes[0] in COVERED_CWE]
    items, seen = [], set()
    for a in advs:
        cwe = a.cwes[0]
        for org, repo, sha in a.fix_commits:
            local = CLONES.get(repo)
            if not local or not Path(local).exists():
                continue
            try:
                for c in Repository(local, single=sha).traverse_commits():
                    for mf in c.modified_files:
                        if not (mf.filename or "").endswith(".py") or not mf.source_code_before:
                            continue
                        src = mf.source_code_before
                        nfun = len(mf.methods_before or [])
                        changed = [m.name for m in (mf.changed_methods or [])]
                        key = (repo, mf.old_path or mf.filename)
                        if (not (MIN_CHARS <= len(src) <= MAX_CHARS) or nfun < MIN_FUNCS
                                or not changed or key in seen):
                            continue
                        seen.add(key)
                        items.append({"cve": a.cve, "cwe": cwe, "repo": repo,
                                      "file_path": mf.old_path or mf.filename,
                                      "n_functions": nfun, "gt_functions": sorted(set(changed)),
                                      "file_content": src,
                                      "commit_date": c.committer_date.date().isoformat()})
            except Exception:
                continue
    # balance: keep a spread, cap to TARGET
    items = items[:TARGET]
    out = Path("ft-rig/data/out/haystack_eval.jsonl")
    with open(out, "w") as f:
        for it in items:
            f.write(json.dumps(it) + "\n")
    print(f"haystacks={len(items)} time={time.time()-t0:.1f}s -> {out}")
    if items:
        import statistics
        print(f"avg functions/file={statistics.mean(i['n_functions'] for i in items):.1f}, "
              f"avg chars={statistics.mean(len(i['file_content']) for i in items):.0f}")
        from collections import Counter
        print("CWEs:", dict(Counter(i['cwe'] for i in items)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
