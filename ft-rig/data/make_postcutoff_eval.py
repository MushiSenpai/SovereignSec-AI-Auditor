#!/usr/bin/env python3
"""Build a POST-CUTOFF, leak-resistant eval set (PLAN §8.3, addresses BLOG E6 leakage).

The held-out used so far is same-distribution pre/post-fix pairs from data the base model
likely saw — so high scores are leakage-adjacent. This builds a harder set: real CVEs whose
ADVISORY was published in 2025+ AND whose FIX COMMIT lands after the model's training cutoff
(~2024-07), so the base model could not have memorized them.

OSV(django/flask/werkzeug) -> advisories published >= CUTOFF_ADV -> fix commits in the local
clones with committer_date >= CUTOFF_COMMIT -> vuln/patch pairs -> hygiene -> eval records.

Run: PYTHONPATH=ft-rig .venv/bin/python -m data.make_postcutoff_eval
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "ft-rig")
from data.mine_ghsa import iter_pypi_advisories  # noqa: E402
from data.records import calibration_negative, taint_trace_audit  # noqa: E402
from data.verify_labels import is_security_relevant  # noqa: E402

CLONES = {"django": ".tmp/repos/django", "flask": ".tmp/repos/flask", "werkzeug": ".tmp/repos/werkzeug"}
CUTOFF_ADV = datetime(2025, 1, 1, tzinfo=timezone.utc)      # advisory published on/after
CUTOFF_COMMIT = datetime(2024, 7, 1, tzinfo=timezone.utc)   # fix commit on/after (post training data)
MAX_CODE = 1400


def osv_dir_with_published(pkgs):
    """Write OSV advisories to a dir; return (dir, {ghsa_id: published_datetime})."""
    root = Path(tempfile.mkdtemp()) / "advdb" / "x"
    root.mkdir(parents=True)
    pub = {}
    for pkg in pkgs:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps({"package": {"ecosystem": "PyPI", "name": pkg}}).encode(),
            headers={"Content-Type": "application/json"})
        for v in json.loads(urllib.request.urlopen(req, timeout=30).read()).get("vulns", []):
            if not v.get("id", "").startswith("GHSA"):
                continue
            (root / f"{v['id']}.json").write_bytes(json.dumps(v).encode())
            p = v.get("published")
            if p:
                try:
                    pub[v["id"]] = datetime.fromisoformat(p.replace("Z", "+00:00"))
                except ValueError:
                    pass
    return str(root.parent), pub


def main() -> int:
    from pydriller import Repository
    t0 = time.time()
    advdir, published = osv_dir_with_published(["Django", "Flask", "Werkzeug"])
    advs = [a for a in iter_pypi_advisories(advdir)
            if published.get(a.ghsa_id) and published[a.ghsa_id] >= CUTOFF_ADV]
    print(f"post-2025 advisories: {len(advs)}")

    pairs = []
    for a in advs:
        cwe = a.cwes[0] if a.cwes else None
        for org, repo, sha in a.fix_commits:
            local = CLONES.get(repo)
            if not local or not Path(local).exists():
                continue
            try:
                for c in Repository(local, single=sha).traverse_commits():
                    if c.committer_date < CUTOFF_COMMIT:      # double-filter: post-cutoff commit
                        continue
                    for mf in c.modified_files:
                        if not (mf.filename or "").endswith(".py"):
                            continue
                        before = {m.name: m for m in (mf.methods_before or [])}
                        for m in (mf.changed_methods or []):
                            b = before.get(m.name)
                            if not b or not mf.source_code_before or not mf.source_code:
                                continue
                            vuln = "\n".join(mf.source_code_before.split("\n")[b.start_line - 1:b.end_line])
                            patched = "\n".join(mf.source_code.split("\n")[m.start_line - 1:m.end_line])
                            if vuln.strip() == patched.strip() or len(vuln) > MAX_CODE or len(patched) > MAX_CODE:
                                continue
                            pairs.append({"cve": a.cve, "cwe": cwe, "repo": repo, "file": mf.filename,
                                          "func": m.name, "vulnerable": vuln, "patched": patched,
                                          "published": published[a.ghsa_id].date().isoformat(),
                                          "commit_date": c.committer_date.date().isoformat()})
            except Exception:
                continue

    pairs = [p for p in pairs if is_security_relevant(p)]
    recs = []
    for p in pairs:
        cwe = p["cwe"] or "CWE-Unknown"
        meta = {"cwe_seed_id": f"{p['repo']}:{cwe}:{p['cve']}", "cve": p["cve"],
                "published": p["published"], "commit_date": p["commit_date"], "source": "postcutoff"}
        recs.append(taint_trace_audit(f"# {p['repo']}/{p['file']} :: {p['func']}\n{p['vulnerable']}",
                                      "Pre-fix function from a post-cutoff CVE.",
                                      {"cwe": cwe, "severity": "high", "confidence": 0.85}, dict(meta)))
        recs.append(calibration_negative(f"# {p['repo']}/{p['file']} :: {p['func']}\n{p['patched']}",
                                         "Patched (post-cutoff) version.", [cwe], dict(meta)))

    out = Path("ft-rig/data/out/postcutoff_eval.jsonl")
    with open(out, "w") as f:
        for r in recs:
            f.write(json.dumps({"messages": r.messages, "objective": r.objective, "metadata": r.metadata}) + "\n")
    print(f"pairs={len(pairs)} records={len(recs)} time={time.time()-t0:.1f}s -> {out}")
    print("CWEs:", dict(Counter(p['cwe'] for p in pairs if p.get('cwe')).most_common(8)))
    print("date range:", min((p['commit_date'] for p in pairs), default='-'),
          "->", max((p['commit_date'] for p in pairs), default='-'))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
