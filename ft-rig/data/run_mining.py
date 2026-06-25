#!/usr/bin/env python3
"""M1 bulk: mine REAL vuln->patch pairs from cloned full-depth repos (IMPL_SPEC §0).

OSV (django/flask/werkzeug) -> fix commits (FIX|WEB) -> PyDriller before/after methods
on the LOCAL FULL-DEPTH clones -> hygiene -> ft-rig/data/out/mined_pairs.jsonl.

Run: PYTHONPATH=ft-rig .venv-train/bin/python -m data.run_mining
(needs full-depth clones under .tmp/repos and the `pydriller` dep.)
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import urllib.request
from collections import Counter
from pathlib import Path

sys.path.insert(0, "ft-rig")
from data.mine_ghsa import Advisory, extract_fix_pairs, iter_pypi_advisories  # noqa: E402
from data.verify_labels import untangle  # noqa: E402

CLONES = {"django": ".tmp/repos/django", "flask": ".tmp/repos/flask", "werkzeug": ".tmp/repos/werkzeug"}


def osv_to_dir(pkgs) -> str:
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
    t0 = time.time()
    advs = list(iter_pypi_advisories(osv_to_dir(["Django", "Flask", "Werkzeug"])))
    pairs = []
    for a in advs:
        for org, repo, sha in a.fix_commits:
            local = CLONES.get(repo)
            if not local or not Path(local).exists():
                continue
            one = Advisory(ghsa_id=a.ghsa_id, cve=a.cve, cwes=a.cwes,
                           packages=a.packages, fix_commits=[(org, repo, sha)])
            try:
                for p in extract_fix_pairs(one, local):
                    pairs.append({"ghsa": p.ghsa_id, "cve": p.cve, "cwe": p.cwe, "repo": repo,
                                  "fix_sha": p.fix_sha, "file": p.file, "func": p.func,
                                  "vulnerable": p.vulnerable, "patched": p.patched})
            except Exception:
                continue
    clean = untangle(pairs)
    out = Path("ft-rig/data/out/mined_pairs.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        for p in clean:
            f.write(json.dumps(p) + "\n")
    cwes = Counter(p["cwe"] for p in clean if p.get("cwe"))
    print(f"advisories={len(advs)} raw_pairs={len(pairs)} after_hygiene={len(clean)} "
          f"time={time.time()-t0:.1f}s -> {out}")
    print("top CWEs:", dict(cwes.most_common(8)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
