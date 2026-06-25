"""Local (no-Docker) patch oracle for in-repo fixtures + CI (IMPL_SPEC §5).

The Docker/N-run gate in oracle.py is for arbitrary target repos. For our own
seeded fixtures (whose exploit uses the Flask test client, no network) this
lighter oracle runs the gate directly on a temp copy:

    exploit_pre == SUCCESS  AND  exploit_post == FAILURE  AND  tests still PASS

"Tests pass" alone is a weak oracle (ICSE-2026) — the negative exploit oracle is
what proves the fix. Runs N times; unanimous-or-reject.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional


@dataclass
class LocalVerdict:
    verdict: str          # FIXED | NOT_REAL | OVERFIT_OR_BROKEN | FLAKY_REJECT
    runs: list
    detail: str = ""


def _run(py: str, script: str, cwd: str) -> int:
    return subprocess.run([py, script], cwd=cwd, capture_output=True, text=True,
                          timeout=120, check=False).returncode


def _pytest_ok(py: str, cwd: str) -> bool:
    r = subprocess.run([py, "-m", "pytest", "-q", "tests/"], cwd=cwd,
                       capture_output=True, text=True, timeout=180, check=False)
    return r.returncode == 0


def verify_patch_local(
    repo_dir: str,
    exploit_rel: str,                       # e.g. "exploits/check_sqli.py" — exit 0 == exploit landed
    patch_fn: Callable[[Path], None],       # mutates the temp copy in place (applies the fix)
    python: Optional[str] = None,
    run_tests: bool = True,
    n: int = 3,
) -> LocalVerdict:
    py = python or sys.executable
    runs = []
    for _ in range(n):
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp) / "repo"
            shutil.copytree(repo_dir, dst, ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "app.db"))
            # 1) negative oracle baseline: exploit MUST succeed pre-patch
            if _run(py, exploit_rel, str(dst)) != 0:
                runs.append("NOT_REAL")
                continue
            # 2) apply the candidate patch in this same instance
            patch_fn(dst)
            # 3) exploit MUST now fail, AND tests MUST still pass
            exploit_gone = _run(py, exploit_rel, str(dst)) != 0
            tests_ok = (not run_tests) or _pytest_ok(py, str(dst))
            runs.append("FIXED" if (exploit_gone and tests_ok) else "OVERFIT_OR_BROKEN")
    verdict = runs[0] if len(set(runs)) == 1 else "FLAKY_REJECT"
    return LocalVerdict(verdict=verdict, runs=runs)
