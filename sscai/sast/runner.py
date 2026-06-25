"""Run Semgrep CE + Bandit fully offline and return normalized Candidates.

IMPL_SPEC §2 corrections baked in:
  - NO `--offline` flag and NO $SEMGREP_RULES_CACHE_DIR (both are hallucinations).
    Offline = local --config dir + metrics/version-check off + OS-level egress block.
  - Belt-and-suspenders version-check kill: flag AND env var (issue #9805 fired
    despite the flag). Real guarantee is running under `firejail --net=none`.
  - check=False: semgrep/bandit exit 1 means FINDINGS FOUND, not an error (2+ = error).
  - Pin semgrep exactly and re-verify JSON shape on bumps (gating shipped silently).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .normalize import Candidate, from_bandit, from_semgrep

# Default to our shipped rules dir (our rules ONLY — never `p/...` or `auto`).
DEFAULT_RULES_DIR = str(Path(__file__).parent / "rules")

_OFFLINE_ENV = {**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0",
                "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}


def run_semgrep(target: str, rules_dir: str = DEFAULT_RULES_DIR, timeout: int = 120) -> dict:
    proc = subprocess.run(
        ["semgrep", "scan", "--config", rules_dir,
         "--json", "--metrics=off", "--disable-version-check",
         "--quiet", "--no-git-ignore", "--timeout", "60",
         "--max-target-bytes", "2000000", target],
        capture_output=True, text=True, env=_OFFLINE_ENV, timeout=timeout, check=False,
    )
    if proc.returncode >= 2:
        raise RuntimeError(f"semgrep error (exit {proc.returncode}): {proc.stderr[:500]}")
    return json.loads(proc.stdout or '{"results": [], "errors": []}')


def run_bandit(target: str, timeout: int = 120) -> dict:
    # -ll => MEDIUM+ severity. We do NOT pass -ii: Bandit rates SQL injection (B608)
    # at LOW confidence, so a medium-confidence floor silently drops real SQLi. We
    # keep all confidences and let L4/taint triage (confidence is fed to L4 as a prior).
    # (Empirically verified on the seeded repo, 2026-06-24 — see BLOG_QUEUE.md.)
    proc = subprocess.run(
        ["bandit", "-r", target, "-f", "json", "-ll", "-q"],
        capture_output=True, text=True, env=_OFFLINE_ENV, timeout=timeout, check=False,
    )
    if proc.returncode >= 2 and not proc.stdout:
        raise RuntimeError(f"bandit error (exit {proc.returncode}): {proc.stderr[:500]}")
    return json.loads(proc.stdout or '{"results": []}')


def scan(target: str, rules_dir: str = DEFAULT_RULES_DIR,
         use_bandit: bool = True) -> list[Candidate]:
    """Run both tools, return the combined candidate list (dedup by fingerprint)."""
    cands: dict[str, Candidate] = {}
    for r in run_semgrep(target, rules_dir).get("results", []):
        c = from_semgrep(r)
        cands[c.fingerprint] = c
    if use_bandit:
        for r in run_bandit(target).get("results", []):
            c = from_bandit(r)
            cands.setdefault(c.fingerprint, c)
    return list(cands.values())
