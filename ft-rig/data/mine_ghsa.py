"""Mine GitHub Security Advisories → fix commits → labeled Python pairs (IMPL_SPEC §0).

Source: a LOCAL clone of github/advisory-database (CC-BY-4.0, commercial-OK), pulled
once in the M0 setup phase (the advisory-database repo itself is JSON-only, so a
--depth 1 clone is fine). Layout: advisories/github-reviewed/YYYY/MM/GHSA-xxxx/GHSA-xxxx.json
Each file is OSV format. We keep PyPI advisories, harvest commit URLs, then use
PyDriller to extract before/after function bodies from the fix commit.

VERIFIED (grounding re-run 2026-06-24, IMPL_SPEC §"Component 1"):
  - CRITICAL: GHSA tags fix-commit links as references[].type == "WEB", NOT "FIX"
    (confirmed on CVE-2024-56374 / GHSA-qcgg-j2x8-h9g8 — all 4 Django fix commits
    are WEB). Harvest from BOTH FIX and WEB references or you find almost nothing.
  - The FRAMEWORK repos you clone for PyDriller MUST be FULL-DEPTH (PyDriller diffs
    a commit against its PARENT; a --depth 1 framework clone yields empty pairs).
    `git fetch --unshallow` if needed.
  - CWE from database_specific.cwe_ids[]; CVE join key from aliases[] (CVE-*/PYSEC-*).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

_COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")


@dataclass
class Advisory:
    ghsa_id: str
    cve: Optional[str]
    cwes: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)   # PyPI package names
    fix_commits: list[tuple[str, str, str]] = field(default_factory=list)  # (owner, repo, sha)


def iter_pypi_advisories(advisory_db_dir: str) -> Iterator[Advisory]:
    """Walk a local advisory-database clone, yield PyPI advisories with fix commits."""
    for path in Path(advisory_db_dir).rglob("GHSA-*.json"):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        affected = data.get("affected", []) or []
        pkgs = [a["package"]["name"] for a in affected
                if (a.get("package") or {}).get("ecosystem") == "PyPI"]
        if not pkgs:
            continue
        fixes = []
        seen: set[tuple[str, str, str]] = set()
        for ref in data.get("references", []) or []:
            # VERIFIED: harvest from BOTH FIX and WEB — GHSA tags fix commits as WEB.
            if ref.get("type") in ("FIX", "WEB"):
                m = _COMMIT_RE.search(ref.get("url", ""))
                if m:
                    key = (m.group(1), m.group(2).removesuffix(".git"), m.group(3))
                    if key not in seen:
                        seen.add(key)
                        fixes.append(key)
        if not fixes:
            continue
        cwes = (data.get("database_specific") or {}).get("cwe_ids", []) or []
        cve = next((a for a in data.get("aliases", []) if a.startswith("CVE-")), None)
        yield Advisory(ghsa_id=data.get("id", path.stem), cve=cve, cwes=cwes,
                       packages=pkgs, fix_commits=fixes)


@dataclass
class MinedPair:
    ghsa_id: str
    cve: Optional[str]
    cwe: Optional[str]
    repo: str
    fix_sha: str
    file: str
    func: str
    vulnerable: str
    patched: str


def extract_fix_pairs(adv: Advisory, local_repo_path: str) -> list[MinedPair]:
    """Use PyDriller to pull before/after of each Python method the fix touched.

    `local_repo_path` is a clone of owner/repo (pulled in M0). PyDriller API:
      Repository(path, single=sha).traverse_commits() -> commit.modified_files
      mf.changed_methods / mf.methods_before ; source via mf.source_code_before/source_code.
    """
    from pydriller import Repository  # rig dep; import locally

    pairs: list[MinedPair] = []
    cwe = adv.cwes[0] if adv.cwes else None
    for _, _, sha in adv.fix_commits:
        for commit in Repository(local_repo_path, single=sha).traverse_commits():
            for mf in commit.modified_files:
                if not (mf.filename or "").endswith(".py"):
                    continue
                before_by_name = {m.name: m for m in (mf.methods_before or [])}
                for m in (mf.changed_methods or []):
                    b = before_by_name.get(m.name)
                    if not b:
                        continue  # newly added function — no "vulnerable" precursor
                    pairs.append(MinedPair(
                        ghsa_id=adv.ghsa_id, cve=adv.cve, cwe=cwe,
                        repo=f"{mf.new_path or mf.old_path}", fix_sha=sha,
                        file=mf.filename, func=m.name,
                        vulnerable=_slice(mf.source_code_before, b.start_line, b.end_line),
                        patched=_slice(mf.source_code, m.start_line, m.end_line),
                    ))
    return pairs


def _slice(source: Optional[str], start: Optional[int], end: Optional[int]) -> str:
    if not source or not start or not end:
        return ""
    return "\n".join(source.splitlines()[start - 1:end])
