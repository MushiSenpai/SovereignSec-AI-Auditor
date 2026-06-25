"""Label hygiene (IMPL_SPEC §0; PLAN §7.1) — the difference between 68% and 3% F1.

Three jobs, all mandatory:
  1. untangle tangled commits (a CVE-fix commit bundles refactors/tests → don't
     label every touched function vulnerable),
  2. de-duplicate (MinHashLSH),
  3. chronological split (NEVER random — random splits leak near-dups/future code).
"""
from __future__ import annotations

import re
from typing import Any, Iterable

_TEST_RE = re.compile(r"(^|/)(test_|tests?/|conftest\.py|.*_test\.py$)")
_WS_RE = re.compile(r"\s+")


def is_security_relevant(pair: dict) -> bool:
    """Heuristic untangle: drop test/doc/format-only changes from fix commits."""
    f = pair.get("file", "") or pair.get("filename", "")
    if _TEST_RE.search(f) or f.endswith((".md", ".rst", ".txt")):
        return False
    vuln = _WS_RE.sub(" ", pair.get("vulnerable", "")).strip()
    patched = _WS_RE.sub(" ", pair.get("patched", "")).strip()
    return bool(vuln) and bool(patched) and vuln != patched  # not whitespace-only


def untangle(pairs: Iterable[dict]) -> list[dict]:
    return [p for p in pairs if is_security_relevant(p)]


def _norm_tokens(code: str) -> list[str]:
    return re.findall(r"[A-Za-z_]\w+|\S", code or "")


def dedup(pairs: list[dict], threshold: float = 0.85, num_perm: int = 128) -> list[dict]:
    """MinHashLSH near-dup removal over the vulnerable-code token stream."""
    try:
        from datasketch import MinHash, MinHashLSH
    except ImportError:
        return pairs  # rig dep; no-op if absent (flagged in setup)
    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    kept: list[dict] = []
    for i, p in enumerate(pairs):
        mh = MinHash(num_perm=num_perm)
        for tok in _norm_tokens(p.get("vulnerable", "")):
            mh.update(tok.encode())
        if lsh.query(mh):           # a near-duplicate already kept
            continue
        lsh.insert(f"k{i}", mh)
        kept.append(p)
    return kept


def chronological_split(records: list[dict], date_key: str = "date",
                        holdout_frac: float = 0.1) -> tuple[list[dict], list[dict]]:
    """Sort by date; newest `holdout_frac` is eval (no future leakage into train)."""
    ordered = sorted(records, key=lambda r: r.get(date_key, ""))
    cut = int(len(ordered) * (1 - holdout_frac))
    return ordered[:cut], ordered[cut:]
