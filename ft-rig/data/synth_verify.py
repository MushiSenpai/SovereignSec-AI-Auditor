"""VERIFY gate — the triple-lock (IMPL_SPEC §6). NON-NEGOTIABLE.

A generated cell enters the dataset only if ALL agree:
  (a) Semgrep (our rules) fires on the claimed CWE for the vulnerable code and is
      SILENT on the secure pair,
  (b) Bandit corroborates (numeric CWE id compare, None-guarded),
  (c) the runnable EXPLOIT triggers on the vulnerable version and FAILS on the secure
      one — this is the AUTHORITATIVE ground truth; SAST is corroboration.

Verified corrections baked in:
  - NO `--offline` flag / no $SEMGREP_RULES_CACHE_DIR (hallucinations) — reuse
    sscai.sast.runner (local rules + metrics/version-check off).
  - Bandit issue_cwe.id is a NUMBER; compare ints, guard None (absent pre-1.7.3).
  - Run the exploit under nsjail/bubblewrap --net=none (generated PoCs literally
    execute code — pickle etc.). Firejail --private does NOT chroot/chdir → prefer
    bubblewrap/nsjail with explicit bind + chdir. NEVER run on the host namespace.
"""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sscai.sast import run_bandit, run_semgrep


@dataclass
class Verdict:
    verified: bool
    semgrep_fires_on_vuln: bool
    semgrep_silent_on_secure: bool
    bandit_corroborates: bool
    exploit_triggers_on_vuln: bool
    exploit_fails_on_secure: bool


def _semgrep_hits_cwe(report: dict, cwe: str) -> bool:
    want = cwe.upper()
    for r in report.get("results", []):
        cwes = ((r.get("extra") or {}).get("metadata") or {}).get("cwe", []) or []
        if any(want in str(c).upper() for c in (cwes if isinstance(cwes, list) else [cwes])):
            return True
    return False


def _bandit_hits_cwe(report: dict, cwe: str) -> bool:
    try:
        want = int(cwe.split("-")[1])
    except (IndexError, ValueError):
        return False
    for r in report.get("results", []):
        cid = (r.get("issue_cwe") or {}).get("id")     # numeric, or None pre-1.7.3
        if cid is not None and int(cid) == want:
            return True
    return False


def _write(d: Path, name: str, code: str) -> str:
    p = d / name
    p.write_text(code)
    return str(p)


def run_exploit_sandboxed(workdir: str, exploit_file: str, timeout: int = 30) -> bool:
    """True == exploit asserted success. Run under nsjail/bubblewrap --net=none.

    [RUNTIME CHECK] pick the sandbox available on the box; assert on an explicit
    sentinel/exit, not a bare process code (a crashed-but-0 reads as a landed exploit).
    """
    cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", "/usr", "/usr",
           "--ro-bind", "/lib", "/lib", "--bind", workdir, workdir, "--chdir", workdir,
           "python3", exploit_file]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode == 0  # exploit's own asserts define success
    except FileNotFoundError:
        raise RuntimeError("bubblewrap (bwrap) not found — install a sandbox; do NOT run on host")
    except subprocess.TimeoutExpired:
        return False


def verify_cell(cell, rules_dir: str | None = None) -> Verdict:
    """Run the triple-lock on a generated Cell (synth_generate.Cell)."""
    p = cell.payload
    with tempfile.TemporaryDirectory() as vd, tempfile.TemporaryDirectory() as sd:
        vdir, sdir = Path(vd), Path(sd)
        _write(vdir, "app.py", p["vulnerable_code"])
        _write(sdir, "app.py", p["secure_code"])
        _write(vdir, "exploit.py", p["exploit"])
        _write(sdir, "exploit.py", p["exploit"])

        sg_v = run_semgrep(str(vdir), rules_dir) if rules_dir else run_semgrep(str(vdir))
        sg_s = run_semgrep(str(sdir), rules_dir) if rules_dir else run_semgrep(str(sdir))
        bd_v = run_bandit(str(vdir))

        v = Verdict(
            verified=False,
            semgrep_fires_on_vuln=_semgrep_hits_cwe(sg_v, cell.cwe),
            semgrep_silent_on_secure=not _semgrep_hits_cwe(sg_s, cell.cwe),
            bandit_corroborates=_bandit_hits_cwe(bd_v, cell.cwe),
            exploit_triggers_on_vuln=run_exploit_sandboxed(str(vdir), "exploit.py"),
            exploit_fails_on_secure=not run_exploit_sandboxed(str(sdir), "exploit.py"),
        )
        # Authoritative: the exploit. SAST (semgrep OR bandit) corroborates.
        v.verified = (
            v.exploit_triggers_on_vuln and v.exploit_fails_on_secure
            and (v.semgrep_fires_on_vuln or v.bandit_corroborates)
            and v.semgrep_silent_on_secure
        )
        return v
