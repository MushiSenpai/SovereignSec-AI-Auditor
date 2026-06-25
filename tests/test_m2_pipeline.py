"""M2 acceptance tests — the L1-L5 layers against the seeded fixture (PHASE1_DESIGN §3).

Run:  PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=. .venv/bin/python -m pytest tests/test_m2_pipeline.py -q
(semgrep + bandit must be on PATH for the L3 test.)
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
REPO = str(ROOT / "demo" / "seeded_repo")


# ---- L1: call graph + cross-file taint ----
def test_l1_call_graph_is_cross_file():
    from sscai.graph.resolver import RepoGraph
    g = RepoGraph(REPO).build()
    edges = {(u.split("::")[-1], v.split("::")[-1]) for u, v in g.g.edges()}
    # app.user -> services.user_lookup -> db.find_user, all in different files
    assert ("user@21", "user_lookup@9") in edges
    assert ("user_lookup@9", "find_user@29") in edges


def test_l1_taint_finds_exactly_the_crossfile_sqli():
    from sscai.graph.taint import analyze_repo
    paths = analyze_repo(REPO)
    assert len(paths) == 1                       # the SQLi only; no FP, XSS not a call-sink
    p = paths[0]
    assert p.cwe == "CWE-89"
    joined = " ".join(p.steps)
    assert "user" in joined and "user_lookup" in joined and "find_user" in joined
    assert "execute" in joined                   # reaches the sink


def test_l1_taint_does_not_flag_parameterized_query():
    from sscai.graph.taint import analyze_repo
    # find_user_safe is parameterized -> must never appear as a taint sink
    assert all("find_user_safe" not in s for p in analyze_repo(REPO) for s in p.steps)


# ---- L3: deterministic SAST ----
def test_l3_sast_finds_both_and_not_the_fp():
    from sscai.sast import scan
    cands = [c for c in scan(REPO) if "/tests/" not in c.path and "/exploits/" not in c.path]
    cwes = {(Path(c.path).name, c.cwe[0].split(":")[0]) for c in cands if c.cwe}
    assert ("app.py", "CWE-79") in cwes          # reflected XSS (single-file taint)
    assert ("db.py", "CWE-89") in cwes           # SQLi sink (Bandit)
    # the parameterized find_user_safe (lines ~43-51) must not be flagged
    assert not any(Path(c.path).name == "db.py" and 43 <= c.line <= 51 for c in cands)


# ---- L4: agent orchestration (mock backend, no GPU) ----
def test_l4_agent_loop_drives_tools_and_emits_findings():
    from sscai.agent import AuditContext, AuditAgent

    class Mock:
        def __init__(self): self.i = -1
        def act(self, messages):
            self.i += 1
            plan = [
                {"tool": "run_semgrep", "args": {}},
                {"tool": "run_taint", "args": {}},
                {"tool": "emit_finding", "args": {"finding": {"cwe": "CWE-89", "file": "db.py", "line": 37, "title": "SQLi"}}},
                {"tool": "finish", "args": {}},
            ]
            return plan[self.i]

    ctx = AuditContext(REPO)
    agent = AuditAgent(ctx)
    findings = agent.run(Mock(), "audit")
    tools_used = [t["action"]["tool"] for t in agent.trace]
    assert tools_used == ["run_semgrep", "run_taint", "emit_finding", "finish"]
    assert len(findings) == 1 and findings[0]["cwe"] == "CWE-89"


# ---- L5: dynamic patch oracle (local, no Docker) ----
def test_l5_oracle_confirms_sqli_patch():
    from sscai.validation.local_oracle import verify_patch_local
    VULN = ("    query = \"SELECT id, name, email FROM users WHERE name = '%s'\" % username\n"
            "    cur.execute(query)  # << SQLi sink (CWE-89)")
    FIX = "    cur.execute(\"SELECT id, name, email FROM users WHERE name = ?\", (username,))"

    def patch_fn(repo: Path):
        db = repo / "db.py"
        t = db.read_text()
        assert VULN in t
        db.write_text(t.replace(VULN, FIX))

    v = verify_patch_local(REPO, "exploits/check_sqli.py", patch_fn, n=3)
    assert v.verdict == "FIXED", v.runs


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
