"""Shared audit context — lazily ties L1/L2/L3/L5 together for the agent (L4).

The agent's tools (tools.dispatch) read/write this. Layers are built on first use
so a cheap run (e.g. SAST-only) doesn't pay for the graph.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AuditContext:
    root: str
    findings: list = field(default_factory=list)   # list[dict] (FINDING_SCHEMA shape)
    _graph: object = None
    _taint: Optional[list] = None
    _cands: Optional[list] = None

    def graph(self):
        if self._graph is None:
            from sscai.graph.resolver import RepoGraph
            self._graph = RepoGraph(self.root).build()
        return self._graph

    def taint(self):
        if self._taint is None:
            from sscai.graph.taint import analyze_repo
            self._taint = analyze_repo(self.root)
        return self._taint

    def candidates(self):
        if self._cands is None:
            from sscai.sast import scan
            self._cands = [c for c in scan(self.root)
                           if "/tests/" not in c.path and "/exploits/" not in c.path]
        return self._cands

    def read_window(self, rel: str, start: int = 1, end: Optional[int] = None) -> str:
        p = Path(self.root) / rel
        if not p.exists():
            p = Path(rel)
        lines = p.read_text(errors="replace").splitlines()
        end = end or min(len(lines), start + 60)
        return "\n".join(f"{i}: {lines[i-1]}" for i in range(max(1, start), min(len(lines), end) + 1))
