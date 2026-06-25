"""Semantic resolution: build the real call/import graph with Jedi (IMPL_SPEC §1).

Tree-sitter gives syntax; it cannot resolve imports, aliases, or self.method()
dispatch. Jedi does. Wrap EVERY goto/get_references in try/except — Jedi raises
on partial/broken code. Prefer targeted goto(line,col) over Project.search to
bound cost on large repos.

Output: a networkx.DiGraph (call edges + import edges) + a symbol table,
serialized via nx.node_link_data() to node-link JSON for L2 / the agent.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import networkx as nx


@dataclass
class Symbol:
    name: str
    path: str
    line: int
    col: int
    kind: str  # "function" | "class" | "module" | ...

    @property
    def qid(self) -> str:
        return f"{self.path}::{self.name}@{self.line}"


class RepoGraph:
    """Call/import graph + symbol table for a Python repo."""

    def __init__(self, root: str):
        self.root = root
        self.g = nx.DiGraph()
        self.symbols: dict[str, Symbol] = {}

    # ---- construction (Jedi) -------------------------------------------------
    def _py_files(self) -> list[str]:
        out = []
        for p in Path(self.root).rglob("*.py"):
            sp = str(p)
            if "/.venv/" in sp or "/__pycache__/" in sp:
                continue
            out.append(sp)
        return out

    def _rel(self, path: str) -> str:
        try:
            return str(Path(path).resolve().relative_to(Path(self.root).resolve()))
        except ValueError:
            return path

    def build(self) -> "RepoGraph":
        """Populate `g` (call edges) and `symbols` over all .py files under root.

        Tree-sitter finds function defs + call sites (syntax); Jedi resolves each
        call to its definition across files (semantics). Edges carry the call-site
        line + name so L2/taint can join against them. (IMPL_SPEC §1.)
        """
        import jedi
        from .parser import PyParser

        parser = PyParser()
        proj = jedi.Project(self.root)
        # function ranges per file (to find the enclosing caller of each call site)
        ranges: dict[str, list[tuple[int, int, str]]] = {}

        for f in self._py_files():
            code = Path(f).read_text(errors="replace")
            rel = self._rel(f)
            fns = parser.functions(code)
            ranges[f] = [(fn.start_line, fn.end_line, fn.name) for fn in fns]
            for fn in fns:
                s = Symbol(name=fn.name, path=rel, line=fn.start_line, col=0, kind="function")
                self.symbols[s.qid] = s
                self.g.add_node(s.qid)
            self.g.add_node(f"{rel}::<module>@0")  # module-level caller bucket

        for f in self._py_files():
            code = Path(f).read_text(errors="replace")
            rel = self._rel(f)
            script = jedi.Script(code=code, path=f, project=proj)
            for cs in parser.call_sites(code):
                caller = self._enclosing(ranges[f], cs.line, rel)
                try:
                    defs = script.goto(cs.line, cs.col, follow_imports=True,
                                       follow_builtin_imports=False)
                except Exception:
                    continue
                for d in defs:
                    mp = str(d.module_path) if d.module_path else ""
                    if not mp.endswith(".py") or not d.line:
                        continue
                    if Path(self.root).resolve() not in Path(mp).resolve().parents:
                        continue  # keep in-repo edges only
                    callee = f"{self._rel(mp)}::{d.name}@{d.line}"
                    self.g.add_edge(caller, callee, callsite_line=cs.line, name=cs.name)
        return self

    @staticmethod
    def _enclosing(ranges: list[tuple[int, int, str]], line: int, rel: str) -> str:
        best = None
        for s, e, name in ranges:
            if s <= line <= e and (best is None or s > best[0]):
                best = (s, e, name)
        return f"{rel}::{best[2]}@{best[0]}" if best else f"{rel}::<module>@0"

    # ---- queries used by L2 / the agent -------------------------------------
    def callers(self, qid: str) -> list[str]:
        return list(self.g.predecessors(qid)) if qid in self.g else []

    def callees(self, qid: str) -> list[str]:
        return list(self.g.successors(qid)) if qid in self.g else []

    def definition(self, name: str) -> Optional[Symbol]:
        return next((s for s in self.symbols.values() if s.name == name), None)

    def to_json(self) -> dict:
        return nx.node_link_data(self.g)
