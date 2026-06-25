"""L1 — repo graph: tree-sitter parse (syntax) + Jedi resolution (semantics) +
custom inter-procedural taint worklist. All offline, all MIT/BSD.

IMPL_SPEC §1: tree-sitter is syntax-only — NEVER build the call graph from
tree-sitter captures; use Jedi for name/import/dispatch resolution.
"""
from .parser import PyParser, node_text

__all__ = ["PyParser", "node_text"]
