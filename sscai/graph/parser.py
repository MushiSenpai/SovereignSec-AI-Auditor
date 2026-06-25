"""Tree-sitter Python parsing (IMPL_SPEC §1 — verified 0.25 API).

CRITICAL verified API (breaking change since tree-sitter 0.23, current in 0.25):
  - Language(tspython.language())  -- language() returns a PyCapsule; this is the
    ONLY accepted form. The old Language('build/py.so','python') is removed.
  - Parser(PY)                     -- language goes in the constructor.
  - QueryCursor(Query(PY, SRC))    -- lang.query()/Query.captures() are removed;
    cur.captures(root) -> dict[str, list[Node]] in 0.25.
  - source MUST be bytes: code.encode("utf8").

Air-gap: use the per-language wheel `tree-sitter-python` (precompiled, offline).
Do NOT use tree_sitter_languages (unmaintained) or tree-sitter-language-pack
(fetches grammars on first use -> egress). Pin both wheels together (ABI).
"""
from __future__ import annotations

from dataclasses import dataclass

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_python as tspython

PY = Language(tspython.language())

# Captures function defs, call sites, and string-format expressions (taint seeds).
_QUERY = """
(function_definition name: (identifier) @func.name) @func.def
(call function: [ (identifier) @call.name
                  (attribute attribute: (identifier) @call.attr) ]) @call.site
(call function: (attribute object: (identifier) @recv)) @call.recv
"""


def node_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf8", "replace")


@dataclass
class FuncDef:
    name: str
    start_line: int      # 1-based
    end_line: int


@dataclass
class CallSite:
    name: str            # callee name or attribute (e.g. "execute")
    receiver: str | None # e.g. "cur" in cur.execute(...)
    line: int            # 1-based
    col: int = 0         # 0-based column of the name token (for Jedi goto)


class PyParser:
    """Parse one Python file into its function defs + call sites (syntax only)."""

    def __init__(self):
        self._parser = Parser(PY)
        self._cursor = QueryCursor(Query(PY, _QUERY))

    def parse(self, code: str):
        return self._parser.parse(code.encode("utf8"))

    def functions(self, code: str) -> list[FuncDef]:
        src = code.encode("utf8")
        tree = self.parse(code)
        caps = self._cursor.captures(tree.root_node)  # dict[str, list[Node]]
        out: list[FuncDef] = []
        for defn in caps.get("func.def", []):
            name_node = defn.child_by_field_name("name")
            name = node_text(name_node, src) if name_node else "<lambda>"
            out.append(FuncDef(name=name,
                               start_line=defn.start_point[0] + 1,
                               end_line=defn.end_point[0] + 1))
        return out

    def call_sites(self, code: str) -> list[CallSite]:
        src = code.encode("utf8")
        tree = self.parse(code)
        caps = self._cursor.captures(tree.root_node)
        sites: list[CallSite] = []
        for n in caps.get("call.attr", []) + caps.get("call.name", []):
            recv = None
            parent = n.parent  # attribute node, if any
            if parent is not None and parent.type == "attribute":
                obj = parent.child_by_field_name("object")
                if obj is not None:
                    recv = node_text(obj, src)
            sites.append(CallSite(name=node_text(n, src), receiver=recv,
                                  line=n.start_point[0] + 1, col=n.start_point[1]))
        return sites
