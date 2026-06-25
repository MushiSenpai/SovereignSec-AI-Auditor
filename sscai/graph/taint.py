"""Custom inter-procedural taint (IMPL_SPEC §1) — the part we build.

Semgrep CE taint is single-file. Cross-file flows (the seeded demo's
app -> services -> db SQLi) need this. Summary-based worklist:
  1. intra-proc: per function, which PARAMS reach a sink (arg0-focus + format
     propagation), considering callee summaries;
  2. inter-proc: propagate to a fixpoint over the call graph (resolved by name);
  3. paths: from a SOURCE-tainted var, trace through callees to the sink.

Precision note: sinks are FOCUSED on their first positional arg (the query string
for execute, the command for system, ...). That's why `cur.execute(sql, (user,))`
(parameterized — user is arg1, sql literal is arg0) is correctly NOT flagged, while
`cur.execute(tainted_query)` is. This is the focus-metavariable idea in code.

Honest scope: field-sensitivity-light; name-based callee resolution; misses
reflection / dynamic dispatch / response-sink XSS. Not CodeQL. The RepoGraph (Jedi)
is the robust resolver for production cross-file ambiguity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Parser
from .parser import PY, node_text
from .spec import TaintSpec, load_spec


@dataclass
class TaintPath:
    source: str
    sink: str
    steps: list[str]
    cwe: str = "CWE-89"


# Map a sink's last component to its vulnerability class (was hardcoded CWE-89 — bug).
_SINK_CWE = {
    "execute": "CWE-89", "executescript": "CWE-89", "raw": "CWE-89", "extra": "CWE-89",
    "system": "CWE-78", "Popen": "CWE-78", "popen": "CWE-78", "run": "CWE-78",
    "call": "CWE-78", "check_output": "CWE-78",
    "eval": "CWE-95", "exec": "CWE-95",
    "loads": "CWE-502", "load": "CWE-502",
    "open": "CWE-22", "send_file": "CWE-22", "send_from_directory": "CWE-22",
    "urlopen": "CWE-918", "Request": "CWE-918", "get": "CWE-918", "post": "CWE-918",
}


def _sink_cwe(sink_desc: str) -> str:
    import re
    m = re.search(r": ([\w.]+)\(\.\.\.\) \[sink\]", sink_desc or "")
    if not m:
        return "CWE-89"
    return _SINK_CWE.get(m.group(1).split(".")[-1], "CWE-89")


@dataclass
class _Call:
    line: int
    dotted: str
    args: list[set]          # vars referenced per positional arg
    is_sink: bool
    is_source: bool


@dataclass
class _Func:
    name: str
    path: str
    start: int
    params: list[str]
    assigns: list[tuple]     # (target, rhs_vars:set, has_source:bool, sanitized:bool)
    calls: list[_Call]
    sink_lines: dict = field(default_factory=dict)  # focus-var -> line (direct sinks)


def _idents(node, src: bytes) -> set:
    out = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "identifier":
            out.add(node_text(n, src))
        # don't descend into the attribute's attribute name / call func name handled by caller
        stack.extend(n.children)
    return out


def _dotted(func_node, src: bytes) -> str:
    return node_text(func_node, src) if func_node else ""


class TaintAnalyzer:
    def __init__(self, root: str, spec: TaintSpec | None = None):
        self.root = root
        self.spec = spec or load_spec()
        # Match on the last TWO components (e.g. "requests.get", "request.get_json") so
        # ambiguous tails like ".get" don't conflate a source (args.get) with a sink
        # (requests.get). Distinctive single tails still match alone.
        self._sink_last2 = {".".join(s.split(".")[-2:]) for s in self.spec.sinks}
        self._sink_last1 = {"execute", "executescript", "system", "eval", "exec",
                            "loads", "urlopen", "Popen", "popen", "open"}
        self._src_last2 = {".".join(s.split(".")[-2:]) for s in self.spec.sources}
        self._sanitizers = {s.split(".")[-1] for s in self.spec.sanitizers}
        self._parser = Parser(PY)
        self.funcs: list[_Func] = []
        self.by_name: dict[str, list[_Func]] = {}

    # ---- matchers ----
    def _is_source(self, dotted: str) -> bool:
        p = dotted.split(".")
        return ".".join(p[-2:]) in self._src_last2 or dotted.endswith(".query_params")

    def _is_sink(self, dotted: str) -> bool:
        p = dotted.split(".")
        return ".".join(p[-2:]) in self._sink_last2 or p[-1] in self._sink_last1

    def _is_sanitizer(self, dotted: str) -> bool:
        return dotted.split(".")[-1] in self._sanitizers

    # ---- extraction ----
    def _py_files(self) -> list[str]:
        return [str(p) for p in Path(self.root).rglob("*.py")
                if "/.venv/" not in str(p) and "/__pycache__/" not in str(p)]

    def _arg_sets(self, call_node, src: bytes) -> list[set]:
        arglist = call_node.child_by_field_name("arguments")
        args = []
        if arglist:
            for ch in arglist.named_children:
                args.append(_idents(ch, src))
        return args

    def _extract_func(self, fn_node, src: bytes, rel: str) -> _Func:
        name_node = fn_node.child_by_field_name("name")
        params_node = fn_node.child_by_field_name("parameters")
        params = []
        if params_node:
            for ch in params_node.named_children:
                ident = ch if ch.type == "identifier" else ch.child_by_field_name("name")
                if ident is not None and ident.type == "identifier":
                    params.append(node_text(ident, src))
        f = _Func(name=node_text(name_node, src) if name_node else "<anon>",
                  path=rel, start=fn_node.start_point[0] + 1, params=params,
                  assigns=[], calls=[])
        body = fn_node.child_by_field_name("body")
        if body:
            self._walk_body(body, src, f)
        return f

    def _walk_body(self, node, src: bytes, f: _Func):
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "function_definition":
                continue  # nested function handled separately
            if n.type == "assignment":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is not None and left.type == "identifier" and right is not None:
                    has_source = self._expr_has_source(right, src)
                    sanitized = (right.type == "call" and
                                 self._is_sanitizer(_dotted(right.child_by_field_name("function"), src)))
                    f.assigns.append((node_text(left, src), _idents(right, src), has_source, sanitized))
            elif n.type == "call":
                fnode = n.child_by_field_name("function")
                dotted = _dotted(fnode, src)
                args = self._arg_sets(n, src)
                f.calls.append(_Call(line=n.start_point[0] + 1, dotted=dotted, args=args,
                                     is_sink=self._is_sink(dotted), is_source=self._is_source(dotted)))
            stack.extend(n.children)

    def _expr_has_source(self, node, src: bytes) -> bool:
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "call" and self._is_source(_dotted(n.child_by_field_name("function"), src)):
                return True
            stack.extend(n.children)
        return False

    def build(self) -> "TaintAnalyzer":
        for fp in self._py_files():
            src = Path(fp).read_bytes()
            rel = self._relpath(fp)
            tree = self._parser.parse(src)
            stack = [tree.root_node]
            while stack:
                n = stack.pop()
                if n.type == "function_definition":
                    f = self._extract_func(n, src, rel)
                    self.funcs.append(f)
                    self.by_name.setdefault(f.name, []).append(f)
                stack.extend(n.children)
        return self

    def _relpath(self, p: str) -> str:
        try:
            return str(Path(p).resolve().relative_to(Path(self.root).resolve()))
        except ValueError:
            return p

    # ---- intra-proc taint given a seed set; returns (reached_sink, sink_desc, callee_hops) ----
    def _propagate(self, f: _Func, tainted: set, summaries: dict):
        t = set(tainted)
        changed = True
        while changed:
            changed = False
            for target, rhs_vars, has_source, sanitized in f.assigns:
                if sanitized:
                    continue
                if (rhs_vars & t or has_source) and target not in t:
                    t.add(target); changed = True
        # direct sink: focus arg0
        for c in f.calls:
            if c.is_sink and c.args and (c.args[0] & t):
                return True, f"{f.path}::{f.name}: {c.dotted}(...) [sink] @L{c.line}", None
        # cross-file: tainted arg into callee whose summary says that param reaches a sink
        for c in f.calls:
            callee = self._resolve(c.dotted, len(c.args))
            if not callee:
                continue
            reaches = summaries.get(id(callee), set())
            for i, argvars in enumerate(c.args):
                if (argvars & t) and i in reaches:
                    return True, None, (c, callee, i)
        return False, None, None

    def _resolve(self, dotted: str, argc: int):
        cands = self.by_name.get(dotted.split(".")[-1], [])
        for fn in cands:
            if len(fn.params) >= 1:  # has at least one param to receive taint
                return fn
        return cands[0] if cands else None

    # ---- summaries: which param indices reach a sink (fixpoint) ----
    def _summaries(self) -> dict:
        summ: dict = {id(f): set() for f in self.funcs}
        changed = True
        while changed:
            changed = False
            for f in self.funcs:
                for i, p in enumerate(f.params):
                    if i in summ[id(f)]:
                        continue
                    reached, _, _ = self._propagate(f, {p}, summ)
                    if reached:
                        summ[id(f)].add(i); changed = True
        return summ

    # ---- public: find source->sink paths ----
    def analyze(self) -> list[TaintPath]:
        summ = self._summaries()
        paths: list[TaintPath] = []
        for f in self.funcs:
            # seed: vars assigned from a source
            seed = {tgt for tgt, _, has_src, san in f.assigns if has_src and not san}
            if not seed:
                continue
            steps, sink_desc = self._trace(f, seed, summ, [])
            if sink_desc:
                src_desc = f"{f.path}::{f.name}: tainted source @L{f.start}"
                paths.append(TaintPath(source=src_desc, sink=sink_desc,
                                       steps=[src_desc] + steps, cwe=_sink_cwe(sink_desc)))
        return paths

    def _trace(self, f: _Func, tainted: set, summ: dict, acc: list, depth: int = 0):
        if depth > 8:
            return acc, None
        reached, sink_desc, hop = self._propagate(f, tainted, summ)
        if sink_desc:
            return acc + [sink_desc], sink_desc
        if hop:
            call, callee, i = hop
            step = f"{f.path}::{f.name} -> {callee.path}::{callee.name}() [arg {i}] @L{call.line}"
            param = callee.params[i] if i < len(callee.params) else (callee.params[0] if callee.params else "")
            return self._trace(callee, {param}, summ, acc + [step], depth + 1)
        return acc, None


def analyze_repo(root: str, spec: TaintSpec | None = None) -> list[TaintPath]:
    return TaintAnalyzer(root, spec).build().analyze()


# Back-compat stubs referenced elsewhere (now implemented via TaintAnalyzer).
def function_summaries(repo_graph, spec):  # pragma: no cover
    raise NotImplementedError("use TaintAnalyzer(root, spec).build()._summaries()")


def propagate(repo_graph, summaries, spec):  # pragma: no cover
    raise NotImplementedError("use analyze_repo(root, spec)")
