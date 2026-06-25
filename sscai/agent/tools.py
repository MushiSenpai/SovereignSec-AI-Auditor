"""Agent tool definitions + dispatch (IMPL_SPEC §4).

Tools wrap the deterministic layers. Context discipline (IMPL_SPEC §4): always
line-window read_file, truncate observations to a byte budget, compress old steps
into a rolling summary — long repos blow the context otherwise.
"""
from __future__ import annotations

OBS_BUDGET = 4000  # bytes per tool observation returned to the model

# OpenAI tools array (JSON-Schema params) passed to vLLM's chat endpoint.
TOOLS = [
    {"type": "function", "function": {
        "name": "read_file", "description": "Read a line-windowed slice of a file.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "start": {"type": "integer"}, "end": {"type": "integer"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "ast_query", "description": "L1: callers/callees/definition for a symbol.",
        "parameters": {"type": "object", "properties": {
            "symbol": {"type": "string"},
            "kind": {"type": "string", "enum": ["callers", "callees", "definition"]}},
            "required": ["symbol", "kind"]}}},
    {"type": "function", "function": {
        "name": "grep", "description": "Regex search across the repo.",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}},
                       "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "run_semgrep", "description": "L3: run our SAST rules, return candidates.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}},
                       "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "run_tests", "description": "Run the repo test suite.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "propose_patch", "description": "Propose a unified-diff patch.",
        "parameters": {"type": "object", "properties": {"diff": {"type": "string"}},
                       "required": ["diff"]}}},
    {"type": "function", "function": {
        "name": "validate", "description": "L5: run the dynamic oracle on a finding+patch.",
        "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}},
                       "required": ["finding_id"]}}},
    {"type": "function", "function": {
        "name": "emit_finding", "description": "Record a confirmed finding (FINDING_SCHEMA).",
        "parameters": {"type": "object", "properties": {"finding": {"type": "object"}},
                       "required": ["finding"]}}},
    {"type": "function", "function": {
        "name": "finish", "description": "End the audit.",
        "parameters": {"type": "object", "properties": {"summary": {"type": "string"}}}}},
]


def dispatch(name: str, args: dict, ctx) -> str:
    """Route a tool call to a deterministic layer against the AuditContext `ctx`.
    Returns an observation string (caller truncates to OBS_BUDGET)."""
    try:
        if name == "run_semgrep":
            cs = ctx.candidates()
            return f"{len(cs)} SAST candidate(s):\n" + "\n".join(
                f"- [{c.tool}] {c.path}:{c.line} {c.cwe} (rule {c.rule_id}, sev {c.severity})" for c in cs
            )
        if name == "run_taint":
            tp = ctx.taint()
            out = [f"{len(tp)} cross-file taint path(s):"]
            for p in tp:
                out.append(f"- [{p.cwe}] " + "  ".join(p.steps))
            return "\n".join(out)
        if name == "ast_query":
            g, sym, kind = ctx.graph(), args.get("symbol", ""), args.get("kind", "definition")
            node = next((q for q in g.g.nodes if f"::{sym}@" in q), None)
            if kind == "callers":
                return f"callers of {sym}: {g.callers(node) if node else []}"
            if kind == "callees":
                return f"callees of {sym}: {g.callees(node) if node else []}"
            d = g.definition(sym)
            return f"definition: {d.qid if d else 'not found'}"
        if name == "read_file":
            return ctx.read_window(args["path"], args.get("start", 1), args.get("end"))
        if name == "grep":
            return _grep(ctx.root, args.get("pattern", ""))
        if name == "emit_finding":
            f = args.get("finding", args)
            ctx.findings.append(f)
            return f"recorded finding {f.get('cwe')} @ {f.get('file')}:{f.get('line')}"
        if name == "validate":
            return ("validate: provide a patch + exploit oracle; use "
                    "sscai.validation.local_oracle.verify_patch_local (L5)")
        if name == "finish":
            return "audit complete"
        return f"unknown tool: {name}"
    except Exception as e:  # tools must never crash the loop — return the error as obs
        return f"tool {name} error: {e!r}"


def _grep(root: str, pattern: str) -> str:
    import re
    from pathlib import Path
    rx = re.compile(pattern)
    hits = []
    for p in Path(root).rglob("*.py"):
        if "/.venv/" in str(p):
            continue
        for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if rx.search(line):
                hits.append(f"{p.name}:{i}: {line.strip()[:120]}")
    return "\n".join(hits[:50]) or "no matches"
