"""Agentic auditor (M4+) — trace -> hypothesize -> validate, not one-shot file audit.

The one-shot "system" config just dumps SAST lines at the LLM. This does the real loop:
  1. TRACE     — run cross-function taint (L1) + SAST (L3) over the module.
  2. CONFIRM   — taint source->sink paths are deterministically confirmed by the engine
                 (no LLM guess needed) and localized to the sink's function.
  3. HYPOTHESIZE+VALIDATE — for each remaining SAST alert, the LLM triages the specific
                 function ("real, or sanitized/parameterized?"); only confirmed alerts are kept.
This raises RECALL (taint finds cross-function flows the LLM misses) and PRECISION (triage
drops decoy/sanitized SAST false positives) over both bare and one-shot.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sscai.graph.parser import PyParser


def _enclosing(funcs, line: int):
    best = None
    for f in funcs:  # FuncDef(start_line, end_line, name)
        if f.start_line <= line <= f.end_line and (best is None or f.start_line > best.start_line):
            best = f
    return best


def _sink_function(path) -> str | None:
    # taint sink desc looks like "mod.py::find_user: cur.execute(...) [sink] @L37"
    s = getattr(path, "sink", "") or ""
    if "::" in s:
        return s.split("::", 1)[1].split(":")[0].split("(")[0].strip()
    return None


def _func_code(code: str, fdef) -> str:
    lines = code.splitlines()
    return "\n".join(lines[fdef.start_line - 1:fdef.end_line])[:1200]


def agentic_audit(backend, code: str) -> dict:
    """Returns {confirmed: {function: cwe}, steps: [...]} for a single module."""
    from sscai.graph.taint import analyze_repo
    from sscai.sast import scan

    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "mod.py").write_text(code)
        try:
            sast = scan(d)
        except Exception:
            sast = []
        try:
            taint = analyze_repo(d)
        except Exception:
            taint = []

    funcs = PyParser().functions(code)
    confirmed: dict[str, str] = {}
    steps: list[str] = []

    # 2. CONFIRM — taint paths are engine-validated source->sink flows.
    for p in taint:
        fn = _sink_function(p)
        if fn:
            confirmed[fn] = p.cwe
            steps.append(f"TRACE: taint confirmed {p.cwe} in `{fn}` (source->sink path)")

    # 3. HYPOTHESIZE + VALIDATE — LLM triages each remaining SAST alert at its function.
    for c in sast:
        fdef = _enclosing(funcs, c.line)
        if not fdef or fdef.name in confirmed:
            continue
        cwe = c.cwe[0].split(":")[0] if c.cwe else "?"
        verdict = backend.complete([
            {"role": "system", "content":
             "You triage one static-analysis alert. Answer exactly REAL if user-controlled input "
             "reaches a dangerous sink unsanitized, or SAFE if it is parameterized / escaped / "
             "validated / not user-controlled. One word only."},
            {"role": "user", "content":
             f"Alert: {cwe} at line {c.line} in function `{fdef.name}`:\n"
             f"```python\n{_func_code(code, fdef)}\n```\nREAL or SAFE?"}], 8)
        if "real" in verdict.strip().lower():
            confirmed[fdef.name] = cwe
            steps.append(f"VALIDATE: triage confirmed {cwe} in `{fdef.name}`")
        else:
            steps.append(f"VALIDATE: dropped alert in `{fdef.name}` (judged safe)")

    return {"confirmed": confirmed, "steps": steps}


def format_findings(result: dict) -> str:
    c = result.get("confirmed", {})
    if not c:
        return "No finding."
    prov = result.get("provenance", {})
    return "Confirmed vulnerabilities:\n" + "\n".join(
        f"- function `{fn}`: {cwe}" + (f" [{prov[fn]}]" if fn in prov else "")
        for fn, cwe in c.items())


def structured_llm_findings(backend, code: str) -> list:
    """LLM breadth audit -> [(function, cwe)] across ALL classes (no SAST hints — those
    anchor the model and hurt; BLOG E9). Independent, then merged with the system."""
    import json
    import re
    out = backend.complete([
        {"role": "system", "content":
         'List EVERY function in this file that contains a security vulnerability, as JSON: '
         '{"findings":[{"function":"name","cwe":"CWE-XX"}]}. Empty findings if none.'},
        {"role": "user", "content": f"```python\n{code}\n```"}], 320)
    m = re.search(r"\{.*\}", out or "", re.S)
    try:
        obj = json.loads(m.group(0)) if m else {}
    except json.JSONDecodeError:
        return []
    return [(f.get("function"), f.get("cwe", "?")) for f in obj.get("findings", [])
            if isinstance(f, dict) and f.get("function")]


def hybrid_audit(backend, code: str, agentic_result: dict | None = None) -> dict:
    """Merge LLM breadth + system precision (NOT SAST->LLM). The LLM audits independently
    (breadth across all classes); the system confirms independently (precise, cross-file);
    we union them. System-confirmed findings carry deterministic taint/SAST proof and
    override the LLM's tag for the same function. (The architecture BLOG E9 pointed to.)"""
    ag = agentic_result if agentic_result is not None else agentic_audit(backend, code)
    merged: dict[str, str] = {}
    prov: dict[str, str] = {}
    for fn, cwe in structured_llm_findings(backend, code):
        merged[fn] = cwe
        prov[fn] = "llm"
    for fn, cwe in ag.get("confirmed", {}).items():        # system overrides -> high confidence
        merged[fn] = cwe
        prov[fn] = "system-confirmed"
    return {"confirmed": merged, "provenance": prov}
