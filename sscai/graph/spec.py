"""Taint spec loader (IMPL_SPEC §1) — sources / sinks / sanitizers as data.

Mirrors Semgrep's source/sink/sanitizer keys so the same spec drives both our
custom Semgrep rules and the cross-file taint worklist (taint.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # yaml is a runtime dep; loader degrades to defaults
    yaml = None

DEFAULT = {
    # Coverage push: broadened toward OWASP. Matcher uses last-component / suffix.
    "sources": ["flask.request.args.get", "flask.request.form.get", "flask.request.values.get",
                "django.http.HttpRequest.GET", "fastapi.Request.query_params",
                "flask.request.get_json", "flask.request.cookies.get"],
    "sinks": ["cursor.execute", "subprocess.Popen", "os.system", "eval",   # injection / cmdi
              "pickle.loads", "marshal.loads", "yaml.load",                # deserialization (CWE-502)
              "builtins.open", "io.open", "send_file",                     # path traversal (CWE-22)
              "urllib.request.urlopen", "requests.get", "requests.post",   # SSRF (CWE-918)
              "httpx.get", "httpx.post"],
    "sanitizers": ["shlex.quote", "markupsafe.escape", "int", "django.db.models.Q",
                   "werkzeug.utils.secure_filename", "os.path.basename", "yaml.safe_load"],
}


@dataclass
class TaintSpec:
    sources: list[str] = field(default_factory=lambda: list(DEFAULT["sources"]))
    sinks: list[str] = field(default_factory=lambda: list(DEFAULT["sinks"]))
    sanitizers: list[str] = field(default_factory=lambda: list(DEFAULT["sanitizers"]))


def load_spec(path: str | None = None) -> TaintSpec:
    if not path or yaml is None or not Path(path).exists():
        return TaintSpec()
    data = yaml.safe_load(Path(path).read_text()) or {}
    return TaintSpec(
        sources=data.get("sources", DEFAULT["sources"]),
        sinks=data.get("sinks", DEFAULT["sinks"]),
        sanitizers=data.get("sanitizers", DEFAULT["sanitizers"]),
    )
