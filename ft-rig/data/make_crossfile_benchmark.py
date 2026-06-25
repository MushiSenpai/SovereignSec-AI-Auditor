#!/usr/bin/env python3
"""Cross-file benchmark — the headline the single-file haystack can't show.

Each app is a 3-layer package where the vulnerability flows ACROSS files:
  routes.py (user input)  ->  services.py (passthrough helper)  ->  sink_layer (dangerous call)
A per-file LLM audit is blind: auditing the sink file alone, it can't tell the param is
user-controlled (the source is in another file). Our cross-file taint engine follows the flow.

Writes app dirs under ft-rig/data/out/crossfile/<app>/ + a manifest jsonl.
Run: .venv/bin/python ft-rig/data/make_crossfile_benchmark.py
"""
from __future__ import annotations

import json
from pathlib import Path

# (cwe, sink_file, sink_func, sink_func_src, safe_sink_src, sink_imports)
SINKS = {
    "CWE-89": ("db.py", "run_user_query", '''def run_user_query(name):
    cur = _conn().cursor()
    query = "SELECT id, email FROM users WHERE name = '%s'" % name   # SQLi sink
    cur.execute(query)
    return cur.fetchone()''', '''def count_active_users():
    cur = _conn().cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE active = 1")
    return cur.fetchone()[0]''', "import sqlite3\ndef _conn():\n    return sqlite3.connect('app.db')"),
    "CWE-78": ("ops.py", "probe_host", '''def probe_host(host):
    os.system("ping -c 1 " + host)   # command-injection sink
    return True''', '''def disk_free():
    return subprocess.run(["df", "-h"], capture_output=True, text=True).stdout''', "import os, subprocess"),
    "CWE-918": ("fetch.py", "fetch_preview", '''def fetch_preview(url):
    resp = requests.get(url, timeout=5)   # SSRF sink
    return resp.text[:2048]''', '''def fetch_status_page():
    return requests.get("https://status.internal/health", timeout=5).json()''', "import requests"),
    "CWE-22": ("files.py", "read_document", '''def read_document(fname):
    with open("/srv/docs/" + fname) as fh:   # path-traversal sink
        return fh.read()''', '''def list_templates():
    import os
    return os.listdir("/srv/templates")''', ""),
    "CWE-502": ("cache.py", "restore_session", '''def restore_session(blob):
    raw = base64.b64decode(blob)
    return pickle.loads(raw)   # insecure-deserialization sink''', '''def cache_key(user_id):
    return "sess:%d" % int(user_id)''', "import pickle, base64"),
}

ROUTES = '''"""HTTP routes (user input enters here)."""
from flask import Blueprint, request, jsonify
from services import {svc}, list_settings, ping

bp = Blueprint("app", __name__)


@bp.route("/health")
def health():
    return jsonify({{"ok": ping()}})


@bp.route("/settings")
def settings():
    return jsonify(list_settings())


@bp.route("/{route}")
def {route}_view():
    value = {source}            # user-controlled
    result = {svc}(value)       # -> services -> sink (cross-file)
    return jsonify({{"result": str(result)[:200]}})
'''

SERVICES = '''"""Service layer — passes the value through to the {sink_file} layer (taint passthrough)."""
from {sink_mod} import {sink_func}, {safe_func}


def ping():
    return True


def list_settings():
    return {{"theme": "dark", "lang": "en"}}


def {svc}(value):
    """Hands user input to the data/IO layer unchanged."""
    return {sink_func}(value)      # cross-file taint propagation
'''


def main():
    root = Path("ft-rig/data/out/crossfile")
    root.mkdir(parents=True, exist_ok=True)
    manifest = []
    for i, (cwe, (sf, fn, src, safe, imports)) in enumerate(SINKS.items()):
        sink_mod = sf[:-3]
        app = f"app{i}_{sink_mod}"
        d = root / app
        d.mkdir(exist_ok=True)
        safe_name = "count_active_users" if cwe == "CWE-89" else (
            "disk_free" if cwe == "CWE-78" else "fetch_status_page" if cwe == "CWE-918"
            else "list_templates" if cwe == "CWE-22" else "cache_key")
        (d / sf).write_text((imports + "\n\n\n" if imports else "") + src + "\n\n\n" + safe + "\n")
        svc = {"CWE-89": "lookup_user", "CWE-78": "network_probe", "CWE-918": "preview_link",
               "CWE-22": "open_doc", "CWE-502": "load_session"}[cwe]
        route = {"CWE-89": "user", "CWE-78": "probe", "CWE-918": "preview",
                 "CWE-22": "doc", "CWE-502": "session"}[cwe]
        source = "request.args.get('q', '')" if cwe != "CWE-502" else "request.get_json(silent=True).get('blob', '')"
        (d / "services.py").write_text(SERVICES.format(
            sink_file=sf, sink_mod=sink_mod, sink_func=fn, safe_func=safe_name, svc=svc))
        (d / "routes.py").write_text(ROUTES.format(svc=svc, route=route, source=source))
        files = {p.name: p.read_text() for p in d.glob("*.py")}
        manifest.append({"app": app, "app_dir": str(d), "cwe": cwe, "gt_file": sf,
                         "gt_function": fn, "source_file": "routes.py", "files": files,
                         "n_files": len(files)})
    out = Path("ft-rig/data/out/crossfile_manifest.jsonl")
    with open(out, "w") as f:
        for m in manifest:
            f.write(json.dumps(m) + "\n")
    print(f"wrote {len(manifest)} cross-file apps -> {root}/  (manifest: {out})")
    for m in manifest:
        print(f"  {m['app']}: {m['cwe']} flows routes.py -> services.py -> {m['gt_file']}::{m['gt_function']}")


if __name__ == "__main__":
    main()
