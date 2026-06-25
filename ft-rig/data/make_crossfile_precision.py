#!/usr/bin/env python3
"""Cross-file PRECISION benchmark — the system's true headline value.

The plain cross-file benchmark tied (per-file LLM 1.0 = system 1.0) because the sinks looked
obviously bad in isolation. This one adds DECOYS: functions that use the SAME dangerous sink on
SAFE input (a constant URL, a trusted local file). A per-file LLM pattern-matches
"requests.get -> SSRF" and flags the decoy (FALSE POSITIVE); the cross-file taint engine sees no
user source reaching the decoy, so it does NOT. Metric = precision (FP on decoys).

routes.py (user input) -> services.py -> sink_layer:: REAL vuln  (taint reaches it)
sink_layer also defines DECOY functions: same sink, SAFE constant/local input (no user source).

Run: .venv/bin/python ft-rig/data/make_crossfile_precision.py
"""
from __future__ import annotations

import json
from pathlib import Path

# cwe -> (sink_mod, real_func, real_src, decoy_funcs_src, imports, svc, route, source_expr)
APPS = {
    "CWE-918": ("fetch", "fetch_user_link", '''def fetch_user_link(url):
    return requests.get(url, timeout=5).text[:2000]''',
                '''def refresh_status_board():
    # SAFE: constant internal URL, no user input
    return requests.get("https://status.internal/health", timeout=5).json()


def sync_exchange_rates():
    # SAFE: fixed trusted endpoint
    return requests.get("https://rates.internal/latest", timeout=5).json()''',
                "import requests", "preview_link", "preview", "request.args.get('url', '')"),
    "CWE-22": ("storage", "read_user_file", '''def read_user_file(fname):
    with open("/srv/uploads/" + fname) as fh:
        return fh.read()''',
               '''def load_app_config():
    # SAFE: constant path
    with open("/etc/myapp/config.yaml") as fh:
        return fh.read()


def read_license():
    # SAFE: fixed bundled file
    with open("/opt/myapp/LICENSE") as fh:
        return fh.read()''',
               "", "open_doc", "doc", "request.args.get('f', '')"),
    "CWE-502": ("cache", "load_user_blob", '''def load_user_blob(blob):
    import base64
    return pickle.loads(base64.b64decode(blob))''',
                '''def load_model():
    # SAFE: trusted local artifact, not user input
    with open("/var/models/ranker.pkl", "rb") as fh:
        return pickle.loads(fh.read())


def load_warm_cache():
    # SAFE: local cache file written by us
    with open("/var/cache/warm.pkl", "rb") as fh:
        return pickle.loads(fh.read())''',
                "import pickle", "load_session", "session", "request.args.get('blob', '')"),
    "CWE-89": ("db", "find_by_name", '''def find_by_name(name):
    cur = _conn().cursor()
    cur.execute("SELECT id, email FROM users WHERE name = '%s'" % name)
    return cur.fetchone()''',
               '''def stats_by_level():
    # SAFE: LEVEL is a module constant, not user input
    cur = _conn().cursor()
    cur.execute("SELECT COUNT(*) FROM logs WHERE level = '%s'" % LEVEL)
    return cur.fetchone()[0]


def recent_signups():
    # SAFE: no interpolation at all
    cur = _conn().cursor()
    cur.execute("SELECT email FROM users ORDER BY created_at DESC LIMIT 10")
    return cur.fetchall()''',
               "import sqlite3\nLEVEL = 'info'\ndef _conn():\n    return sqlite3.connect('app.db')",
               "lookup_user", "user", "request.args.get('name', '')"),
    "CWE-78": ("ops", "ping_target", '''def ping_target(host):
    os.system("ping -c 1 " + host)''',
               '''def rotate_logs():
    # SAFE: constant command, no user input
    os.system("logrotate /etc/logrotate.conf")


def backup_db():
    # SAFE: fixed args
    os.system("pg_dump app > /backups/app.sql")''',
               "import os", "network_probe", "probe", "request.args.get('host', '')"),
}

ROUTES = '''"""HTTP routes (user input enters here)."""
from flask import Blueprint, request, jsonify
from services import {svc}, status, settings

bp = Blueprint("app", __name__)


@bp.route("/status")
def status_view():
    return jsonify(status())


@bp.route("/settings")
def settings_view():
    return jsonify(settings())


@bp.route("/{route}")
def {route}_view():
    value = {source}        # user-controlled
    return jsonify({{"result": str({svc}(value))[:200]}})
'''

SERVICES = '''"""Service layer -> {sink_mod} (taint passthrough for the user route only)."""
from {sink_mod} import {real_func}


def status():
    return {{"ok": True}}


def settings():
    return {{"theme": "dark"}}


def {svc}(value):
    return {real_func}(value)     # cross-file: user input reaches the real sink
'''


def main():
    root = Path("ft-rig/data/out/crossfile_prec")
    root.mkdir(parents=True, exist_ok=True)
    manifest = []
    for i, (cwe, (mod, rf, rsrc, decoys, imports, svc, route, source)) in enumerate(APPS.items()):
        app = f"app{i}_{mod}"
        d = root / app
        d.mkdir(exist_ok=True)
        (d / f"{mod}.py").write_text(
            (imports + "\n\n\n" if imports else "") + rsrc + "\n\n\n" + decoys + "\n")
        (d / "services.py").write_text(SERVICES.format(sink_mod=mod, real_func=rf, svc=svc))
        (d / "routes.py").write_text(ROUTES.format(svc=svc, route=route, source=source))
        # decoy function names (must NOT be flagged)
        decoy_names = [ln.split("def ", 1)[1].split("(")[0] for ln in decoys.splitlines() if ln.startswith("def ")]
        files = {p.name: p.read_text() for p in d.glob("*.py")}
        manifest.append({"app": app, "app_dir": str(d), "cwe": cwe, "gt_file": f"{mod}.py",
                         "gt_function": rf, "decoy_functions": decoy_names, "files": files})
    out = Path("ft-rig/data/out/crossfile_prec_manifest.jsonl")
    with open(out, "w") as f:
        for m in manifest:
            f.write(json.dumps(m) + "\n")
    print(f"wrote {len(manifest)} precision apps -> {root}/")
    for m in manifest:
        print(f"  {m['app']} [{m['cwe']}]: REAL={m['gt_function']}  DECOYS(safe)={m['decoy_functions']}")


if __name__ == "__main__":
    main()
