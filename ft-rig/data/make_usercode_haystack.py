#!/usr/bin/env python3
"""User-code haystack (INSIGHTS #7 — the product's REAL domain).

The mined CVEs are frameworks fixing their own internals (Django auditing Django).
The product audits USER application code that *uses* frameworks — where textbook
patterns appear and our taint/SAST actually fire. This generates realistic Flask
modules: ~10-13 functions each, ONE planted vulnerability in a user idiom our system
covers, buried among safe functions. Same eval format as the framework haystack so
we can compare bare vs system on the domain the system is built for.

Run: .venv/bin/python ft-rig/data/make_usercode_haystack.py
"""
from __future__ import annotations

import json
from pathlib import Path

HEADER = '''import os, pickle, base64, subprocess
from flask import Flask, request, jsonify
from markupsafe import escape
app = Flask(__name__)
def get_cursor():
    return app.config["DB"].cursor()
'''

# --- SAFE functions (realistic, properly secured) ---
SAFE = {
    "get_user_by_id": '''@app.route("/user/<int:uid>")
def get_user_by_id(uid):
    cur = get_cursor()
    cur.execute("SELECT id, name, email FROM users WHERE id = ?", (uid,))
    row = cur.fetchone()
    return jsonify({"id": row[0], "name": row[1]}) if row else ("not found", 404)''',
    "search_products": '''@app.route("/products")
def search_products():
    term = request.args.get("q", "")
    cur = get_cursor()
    cur.execute("SELECT name, price FROM products WHERE name LIKE ?", ("%" + term + "%",))
    return jsonify([{"name": r[0], "price": r[1]} for r in cur.fetchall()])''',
    "render_greeting": '''@app.route("/hello")
def render_greeting():
    name = request.args.get("name", "world")
    return "<h1>Hello " + str(escape(name)) + "</h1>"''',
    "healthcheck": '''@app.route("/health")
def healthcheck():
    return jsonify({"status": "ok", "version": app.config.get("VERSION", "1.0")})''',
    "list_orders": '''@app.route("/orders")
def list_orders():
    page = int(request.args.get("page", "1"))
    cur = get_cursor()
    cur.execute("SELECT id, total FROM orders LIMIT 20 OFFSET ?", ((page - 1) * 20,))
    return jsonify([{"id": r[0], "total": r[1]} for r in cur.fetchall()])''',
    "validate_coupon": '''@app.route("/coupon")
def validate_coupon():
    code = request.args.get("code", "")
    if not code.isalnum():
        return ("invalid", 400)
    cur = get_cursor()
    cur.execute("SELECT discount FROM coupons WHERE code = ?", (code,))
    row = cur.fetchone()
    return jsonify({"discount": row[0] if row else 0})''',
    "convert_image_safe": '''@app.route("/thumb")
def convert_image_safe():
    name = request.args.get("file", "")
    if not name.isalnum():
        return ("bad name", 400)
    subprocess.run(["convert", name + ".png", "thumb.png"], check=True)
    return ("ok", 200)''',
    "read_doc_safe": '''@app.route("/doc")
def read_doc_safe():
    from werkzeug.utils import secure_filename
    fn = secure_filename(request.args.get("f", ""))
    with open(os.path.join("/srv/docs", fn)) as fh:
        return fh.read()''',
    "update_profile": '''@app.route("/profile", methods=["POST"])
def update_profile():
    uid = int(request.form["uid"])
    bio = request.form.get("bio", "")[:280]
    cur = get_cursor()
    cur.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, uid))
    return ("saved", 200)''',
    "logout": '''@app.route("/logout")
def logout():
    from flask import session
    session.clear()
    return ("bye", 200)''',
    "metrics": '''@app.route("/metrics")
def metrics():
    cur = get_cursor()
    cur.execute("SELECT COUNT(*) FROM orders")
    return jsonify({"orders": cur.fetchone()[0]})''',
    "set_locale": '''@app.route("/locale")
def set_locale():
    loc = request.args.get("loc", "en")
    if loc not in {"en", "fr", "de", "es"}:
        loc = "en"
    return jsonify({"locale": loc})''',
}

# --- VULNERABLE functions (user idioms our SAST/taint cover) ---
VULN = {
    "CWE-89": ("search_by_name", '''@app.route("/find")
def search_by_name():
    name = request.args.get("name", "")
    cur = get_cursor()
    query = "SELECT id, email FROM users WHERE name = '%s'" % name
    cur.execute(query)
    return jsonify(cur.fetchall())'''),
    "CWE-79": ("show_comment", '''@app.route("/comment")
def show_comment():
    text = request.args.get("text", "")
    return "<div class='comment'>" + text + "</div>"'''),
    "CWE-78": ("ping_host", '''@app.route("/ping")
def ping_host():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)
    return ("pinged", 200)'''),
}


def assemble(vuln_cwe, module_idx, n_safe=10):
    vfn_name, vfn_src = VULN[vuln_cwe]
    safe_names = list(SAFE)
    # deterministic rotation so vuln lands in a different position each module
    rot = (module_idx * 3) % len(safe_names)
    chosen = (safe_names[rot:] + safe_names[:rot])[:n_safe]
    insert_at = module_idx % (n_safe + 1)
    bodies = [SAFE[n] for n in chosen]
    bodies.insert(insert_at, vfn_src)
    content = HEADER + "\n\n" + "\n\n".join(bodies) + "\n"
    return {"cve": f"synthetic-usercode-{module_idx}", "cwe": vuln_cwe, "repo": "usercode",
            "file_path": f"app/views_{module_idx}.py", "n_functions": len(bodies),
            "gt_functions": [vfn_name], "file_content": content}


def main():
    items = []
    idx = 0
    for cwe in ["CWE-89", "CWE-79", "CWE-78"]:
        for _ in range(3):                       # 3 modules per CWE = 9 haystacks
            items.append(assemble(cwe, idx))
            idx += 1
    out = Path("ft-rig/data/out/usercode_haystack.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        for it in items:
            f.write(json.dumps(it) + "\n")
    import statistics
    print(f"user-code haystacks={len(items)} avg functions={statistics.mean(i['n_functions'] for i in items):.1f} -> {out}")
    from collections import Counter
    print("CWEs:", dict(Counter(i['cwe'] for i in items)))


if __name__ == "__main__":
    main()
