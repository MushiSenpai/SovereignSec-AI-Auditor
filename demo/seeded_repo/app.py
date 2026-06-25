"""Seeded vulnerable Flask app — fixture for SovereignSec-AI. DO NOT DEPLOY.

Planted ground truth (see GROUND_TRUTH.json):
  - CWE-89  SQL injection via a CROSS-FILE taint path: app.user -> services.user_lookup -> db.find_user
  - CWE-79  reflected XSS (in-file): app.greet
  - FALSE POSITIVE: app.safe_user -> db.find_user_safe (parameterized; must NOT be reported)

It is intentionally vulnerable so the auditor's L1-L5 can be acceptance-tested
(cross-file taint, FP suppression, dynamic validation) and so it can be the
M5 split-screen demo target.
"""
from flask import Flask, request
import db
from services import user_lookup
from db import find_user_safe

app = Flask(__name__)


@app.route("/user")
def user():
    username = request.args.get("name", "")  # TAINT SOURCE (user-controlled)
    profile = user_lookup(username)           # -> services.user_lookup -> db.find_user (SQLi sink)
    if not profile:
        return "not found", 404
    return {"id": profile[0], "name": profile[1], "email": profile[2]}


@app.route("/greet")
def greet():
    name = request.args.get("name", "")       # TAINT SOURCE (user-controlled)
    return "<h1>Hello " + name + "</h1>"       # CWE-79: reflected XSS — unescaped into HTML


@app.route("/safe-user")
def safe_user():
    username = request.args.get("name", "")
    profile = find_user_safe(username)         # parameterized query -> planted FALSE POSITIVE
    return {"ok": bool(profile)}


if __name__ == "__main__":
    db.init_db()
    app.run(port=5001)
