"""Functional tests (NOT security tests).

L5 runs these as the 'full suite' regression gate: a candidate patch for the
SQLi/XSS findings must keep ALL of these green, or the patch is rejected as
behavior-breaking (PLAN §8.2 — "tests pass" is necessary, not sufficient).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import db  # noqa: E402
from app import app  # noqa: E402


def setup_module(_):
    db.init_db()


def _client():
    return app.test_client()


def test_known_user_found():
    r = _client().get("/user?name=alice")
    assert r.status_code == 200
    assert r.get_json()["email"] == "alice@example.com"


def test_unknown_user_404():
    r = _client().get("/user?name=nobody")
    assert r.status_code == 404


def test_greet_contains_name():
    r = _client().get("/greet?name=World")
    assert b"Hello World" in r.data


def test_safe_user_ok():
    r = _client().get("/safe-user?name=alice")
    assert r.get_json()["ok"] is True
