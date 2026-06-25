"""Data layer for the seeded vulnerable demo app.

INTENTIONALLY VULNERABLE — fixture for testing the SovereignSec-AI auditor's
L1-L5 layers, and the M5 demo target. DO NOT DEPLOY. See README.md.
"""
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")


def _conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = _conn()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    cur.execute("DELETE FROM users")
    cur.executemany(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        [("alice", "alice@example.com"), ("bob", "bob@example.com")],
    )
    conn.commit()
    conn.close()


def find_user(username):
    """VULNERABLE (CWE-89): `username` reaches raw SQL via string formatting.

    Cross-file taint path: app.user() -> services.user_lookup() -> here.
    """
    conn = _conn()
    cur = conn.cursor()
    query = "SELECT id, name, email FROM users WHERE name = '%s'" % username
    cur.execute(query)  # << SQLi sink (CWE-89)
    row = cur.fetchone()
    conn.close()
    return row


def find_user_safe(username):
    """SAFE — planted FALSE POSITIVE. Parameterized query; a naive matcher that
    flags any cur.execute() will wrongly report this. L4 must drop it."""
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email FROM users WHERE name = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row
