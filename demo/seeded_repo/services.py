"""Service layer — propagates user input to the data layer (taint passthrough).

This file exists to force a CROSS-FILE taint path so L1's call graph + L2's
graph-walk retrieval are actually exercised: app.py -> services.py -> db.py.
"""
from db import find_user


def user_lookup(username):
    """Passes user-controlled `username` straight to the DB layer (no sanitization)."""
    return find_user(username)  # cross-file taint propagation -> db.find_user (SQLi)
