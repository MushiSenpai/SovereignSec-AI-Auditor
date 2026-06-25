"""Load the CVEfixes Python subset (IMPL_SPEC §"Component 1", verified 2026-06-24).

CVEfixes is a relational **SQLite** DB (Zenodo DOI 10.5281/zenodo.4476563, CC-BY-4.0).
Verified schema: cve(cve_id, published_date), fixes(cve_id, hash, repo_url),
commits(hash, repo_url, committer_date, msg, parents, ...), file_change(file_change_id,
hash, filename, programming_language, code_before, code_after, ...), method_change(
method_change_id, file_change_id, name, signature, code, before_change, start_line,
end_line, ...). We pull method-level before/after for Python file changes and pair on
(filename, name, signature) — signature disambiguates overloaded/renamed methods.

NOTE (verified): **MoreFixes is PostgreSQL, NOT SQLite** (postgrescvedumper.sql.zip,
Zenodo 13983082; ~29,203 CVEs / 35,276 fix commits / 39,931 patch files). For MoreFixes,
load into local Postgres and query via psycopg (still offline) — this loader is
CVEfixes/SQLite only. `before_change` is text 'True'/'False' in SQLite (normalized
case-insensitively below) but a native bool on MoreFixes-Postgres.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Iterator, Optional

_PY_METHODS_SQL = """
SELECT c.cve_id           AS cve,
       fc.filename        AS filename,
       mc.name            AS func,
       mc.signature       AS signature,
       mc.before_change   AS before_change,
       mc.code            AS code,
       cm.committer_date  AS committer_date
FROM method_change mc
JOIN file_change fc ON fc.file_change_id = mc.file_change_id
JOIN commits     cm ON cm.hash = fc.hash
JOIN fixes       x  ON x.hash = fc.hash
JOIN cve         c  ON c.cve_id = x.cve_id
WHERE fc.programming_language = 'Python'
"""


@dataclass
class CvefixesMethod:
    cve: str
    filename: str
    func: str
    signature: str
    before_change: bool
    code: str
    committer_date: Optional[str] = None


def iter_python_methods(db_path: str) -> Iterator[CvefixesMethod]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        for r in conn.execute(_PY_METHODS_SQL):
            yield CvefixesMethod(
                cve=r["cve"], filename=r["filename"], func=r["func"],
                signature=r["signature"] or "",
                # SQLite text 'True'/'False'; case-insensitive (native bool on MoreFixes-PG)
                before_change=str(r["before_change"]).lower() in ("true", "before", "1"),
                code=r["code"] or "",
                committer_date=r["committer_date"],
            )
    finally:
        conn.close()


def pair_by_method(methods: Iterator[CvefixesMethod]) -> list[dict]:
    """Collapse before/after rows of the same (file, func, signature) into pairs."""
    buckets: dict[tuple, dict] = {}
    for m in methods:
        key = (m.cve, m.filename, m.func, m.signature)
        slot = buckets.setdefault(key, {"cve": m.cve, "file": m.filename, "func": m.func,
                                        "signature": m.signature, "date": m.committer_date})
        slot["vulnerable" if m.before_change else "patched"] = m.code
    return [b for b in buckets.values()
            if b.get("vulnerable") and b.get("patched")
            and b["vulnerable"].strip() != b["patched"].strip()]
