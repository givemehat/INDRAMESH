"""Durable scan history in SQLite (opt-in).

The console's scan history lived only in `_STATE`, an in-process dict: a restart erased
every past scan, so "readiness tracked over time" was a claim the server could not back.
This store persists history entries as JSON blobs when INDRAMESH_HISTORY_DB points at a
SQLite file; with the variable unset the behaviour is exactly the old in-memory one, so
a dev loop never writes files it did not ask for.

Design notes:
  * One JSON blob per entry rather than a normalised schema: the entry shape is owned by
    `server.py` and changes with the response payload; re-deriving columns would couple
    this module to that shape for no reader benefit.
  * `id` is the scan id from server.py (second-resolution timestamp), so PRIMARY KEY
    collision means "same second", and INSERT OR REPLACE keeps the newest.
  * Retention deletes everything beyond the newest RETAIN rows on every append, so the
    file cannot grow without bound even if the caller forgets its own cap.
  * All functions no-op (or return empty) when the env var is unset -- the store is a
    passenger, never the pilot.
"""
import json
import os
import sqlite3

RETAIN = 50
_TABLE = ("CREATE TABLE IF NOT EXISTS history "
          "(id TEXT PRIMARY KEY, ts TEXT NOT NULL, blob TEXT NOT NULL)")


def db_path():
    return os.environ.get("INDRAMESH_HISTORY_DB") or None


def _connect(path):
    conn = sqlite3.connect(path)
    conn.execute(_TABLE)
    return conn


def append(entry: dict) -> bool:
    """Persist one history entry; returns False when the store is disabled."""
    path = db_path()
    if not path or not isinstance(entry, dict) or not entry.get("id"):
        return False
    with _connect(path) as conn:
        conn.execute("INSERT OR REPLACE INTO history (id, ts, blob) VALUES (?, ?, ?)",
                     (str(entry["id"]), str(entry.get("scanned_at") or ""),
                      json.dumps(entry, default=str)))
        conn.execute("DELETE FROM history WHERE id NOT IN "
                     "(SELECT id FROM history ORDER BY ts DESC, id DESC LIMIT ?)",
                     (RETAIN,))
    return True


def list_recent(limit: int = 20) -> list:
    """Newest-first list of persisted entries; empty when disabled or absent."""
    path = db_path()
    if not path or not os.path.exists(path):
        return []
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT blob FROM history ORDER BY ts DESC, id DESC LIMIT ?",
            (int(limit),)).fetchall()
    return [json.loads(r[0]) for r in rows]


def get(entry_id) -> dict | None:
    """Fetch one persisted entry by id; None when disabled, absent or malformed."""
    path = db_path()
    if not path or not os.path.exists(path) or entry_id is None:
        return None
    with _connect(path) as conn:
        row = conn.execute("SELECT blob FROM history WHERE id = ?",
                           (str(entry_id),)).fetchone()
    if not row:
        return None
    try:
        entry = json.loads(row[0])
    except (TypeError, ValueError):
        return None
    return entry if isinstance(entry, dict) else None
