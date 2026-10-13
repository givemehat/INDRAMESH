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
  * `id` is a unique scan id from server.py (timestamp + micros + random suffix),
    so PRIMARY KEY collision means a true duplicate; INSERT OR REPLACE keeps newest.
  * Retention deletes everything beyond the newest RETAIN rows on every append, so the
    file cannot grow without bound even if the caller forgets its own cap.
  * All functions no-op (or return empty) when the env var is unset -- the store is a
    passenger, never the pilot.
  * Concurrency: WAL mode + busy timeout so parallel /api/scan do not hit
    "database is locked"; parent dirs auto-created; corrupt rows skipped, never raised.
"""
import json
import os
import sqlite3
from pathlib import Path

RETAIN = 50
_TABLE = ("CREATE TABLE IF NOT EXISTS history "
          "(id TEXT PRIMARY KEY, ts TEXT NOT NULL, blob TEXT NOT NULL)")


def db_path():
    return os.environ.get("INDRAMESH_HISTORY_DB") or None


def _connect(path):
    # Enterprise-grade: auto-create parent dirs, WAL + busy timeout so
    # concurrent scans do not raise "database is locked".
    try:
        parent = os.path.dirname(os.path.abspath(str(path)))
        if parent:
            os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
    conn = sqlite3.connect(str(path), timeout=10.0, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.Error as exc:
        # Degraded but functional (rollback-journal mode); surface once so
        # operators know durability is reduced instead of failing silently.
        print(f"[IndraMesh] History store pragma notice: {exc}")
    conn.execute(_TABLE)
    return conn


def append(entry: dict) -> bool:
    """Persist one history entry; returns False when the store is disabled."""
    path = db_path()
    if not path or not isinstance(entry, dict) or not entry.get("id"):
        return False
    try:
        with _connect(path) as conn:
            conn.execute("INSERT OR REPLACE INTO history (id, ts, blob) VALUES (?, ?, ?)",
                         (str(entry["id"]), str(entry.get("scanned_at") or ""),
                          json.dumps(entry, default=str)))
            conn.execute("DELETE FROM history WHERE id NOT IN "
                         "(SELECT id FROM history ORDER BY ts DESC, id DESC LIMIT ?)",
                         (RETAIN,))
    except (sqlite3.Error, OSError, ValueError) as exc:
        print(f"[IndraMesh] History store append notice: {exc}")
        return False
    return True


def list_recent(limit: int = 20) -> list:
    """Newest-first list of persisted entries; empty when disabled or absent."""
    path = db_path()
    if not path or not os.path.exists(path):
        return []
    try:
        with _connect(path) as conn:
            rows = conn.execute(
                "SELECT blob FROM history ORDER BY ts DESC, id DESC LIMIT ?",
                (int(limit),)).fetchall()
    except (sqlite3.Error, OSError, ValueError):
        return []
    out = []
    for r in rows:
        try:
            entry = json.loads(r[0])
        except (TypeError, ValueError):
            continue
        if isinstance(entry, dict):
            out.append(entry)
    return out


def get(entry_id) -> dict | None:
    """Fetch one persisted entry by id; None when disabled, absent or malformed."""
    path = db_path()
    if not path or not os.path.exists(path) or entry_id is None:
        return None
    try:
        with _connect(path) as conn:
            row = conn.execute("SELECT blob FROM history WHERE id = ?",
                               (str(entry_id),)).fetchone()
    except (sqlite3.Error, OSError, ValueError):
        return None
    if not row:
        return None
    try:
        entry = json.loads(row[0])
    except (TypeError, ValueError):
        return None
    return entry if isinstance(entry, dict) else None
