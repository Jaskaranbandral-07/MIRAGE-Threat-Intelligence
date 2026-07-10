"""
MIRAGE — Database Connection Manager
=====================================
Provides thread-safe SQLite access with:
  • Thread-local connection storage
  • Automatic schema + seed-signature initialization
  • WAL mode for concurrent reads
  • Context manager for explicit transactions

Usage::

    from database.db import init_db, get_db, close_db

    init_db()           # call once at startup
    db = get_db()       # returns a thread-local connection
    close_db()          # call on thread teardown
"""

import os
import sqlite3
import threading
from contextlib import contextmanager

import sys

# ── Resolve project root so we can import config.py ────────────────────────
_DB_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_DB_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from config import Config  # noqa: E402

# ── Thread-local storage ───────────────────────────────────────────────────
_local = threading.local()

# ── SQL file paths (relative to this file) ─────────────────────────────────
_SCHEMA_PATH = os.path.join(_DB_DIR, 'schema.sql')
_SEED_PATH = os.path.join(_DB_DIR, 'seed_signatures.sql')


def _read_sql_file(path: str) -> str:
    """Read and return the contents of a SQL file."""
    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read()


def _create_connection() -> sqlite3.Connection:
    """Create a new SQLite connection with recommended pragmas."""
    conn = sqlite3.connect(Config.DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=5000')
    return conn


def init_db() -> None:
    """Initialise the database: create tables, seed technique signatures.

    Safe to call multiple times — all DDL uses ``IF NOT EXISTS`` and
    seed inserts use ``INSERT OR IGNORE``.
    """
    conn = _create_connection()
    try:
        # Execute schema
        schema_sql = _read_sql_file(_SCHEMA_PATH)
        conn.executescript(schema_sql)

        # Seed ATT&CK technique signatures
        seed_sql = _read_sql_file(_SEED_PATH)
        conn.executescript(seed_sql)

        conn.commit()
        print(f"[MIRAGE] Database initialised → {Config.DATABASE_PATH}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    """Return the thread-local database connection.

    Creates a new connection on first call within each thread.
    """
    conn = getattr(_local, 'connection', None)
    if conn is None:
        conn = _create_connection()
        _local.connection = conn
    return conn


def close_db() -> None:
    """Close the thread-local database connection (if any)."""
    conn = getattr(_local, 'connection', None)
    if conn is not None:
        conn.close()
        _local.connection = None


@contextmanager
def transaction():
    """Context manager that wraps a block in a SQLite transaction.

    Usage::

        from database.db import transaction, get_db

        with transaction() as conn:
            conn.execute("INSERT INTO ...")
            conn.execute("UPDATE ...")
        # auto-committed here; rolled back on exception
    """
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
