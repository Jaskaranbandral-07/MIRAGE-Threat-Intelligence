#!/usr/bin/env python3
"""
MIRAGE Ingestion — Unified Honeypot Log Watcher
================================================

Long-running daemon that watches JSON log files from all new honeypots
and normalises events into the MIRAGE database.

Supported honeypots:
  • credential_trap  (FTP / Telnet / SMTP / VNC)
  • wordpot          (WordPress)
  • elasticpot       (Elasticsearch)
  • adbhoney         (Android Debug Bridge)

All honeypots emit a unified JSON format::

    {
        "timestamp":   "2025-01-01T00:00:00Z",
        "event_type":  "connection|login_attempt|command|disconnect",
        "source_ip":   "1.2.3.4",
        "source_port": 54321,
        "protocol":    "ftp|telnet|smtp|vnc|wordpress|elasticsearch|adb",
        "honeypot":    "credential_trap|wordpot|elasticpot|adbhoney",
        "username":    "admin",
        "password":    "password123",
        "raw_input":   "...",
        "details":     { ... }
    }

Supports two modes:
  • **live** (default) — continuously watches log files for new lines
  • **batch** (``--batch``) — processes all files once and exits

Usage::

    # Live daemon
    python unified_watcher.py

    # One-shot batch import
    python unified_watcher.py --batch

No LLM/AI calls — all processing is deterministic.
"""

import sys
import os
import json
import time
import signal
import logging
import argparse
import threading
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Path bootstrap — project root on sys.path
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import get_db, init_db
from config import Config
from analytics.attack_tagger import _cache as tagger_cache

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("mirage.unified_watcher")

# ---------------------------------------------------------------------------
# Log files to watch
# ---------------------------------------------------------------------------
LOG_FILES = [
    "/var/log/honeypot/credential_trap.json",
    "/var/log/honeypot/wordpot.json",
    "/var/log/honeypot/elasticpot.json",
    "/var/log/honeypot/adbhoney.json",
]

# ---------------------------------------------------------------------------
# Globals (per-thread safe via threading.local and locks)
# ---------------------------------------------------------------------------
# Maps (honeypot, source_ip, source_port) → our integer session_ids in the DB
_session_map: dict[tuple, int] = {}
_session_map_lock = threading.Lock()

# Tracks the next sequence number for each DB session_id
_seq_counters: dict[int, int] = {}
_seq_lock = threading.Lock()

# Tracks the ISO timestamp of the last command per DB session_id
_last_ts: dict[int, str] = {}
_last_ts_lock = threading.Lock()

# Tracks start_time for sessions (for duration calculation on disconnect)
_session_start: dict[int, str] = {}
_session_start_lock = threading.Lock()

# Graceful-shutdown flag
_running = True

# Stats
_stats = {"processed": 0, "skipped": 0, "errors": 0}
_stats_lock = threading.Lock()

# DB write lock (SQLite needs serialised writes)
_db_lock = threading.Lock()


def _handle_sigterm(*_):
    """Set the shutdown flag on SIGTERM / SIGINT."""
    global _running
    logger.info("Shutdown signal received — finishing up …")
    _running = False


signal.signal(signal.SIGTERM, _handle_sigterm)
signal.signal(signal.SIGINT, _handle_sigterm)


# ==========================================================================
# Helper functions
# ==========================================================================

def _now_iso():
    """Current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_ts(ts_str: str | None) -> str:
    """
    Normalise a timestamp into our standard ISO format.
    Falls back to *now* if the string is missing or unparseable.
    """
    if not ts_str:
        return _now_iso()
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (ValueError, TypeError):
        return _now_iso()


def _compute_delta_ms(session_id: int, current_iso: str) -> int | None:
    """
    Return milliseconds since the previous command in this session,
    or None if this is the first command.
    """
    with _last_ts_lock:
        prev = _last_ts.get(session_id)
    if prev is None:
        return None
    try:
        prev_dt = datetime.fromisoformat(prev.replace("Z", "+00:00"))
        curr_dt = datetime.fromisoformat(current_iso.replace("Z", "+00:00"))
        return max(0, int((curr_dt - prev_dt).total_seconds() * 1000))
    except (ValueError, TypeError):
        return None


def _next_seq(session_id: int) -> int:
    """Increment and return the next sequence number for a session."""
    with _seq_lock:
        seq = _seq_counters.get(session_id, 0) + 1
        _seq_counters[session_id] = seq
    return seq


def _inc_stat(key: str):
    """Thread-safe stats increment."""
    with _stats_lock:
        _stats[key] += 1


# ==========================================================================
# Database helpers
# ==========================================================================

def _upsert_source(db, ip: str, ts_iso: str):
    """Insert or update the ``sources`` row for this IP."""
    with _db_lock:
        db.execute(
            """
            INSERT INTO sources (ip_address, first_seen, last_seen, session_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(ip_address) DO UPDATE SET
                last_seen     = excluded.last_seen,
                session_count = session_count + 1
            """,
            (ip, ts_iso, ts_iso),
        )
        db.commit()


def _create_session(db, ip: str, protocol: str, ts_iso: str) -> int:
    """Insert a new session and return its ``session_id``."""
    with _db_lock:
        cursor = db.execute(
            """
            INSERT INTO sessions (source_ip, protocol, start_time)
            VALUES (?, ?, ?)
            """,
            (ip, protocol, ts_iso),
        )
        db.commit()
        return cursor.lastrowid


def _close_session(db, session_id: int, end_iso: str, start_iso: str | None):
    """
    Set end_time and duration_seconds on a session.
    ``start_iso`` can be None — in that case duration is omitted.
    """
    duration = None
    if start_iso:
        try:
            s = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
            e = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
            duration = max(0, int((e - s).total_seconds()))
        except (ValueError, TypeError):
            pass

    with _db_lock:
        db.execute(
            """
            UPDATE sessions
            SET end_time = ?, duration_seconds = ?
            WHERE session_id = ?
            """,
            (end_iso, duration, session_id),
        )
        db.commit()


def _insert_command(db, session_id: int, raw_input: str, ts_iso: str):
    """Record a single command for the given session, filtering out garbage."""
    # Filter 1: Empty or whitespace-only commands
    if not raw_input.strip():
        return
        
    # Filter 2: High percentage of non-printable characters (binary noise like Telnet negotiation)
    non_printable = sum(1 for c in raw_input if not (32 <= ord(c) <= 126 or c in '\r\n\t'))
    if len(raw_input) > 0 and (non_printable / len(raw_input)) > 0.5:
        return
    seq = _next_seq(session_id)
    delta_ms = _compute_delta_ms(session_id, ts_iso)

    with _db_lock:
        cursor = db.execute(
            """
            INSERT INTO commands
                (session_id, sequence_number, raw_input, timestamp, time_since_prev_ms)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, seq, raw_input, ts_iso, delta_ms),
        )
        command_id = cursor.lastrowid
        
        # Real-time technique tagging
        patterns = tagger_cache.patterns
        if patterns:
            for pat in patterns:
                if pat['compiled'].search(raw_input):
                    try:
                        db.execute(
                            'INSERT OR IGNORE INTO session_techniques '
                            '(session_id, signature_id, matched_command_id) '
                            'VALUES (?, ?, ?)',
                            (session_id, pat['signature_id'], command_id),
                        )
                    except Exception as e:
                        logger.error("Failed real-time tag: %s", e)

        db.commit()

    # Update last-timestamp tracker
    with _last_ts_lock:
        _last_ts[session_id] = ts_iso


def _insert_credential(db, session_id: int | None, source_ip: str,
                        protocol: str, username: str | None,
                        password: str | None, ts_iso: str,
                        success: bool = False):
    """Record a credential attempt in the ``credentials`` table."""
    with _db_lock:
        db.execute(
            """
            INSERT INTO credentials
                (session_id, source_ip, protocol, username, password,
                 timestamp, success)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, source_ip, protocol, username, password,
             ts_iso, 1 if success else 0),
        )
        db.commit()


# ==========================================================================
# Session key helpers
# ==========================================================================

def _session_key(event: dict) -> tuple:
    """Build a unique key for session tracking from event fields."""
    return (
        event.get("honeypot", ""),
        event.get("source_ip", "unknown"),
        event.get("source_port", 0),
    )


def _get_or_create_session(db, event: dict, ts_iso: str) -> int:
    """Resolve or create a DB session for this event."""
    key = _session_key(event)
    with _session_map_lock:
        db_sid = _session_map.get(key)
    if db_sid is not None:
        return db_sid

    ip = event.get("source_ip", "unknown")
    protocol = event.get("protocol", "unknown")

    _upsert_source(db, ip, ts_iso)
    db_sid = _create_session(db, ip, protocol, ts_iso)

    with _session_map_lock:
        _session_map[key] = db_sid
    with _session_start_lock:
        _session_start[db_sid] = ts_iso

    logger.debug("Late-join session: key=%s → db=%s", key, db_sid)
    return db_sid


# ==========================================================================
# Event dispatch
# ==========================================================================

def _process_event(db, event: dict):
    """
    Dispatch a single unified JSON event to the appropriate DB handler.

    Recognised event types:
      - connection
      - login_attempt
      - command
      - disconnect
    """
    event_type = event.get("event_type", "")
    ts = _parse_ts(event.get("timestamp"))
    ip = event.get("source_ip", "unknown")
    protocol = event.get("protocol", "unknown")

    # ------------------------------------------------------------------
    # connection — new session
    # ------------------------------------------------------------------
    if event_type == "connection":
        key = _session_key(event)

        _upsert_source(db, ip, ts)
        sid = _create_session(db, ip, protocol, ts)

        with _session_map_lock:
            _session_map[key] = sid
        with _session_start_lock:
            _session_start[sid] = ts

        logger.debug(
            "New session: honeypot=%s ip=%s → db=%s",
            event.get("honeypot", "?"), ip, sid,
        )
        _inc_stat("processed")
        return

    # ------------------------------------------------------------------
    # Resolve DB session_id (auto-create if connect was missed)
    # ------------------------------------------------------------------
    db_sid = _get_or_create_session(db, event, ts)

    # ------------------------------------------------------------------
    # login_attempt — insert into commands AND credentials
    # ------------------------------------------------------------------
    if event_type == "login_attempt":
        username = event.get("username")
        password = event.get("password")
        success = event.get("details", {}).get("success", False)

        label = "LOGIN SUCCESS" if success else "LOGIN FAILED"
        _insert_command(
            db, db_sid,
            f"{label}: {username or '?'}/{password or '?'}",
            ts,
        )
        _insert_credential(
            db, db_sid, ip, protocol,
            username, password, ts, success=success,
        )

    # ------------------------------------------------------------------
    # command — insert into commands
    # ------------------------------------------------------------------
    elif event_type == "command":
        raw = event.get("raw_input", "")
        _insert_command(db, db_sid, raw, ts)

    # ------------------------------------------------------------------
    # disconnect — close the session
    # ------------------------------------------------------------------
    elif event_type == "disconnect":
        key = _session_key(event)

        with _session_start_lock:
            start_ts = _session_start.pop(db_sid, None)
        _close_session(db, db_sid, ts, start_ts)

        # Clean up in-memory maps
        with _session_map_lock:
            _session_map.pop(key, None)
        with _seq_lock:
            _seq_counters.pop(db_sid, None)
        with _last_ts_lock:
            _last_ts.pop(db_sid, None)

        logger.debug("Closed session: db=%s", db_sid)

    else:
        # Unknown event — skip silently
        _inc_stat("skipped")
        return

    _inc_stat("processed")


# ==========================================================================
# File-reading helpers
# ==========================================================================

def _read_lines(fh):
    """
    Yield (line_number, parsed_dict) for every valid JSON line from *fh*.
    Malformed lines are skipped with a warning.
    """
    for lineno, raw in enumerate(fh, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            yield lineno, json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping malformed JSON at line %d: %s", lineno, exc)
            _inc_stat("errors")


def _batch_process_file(path: str):
    """Read an entire honeypot log file and import every event."""
    if not os.path.exists(path):
        logger.warning("Log file does not exist (skipping batch): %s", path)
        return

    logger.info("Batch processing %s …", path)
    db = get_db()

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, event in _read_lines(fh):
            try:
                _process_event(db, event)
            except Exception:
                logger.exception(
                    "Error processing line %d in %s — skipping", lineno, path,
                )
                _inc_stat("errors")


def _tail_file(path: str, poll_interval: float = 1.0):
    """
    Continuously tail a single honeypot log file.  Uses simple size-based
    polling (no external dependency required).

    This function is designed to run in its own thread.
    """
    logger.info("Tailing %s (poll every %.1fs) …", path, poll_interval)
    db = get_db()

    # If the file doesn't exist yet, wait for it
    while _running and not os.path.exists(path):
        logger.info("Waiting for log file to appear: %s", path)
        time.sleep(poll_interval * 5)

    if not _running:
        return

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        # Jump to end — we only want new events in live mode
        fh.seek(0, os.SEEK_END)

        last_report = time.time()

        while _running:
            line = fh.readline()

            if not line:
                # No new data — sleep and retry
                time.sleep(poll_interval)

                # Handle log rotation: if the file shrank, reopen
                try:
                    if os.path.getsize(path) < fh.tell():
                        logger.info(
                            "Log file appears rotated — reopening: %s", path,
                        )
                        break  # Break to restart via outer loop
                except OSError:
                    pass

                # Periodic stats
                if time.time() - last_report >= 60:
                    _log_stats()
                    last_report = time.time()

                continue

            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Skipping malformed JSON line in %s: %s", path, exc,
                )
                _inc_stat("errors")
                continue

            try:
                _process_event(db, event)
            except Exception:
                logger.exception(
                    "Error processing live event in %s — skipping", path,
                )
                _inc_stat("errors")


def _tail_file_forever(path: str, poll_interval: float = 1.0):
    """
    Wrapper around _tail_file that restarts on rotation / crash.
    Designed to run in a dedicated thread.
    """
    while _running:
        try:
            _tail_file(path, poll_interval=poll_interval)
        except Exception:
            logger.exception(
                "Tail loop for %s crashed — restarting in 5s", path,
            )
            time.sleep(5)


def _log_stats():
    """Emit current processing statistics."""
    with _stats_lock:
        p, s, e = _stats["processed"], _stats["skipped"], _stats["errors"]
    with _session_map_lock:
        active = len(_session_map)
    logger.info(
        "Stats — processed=%d  skipped=%d  errors=%d  active_sessions=%d",
        p, s, e, active,
    )


# ==========================================================================
# Entry point
# ==========================================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "MIRAGE — Unified honeypot log watcher and database ingestion "
            "daemon for credential_trap, wordpot, elasticpot, and adbhoney"
        ),
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Process all existing log files in one pass and exit (no tailing)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Seconds between poll cycles in live mode (default: 1.0)",
    )
    args = parser.parse_args()

    # Ensure the database schema exists
    try:
        init_db()
        logger.info("Database initialised.")
    except Exception:
        logger.exception("Could not initialise database — proceeding anyway")

    if args.batch:
        # ── Batch mode: process each file sequentially ────────────────
        for log_path in LOG_FILES:
            _batch_process_file(log_path)
        _log_stats()
        logger.info("Batch import complete.")
    else:
        # ── Live mode: one thread per log file ────────────────────────
        threads: list[threading.Thread] = []
        for log_path in LOG_FILES:
            t = threading.Thread(
                target=_tail_file_forever,
                args=(log_path, args.poll_interval),
                name=f"watcher-{os.path.basename(log_path)}",
                daemon=True,
            )
            t.start()
            threads.append(t)
            logger.info("Started watcher thread for %s", log_path)

        # Wait for shutdown signal
        try:
            while _running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        _log_stats()
        logger.info("Unified watcher stopped.")


if __name__ == "__main__":
    main()
