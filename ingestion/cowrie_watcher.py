#!/usr/bin/env python3
"""
MIRAGE Ingestion — Cowrie SSH Honeypot Log Watcher
==================================================

Long-running daemon that tails Cowrie's JSON log file and normalises
every event into the MIRAGE database (sources → sessions → commands).

Supports two modes:
  • **live** (default) — continuously watches the log file for new lines
  • **batch** (``--batch``) — processes the entire file once and exits

Usage::

    # Live daemon
    python cowrie_watcher.py

    # One-shot batch import
    python cowrie_watcher.py --batch

No LLM/AI calls — all processing is deterministic.
"""

import sys
import os
import json
import time
import signal
import logging
import argparse
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Path bootstrap — project root on sys.path
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import get_db, init_db
from config import Config

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("mirage.cowrie_watcher")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
# Maps Cowrie hex session IDs → our integer session_ids in the DB
_session_map: dict[str, int] = {}

# Tracks the next sequence number for each DB session_id
_seq_counters: dict[int, int] = {}

# Tracks the ISO timestamp of the last command per DB session_id
_last_ts: dict[int, str] = {}

# Graceful-shutdown flag
_running = True

# Stats
_stats = {"processed": 0, "skipped": 0, "errors": 0}


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
    Normalise a Cowrie timestamp into our standard ISO format.
    Falls back to *now* if the string is missing or unparseable.
    """
    if not ts_str:
        return _now_iso()
    try:
        # Cowrie typically uses ISO-8601 with or without trailing Z
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (ValueError, TypeError):
        return _now_iso()


def _compute_delta_ms(session_id: int, current_iso: str) -> int | None:
    """
    Return milliseconds since the previous command in this session,
    or None if this is the first command.
    """
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
    seq = _seq_counters.get(session_id, 0) + 1
    _seq_counters[session_id] = seq
    return seq


# ==========================================================================
# Database helpers
# ==========================================================================

def _upsert_source(db, ip: str, ts_iso: str):
    """Insert or update the ``sources`` row for this IP."""
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


def _create_session(db, ip: str, ts_iso: str) -> int:
    """Insert a new SSH session and return its ``session_id``."""
    cursor = db.execute(
        """
        INSERT INTO sessions (source_ip, protocol, start_time)
        VALUES (?, 'ssh', ?)
        """,
        (ip, ts_iso),
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
    """Record a single command for the given session."""
    seq = _next_seq(session_id)
    delta_ms = _compute_delta_ms(session_id, ts_iso)

    db.execute(
        """
        INSERT INTO commands
            (session_id, sequence_number, raw_input, timestamp, time_since_prev_ms)
        VALUES (?, ?, ?, ?, ?)
        """,
        (session_id, seq, raw_input, ts_iso, delta_ms),
    )
    db.commit()

    # Update last-timestamp tracker
    _last_ts[session_id] = ts_iso


# ==========================================================================
# Event dispatch
# ==========================================================================

def _process_event(db, event: dict):
    """
    Dispatch a single Cowrie JSON event to the appropriate DB handler.

    Recognised event types:
      - cowrie.session.connect
      - cowrie.login.success / cowrie.login.failed
      - cowrie.command.input / cowrie.command.failed
      - cowrie.session.file_download
      - cowrie.session.closed
    """
    eid = event.get("eventid", "")
    ts  = _parse_ts(event.get("timestamp"))
    ip  = event.get("src_ip", "unknown")
    hex_sid = event.get("session", "")

    # ------------------------------------------------------------------
    # cowrie.session.connect — new SSH session
    # ------------------------------------------------------------------
    if eid == "cowrie.session.connect":
        _upsert_source(db, ip, ts)
        sid = _create_session(db, ip, ts)
        _session_map[hex_sid] = sid
        logger.debug("New session: cowrie=%s → db=%s  ip=%s", hex_sid, sid, ip)
        return

    # Resolve the DB session_id; skip if we never saw the connect event
    db_sid = _session_map.get(hex_sid)
    if db_sid is None:
        # Late-join: create session on-the-fly so we don't lose data
        _upsert_source(db, ip, ts)
        db_sid = _create_session(db, ip, ts)
        _session_map[hex_sid] = db_sid
        logger.debug("Late-join session: cowrie=%s → db=%s  ip=%s", hex_sid, db_sid, ip)

    # ------------------------------------------------------------------
    # cowrie.login.success
    # ------------------------------------------------------------------
    if eid == "cowrie.login.success":
        user = event.get("username", "?")
        pwd  = event.get("password", "?")
        _insert_command(db, db_sid, f"LOGIN SUCCESS: {user}/{pwd}", ts)

    # ------------------------------------------------------------------
    # cowrie.login.failed
    # ------------------------------------------------------------------
    elif eid == "cowrie.login.failed":
        user = event.get("username", "?")
        pwd  = event.get("password", "?")
        _insert_command(db, db_sid, f"LOGIN FAILED: {user}/{pwd}", ts)

    # ------------------------------------------------------------------
    # cowrie.command.input
    # ------------------------------------------------------------------
    elif eid == "cowrie.command.input":
        cmd = event.get("input", "")
        _insert_command(db, db_sid, cmd, ts)

    # ------------------------------------------------------------------
    # cowrie.command.failed
    # ------------------------------------------------------------------
    elif eid == "cowrie.command.failed":
        cmd = event.get("input", "")
        _insert_command(db, db_sid, f"{cmd} (FAILED)", ts)

    # ------------------------------------------------------------------
    # cowrie.session.file_download
    # ------------------------------------------------------------------
    elif eid == "cowrie.session.file_download":
        url = event.get("url", event.get("outfile", "unknown"))
        _insert_command(db, db_sid, f"FILE_DOWNLOAD: {url}", ts)

    # ------------------------------------------------------------------
    # cowrie.session.closed
    # ------------------------------------------------------------------
    elif eid == "cowrie.session.closed":
        # Fetch start_time from the DB for duration calculation
        row = db.execute(
            "SELECT start_time FROM sessions WHERE session_id = ?",
            (db_sid,),
        ).fetchone()
        start_ts = row["start_time"] if row else None
        _close_session(db, db_sid, ts, start_ts)

        # Clean up in-memory maps
        _session_map.pop(hex_sid, None)
        _seq_counters.pop(db_sid, None)
        _last_ts.pop(db_sid, None)
        logger.debug("Closed session: db=%s", db_sid)

    else:
        # Unknown event — skip silently
        _stats["skipped"] += 1
        return

    _stats["processed"] += 1


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
            _stats["errors"] += 1


def _batch_process(path: str):
    """Read the entire Cowrie log file and import every event."""
    logger.info("Batch processing %s …", path)
    db = get_db()

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, event in _read_lines(fh):
            try:
                _process_event(db, event)
            except Exception:
                logger.exception("Error processing line %d — skipping", lineno)
                _stats["errors"] += 1

    _log_stats()
    logger.info("Batch import complete.")


def _tail_file(path: str, poll_interval: float = 1.0):
    """
    Continuously tail the Cowrie log file.  Uses simple size-based polling
    (no external dependency required).
    """
    logger.info("Tailing %s (poll every %.1fs) …", path, poll_interval)
    db = get_db()

    # If the file doesn't exist yet, wait for it
    while _running and not os.path.exists(path):
        logger.info("Waiting for log file to appear: %s", path)
        time.sleep(poll_interval * 5)

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
                        logger.info("Log file appears rotated — reopening")
                        fh.close()
                        fh_new = open(path, "r", encoding="utf-8", errors="replace")
                        # Replace file handle reference (Python lets us rebind)
                        # We break and restart via outer loop instead
                        break
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
                logger.warning("Skipping malformed JSON line: %s", exc)
                _stats["errors"] += 1
                continue

            try:
                _process_event(db, event)
            except Exception:
                logger.exception("Error processing live event — skipping")
                _stats["errors"] += 1


def _log_stats():
    """Emit current processing statistics."""
    logger.info(
        "Stats — processed=%d  skipped=%d  errors=%d  active_sessions=%d",
        _stats["processed"],
        _stats["skipped"],
        _stats["errors"],
        len(_session_map),
    )


# ==========================================================================
# Entry point
# ==========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="MIRAGE — Cowrie SSH log watcher and database ingestion daemon",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Process the existing log file in one pass and exit (no tailing)",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Override the Cowrie log path (default: Config.COWRIE_LOG_PATH)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Seconds between poll cycles in live mode (default: 1.0)",
    )
    args = parser.parse_args()

    log_path = args.log_file or getattr(Config, "COWRIE_LOG_PATH", "/var/log/cowrie/cowrie.json")

    # Ensure the database schema exists
    try:
        init_db()
        logger.info("Database initialised.")
    except Exception:
        logger.exception("Could not initialise database — proceeding anyway")

    if args.batch:
        _batch_process(log_path)
    else:
        # Live tail — restart on rotation
        while _running:
            try:
                _tail_file(log_path, poll_interval=args.poll_interval)
            except Exception:
                logger.exception("Tail loop crashed — restarting in 5s")
                time.sleep(5)

        _log_stats()
        logger.info("Cowrie watcher stopped.")


if __name__ == "__main__":
    main()
