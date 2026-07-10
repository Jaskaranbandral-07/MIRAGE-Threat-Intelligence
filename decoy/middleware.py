"""
MIRAGE Decoy Middleware — HTTP Request Logger

Intercepts every Flask request and logs it into the MIRAGE database:
  - Upserts source IP into `sources`
  - Groups requests into sessions (30-min window by default)
  - Records each request as a `commands` row with sequencing and timing

Designed to be non-intrusive: all DB errors are caught so logging
never crashes the honeypot application itself.
"""

import sys
import os
import time
import logging
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Path bootstrap — allow imports from the project root
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import get_db
from config import Config

logger = logging.getLogger("mirage.middleware")

# ---------------------------------------------------------------------------
# Internal state: per-request timing stash
# ---------------------------------------------------------------------------
_REQUEST_START_ATTR = "_mirage_req_start"


def _get_client_ip(request):
    """
    Extract the real client IP.  Honour X-Forwarded-For when present (first
    entry) so that the system works behind reverse proxies / Docker.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _now_iso():
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _upsert_source(db, ip):
    """
    Insert the source IP if new, or update last_seen and bump session_count.
    Uses INSERT … ON CONFLICT for an atomic upsert.
    """
    now = _now_iso()
    db.execute(
        """
        INSERT INTO sources (ip_address, first_seen, last_seen, session_count)
        VALUES (?, ?, ?, 1)
        ON CONFLICT(ip_address) DO UPDATE SET
            last_seen     = excluded.last_seen,
            session_count = session_count + 1
        """,
        (ip, now, now),
    )
    db.commit()


def _find_or_create_session(db, ip):
    """
    Look for an active HTTP session from this IP whose last command was
    within the configured window (default 1800 s).  Reuse it if found;
    otherwise create a fresh one.

    Returns (session_id, is_new_session).
    """
    window = getattr(Config, "HTTP_SESSION_WINDOW_SECONDS", 1800)
    now = _now_iso()

    # Find most recent HTTP session from this IP
    row = db.execute(
        """
        SELECT s.session_id, MAX(c.timestamp) AS last_cmd_ts
        FROM sessions s
        LEFT JOIN commands c ON c.session_id = s.session_id
        WHERE s.source_ip = ? AND s.protocol = 'http'
        GROUP BY s.session_id
        ORDER BY s.start_time DESC
        LIMIT 1
        """,
        (ip,),
    ).fetchone()

    if row and row["last_cmd_ts"]:
        try:
            last_ts = datetime.fromisoformat(
                row["last_cmd_ts"].replace("Z", "+00:00")
            )
            now_dt = datetime.now(timezone.utc)
            delta = (now_dt - last_ts).total_seconds()
            if delta <= window:
                return row["session_id"], False
        except (ValueError, TypeError):
            pass  # Fall through to create a new session

    # Create a new session
    cursor = db.execute(
        """
        INSERT INTO sessions (source_ip, protocol, start_time)
        VALUES (?, 'http', ?)
        """,
        (ip, now),
    )
    db.commit()
    return cursor.lastrowid, True


def _next_sequence(db, session_id):
    """Return the next sequence_number for a given session."""
    row = db.execute(
        "SELECT COALESCE(MAX(sequence_number), 0) AS mx FROM commands WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    return (row["mx"] if row else 0) + 1


def _time_since_prev(db, session_id, current_ts_iso):
    """
    Compute milliseconds elapsed since the previous command in this session.
    Returns None if this is the first command.
    """
    row = db.execute(
        """
        SELECT timestamp FROM commands
        WHERE session_id = ?
        ORDER BY sequence_number DESC
        LIMIT 1
        """,
        (session_id,),
    ).fetchone()

    if not row or not row["timestamp"]:
        return None

    try:
        prev_dt = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
        curr_dt = datetime.fromisoformat(current_ts_iso.replace("Z", "+00:00"))
        return max(0, int((curr_dt - prev_dt).total_seconds() * 1000))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_middleware(app):
    """
    Register before_request / after_request hooks on the given Flask app
    so that every HTTP request is logged into the MIRAGE database.
    """

    @app.before_request
    def _before():
        """Stash the request start time for later duration calculation."""
        from flask import request, g
        g._mirage_req_start = time.time()

    @app.after_request
    def _after(response):
        """
        Log the completed request into the database.

        Steps:
          1. Upsert source IP
          2. Find or create an HTTP session
          3. Insert a commands row
        """
        from flask import request, g

        try:
            ip = _get_client_ip(request)
            
            # Ignore local health checks to prevent database pollution
            if ip in ("127.0.0.1", "localhost"):
                return response
                
            raw_input = f"{request.method} {request.path}"
            now = _now_iso()

            db = get_db()

            # 1. Upsert source
            _upsert_source(db, ip)

            # 2. Session management
            session_id, _ = _find_or_create_session(db, ip)

            # 3. Command insertion
            seq = _next_sequence(db, session_id)
            delta_ms = _time_since_prev(db, session_id, now)

            db.execute(
                """
                INSERT INTO commands
                    (session_id, sequence_number, raw_input, timestamp, time_since_prev_ms)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_id, seq, raw_input, now, delta_ms),
            )
            db.commit()

            # Log for observability
            logger.debug(
                "Logged request: ip=%s session=%s seq=%s input=%s",
                ip, session_id, seq, raw_input,
            )

        except Exception:
            # NEVER let logging break the decoy
            logger.exception("Middleware DB logging failed — swallowed error")

        return response
