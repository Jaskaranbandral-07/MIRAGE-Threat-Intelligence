"""
MIRAGE — Bot Detector
======================
Statistical bot-vs-human classifier (PRD §14 stretch goal).

Uses inter-command timing analysis to classify sessions as:
  - **bot**    : Very regular timing (CV < 0.3 with >3 commands)
  - **human**  : Irregular or slow timing (CV > 1.0 or avg > 5s)
  - **unknown** : Everything in between

No model, no LLM — just statistical thresholds on timing variance.

Results are returned as dicts; the dashboard API consumes them directly
without requiring a new database column.

Usage::

    from analytics.bot_detector import classify_session, classify_all_sessions, get_bot_stats

    label   = classify_session(session_id=42)
    results = classify_all_sessions()
    stats   = get_bot_stats()
"""

from __future__ import annotations

import logging
import os
import sys
from statistics import mean, pstdev, variance
from typing import Any

# ── Project imports ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import get_db  # noqa: E402

logger = logging.getLogger(__name__)

# ── Classification thresholds ────────────────────────────────────────────────
BOT_CV_THRESHOLD = 0.3        # Below this CV → bot (very regular)
BOT_MIN_COMMANDS = 3          # Must have >3 commands to declare bot
HUMAN_CV_THRESHOLD = 1.0      # Above this CV → human (irregular)
HUMAN_AVG_THRESHOLD_MS = 5000 # Above this avg inter-command time → human (slow)


def _get_inter_command_times(db, session_id: int) -> list[float]:
    """Fetch non-NULL inter-command times for a session, ordered by sequence."""
    rows = db.execute(
        'SELECT time_since_prev_ms FROM commands '
        'WHERE session_id = ? AND time_since_prev_ms IS NOT NULL '
        'ORDER BY sequence_number',
        (session_id,),
    ).fetchall()
    return [float(r['time_since_prev_ms']) for r in rows]


def _get_command_count(db, session_id: int) -> int:
    """Return total command count for a session."""
    row = db.execute(
        'SELECT COUNT(*) AS cnt FROM commands WHERE session_id = ?',
        (session_id,),
    ).fetchone()
    return row['cnt'] if row else 0


def _compute_timing_metrics(times: list[float]) -> dict[str, float | None]:
    """Compute timing metrics from a list of inter-command times (ms).

    Returns
    -------
    dict
        Keys: ``timing_variance``, ``timing_cv``, ``command_regularity``,
        ``avg_inter_command_time_ms``.  Values may be ``None`` if there
        are insufficient data points.
    """
    if len(times) < 2:
        return {
            'timing_variance': None,
            'timing_cv': None,
            'command_regularity': None,
            'avg_inter_command_time_ms': mean(times) if times else None,
        }

    avg = mean(times)
    std = pstdev(times)
    var = variance(times) if len(times) >= 2 else 0.0

    # Coefficient of variation (std / mean), guarding against division by zero.
    cv = (std / avg) if avg > 0 else 0.0

    # Command regularity = max - min of inter-command times
    regularity = max(times) - min(times)

    return {
        'timing_variance': var,
        'timing_cv': cv,
        'command_regularity': regularity,
        'avg_inter_command_time_ms': avg,
    }


# ── Public API ───────────────────────────────────────────────────────────────

def classify_session(session_id: int) -> str:
    """Classify a single session as 'bot', 'human', or 'unknown'.

    Parameters
    ----------
    session_id : int
        Primary key of the session.

    Returns
    -------
    str
        One of ``'bot'``, ``'human'``, or ``'unknown'``.
    """
    db = get_db()
    command_count = _get_command_count(db, session_id)
    times = _get_inter_command_times(db, session_id)
    metrics = _compute_timing_metrics(times)

    cv = metrics['timing_cv']
    avg_ict = metrics['avg_inter_command_time_ms']

    # Not enough data for any classification
    if cv is None or avg_ict is None:
        logger.debug(
            "Session %d: insufficient timing data (commands=%d) → 'unknown'.",
            session_id, command_count,
        )
        return 'unknown'

    # Rule 1: Very regular timing with enough commands → bot
    if cv < BOT_CV_THRESHOLD and command_count > BOT_MIN_COMMANDS:
        logger.debug(
            "Session %d: CV=%.3f < %.1f, commands=%d > %d → 'bot'.",
            session_id, cv, BOT_CV_THRESHOLD, command_count, BOT_MIN_COMMANDS,
        )
        return 'bot'

    # Rule 2: Highly irregular or slow → human
    if cv > HUMAN_CV_THRESHOLD or avg_ict > HUMAN_AVG_THRESHOLD_MS:
        logger.debug(
            "Session %d: CV=%.3f (>%.1f?) or avg=%.0fms (>%dms?) → 'human'.",
            session_id, cv, HUMAN_CV_THRESHOLD, avg_ict, HUMAN_AVG_THRESHOLD_MS,
        )
        return 'human'

    # Rule 3: In-between → unknown
    logger.debug(
        "Session %d: CV=%.3f, avg=%.0fms, commands=%d → 'unknown'.",
        session_id, cv, avg_ict, command_count,
    )
    return 'unknown'


def classify_all_sessions() -> dict[int, str]:
    """Classify every session in the database.

    Returns
    -------
    dict[int, str]
        Mapping of ``session_id`` → classification label.
    """
    db = get_db()
    rows = db.execute('SELECT session_id FROM sessions ORDER BY session_id').fetchall()
    session_ids = [r['session_id'] for r in rows]

    if not session_ids:
        logger.info("No sessions in the database — nothing to classify.")
        return {}

    results: dict[int, str] = {}
    for sid in session_ids:
        results[sid] = classify_session(sid)

    # Log summary
    counts = _count_labels(results)
    logger.info(
        "Bot detection complete: %d session(s) classified — "
        "bot=%d, human=%d, unknown=%d.",
        len(results), counts['bot'], counts['human'], counts['unknown'],
    )
    return results


def get_bot_stats() -> dict[str, Any]:
    """Return aggregate bot-detection statistics for all sessions.

    Returns
    -------
    dict
        Keys: ``total``, ``bot``, ``human``, ``unknown``,
        ``bot_pct``, ``human_pct``, ``unknown_pct``.
    """
    results = classify_all_sessions()
    counts = _count_labels(results)
    total = len(results)

    if total == 0:
        return {
            'total': 0,
            'bot': 0, 'human': 0, 'unknown': 0,
            'bot_pct': 0.0, 'human_pct': 0.0, 'unknown_pct': 0.0,
        }

    return {
        'total': total,
        'bot': counts['bot'],
        'human': counts['human'],
        'unknown': counts['unknown'],
        'bot_pct': round(counts['bot'] / total * 100, 1),
        'human_pct': round(counts['human'] / total * 100, 1),
        'unknown_pct': round(counts['unknown'] / total * 100, 1),
    }


def _count_labels(results: dict[int, str]) -> dict[str, int]:
    """Count occurrences of each classification label."""
    counts = {'bot': 0, 'human': 0, 'unknown': 0}
    for label in results.values():
        counts[label] = counts.get(label, 0) + 1
    return counts


# ── CLI entry-point ──────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    )
    from database.db import init_db  # noqa: E402
    init_db()

    stats = get_bot_stats()
    print(f"\n{'='*60}")
    print("BOT DETECTION RESULTS")
    print(f"{'='*60}")
    for key, val in stats.items():
        print(f"  {key}: {val}")

    # Detailed per-session output
    results = classify_all_sessions()
    if results:
        print(f"\n{'='*60}")
        print("PER-SESSION CLASSIFICATIONS")
        print(f"{'='*60}")
        for sid, label in sorted(results.items()):
            print(f"  Session {sid:>5d}: {label}")
