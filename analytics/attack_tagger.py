"""
MIRAGE — ATT&CK Tagger
========================
Rule-based MITRE ATT&CK technique tagger (PRD §8).

Behavior:
  1. Load all regex patterns from the ``technique_signatures`` table.
  2. Compile every pattern once (cached at module/instance level).
  3. For each session, match every command against every compiled pattern.
  4. Insert matches into ``session_techniques`` (INSERT OR IGNORE).
  5. Report match statistics.

All classification is rule-based — zero LLM / generative-AI calls.

Usage::

    from analytics.attack_tagger import tag_session, tag_all_sessions, get_session_techniques

    n_matches = tag_session(session_id=42)
    summary   = tag_all_sessions()
    techs     = get_session_techniques(session_id=42)
"""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import Any

# ── Project imports ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import get_db  # noqa: E402

logger = logging.getLogger(__name__)


class _PatternCache:
    """Lazily loads and compiles all technique-signature regex patterns.

    Patterns are compiled once and reused across all sessions and commands,
    avoiding redundant re-compilation on every invocation.
    """

    def __init__(self) -> None:
        self._patterns: list[dict[str, Any]] | None = None

    def _load(self) -> None:
        """Load patterns from the database and compile regexes."""
        db = get_db()
        rows = db.execute(
            'SELECT signature_id, pattern, attack_technique_id, technique_name '
            'FROM technique_signatures'
        ).fetchall()

        self._patterns = []
        for row in rows:
            sig_id = row['signature_id']
            raw_pattern = row['pattern']
            try:
                compiled = re.compile(raw_pattern, re.IGNORECASE)
            except re.error as exc:
                logger.warning(
                    "Invalid regex in signature %d ('%s'): %s — skipping.",
                    sig_id, raw_pattern, exc,
                )
                continue

            self._patterns.append({
                'signature_id': sig_id,
                'compiled': compiled,
                'attack_technique_id': row['attack_technique_id'],
                'technique_name': row['technique_name'],
            })

        logger.info("Loaded and compiled %d technique signature(s).", len(self._patterns))

    @property
    def patterns(self) -> list[dict[str, Any]]:
        """Return compiled patterns, loading from DB on first access."""
        if self._patterns is None:
            self._load()
        return self._patterns  # type: ignore[return-value]

    def reload(self) -> None:
        """Force a reload from the database (useful after inserting new signatures)."""
        self._patterns = None
        logger.info("Pattern cache invalidated — will reload on next access.")


# Module-level singleton pattern cache.
_cache = _PatternCache()


def _get_commands(db, session_id: int) -> list[dict]:
    """Fetch all commands for a session, ordered by sequence_number."""
    rows = db.execute(
        'SELECT command_id, raw_input FROM commands '
        'WHERE session_id = ? ORDER BY sequence_number',
        (session_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _get_untagged_session_ids(db) -> list[int]:
    """Return session IDs that have at least one command but are not yet
    fully represented in ``session_techniques``.

    A session is considered *untagged* if the number of distinct signatures
    matched against it is fewer than the total number of signatures that
    could potentially match.  In practice, we simply re-scan sessions that
    have zero entries in ``session_techniques`` to avoid expensive counting.
    """
    rows = db.execute(
        'SELECT DISTINCT s.session_id '
        'FROM sessions s '
        'JOIN commands c ON c.session_id = s.session_id '
        'WHERE s.session_id NOT IN ('
        '    SELECT DISTINCT session_id FROM session_techniques'
        ') '
        'ORDER BY s.session_id'
    ).fetchall()
    return [r['session_id'] for r in rows]


# ── Public API ───────────────────────────────────────────────────────────────

def tag_session(session_id: int) -> int:
    """Tag a single session with matching ATT&CK techniques.

    Parameters
    ----------
    session_id : int
        Primary key of the session to tag.

    Returns
    -------
    int
        Number of new technique matches inserted.
    """
    db = get_db()
    commands = _get_commands(db, session_id)

    if not commands:
        logger.debug("Session %d has no commands — nothing to tag.", session_id)
        return 0

    patterns = _cache.patterns
    if not patterns:
        logger.warning("No technique signatures loaded — nothing to match against.")
        return 0

    match_count = 0
    for cmd in commands:
        raw_input = cmd['raw_input']
        command_id = cmd['command_id']

        for pat in patterns:
            if pat['compiled'].search(raw_input):
                try:
                    db.execute(
                        'INSERT OR IGNORE INTO session_techniques '
                        '(session_id, signature_id, matched_command_id) '
                        'VALUES (?, ?, ?)',
                        (session_id, pat['signature_id'], command_id),
                    )
                    match_count += 1
                except Exception as exc:
                    logger.error(
                        "Failed to insert match (session=%d, sig=%d, cmd=%d): %s",
                        session_id, pat['signature_id'], command_id, exc,
                    )

    db.commit()
    logger.debug("Session %d: %d technique match(es) inserted.", session_id, match_count)
    return match_count


def tag_all_sessions() -> dict[str, Any]:
    """Tag all untagged sessions with matching ATT&CK techniques.

    Returns
    -------
    dict
        Summary with keys: ``sessions_tagged``, ``total_matches``,
        ``message``.
    """
    db = get_db()
    untagged = _get_untagged_session_ids(db)

    if not untagged:
        msg = "No untagged sessions found."
        logger.info(msg)
        return {'sessions_tagged': 0, 'total_matches': 0, 'message': msg}

    # Ensure patterns are loaded before the loop (fail-fast)
    patterns = _cache.patterns
    if not patterns:
        msg = "No technique signatures in the database — cannot tag."
        logger.warning(msg)
        return {'sessions_tagged': 0, 'total_matches': 0, 'message': msg}

    total_matches = 0
    sessions_tagged = 0

    for sid in untagged:
        n = tag_session(sid)
        if n > 0:
            sessions_tagged += 1
        total_matches += n

    msg = (
        f"Tagged {sessions_tagged} session(s) with "
        f"{total_matches} technique match(es) across {len(untagged)} candidate(s)."
    )
    logger.info(msg)
    return {
        'sessions_tagged': sessions_tagged,
        'total_matches': total_matches,
        'sessions_scanned': len(untagged),
        'message': msg,
    }


def get_session_techniques(session_id: int) -> list[dict]:
    """Return all ATT&CK techniques matched for a given session.

    Parameters
    ----------
    session_id : int
        Primary key of the session.

    Returns
    -------
    list[dict]
        Each dict contains: ``signature_id``, ``attack_technique_id``,
        ``technique_name``, ``pattern``, ``matched_command_id``,
        ``raw_input`` (the command that triggered the match).
    """
    db = get_db()
    rows = db.execute(
        'SELECT st.signature_id, ts.attack_technique_id, ts.technique_name, '
        '       ts.pattern, st.matched_command_id, c.raw_input '
        'FROM session_techniques st '
        'JOIN technique_signatures ts ON st.signature_id = ts.signature_id '
        'LEFT JOIN commands c ON st.matched_command_id = c.command_id '
        'WHERE st.session_id = ? '
        'ORDER BY ts.attack_technique_id',
        (session_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def reload_patterns() -> None:
    """Force reload of technique signature patterns from the database."""
    _cache.reload()


# ── CLI entry-point ──────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    )
    from database.db import init_db  # noqa: E402
    init_db()

    summary = tag_all_sessions()
    print(f"\n{'='*60}")
    print("ATT&CK TAGGING RESULTS")
    print(f"{'='*60}")
    for key, val in summary.items():
        print(f"  {key}: {val}")
