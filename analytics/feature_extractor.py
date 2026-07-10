"""
MIRAGE — Feature Extractor
===========================
Extracts per-session feature vectors for clustering (PRD §7).

Every session is reduced to a fixed-length numeric vector capturing:
  - Volume metrics (command count, unique ratio, duration)
  - Timing metrics (mean/std of inter-command intervals)
  - Binary tool-presence flags (wget, curl, nmap, mining tools, etc.)

All classification is rule-based or statistical — zero LLM calls.

Usage::

    from analytics.feature_extractor import extract_features, extract_all_features, get_feature_matrix

    features = extract_features(session_id=42)
    df        = extract_all_features()
    matrix, ids = get_feature_matrix()
"""

from __future__ import annotations

import logging
import os
import re
import sys
from statistics import mean, pstdev
from typing import Any

import numpy as np
import pandas as pd

# ── Project imports ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import get_db  # noqa: E402

logger = logging.getLogger(__name__)

# ── Feature definitions ─────────────────────────────────────────────────────
# Each binary flag is defined as (feature_name, detection_function).
# Detection functions take raw_input (str) and return bool.

_NC_RE = re.compile(r'\bnc\b|ncat|socat', re.IGNORECASE)
_DD_RE = re.compile(r'\bdd\b', re.IGNORECASE)

BINARY_FLAGS: list[tuple[str, Any]] = [
    ('has_wget',       lambda cmd: 'wget' in cmd.lower()),
    ('has_curl',       lambda cmd: 'curl' in cmd.lower()),
    ('has_chmod',      lambda cmd: 'chmod' in cmd.lower()),
    ('has_etc_passwd', lambda cmd: '/etc/passwd' in cmd.lower()),
    ('has_etc_shadow', lambda cmd: '/etc/shadow' in cmd.lower()),
    ('has_python',     lambda cmd: 'python' in cmd.lower()),
    ('has_perl',       lambda cmd: 'perl' in cmd.lower()),
    ('has_base64',     lambda cmd: 'base64' in cmd.lower()),
    ('has_nc',         lambda cmd: bool(_NC_RE.search(cmd))),
    ('has_nmap',       lambda cmd: 'nmap' in cmd.lower()),
    ('has_dd',         lambda cmd: bool(_DD_RE.search(cmd))),
    ('has_crontab',    lambda cmd: 'crontab' in cmd.lower() or '/etc/cron' in cmd.lower()),
    ('has_ssh_keygen', lambda cmd: 'ssh-keygen' in cmd.lower() or 'authorized_keys' in cmd.lower()),
    ('has_mining',     lambda cmd: any(tok in cmd.lower() for tok in ('xmrig', 'minerd', 'stratum', 'cryptonight'))),
]

# Ordered list of all feature names (used to guarantee consistent column order).
FEATURE_NAMES: list[str] = [
    'command_count',
    'unique_command_ratio',
    'avg_inter_command_time_ms',
    'std_inter_command_time_ms',
    'duration_seconds',
] + [name for name, _ in BINARY_FLAGS]


def _fetch_commands(db, session_id: int) -> list[dict]:
    """Fetch all commands for a session, ordered by sequence_number."""
    rows = db.execute(
        'SELECT command_id, raw_input, time_since_prev_ms '
        'FROM commands WHERE session_id = ? ORDER BY sequence_number',
        (session_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _fetch_session(db, session_id: int) -> dict | None:
    """Fetch session metadata."""
    row = db.execute(
        'SELECT session_id, duration_seconds FROM sessions WHERE session_id = ?',
        (session_id,),
    ).fetchone()
    return dict(row) if row else None


def extract_features(session_id: int) -> dict:
    """Extract the full feature vector for a single session.

    Parameters
    ----------
    session_id : int
        Primary key of the session in the ``sessions`` table.

    Returns
    -------
    dict
        Mapping of feature name → numeric value.  Returns an empty dict
        if the session does not exist.
    """
    db = get_db()
    session = _fetch_session(db, session_id)
    if session is None:
        logger.warning("Session %d not found — returning empty feature dict.", session_id)
        return {}

    commands = _fetch_commands(db, session_id)
    raw_inputs = [c['raw_input'] for c in commands]
    command_count = len(raw_inputs)

    # ── Volume metrics ───────────────────────────────────────────────────
    if command_count == 0:
        unique_ratio = 0.0
    else:
        unique_ratio = len(set(raw_inputs)) / command_count

    # ── Timing metrics ───────────────────────────────────────────────────
    inter_times = [
        c['time_since_prev_ms']
        for c in commands
        if c['time_since_prev_ms'] is not None
    ]
    if inter_times:
        avg_ict = mean(inter_times)
        std_ict = pstdev(inter_times)  # population std-dev
    else:
        avg_ict = 0.0
        std_ict = 0.0

    duration = session.get('duration_seconds') or 0

    # ── Binary flags ─────────────────────────────────────────────────────
    flag_values: dict[str, int] = {}
    for flag_name, detector in BINARY_FLAGS:
        flag_values[flag_name] = int(any(detector(cmd) for cmd in raw_inputs))

    # ── Assemble final vector ────────────────────────────────────────────
    features: dict[str, float] = {
        'command_count': float(command_count),
        'unique_command_ratio': unique_ratio,
        'avg_inter_command_time_ms': avg_ict,
        'std_inter_command_time_ms': std_ict,
        'duration_seconds': float(duration),
    }
    features.update({k: float(v) for k, v in flag_values.items()})

    logger.debug(
        "Extracted %d features for session %d (commands=%d).",
        len(features), session_id, command_count,
    )
    return features


def extract_all_features() -> pd.DataFrame:
    """Extract feature vectors for **every** session in the database.

    Returns
    -------
    pd.DataFrame
        DataFrame indexed by ``session_id`` with one column per feature.
        Returns an empty DataFrame (with correct columns) if no sessions
        exist.
    """
    db = get_db()
    rows = db.execute('SELECT session_id FROM sessions ORDER BY session_id').fetchall()
    session_ids = [r['session_id'] for r in rows]

    if not session_ids:
        logger.info("No sessions found — returning empty DataFrame.")
        return pd.DataFrame(columns=FEATURE_NAMES)

    records: list[dict] = []
    for sid in session_ids:
        feats = extract_features(sid)
        if feats:
            feats['session_id'] = sid
            records.append(feats)

    if not records:
        logger.info("No feature records produced — returning empty DataFrame.")
        return pd.DataFrame(columns=FEATURE_NAMES)

    df = pd.DataFrame(records).set_index('session_id')
    # Guarantee column order
    df = df.reindex(columns=FEATURE_NAMES, fill_value=0.0)
    logger.info("Extracted features for %d sessions (%d features each).", len(df), len(FEATURE_NAMES))
    return df


def get_feature_matrix() -> tuple[np.ndarray, list[int]]:
    """Return the feature matrix and corresponding session IDs, ready for
    clustering.

    Returns
    -------
    tuple[np.ndarray, list[int]]
        ``(feature_matrix, session_ids)`` where ``feature_matrix`` has shape
        ``(n_sessions, n_features)`` and ``session_ids`` is the ordered list
        of session IDs matching each row.
    """
    df = extract_all_features()
    if df.empty:
        logger.info("Feature matrix is empty — no sessions available.")
        return np.empty((0, len(FEATURE_NAMES))), []

    session_ids = df.index.tolist()
    matrix = df.values.astype(np.float64)
    logger.info("Feature matrix shape: %s", matrix.shape)
    return matrix, session_ids


# ── CLI entry-point ──────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    )
    from database.db import init_db  # noqa: E402
    init_db()

    df = extract_all_features()
    if df.empty:
        print("No sessions in the database — nothing to extract.")
    else:
        print(f"\n{'='*60}")
        print(f"Feature matrix: {df.shape[0]} sessions × {df.shape[1]} features")
        print(f"{'='*60}")
        print(df.describe().to_string())
        print(f"\n{'='*60}")
        print(df.to_string())
