"""
MIRAGE — Central Configuration Module
======================================
All runtime settings are loaded from environment variables with sensible
defaults.  Import ``Config`` wherever you need a setting:

    from config import Config
    db_path = Config.DATABASE_PATH

No LLM / generative-AI calls are used anywhere in MIRAGE.
All classification is rule-based or statistical.
"""

import os


class Config:
    """Immutable-style configuration namespace.

    Every attribute can be overridden via the corresponding environment
    variable (see ``.env.example`` for the full list).
    """

    # ── Paths ───────────────────────────────────────────────────────────
    DATABASE_PATH = os.environ.get(
        'MIRAGE_DB_PATH',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mirage.db'),
    )
    COWRIE_LOG_PATH = os.environ.get(
        'COWRIE_LOG_PATH', '/var/log/cowrie/cowrie.json'
    )

    # ── Dashboard server ────────────────────────────────────────────────
    DASHBOARD_HOST = os.environ.get('DASHBOARD_HOST', '0.0.0.0')
    DASHBOARD_PORT = int(os.environ.get('DASHBOARD_PORT', 5000))
    SECRET_KEY = os.environ.get('SECRET_KEY', 'mirage-dashboard-secret')

    # ── Decoy HTTP server ───────────────────────────────────────────────
    DECOY_HOST = os.environ.get('DECOY_HOST', '0.0.0.0')
    DECOY_PORT = int(os.environ.get('DECOY_PORT', 8080))

    # ── Clustering parameters (DBSCAN) ──────────────────────────────────
    CLUSTER_EPS = float(os.environ.get('CLUSTER_EPS', 0.5))
    CLUSTER_MIN_SAMPLES = int(os.environ.get('CLUSTER_MIN_SAMPLES', 3))

    # ── Feature flags ───────────────────────────────────────────────────
    ENABLE_BOT_DETECTION = (
        os.environ.get('ENABLE_BOT_DETECTION', 'true').lower() == 'true'
    )
    ENABLE_LIVE_FEED = (
        os.environ.get('ENABLE_LIVE_FEED', 'true').lower() == 'true'
    )

    # ── HTTP session grouping ───────────────────────────────────────────
    # Requests from the same IP within this window are grouped into one session.
    HTTP_SESSION_WINDOW_SECONDS = int(
        os.environ.get('HTTP_SESSION_WINDOW', 1800)  # 30 minutes
    )

    # ── Dashboard auto-refresh interval (seconds) ──────────────────────
    DASHBOARD_REFRESH_INTERVAL = int(
        os.environ.get('DASHBOARD_REFRESH', 30)
    )
