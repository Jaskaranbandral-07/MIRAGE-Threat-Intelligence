"""
MIRAGE — Analytics Pipeline Orchestrator
==========================================
Runs the full analytics pipeline in sequence:

  1. Initialize database
  2. Feature extraction (all sessions)
  3. DBSCAN clustering (campaign discovery)
  4. MITRE ATT&CK tagging (rule-based)
  5. Bot-vs-human detection (statistical)
  6. Summary report

Runnable as::

    python -m analytics.run_analytics
    python analytics/run_analytics.py
    python analytics/run_analytics.py --verbose

All classification is rule-based or statistical — zero LLM calls.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Any

# ── Project imports ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import init_db  # noqa: E402

from analytics.feature_extractor import extract_all_features  # noqa: E402
from analytics.clustering import run_clustering  # noqa: E402
from analytics.attack_tagger import tag_all_sessions  # noqa: E402
from analytics.bot_detector import classify_all_sessions, get_bot_stats  # noqa: E402

logger = logging.getLogger(__name__)

# ── Pretty-print helpers ────────────────────────────────────────────────────

_DIVIDER = '═' * 70
_THIN_DIVIDER = '─' * 70


def _banner(title: str) -> str:
    """Return a boxed section header."""
    return f"\n{_DIVIDER}\n  {title}\n{_DIVIDER}"


def _section(title: str) -> str:
    """Return a light section header."""
    return f"\n{_THIN_DIVIDER}\n  {title}\n{_THIN_DIVIDER}"


def _print_dict(d: dict[str, Any], indent: int = 4) -> None:
    """Print a dict with indentation, truncating long lists."""
    prefix = ' ' * indent
    for key, val in d.items():
        if isinstance(val, list) and len(val) > 20:
            logger.info("%s%s: [%d items]", prefix, key, len(val))
        else:
            logger.info("%s%s: %s", prefix, key, val)


# ── Pipeline ─────────────────────────────────────────────────────────────────

def run_pipeline(verbose: bool = False) -> dict[str, Any]:
    """Execute the full MIRAGE analytics pipeline.

    Parameters
    ----------
    verbose : bool
        If ``True``, set logging to DEBUG for more granular output.

    Returns
    -------
    dict
        Combined results from all pipeline stages.
    """
    pipeline_start = time.time()
    results: dict[str, Any] = {}

    # ── Step 1: Initialize database ──────────────────────────────────────
    logger.info(_banner("MIRAGE ANALYTICS PIPELINE"))
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized successfully.")

    # ── Step 2: Feature extraction ───────────────────────────────────────
    logger.info(_section("Stage 1 — Feature Extraction"))
    t0 = time.time()
    try:
        df = extract_all_features()
        elapsed = time.time() - t0
        results['feature_extraction'] = {
            'sessions': len(df),
            'features': len(df.columns) if not df.empty else 0,
            'elapsed_seconds': round(elapsed, 3),
        }
        logger.info(
            "    Extracted %d features from %d session(s) in %.3fs.",
            len(df.columns) if not df.empty else 0,
            len(df),
            elapsed,
        )
        if verbose and not df.empty:
            logger.debug("    Feature statistics:\n%s", df.describe().to_string())
    except Exception as exc:
        logger.error("    Feature extraction failed: %s", exc, exc_info=verbose)
        results['feature_extraction'] = {'error': str(exc)}

    # ── Step 3: Clustering ───────────────────────────────────────────────
    logger.info(_section("Stage 2 — Campaign Clustering (DBSCAN)"))
    t0 = time.time()
    try:
        cluster_results = run_clustering()
        elapsed = time.time() - t0
        cluster_results['elapsed_seconds'] = round(elapsed, 3)
        results['clustering'] = cluster_results
        logger.info("    %s", cluster_results.get('message', 'Done.'))
        logger.info(
            "    Clusters: %d | Noise: %d | Silhouette: %s | Time: %.3fs",
            cluster_results.get('n_clusters', 0),
            cluster_results.get('noise_count', 0),
            cluster_results.get('silhouette_score', 'N/A'),
            elapsed,
        )
        if verbose and cluster_results.get('features_dropped'):
            logger.debug(
                "    Features dropped by Spearman filter: %s",
                cluster_results['features_dropped'],
            )
    except Exception as exc:
        logger.error("    Clustering failed: %s", exc, exc_info=verbose)
        results['clustering'] = {'error': str(exc)}

    # ── Step 4: ATT&CK tagging ──────────────────────────────────────────
    logger.info(_section("Stage 3 — MITRE ATT&CK Tagging"))
    t0 = time.time()
    try:
        tag_results = tag_all_sessions()
        elapsed = time.time() - t0
        tag_results['elapsed_seconds'] = round(elapsed, 3)
        results['attack_tagging'] = tag_results
        logger.info("    %s", tag_results.get('message', 'Done.'))
        logger.info(
            "    Sessions tagged: %d | Total matches: %d | Time: %.3fs",
            tag_results.get('sessions_tagged', 0),
            tag_results.get('total_matches', 0),
            elapsed,
        )
    except Exception as exc:
        logger.error("    ATT&CK tagging failed: %s", exc, exc_info=verbose)
        results['attack_tagging'] = {'error': str(exc)}

    # ── Step 5: Bot detection ────────────────────────────────────────────
    logger.info(_section("Stage 4 — Bot Detection (Statistical)"))
    t0 = time.time()
    try:
        bot_classifications = classify_all_sessions()
        bot_stats = get_bot_stats()
        elapsed = time.time() - t0
        bot_stats['elapsed_seconds'] = round(elapsed, 3)
        results['bot_detection'] = bot_stats
        logger.info(
            "    Total: %d | Bot: %d (%.1f%%) | Human: %d (%.1f%%) | Unknown: %d (%.1f%%) | Time: %.3fs",
            bot_stats.get('total', 0),
            bot_stats.get('bot', 0), bot_stats.get('bot_pct', 0),
            bot_stats.get('human', 0), bot_stats.get('human_pct', 0),
            bot_stats.get('unknown', 0), bot_stats.get('unknown_pct', 0),
            elapsed,
        )
        if verbose and bot_classifications:
            for sid, label in sorted(bot_classifications.items()):
                logger.debug("    Session %5d → %s", sid, label)
    except Exception as exc:
        logger.error("    Bot detection failed: %s", exc, exc_info=verbose)
        results['bot_detection'] = {'error': str(exc)}

    # ── Summary ──────────────────────────────────────────────────────────
    total_elapsed = time.time() - pipeline_start
    results['pipeline'] = {
        'total_elapsed_seconds': round(total_elapsed, 3),
        'status': 'complete',
    }

    logger.info(_banner("PIPELINE COMPLETE"))
    logger.info("    Total pipeline time: %.3fs", total_elapsed)

    # Check for any stage errors
    errors = [
        stage for stage, data in results.items()
        if isinstance(data, dict) and 'error' in data
    ]
    if errors:
        logger.warning("    Stages with errors: %s", ', '.join(errors))
        results['pipeline']['status'] = 'complete_with_errors'
    else:
        logger.info("    All stages completed successfully.")

    return results


# ── CLI entry-point ──────────────────────────────────────────────────────────

def main() -> None:
    """Parse CLI arguments and run the analytics pipeline."""
    parser = argparse.ArgumentParser(
        prog='run_analytics',
        description='MIRAGE Analytics Pipeline — run all analysis stages.',
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable DEBUG-level logging for detailed output.',
    )
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    # Suppress noisy third-party loggers unless verbose
    if not args.verbose:
        logging.getLogger('sklearn').setLevel(logging.WARNING)
        logging.getLogger('scipy').setLevel(logging.WARNING)

    results = run_pipeline(verbose=args.verbose)

    # Final console summary (using print for guaranteed visibility)
    print(f"\n{'═'*70}")
    print("  MIRAGE ANALYTICS — FINAL SUMMARY")
    print(f"{'═'*70}")
    for stage, data in results.items():
        if isinstance(data, dict):
            print(f"\n  [{stage}]")
            for k, v in data.items():
                if isinstance(v, list) and len(v) > 10:
                    print(f"    {k}: [{len(v)} items]")
                else:
                    print(f"    {k}: {v}")
        else:
            print(f"  {stage}: {data}")
    print(f"\n{'═'*70}\n")


if __name__ == '__main__':
    main()
