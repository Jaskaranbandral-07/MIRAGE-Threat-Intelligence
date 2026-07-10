"""
MIRAGE — Clustering Pipeline
==============================
Statistical campaign-clustering pipeline (PRD §7).

Pipeline stages:
  1. Extract feature matrix from all sessions
  2. Spearman correlation check — drop redundant features (|ρ| > 0.85)
  3. Standardize with sklearn.preprocessing.StandardScaler
  4. DBSCAN clustering with configurable eps / min_samples
  5. Silhouette score validation (when >1 cluster, excluding noise)
  6. Write cluster assignments back to the database
  7. Return summary dict

All classification is rule-based or statistical — zero LLM calls.

Usage::

    from analytics.clustering import run_clustering, get_silhouette_score

    results = run_clustering()
    score   = get_silhouette_score()
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime
from typing import Any

import numpy as np
from scipy.stats import spearmanr
from sklearn.cluster import DBSCAN
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

# ── Project imports ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config  # noqa: E402
from database.db import get_db  # noqa: E402

from analytics.feature_extractor import (  # noqa: E402
    FEATURE_NAMES,
    extract_all_features,
    get_feature_matrix,
)

logger = logging.getLogger(__name__)

# Module-level cache of the last silhouette score (set by run_clustering).
_last_silhouette: float | None = None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _spearman_filter(matrix: np.ndarray, feature_names: list[str],
                     threshold: float = 0.85) -> tuple[np.ndarray, list[str]]:
    """Drop features whose pairwise |Spearman ρ| exceeds *threshold*.

    When two features are highly correlated the one that appears **later**
    in the original feature list is dropped (preserves the first).

    Parameters
    ----------
    matrix : np.ndarray
        Feature matrix of shape ``(n_samples, n_features)``.
    feature_names : list[str]
        Column names matching the feature axis.
    threshold : float
        Absolute Spearman correlation above which a feature is dropped.

    Returns
    -------
    tuple[np.ndarray, list[str]]
        Filtered ``(matrix, feature_names)``.
    """
    n_features = matrix.shape[1]
    if n_features <= 1:
        return matrix, feature_names

    # Compute full Spearman correlation matrix.
    # scipy.stats.spearmanr returns (correlation, pvalue); for matrix input
    # correlation is an (n_features × n_features) array.
    try:
        corr_result = spearmanr(matrix)
        corr_matrix = np.atleast_2d(corr_result.correlation)
        
        # If the input array is completely constant, spearmanr might return a scalar nan.
        if corr_matrix.shape != (n_features, n_features):
            logger.warning("spearmanr returned shape %s (expected %s). Skipping filter.", 
                           corr_matrix.shape, (n_features, n_features))
            return matrix, feature_names
    except Exception as e:
        logger.warning("spearmanr failed: %s. Skipping filter.", e)
        return matrix, feature_names

    drop_indices: set[int] = set()
    for i in range(n_features):
        if i in drop_indices:
            continue
        for j in range(i + 1, n_features):
            if j in drop_indices:
                continue
            if not np.isnan(corr_matrix[i, j]) and abs(corr_matrix[i, j]) > threshold:
                logger.info(
                    "Dropping feature '%s' (corr %.3f with '%s').",
                    feature_names[j], corr_matrix[i, j], feature_names[i],
                )
                drop_indices.add(j)

    keep = [i for i in range(n_features) if i not in drop_indices]
    filtered_names = [feature_names[i] for i in keep]
    filtered_matrix = matrix[:, keep]

    logger.info(
        "Spearman filter: kept %d / %d features (threshold=%.2f).",
        len(keep), n_features, threshold,
    )
    return filtered_matrix, filtered_names


def _build_cluster_label(cluster_label: int,
                         session_ids: list[int],
                         db) -> str:
    """Generate a human-readable label for a cluster.

    Attempts to label by dominant ATT&CK techniques found in the cluster's
    sessions.  Falls back to ``'Campaign {N}'``.
    """
    if not session_ids:
        return f'Campaign {cluster_label}'

    placeholders = ','.join('?' * len(session_ids))
    rows = db.execute(
        f'SELECT ts.technique_name, COUNT(*) AS cnt '
        f'FROM session_techniques st '
        f'JOIN technique_signatures ts ON st.signature_id = ts.signature_id '
        f'WHERE st.session_id IN ({placeholders}) '
        f'GROUP BY ts.technique_name ORDER BY cnt DESC LIMIT 2',
        session_ids,
    ).fetchall()

    if rows:
        names = [r['technique_name'] for r in rows]
        return f'Campaign {cluster_label} ({", ".join(names)})'
    return f'Campaign {cluster_label}'


def _compute_centroid(matrix: np.ndarray, feature_names: list[str]) -> str:
    """Compute mean feature values and return as a JSON string."""
    means = matrix.mean(axis=0)
    centroid = {name: round(float(val), 6) for name, val in zip(feature_names, means)}
    return json.dumps(centroid)


def _write_clusters_to_db(
    labels: np.ndarray,
    session_ids: list[int],
    raw_matrix: np.ndarray,
    feature_names: list[str],
) -> None:
    """Persist clustering results into the ``clusters`` and ``sessions`` tables."""
    db = get_db()
    unique_labels = set(labels)
    unique_labels.discard(-1)  # exclude noise

    for cluster_label in sorted(unique_labels):
        mask = labels == cluster_label
        cluster_sids = [session_ids[i] for i in range(len(session_ids)) if mask[i]]
        cluster_matrix = raw_matrix[mask]

        if not cluster_sids:
            continue

        # Compute metadata
        placeholders = ','.join('?' * len(cluster_sids))
        time_row = db.execute(
            f'SELECT MIN(start_time) AS first_seen, MAX(start_time) AS last_seen '
            f'FROM sessions WHERE session_id IN ({placeholders})',
            cluster_sids,
        ).fetchone()

        label_text = _build_cluster_label(int(cluster_label), cluster_sids, db)
        centroid_json = _compute_centroid(cluster_matrix, feature_names)
        first_seen = time_row['first_seen'] if time_row else datetime.utcnow().isoformat()
        last_seen = time_row['last_seen'] if time_row else datetime.utcnow().isoformat()

        # Upsert cluster row
        existing = db.execute(
            'SELECT cluster_id FROM clusters WHERE label = ?',
            (label_text,),
        ).fetchone()

        if existing:
            cluster_id = existing['cluster_id']
            db.execute(
                'UPDATE clusters SET first_seen=?, last_seen=?, session_count=?, centroid_features=? '
                'WHERE cluster_id=?',
                (first_seen, last_seen, len(cluster_sids), centroid_json, cluster_id),
            )
        else:
            cursor = db.execute(
                'INSERT INTO clusters (label, first_seen, last_seen, session_count, centroid_features) '
                'VALUES (?, ?, ?, ?, ?)',
                (label_text, first_seen, last_seen, len(cluster_sids), centroid_json),
            )
            cluster_id = cursor.lastrowid

        # Update session → cluster mapping
        for sid in cluster_sids:
            db.execute(
                'UPDATE sessions SET cluster_id = ? WHERE session_id = ?',
                (cluster_id, sid),
            )

        logger.info(
            "Cluster '%s' (id=%d): %d sessions, first_seen=%s, last_seen=%s.",
            label_text, cluster_id, len(cluster_sids), first_seen, last_seen,
        )

    # Noise sessions (label == -1) → cluster_id = NULL
    noise_sids = [session_ids[i] for i in range(len(session_ids)) if labels[i] == -1]
    for sid in noise_sids:
        db.execute('UPDATE sessions SET cluster_id = NULL WHERE session_id = ?', (sid,))

    db.commit()
    logger.info("Cluster assignments committed to database.")


# ── Public API ───────────────────────────────────────────────────────────────

def run_clustering() -> dict[str, Any]:
    """Run the full clustering pipeline.

    Returns
    -------
    dict
        Summary with keys: ``cluster_labels``, ``silhouette_score``,
        ``n_clusters``, ``noise_count``, ``message``.
    """
    global _last_silhouette

    # Step 1: Get feature matrix
    matrix, session_ids = get_feature_matrix()

    if matrix.shape[0] == 0:
        msg = "No sessions available for clustering."
        logger.warning(msg)
        _last_silhouette = None
        return {
            'cluster_labels': [],
            'silhouette_score': None,
            'n_clusters': 0,
            'noise_count': 0,
            'message': msg,
        }

    if matrix.shape[0] < Config.CLUSTER_MIN_SAMPLES:
        msg = (
            f"Only {matrix.shape[0]} session(s) available, need at least "
            f"{Config.CLUSTER_MIN_SAMPLES} (CLUSTER_MIN_SAMPLES). Skipping clustering."
        )
        logger.warning(msg)
        _last_silhouette = None
        return {
            'cluster_labels': [],
            'silhouette_score': None,
            'n_clusters': 0,
            'noise_count': matrix.shape[0],
            'message': msg,
        }

    feature_names = list(FEATURE_NAMES)

    # Step 2: Spearman correlation filter
    filtered_matrix, filtered_names = _spearman_filter(matrix, feature_names)

    # Edge case: all features dropped (highly unlikely but defensive)
    if filtered_matrix.shape[1] == 0:
        logger.warning("All features were dropped by Spearman filter — using original.")
        filtered_matrix = matrix
        filtered_names = feature_names

    # Step 3: Standardize
    scaler = StandardScaler()
    scaled = scaler.fit_transform(filtered_matrix)

    # Handle NaN from constant columns (std=0 → division by zero → NaN)
    scaled = np.nan_to_num(scaled, nan=0.0)

    # Step 4: DBSCAN
    dbscan = DBSCAN(eps=Config.CLUSTER_EPS, min_samples=Config.CLUSTER_MIN_SAMPLES)
    labels = dbscan.fit_predict(scaled)

    n_clusters = len(set(labels) - {-1})
    noise_count = int(np.sum(labels == -1))

    logger.info(
        "DBSCAN complete: %d cluster(s), %d noise point(s) out of %d sessions.",
        n_clusters, noise_count, len(labels),
    )

    # Step 5: Silhouette score
    sil_score: float | None = None
    if n_clusters > 1:
        # Silhouette over non-noise points only
        non_noise_mask = labels != -1
        if np.sum(non_noise_mask) > 1:
            sil_score = float(silhouette_score(scaled[non_noise_mask], labels[non_noise_mask]))
            logger.info("Silhouette score (non-noise): %.4f", sil_score)
        else:
            logger.info("Insufficient non-noise points for silhouette score.")
    elif n_clusters == 1:
        logger.info("Only 1 cluster found — silhouette score not meaningful.")
    else:
        logger.info("No clusters found (all noise).")

    _last_silhouette = sil_score

    # Step 6: Write to database
    _write_clusters_to_db(labels, session_ids, matrix, feature_names)

    # Step 7: Return summary
    return {
        'cluster_labels': labels.tolist(),
        'silhouette_score': sil_score,
        'n_clusters': n_clusters,
        'noise_count': noise_count,
        'features_used': filtered_names,
        'features_dropped': [n for n in feature_names if n not in filtered_names],
        'total_sessions': len(session_ids),
        'message': f"Clustering complete: {n_clusters} campaign(s) identified.",
    }


def get_silhouette_score() -> float | None:
    """Return the silhouette score from the most recent clustering run.

    Returns
    -------
    float or None
        The silhouette score, or ``None`` if clustering hasn't been run
        or only 0–1 clusters were found.
    """
    return _last_silhouette


# ── CLI entry-point ──────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    )
    from database.db import init_db  # noqa: E402
    init_db()

    results = run_clustering()
    print(f"\n{'='*60}")
    print("CLUSTERING RESULTS")
    print(f"{'='*60}")
    for key, val in results.items():
        if key == 'cluster_labels':
            print(f"  {key}: [{len(val)} labels]")
        else:
            print(f"  {key}: {val}")
