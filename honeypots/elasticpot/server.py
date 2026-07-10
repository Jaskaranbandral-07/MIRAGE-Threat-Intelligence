#!/usr/bin/env python3
"""
Elasticpot — Elasticsearch Honeypot Server
============================================
A Flask-based honeypot that mimics a publicly exposed Elasticsearch cluster.
Captures search queries, index creation/deletion attempts (common ransomware
behavior), and cluster enumeration probes.

Part of the MIRAGE Threat Intelligence Project.
"""

import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone

from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_FILE = os.environ.get("HONEYPOT_LOG", "/var/log/honeypot/elasticpot.json")
HONEYPOT_NAME = "elasticpot"
LISTEN_PORT = int(os.environ.get("HONEYPOT_PORT", 9200))

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

logger = logging.getLogger("elasticpot")
logger.setLevel(logging.INFO)
_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(logging.Formatter("[%(asctime)s] %(message)s"))
logger.addHandler(_console)

_log_file_handle = None


def _ensure_log_dir() -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def _get_log_handle():
    global _log_file_handle
    if _log_file_handle is None or _log_file_handle.closed:
        _ensure_log_dir()
        _log_file_handle = open(LOG_FILE, "a", encoding="utf-8")
    return _log_file_handle


def log_event(
    event_type: str,
    source_ip: str = "",
    source_port: int = 0,
    raw_input: str = "",
    details: dict | None = None,
) -> None:
    """Write a JSON event to the log file and stdout."""
    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": event_type,
        "source_ip": source_ip,
        "source_port": source_port,
        "protocol": "elasticsearch",
        "honeypot": HONEYPOT_NAME,
        "username": "",
        "password": "",
        "raw_input": raw_input,
        "details": details or {},
    }
    line = json.dumps(record)
    fh = _get_log_handle()
    fh.write(line + "\n")
    fh.flush()
    logger.info(line)


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Suppress default request logging
logging.getLogger("werkzeug").setLevel(logging.WARNING)


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")


def _client_port() -> int:
    try:
        return request.environ.get("REMOTE_PORT", 0)
    except Exception:
        return 0


@app.before_request
def log_all_requests():
    """Log every incoming HTTP request."""
    log_event(
        "connection",
        source_ip=_client_ip(),
        source_port=_client_port(),
        raw_input=f"{request.method} {request.full_path}",
        details={
            "method": request.method,
            "path": request.path,
            "user_agent": request.headers.get("User-Agent", ""),
        },
    )


# ---- Cluster info (root) ----

CLUSTER_INFO = {
    "name": "es-node-01",
    "cluster_name": "elasticsearch",
    "cluster_uuid": "x8gZ3kRdSp2vz1QmT7LJOQ",
    "version": {
        "number": "7.17.9",
        "build_flavor": "default",
        "build_type": "docker",
        "build_hash": "ef48eb35cf30adf4db14086e8aabd07ef6fb113f",
        "build_date": "2023-01-31T05:34:43.305563851Z",
        "build_snapshot": False,
        "lucene_version": "8.11.1",
        "minimum_wire_compatibility_version": "6.8.0",
        "minimum_index_compatibility_version": "6.0.0-beta1",
    },
    "tagline": "You Know, for Search",
}


@app.route("/")
def cluster_info():
    return jsonify(CLUSTER_INFO)


# ---- _cat/indices ----

FAKE_INDICES = (
    "green open .kibana_1              Ks5mKbR5QXCdF1pFW_VNIQ 1 0   3 0  12.5kb  12.5kb\n"
    "green open customer               TgZjH3l1RnqXkNJLy_VnpA 1 0 500 0   1.2mb   1.2mb\n"
    "green open logstash-2024.01.01    UflQZ3FQS8a3_1wXoNzR6g 5 1 1000 0   5.3mb   2.6mb\n"
    "green open .security-7            IAdQVq8BQAqfLI_wbKzrYw 1 0  42 0 200.1kb 200.1kb\n"
)


@app.route("/_cat/indices")
def cat_indices():
    return FAKE_INDICES, 200, {"Content-Type": "text/plain; charset=UTF-8"}


# ---- _search ----

FAKE_SEARCH = {
    "took": 5,
    "timed_out": False,
    "_shards": {"total": 5, "successful": 5, "skipped": 0, "failed": 0},
    "hits": {
        "total": {"value": 1, "relation": "eq"},
        "max_score": 1.0,
        "hits": [
            {
                "_index": "customer",
                "_type": "_doc",
                "_id": "1",
                "_score": 1.0,
                "_source": {"name": "John Doe", "email": "john@example.com"},
            }
        ],
    },
}


@app.route("/_search", methods=["GET", "POST"])
def search():
    if request.method == "POST":
        body = request.get_data(as_text=True)[:4096]
        log_event(
            "command",
            source_ip=_client_ip(),
            source_port=_client_port(),
            raw_input=body,
            details={"endpoint": "_search", "method": "POST"},
        )
    return jsonify(FAKE_SEARCH)


# ---- _cluster/health ----

CLUSTER_HEALTH = {
    "cluster_name": "elasticsearch",
    "status": "green",
    "timed_out": False,
    "number_of_nodes": 1,
    "number_of_data_nodes": 1,
    "active_primary_shards": 7,
    "active_shards": 7,
    "relocating_shards": 0,
    "initializing_shards": 0,
    "unassigned_shards": 0,
    "delayed_unassigned_shards": 0,
    "number_of_pending_tasks": 0,
    "number_of_in_flight_fetch": 0,
    "task_max_waiting_in_queue_millis": 0,
    "active_shards_percent_as_number": 100.0,
}


@app.route("/_cluster/health")
def cluster_health():
    return jsonify(CLUSTER_HEALTH)


# ---- _nodes ----

NODES_INFO = {
    "_nodes": {"total": 1, "successful": 1, "failed": 0},
    "cluster_name": "elasticsearch",
    "nodes": {
        "x8gZ3kRdSp2vz1QmT7LJOQ": {
            "name": "es-node-01",
            "transport_address": "172.18.0.2:9300",
            "host": "172.18.0.2",
            "ip": "172.18.0.2",
            "version": "7.17.9",
            "roles": ["data", "ingest", "master", "ml", "remote_cluster_client", "transform"],
            "os": {
                "name": "Linux",
                "arch": "amd64",
                "version": "5.15.0-91-generic",
                "available_processors": 4,
            },
            "jvm": {
                "version": "18.0.2.1",
                "vm_name": "OpenJDK 64-Bit Server VM",
                "vm_vendor": "Oracle Corporation",
            },
        }
    },
}


@app.route("/_nodes")
def nodes_info():
    return jsonify(NODES_INFO)


# ---- PUT /_index (index creation) ----

@app.route("/<index_name>", methods=["PUT"])
def create_index(index_name):
    """Log index creation attempts."""
    body = request.get_data(as_text=True)[:4096]
    log_event(
        "command",
        source_ip=_client_ip(),
        source_port=_client_port(),
        raw_input=body,
        details={
            "endpoint": f"PUT /{index_name}",
            "action": "create_index",
            "index_name": index_name,
        },
    )
    return jsonify({
        "acknowledged": True,
        "shards_acknowledged": True,
        "index": index_name,
    })


# ---- DELETE /* (ransomware behavior detection) ----

@app.route("/<path:target>", methods=["DELETE"])
def delete_target(target):
    """Log deletion attempts — common ransomware behavior."""
    log_event(
        "command",
        source_ip=_client_ip(),
        source_port=_client_port(),
        raw_input=f"DELETE /{target}",
        details={
            "endpoint": f"DELETE /{target}",
            "action": "delete",
            "target": target,
            "alert": "potential_ransomware",
        },
    )
    return jsonify({"acknowledged": True})


# ---- Catch-all for other GET paths ----

@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    """Handle all other paths — return a generic Elasticsearch error."""
    body = ""
    if request.method == "POST":
        body = request.get_data(as_text=True)[:4096]

    log_event(
        "command",
        source_ip=_client_ip(),
        source_port=_client_port(),
        raw_input=body or f"{request.method} /{path}",
        details={
            "endpoint": f"/{path}",
            "method": request.method,
        },
    )
    return jsonify({
        "error": {
            "root_cause": [{"type": "index_not_found_exception", "reason": f"no such index [{path}]"}],
            "type": "index_not_found_exception",
            "reason": f"no such index [{path}]",
        },
        "status": 404,
    }), 404


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def _handle_signal(sig, _frame):
    """Handle SIGTERM / SIGINT for graceful shutdown."""
    logger.info("Received signal %s — shutting down Elasticpot", signal.Signals(sig).name)
    global _log_file_handle
    if _log_file_handle and not _log_file_handle.closed:
        _log_file_handle.close()
    sys.exit(0)


def main():
    """Entry point — start Flask development server."""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _ensure_log_dir()
    logger.info("Elasticpot honeypot starting on port %d", LISTEN_PORT)

    app.run(host="0.0.0.0", port=LISTEN_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
