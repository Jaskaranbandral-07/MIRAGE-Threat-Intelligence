# =============================================================================
# MIRAGE Ingestion — Cowrie Log Watcher
# =============================================================================
# Long-running daemon that tails Cowrie's JSON log and normalises events
# into the MIRAGE database for downstream analysis.
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="MIRAGE Project <mirage@bartigo-internal.net>"
LABEL description="Cowrie SSH honeypot log ingestion daemon"

WORKDIR /app

# Install minimal dependencies
RUN pip install --no-cache-dir watchdog

# Copy the ingestion module
COPY . .

# The Cowrie log file is expected to be mounted at the path
# specified by Config.COWRIE_LOG_PATH (default: /var/log/cowrie/cowrie.json)
# Mount example:
#   docker run -v /var/log/cowrie:/var/log/cowrie mirage-ingestion

CMD ["python", "ingestion/cowrie_watcher.py"]
