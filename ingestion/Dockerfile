FROM python:3.11-slim
LABEL maintainer="MIRAGE Project"
LABEL description="Honeypot log ingestion daemon"
WORKDIR /app
RUN pip install --no-cache-dir watchdog
COPY . .
RUN echo '#!/bin/bash' > /app/start.sh && \
    echo 'python ingestion/cowrie_watcher.py &' >> /app/start.sh && \
    echo 'python ingestion/unified_watcher.py &' >> /app/start.sh && \
    echo 'wait' >> /app/start.sh && \
    chmod +x /app/start.sh
CMD ["/bin/bash", "/app/start.sh"]
