# =============================================================================
# MIRAGE Decoy — Honeypot Flask Application
# =============================================================================
# Deliberately vulnerable web application that logs attacker interactions
# into the MIRAGE database for analysis by the classification pipeline.
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="MIRAGE Project <mirage@bartigo-internal.net>"
LABEL description="Honeypot decoy web application"

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir flask flask-cors PyJWT

# Copy the decoy application
COPY . .

EXPOSE 8080

# Health-check against the landing page
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/')"

CMD ["python", "decoy/app.py"]
