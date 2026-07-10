FROM python:3.11-slim
WORKDIR /app
COPY server.py .
RUN pip install --no-cache-dir flask && mkdir -p /var/log/honeypot
EXPOSE 8081
CMD ["python", "server.py"]
