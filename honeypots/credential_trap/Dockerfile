FROM python:3.11-slim
WORKDIR /app
COPY server.py .
RUN mkdir -p /var/log/honeypot
EXPOSE 21 23 25 5900
CMD ["python", "server.py"]
