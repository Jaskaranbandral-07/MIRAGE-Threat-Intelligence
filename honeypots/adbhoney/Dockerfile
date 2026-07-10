FROM python:3.11-slim
WORKDIR /app
COPY server.py .
RUN mkdir -p /var/log/honeypot
EXPOSE 5555
CMD ["python", "server.py"]
