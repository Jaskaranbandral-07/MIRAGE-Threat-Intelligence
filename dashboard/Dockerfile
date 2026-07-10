FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir flask flask-cors pandas scikit-learn scipy
COPY . .
EXPOSE 5000
CMD ["python", "dashboard/app.py"]
