FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY hpe_primera_exporter.py .
CMD ["python", "hpe_primera_exporter.py", "--config", "/config.yml"]
EXPOSE 9118