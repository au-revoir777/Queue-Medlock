FROM python:3.11-slim
WORKDIR /app
COPY scripts/seed/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scripts/seed/seed.py .
CMD ["python", "seed.py"]
