FROM python:3.11-slim
WORKDIR /app
ENV PYTHONPATH=/app/mtls
COPY control-plane/auth-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY control-plane/auth-service/app/ ./app/
COPY mtls/mtls_requests.py ./mtls/mtls_requests.py
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--timeout-keep-alive", "30", \
     "--log-level", "warning", \
     "--ssl-keyfile", "/certs/auth-service.key", \
     "--ssl-certfile", "/certs/auth-service.crt", \
     "--ssl-ca-certs", "/certs/ca.crt", \
     "--ssl-cert-reqs", "2"]
