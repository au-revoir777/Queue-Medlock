FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# --workers 2: uses both CPU cores available in a typical Docker container.
#   Each worker is an independent process with its own DB pool and token
#   cache, doubling throughput on CPU-bound request parsing and hashing.
#   Keep at 2 for a 2-vCPU container; raise to (2×CPUs)+1 on larger hosts.
#
# --timeout-keep-alive 30: holds HTTP/1.1 keep-alive connections open for
#   30s so the stress test's persistent sessions don't pay TCP setup cost
#   on every request (default is 5s which causes reconnects under load).
#
# --log-level warning: suppresses per-request access logs which add ~2ms
#   of I/O per request under high throughput.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--timeout-keep-alive", "30", \
     "--log-level", "warning"]
