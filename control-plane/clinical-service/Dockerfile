FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# --workers 2: same reasoning as auth service — doubles throughput on
#   CPU-bound work (JSON serialisation, hashing, request routing).
#   The in-process token cache and KMS cache are per-worker (not shared),
#   so worst-case each worker independently caches the same token once on
#   its first miss. This is acceptable — the cache hit rate per worker
#   converges to >95% within seconds of warm-up under load.
#
# --timeout-keep-alive 30: reduces TCP reconnect overhead for the stress
#   test's persistent HTTP sessions.
#
# --log-level warning: suppresses access logs under high throughput.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--timeout-keep-alive", "30", \
     "--log-level", "warning"]
