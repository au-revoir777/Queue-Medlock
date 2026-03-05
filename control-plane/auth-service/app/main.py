"""
MedLock Auth Service
=====================
Performance fixes — iteration 3
---------------------------------
Previous state (after iteration 2):
  login    p95=145ms  SLA=200ms  ✓ PASS
  validate p95=140ms  SLA=50ms   ✗

Remaining problem
-----------------
validate p95=140ms despite the token cache being warm (>99% cache hits).

Root cause: FastAPI dispatches `sync def` endpoints into a threadpool
(anyio's default WorkerThread pool). With 15 concurrent validate threads
hitting 2 workers, each worker queues ~7-8 sync tasks. Those threads
compete for the Python GIL on every dict access and lock acquisition.
The GIL switch interval is 5ms — with 8 threads queued, a thread can
wait up to 40ms before it even runs, before touching the cache.

The cache was working correctly. The overhead was the dispatch mechanism,
not the cache logic itself.

Fix: convert validate() to `async def`
-------------------------------------
`async def` endpoints run directly on the uvicorn event loop — no
threadpool dispatch, no thread creation, no GIL contention for the
fast path. A cache hit (dict lookup + return) completes in <0.1ms
on the event loop, and 15 concurrent requests are handled by
cooperative multitasking with zero waiting.

For the rare cache miss (~0.3% of requests = 18 out of 6616 in the
stress test), the DB call is dispatched via asyncio.get_event_loop()
.run_in_executor() so it doesn't block the event loop.

Secondary fix: lock-free cache reads
--------------------------------------
CPython dict reads under the GIL are effectively atomic — two threads
cannot corrupt a dict by simultaneously reading it. The threading.Lock
in _cache_get was adding unnecessary contention (lock acquire/release
overhead per request). Reads are now lock-free. Writes still use the
lock because dict.__setitem__ is not atomic with the expiry check.

Result: validate fast path (cache hit) = pure async dict lookup,
no locks, no threads, no DB. Target p95 well under 50ms.
"""

from fastapi import FastAPI, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from prometheus_client import Counter, generate_latest
from contextlib import contextmanager
import hashlib, time, os, threading, asyncio
import psycopg2, psycopg2.extras, psycopg2.pool
import mtls_requests as requests  # replaces: import requests

app = FastAPI(title="MedLock Auth Service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
TOKEN_TTL_SECONDS = 3600
TOKEN_CACHE_TTL = int(os.environ.get("TOKEN_CACHE_TTL", "120"))

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is not set")

# ----------------------------------------------------------------
# Connection pool  (min_conn=8 — pre-opens connections at startup)
# ----------------------------------------------------------------

_pool = None


def _init_pool(min_conn=8, max_conn=50, retries=10, delay=2.0):
    global _pool
    for attempt in range(1, retries + 1):
        try:
            _pool = psycopg2.pool.ThreadedConnectionPool(
                min_conn,
                max_conn,
                DATABASE_URL,
                connect_timeout=5,
            )
            print(f"[auth] DB pool ready (attempt {attempt})")
            return
        except Exception as exc:
            print(f"[auth] Not ready ({attempt}/{retries}): {exc}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to Postgres after retries")


@contextmanager
def db():
    conn = _pool.getconn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.putconn(conn)


def _get_conn():
    return psycopg2.connect(DATABASE_URL, connect_timeout=5)


def _create_tables():
    with db() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_users (
                hospital_id   TEXT NOT NULL,
                staff_id      TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                department    TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'doctor',
                created_at    DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (hospital_id, staff_id)
            )
            """
        )
        cur.execute(
            "ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'doctor'"
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token       TEXT PRIMARY KEY,
                hospital_id TEXT NOT NULL,
                staff_id    TEXT NOT NULL,
                department  TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'doctor',
                issued_at   DOUBLE PRECISION NOT NULL,
                expires_at  DOUBLE PRECISION NOT NULL
            )
            """
        )
        cur.execute(
            "ALTER TABLE auth_tokens ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'doctor'"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_tokens_token      ON auth_tokens (token)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at ON auth_tokens (expires_at)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_tokens_staff      ON auth_tokens (hospital_id, staff_id)"
        )


_init_pool()
_create_tables()

# ----------------------------------------------------------------
# Token cache
#
# Reads are lock-free — CPython dict reads under the GIL are atomic.
# Two threads reading simultaneously cannot produce a torn value.
# Writes use a lock because the check-then-set pattern (read expiry,
# write new entry) must be atomic to avoid a race between two threads
# both deciding to evict and rewrite the same key.
# ----------------------------------------------------------------

_token_cache: dict[str, tuple[dict, float]] = {}
_cache_write_lock = threading.Lock()


def _cache_get(token: str) -> dict | None:
    # Lock-free read — safe under CPython GIL
    entry = _token_cache.get(token)
    if entry is None:
        return None
    identity, expires_at = entry
    if time.time() > expires_at:
        # Best-effort eviction — no lock needed; worst case another thread
        # reads a stale entry and falls through to the DB path (harmless)
        _token_cache.pop(token, None)
        return None
    return identity


def _cache_set(token: str, identity: dict):
    with _cache_write_lock:
        _token_cache[token] = (identity, time.time() + TOKEN_CACHE_TTL)


def _cache_invalidate(token: str):
    with _cache_write_lock:
        _token_cache.pop(token, None)


# ----------------------------------------------------------------
# DB validate — runs in executor (called only on cache miss)
# ----------------------------------------------------------------


def _db_validate(token: str) -> dict | None:
    """Blocking DB lookup — intended to run in a thread via run_in_executor."""
    with db() as cur:
        cur.execute(
            """
            SELECT hospital_id, staff_id, department, role, issued_at, expires_at
            FROM auth_tokens WHERE token=%s
            """,
            (token,),
        )
        return cur.fetchone()


# ----------------------------------------------------------------
# Prometheus
# ----------------------------------------------------------------

requests_total = Counter("auth_http_requests_total", "Total HTTP requests")
login_success_total = Counter(
    "auth_login_success_total", "Successful logins", ["hospital_id"]
)
login_failure_total = Counter(
    "auth_login_failure_total", "Failed logins", ["hospital_id"]
)
registrations_total = Counter(
    "auth_registrations_total", "Registrations", ["hospital_id"]
)
validate_cache_hits = Counter("auth_validate_cache_hits_total", "Validate cache hits")
validate_cache_misses = Counter(
    "auth_validate_cache_misses_total", "Validate cache misses"
)


@app.middleware("http")
async def count_requests(request, call_next):
    requests_total.inc()
    return await call_next(request)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type="text/plain")


@app.get("/health")
def health():
    try:
        conn = _get_conn()
        conn.close()
        return {"status": "ok", "database": "ok"}
    except Exception as exc:
        return {"status": "degraded", "database": str(exc)}


# ----------------------------------------------------------------
# Models
# ----------------------------------------------------------------


class RegisterPayload(BaseModel):
    hospital_id: str
    staff_id: str
    password: str
    department: str
    role: str = "doctor"


class LoginPayload(BaseModel):
    hospital_id: str
    staff_id: str
    password: str


class ValidatePayload(BaseModel):
    token: str


# ----------------------------------------------------------------
# Routes
# ----------------------------------------------------------------


@app.post("/register")
def register(payload: RegisterPayload):
    with db() as cur:
        cur.execute(
            "SELECT 1 FROM auth_users WHERE hospital_id=%s AND staff_id=%s",
            (payload.hospital_id, payload.staff_id),
        )
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="User already exists")
        hashed = hashlib.sha256(payload.password.encode()).hexdigest()
        cur.execute(
            """
            INSERT INTO auth_users (hospital_id, staff_id, password_hash, department, role, created_at)
            VALUES (%s,%s,%s,%s,%s,%s)
            """,
            (
                payload.hospital_id,
                payload.staff_id,
                hashed,
                payload.department,
                payload.role,
                time.time(),
            ),
        )
    registrations_total.labels(hospital_id=payload.hospital_id).inc()
    return {"status": "created"}


@app.post("/login")
def login(payload: LoginPayload):
    now = time.time()
    hashed = hashlib.sha256(payload.password.encode()).hexdigest()
    token = hashlib.sha256(
        f"{payload.hospital_id}{payload.staff_id}{now}".encode()
    ).hexdigest()

    with db() as cur:
        cur.execute(
            "SELECT password_hash, department, role FROM auth_users WHERE hospital_id=%s AND staff_id=%s",
            (payload.hospital_id, payload.staff_id),
        )
        user = cur.fetchone()

        if not user:
            login_failure_total.labels(hospital_id=payload.hospital_id).inc()
            raise HTTPException(status_code=404, detail="User not found")

        if user["password_hash"] != hashed:
            login_failure_total.labels(hospital_id=payload.hospital_id).inc()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Single CTE: atomic expired-token cleanup + new token insert
        cur.execute(
            """
            WITH cleanup AS (
                DELETE FROM auth_tokens
                WHERE hospital_id = %s AND staff_id = %s AND expires_at < %s
            )
            INSERT INTO auth_tokens
                (token, hospital_id, staff_id, department, role, issued_at, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (token) DO UPDATE SET
                issued_at  = EXCLUDED.issued_at,
                expires_at = EXCLUDED.expires_at
            """,
            (
                payload.hospital_id,
                payload.staff_id,
                now,
                token,
                payload.hospital_id,
                payload.staff_id,
                user["department"],
                user["role"],
                now,
                now + TOKEN_TTL_SECONDS,
            ),
        )

    login_success_total.labels(hospital_id=payload.hospital_id).inc()

    identity = {
        "hospital_id": payload.hospital_id,
        "staff_id": payload.staff_id,
        "department": user["department"],
        "role": user["role"],
        "issued_at": now,
    }
    # Pre-warm cache so the issuing worker never has a cold validate miss
    _cache_set(token, identity)
    return {"access_token": token}


@app.post("/validate")
async def validate(payload: ValidatePayload):
    """
    async def — runs on the event loop, not in a threadpool.

    Fast path (cache hit, >99% of requests after warm-up):
      Pure dict lookup, <0.1ms, zero DB/network I/O, zero thread overhead.
      15 concurrent requests are handled cooperatively with no queuing.

    Slow path (cache miss, <1% of requests):
      Dispatches the blocking DB call to the default executor (threadpool)
      via run_in_executor so the event loop is not blocked.
    """
    # Fast path — lock-free read, runs on event loop
    cached = _cache_get(payload.token)
    if cached is not None:
        validate_cache_hits.inc()
        return cached

    # Slow path — DB call in executor (doesn't block event loop)
    validate_cache_misses.inc()
    loop = asyncio.get_event_loop()
    record = await loop.run_in_executor(None, _db_validate, payload.token)

    if not record:
        raise HTTPException(status_code=401, detail="Invalid token")
    if time.time() > record["expires_at"]:
        raise HTTPException(status_code=401, detail="Token expired")

    identity = {
        "hospital_id": record["hospital_id"],
        "staff_id": record["staff_id"],
        "department": record["department"],
        "role": record["role"],
        "issued_at": record["issued_at"],
    }
    _cache_set(payload.token, identity)
    return identity
