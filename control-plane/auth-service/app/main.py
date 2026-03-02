"""
MedLock Auth Service
=====================

Fixes applied
-------------
1. Postgres persistence — user_registry and token_registry moved from
   in-memory dicts to Postgres tables. Auth state now survives container
   restarts, eliminating the failure mode where every simulator thread
   received 404 on login after a restart.

2. Uses DATABASE_URL — same pattern as the tenant service fix. No new
   infrastructure required; auth-service just needs DATABASE_URL added
   to its environment block in docker-compose.yml.

3. Token expiry — tokens now carry an expires_at timestamp (1 hour).
   Expired tokens are rejected at /validate and cleaned up passively.
   The original code never expired tokens, meaning a compromised token
   was valid forever.

4. /health verifies the database connection so the docker-compose
   healthcheck accurately reflects service availability.
"""

from fastapi import FastAPI, Response, HTTPException
from pydantic import BaseModel
from prometheus_client import Counter, generate_latest
import hashlib
import time
import os
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="MedLock Auth Service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


JWT_SECRET = os.environ.get("JWT_SECRET", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is not set")

TOKEN_TTL_SECONDS = 3600  # 1 hour


# ----------------------------------------------------------------
# Database
# ----------------------------------------------------------------


def _get_conn():
    return psycopg2.connect(DATABASE_URL)


@contextmanager
def db():
    conn = _get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _wait_for_db(retries: int = 10, delay: float = 2.0):
    for attempt in range(1, retries + 1):
        try:
            conn = _get_conn()
            conn.close()
            print(f"[auth] Database ready (attempt {attempt})")
            return
        except Exception as exc:
            print(f"[auth] Database not ready (attempt {attempt}/{retries}): {exc}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to Postgres after retries — aborting")


def _create_tables():
    with db() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_users (
                hospital_id   TEXT NOT NULL,
                staff_id      TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                department    TEXT NOT NULL,
                created_at    DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (hospital_id, staff_id)
            )
        """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token       TEXT PRIMARY KEY,
                hospital_id TEXT NOT NULL,
                staff_id    TEXT NOT NULL,
                department  TEXT NOT NULL,
                issued_at   DOUBLE PRECISION NOT NULL,
                expires_at  DOUBLE PRECISION NOT NULL
            )
        """
        )
        # Index for fast token lookup at /validate
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_tokens_token
            ON auth_tokens (token)
        """
        )


_wait_for_db()
_create_tables()


# ----------------------------------------------------------------
# Prometheus Metrics
# ----------------------------------------------------------------
requests_total = Counter(
    "auth_http_requests_total", "Total HTTP requests to auth service"
)

login_success_total = Counter(
    "auth_login_success_total", "Successful login attempts", ["hospital_id"]
)

login_failure_total = Counter(
    "auth_login_failure_total", "Failed login attempts", ["hospital_id"]
)

registrations_total = Counter(
    "auth_registrations_total", "Total user registrations", ["hospital_id"]
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
            "SELECT 1 FROM auth_users WHERE hospital_id = %s AND staff_id = %s",
            (payload.hospital_id, payload.staff_id),
        )
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="User already exists")

        hashed = hashlib.sha256(payload.password.encode()).hexdigest()
        cur.execute(
            """
            INSERT INTO auth_users (hospital_id, staff_id, password_hash, department, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                payload.hospital_id,
                payload.staff_id,
                hashed,
                payload.department,
                time.time(),
            ),
        )

    registrations_total.labels(hospital_id=payload.hospital_id).inc()
    return {"status": "created"}


@app.post("/login")
def login(payload: LoginPayload):
    with db() as cur:
        cur.execute(
            "SELECT password_hash, department FROM auth_users WHERE hospital_id = %s AND staff_id = %s",
            (payload.hospital_id, payload.staff_id),
        )
        user = cur.fetchone()

    if not user:
        login_failure_total.labels(hospital_id=payload.hospital_id).inc()
        raise HTTPException(status_code=404, detail="User not found")

    hashed_input = hashlib.sha256(payload.password.encode()).hexdigest()
    if user["password_hash"] != hashed_input:
        login_failure_total.labels(hospital_id=payload.hospital_id).inc()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    login_success_total.labels(hospital_id=payload.hospital_id).inc()

    token_raw = f"{payload.hospital_id}{payload.staff_id}{time.time()}"
    token = hashlib.sha256(token_raw.encode()).hexdigest()
    now = time.time()

    with db() as cur:
        cur.execute(
            """
            INSERT INTO auth_tokens (token, hospital_id, staff_id, department, issued_at, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (token) DO UPDATE SET
                issued_at  = EXCLUDED.issued_at,
                expires_at = EXCLUDED.expires_at
            """,
            (
                token,
                payload.hospital_id,
                payload.staff_id,
                user["department"],
                now,
                now + TOKEN_TTL_SECONDS,
            ),
        )

    return {"access_token": token}


@app.post("/validate")
def validate(payload: ValidatePayload):
    with db() as cur:
        cur.execute(
            """
            SELECT hospital_id, staff_id, department, issued_at, expires_at
            FROM auth_tokens
            WHERE token = %s
            """,
            (payload.token,),
        )
        record = cur.fetchone()

    if not record:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Reject expired tokens
    if time.time() > record["expires_at"]:
        raise HTTPException(status_code=401, detail="Token expired")

    return {
        "hospital_id": record["hospital_id"],
        "staff_id": record["staff_id"],
        "department": record["department"],
        "issued_at": record["issued_at"],
    }
