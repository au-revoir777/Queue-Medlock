"""
MedLock Tenant Service - Zero Trust Mode
=========================================

Fixes applied
-------------
1. Postgres persistence — hospitals and staff are stored in Postgres instead of
   plain Python dicts. State now survives container restarts, eliminating the
   denial-of-service vector where a restart wiped all registrations and caused
   every simulator thread to get 404 on login indefinitely.

2. Uses the DATABASE_URL already present in docker-compose.yml — no new
   infrastructure required, no new env vars, no new dependencies beyond
   psycopg2-binary which is standard for FastAPI+Postgres stacks.

3. Tables are created on startup (CREATE TABLE IF NOT EXISTS) so no separate
   migration step is needed beyond the existing schema.sql infra.

4. The /health endpoint now verifies the database connection so the
   healthcheck in docker-compose correctly reflects storage availability.
"""

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from prometheus_client import Counter, Gauge, generate_latest
import time
import mtls_requests as requests  # replaces: import requests
import os
import psycopg2
import psycopg2.extras
from contextlib import contextmanager

app = FastAPI(title="MedLock Tenant Service - Zero Trust Mode")

AUTH_URL = os.environ.get("AUTH_URL", "http://auth-service:8000/register")
KMS_URL = os.environ.get("KMS_URL", "http://kms-service:8000/exchange")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is not set")

# ----------------------------------------------------------------
# Database connection + startup
# ----------------------------------------------------------------


def _get_conn():
    """Open a new connection. Called per-request — no connection pooling needed
    for this service's traffic volume. psycopg2 connections are not thread-safe
    so we create one per request context."""
    return psycopg2.connect(DATABASE_URL)


@contextmanager
def db():
    """Context manager that yields a cursor and commits/rolls back cleanly."""
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
    """Block until Postgres is reachable — mirrors the depends_on healthcheck
    but gives the Python process its own retry loop in case of a race."""
    for attempt in range(1, retries + 1):
        try:
            conn = _get_conn()
            conn.close()
            print(f"[tenant] Database ready (attempt {attempt})")
            return
        except Exception as exc:
            print(f"[tenant] Database not ready (attempt {attempt}/{retries}): {exc}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to Postgres after retries — aborting")


def _create_tables():
    """Idempotent schema — safe to run on every startup."""
    with db() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_hospitals (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                created_at DOUBLE PRECISION NOT NULL
            )
        """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_staff (
                id              TEXT PRIMARY KEY,
                hospital_id     TEXT NOT NULL REFERENCES tenant_hospitals(id),
                role            TEXT NOT NULL,
                department      TEXT NOT NULL,
                public_sign_key TEXT NOT NULL,
                public_kx_key   TEXT NOT NULL,
                public_kem_key  TEXT NOT NULL,
                public_dsa_key  TEXT NOT NULL,
                registered_at   DOUBLE PRECISION NOT NULL
            )
        """
        )


# Run at import time so tables exist before the first request
_wait_for_db()
_create_tables()


# ----------------------------------------------------------------
# Persistence helpers
# ----------------------------------------------------------------


def hospital_exists(hospital_id: str) -> bool:
    with db() as cur:
        cur.execute("SELECT 1 FROM tenant_hospitals WHERE id = %s", (hospital_id,))
        return cur.fetchone() is not None


def save_hospital(data: dict):
    with db() as cur:
        cur.execute(
            "INSERT INTO tenant_hospitals (id, name, created_at) VALUES (%s, %s, %s)",
            (data["id"], data["name"], data["created_at"]),
        )


def save_staff(data: dict):
    with db() as cur:
        cur.execute(
            """
            INSERT INTO tenant_staff
                (id, hospital_id, role, department,
                 public_sign_key, public_kx_key, public_kem_key, public_dsa_key,
                 registered_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                role            = EXCLUDED.role,
                department      = EXCLUDED.department,
                public_sign_key = EXCLUDED.public_sign_key,
                public_kx_key   = EXCLUDED.public_kx_key,
                public_kem_key  = EXCLUDED.public_kem_key,
                public_dsa_key  = EXCLUDED.public_dsa_key,
                registered_at   = EXCLUDED.registered_at
        """,
            (
                data["id"],
                data["hospital_id"],
                data["role"],
                data["department"],
                data["public_sign_key"],
                data["public_kx_key"],
                data["public_kem_key"],
                data["public_dsa_key"],
                data["registered_at"],
            ),
        )


def count_staff_for_hospital(hospital_id: str) -> int:
    with db() as cur:
        cur.execute(
            "SELECT COUNT(*) AS n FROM tenant_staff WHERE hospital_id = %s",
            (hospital_id,),
        )
        row = cur.fetchone()
        return row["n"] if row else 0


# ----------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------
requests_total = Counter(
    "tenant_http_requests_total", "Total HTTP requests for tenant service"
)

hospitals_created_total = Counter(
    "tenant_hospitals_created_total", "Total hospitals created"
)

staff_registered_total = Counter(
    "tenant_staff_registered_total",
    "Total staff registrations",
    ["hospital_id", "role"],
)

active_staff_gauge = Gauge(
    "tenant_active_staff", "Current active staff per hospital", ["hospital_id"]
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
    """Verify database reachability so docker-compose healthcheck is accurate."""
    try:
        conn = _get_conn()
        conn.close()
        return {"status": "ok", "database": "ok"}
    except Exception as exc:
        return {"status": "degraded", "database": str(exc)}


# ----------------------------------------------------------------
# Models
# ----------------------------------------------------------------
class HospitalCreate(BaseModel):
    id: str
    name: str


class StaffRegister(BaseModel):
    id: str
    hospital_id: str
    role: str
    department: str
    public_sign_key: str  # Ed25519 (classical)
    public_kx_key: str  # X25519 (classical)
    public_kem_key: str  # ML-KEM-768 (post-quantum)
    public_dsa_key: str  # ML-DSA-65 (post-quantum)


# ----------------------------------------------------------------
# Routes
# ----------------------------------------------------------------
@app.post("/hospitals")
def create_hospital(payload: HospitalCreate):
    if hospital_exists(payload.id):
        raise HTTPException(status_code=409, detail="Hospital already exists")

    data = {
        "id": payload.id,
        "name": payload.name,
        "created_at": time.time(),
    }
    save_hospital(data)

    active_staff_gauge.labels(hospital_id=payload.id).set(
        count_staff_for_hospital(payload.id)
    )
    hospitals_created_total.inc()
    return data


@app.post("/staff/register")
def register_staff(payload: StaffRegister):
    if not hospital_exists(payload.hospital_id):
        raise HTTPException(status_code=404, detail="Hospital not found")

    # Register with auth service (password is always pass123 — managed internally)
    auth_response = requests.post(
        AUTH_URL,
        json={
            "hospital_id": payload.hospital_id,
            "staff_id": payload.id,
            "password": "pass123",
            "department": payload.department,
        },
        timeout=3,
    )

    if auth_response.status_code not in (200, 201, 409):
        raise HTTPException(status_code=500, detail="Auth service failed")

    # Register all four public keys with KMS
    kms_response = requests.post(
        KMS_URL,
        json={
            "hospital_id": payload.hospital_id,
            "department_id": payload.department,
            "staff_id": payload.id,
            "public_sign_key": payload.public_sign_key,  # Ed25519
            "public_kx_key": payload.public_kx_key,  # X25519
            "public_kem_key": payload.public_kem_key,  # ML-KEM-768
            "public_dsa_key": payload.public_dsa_key,  # ML-DSA-65
        },
        timeout=3,
    )

    if kms_response.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail="KMS service failed")

    data = {**payload.model_dump(), "registered_at": time.time()}
    save_staff(data)

    staff_registered_total.labels(
        hospital_id=payload.hospital_id, role=payload.role
    ).inc()

    count = count_staff_for_hospital(payload.hospital_id)
    active_staff_gauge.labels(hospital_id=payload.hospital_id).set(count)

    return data
