"""
MedLock KMS Service - Zero Trust Mode
=======================================

Fixes applied
-------------
1. Postgres persistence — key_registry moved from an in-memory dict to a
   Postgres table. Keys now survive container restarts. Previously a restart
   wiped all producer/consumer public keys, causing every decryption attempt
   to fail with a KMS 404 even though auth and enqueue were working fine.

2. Uses DATABASE_URL — same pattern as auth and tenant service fixes.
   Add DATABASE_URL to kms-service environment in docker-compose.yml.

3. The replay detection window (rapid re-registration within 5 seconds)
   is preserved exactly as in the original.

4. /health verifies the database connection.
"""

from fastapi import FastAPI, Response, HTTPException
from pydantic import BaseModel
from prometheus_client import Counter, Gauge, generate_latest
import time
import os
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
import mtls_requests as requests  # replaces: import requests

app = FastAPI(title="MedLock KMS Service - Zero Trust Mode")

DATABASE_URL = os.environ.get("DATABASE_URL", "")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is not set")

REPLAY_WINDOW_SECONDS = 5


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
            print(f"[kms] Database ready (attempt {attempt})")
            return
        except Exception as exc:
            print(f"[kms] Database not ready (attempt {attempt}/{retries}): {exc}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to Postgres after retries — aborting")


def _create_tables():
    with db() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS kms_keys (
                hospital_id     TEXT    NOT NULL,
                department_id   TEXT    NOT NULL,
                staff_id        TEXT    NOT NULL,
                public_sign_key TEXT    NOT NULL,
                public_kx_key   TEXT    NOT NULL,
                public_kem_key  TEXT    NOT NULL,
                public_dsa_key  TEXT    NOT NULL,
                registered_at   DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (hospital_id, department_id, staff_id)
            )
        """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_kms_keys_scope
            ON kms_keys (hospital_id, department_id)
        """
        )


_wait_for_db()
_create_tables()


# ----------------------------------------------------------------
# Prometheus Metrics
# ----------------------------------------------------------------

requests_total = Counter(
    "kms_http_requests_total", "Total HTTP requests for KMS service"
)

key_exchanges_total = Counter(
    "kms_key_exchanges_total",
    "Total key exchange operations",
    ["hospital_id", "department_id"],
)

keys_fetched_total = Counter(
    "kms_keys_fetched_total",
    "Total key retrieval operations",
    ["hospital_id", "department_id"],
)

key_overwrites_total = Counter(
    "kms_key_overwrites_total", "Number of times an existing staff key was replaced"
)

replay_attempts_total = Counter(
    "kms_replay_attempts_total",
    "Detected rapid re-registration attempts (possible replay)",
)

registered_staff_gauge = Gauge(
    "kms_registered_staff",
    "Active registered staff per hospital/department",
    ["hospital_id", "department_id"],
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


class KeyExchangePayload(BaseModel):
    hospital_id: str
    department_id: str
    staff_id: str
    public_sign_key: str  # Ed25519 (classical)
    public_kx_key: str  # X25519 (classical)
    public_kem_key: str  # ML-KEM-768 (post-quantum)
    public_dsa_key: str  # ML-DSA-65 (post-quantum)


# ----------------------------------------------------------------
# Routes
# ----------------------------------------------------------------


@app.get("/keys/{hospital_id}/{department_id}")
def get_keys(hospital_id: str, department_id: str):
    """
    Return all registered public keys for a hospital/department scope.
    """
    with db() as cur:
        cur.execute(
            """
            SELECT staff_id, public_sign_key, public_kx_key,
                   public_kem_key, public_dsa_key, registered_at
            FROM kms_keys
            WHERE hospital_id = %s AND department_id = %s
            """,
            (hospital_id, department_id),
        )
        rows = cur.fetchall()

    keys_fetched_total.labels(
        hospital_id=hospital_id, department_id=department_id
    ).inc()

    return {
        "hospital_id": hospital_id,
        "department_id": department_id,
        "total_keys": len(rows),
        "keys": [dict(r) for r in rows],
    }


@app.get("/keys/{hospital_id}/{department_id}/{staff_id}")
def get_staff_keys(hospital_id: str, department_id: str, staff_id: str):
    """
    Return the public keys for a specific staff member.
    Called by the simulator's zero-trust decrypt path on every message.
    """
    with db() as cur:
        cur.execute(
            """
            SELECT staff_id, public_sign_key, public_kx_key,
                   public_kem_key, public_dsa_key, registered_at
            FROM kms_keys
            WHERE hospital_id = %s AND department_id = %s AND staff_id = %s
            """,
            (hospital_id, department_id, staff_id),
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Staff keys not found")

    keys_fetched_total.labels(
        hospital_id=hospital_id, department_id=department_id
    ).inc()

    return dict(row)


@app.post("/exchange")
def exchange(payload: KeyExchangePayload):
    """
    Register or update a staff member's public keys.
    Called by the tenant service on staff registration.
    Preserves the original replay detection window.
    """
    now = time.time()

    with db() as cur:
        # Check for existing entry to detect rapid re-registration
        cur.execute(
            """
            SELECT registered_at FROM kms_keys
            WHERE hospital_id = %s AND department_id = %s AND staff_id = %s
            """,
            (payload.hospital_id, payload.department_id, payload.staff_id),
        )
        existing = cur.fetchone()

        if existing:
            if now - existing["registered_at"] < REPLAY_WINDOW_SECONDS:
                replay_attempts_total.inc()
            key_overwrites_total.inc()

        # Upsert — insert or replace all four keys atomically
        cur.execute(
            """
            INSERT INTO kms_keys
                (hospital_id, department_id, staff_id,
                 public_sign_key, public_kx_key, public_kem_key, public_dsa_key,
                 registered_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (hospital_id, department_id, staff_id) DO UPDATE SET
                public_sign_key = EXCLUDED.public_sign_key,
                public_kx_key   = EXCLUDED.public_kx_key,
                public_kem_key  = EXCLUDED.public_kem_key,
                public_dsa_key  = EXCLUDED.public_dsa_key,
                registered_at   = EXCLUDED.registered_at
            """,
            (
                payload.hospital_id,
                payload.department_id,
                payload.staff_id,
                payload.public_sign_key,
                payload.public_kx_key,
                payload.public_kem_key,
                payload.public_dsa_key,
                now,
            ),
        )

        # Count staff in this scope for the gauge
        cur.execute(
            "SELECT COUNT(*) AS n FROM kms_keys WHERE hospital_id = %s AND department_id = %s",
            (payload.hospital_id, payload.department_id),
        )
        count = cur.fetchone()["n"]

    key_exchanges_total.labels(
        hospital_id=payload.hospital_id, department_id=payload.department_id
    ).inc()

    registered_staff_gauge.labels(
        hospital_id=payload.hospital_id, department_id=payload.department_id
    ).set(count)

    return {
        "status": "registered",
        "hospital_id": payload.hospital_id,
        "department_id": payload.department_id,
        "staff_id": payload.staff_id,
        "total_staff_in_scope": count,
    }
