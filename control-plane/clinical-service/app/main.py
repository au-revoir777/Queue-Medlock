"""
MedLock Clinical API Service
=============================
Exposes decrypted clinical records stored by the simulator to the frontend.

Auth
----
Every HTTP endpoint (except /health and /metrics) requires a valid Bearer token.
WebSocket endpoints accept the token as a query parameter: ?token=<token>
Hospital-scoped endpoints enforce that the caller's hospital_id matches the
requested hospital — hospital1 staff cannot read hospital2 records.

Endpoints
---------
GET  /health
GET  /metrics
GET  /patients                                    — all patients
GET  /patients/{patient_id}                       — single patient
GET  /patients/{patient_id}/records               — all records for a patient
GET  /records/{hospital_id}                       — all records for a hospital
GET  /records/{hospital_id}/{department}          — records for one department
GET  /records/{hospital_id}/{department}/urgent   — urgent records only
GET  /records/detail/{record_id}                  — single record by PK

WebSocket
---------
WS   /ws/{hospital_id}/{department}?token=<token>
     Streams new clinical records in real time as the simulator writes them.
     Sends JSON messages. Polls Postgres every 2 seconds for new rows.
     Closes with code 1008 (policy violation) if token is invalid or hospital
     does not match.

WS   /ws/{hospital_id}?token=<token>
     Same as above but streams all departments for a hospital (admin view).
"""

from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from prometheus_client import Counter, generate_latest
import os
import time
import asyncio
import json
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from datetime import datetime
import requests as http_requests
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="MedLock Clinical API Service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


DATABASE_URL = os.environ.get("DATABASE_URL", "")
AUTH_VALIDATE_URL = os.environ.get(
    "AUTH_VALIDATE_URL", "http://auth-service:8000/validate"
)
DEFAULT_PAGE_SIZE = 50
WS_POLL_INTERVAL = 2  # seconds between Postgres polls for WebSocket clients

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is not set")


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
            print(f"[clinical] Database ready (attempt {attempt})")
            return
        except Exception as exc:
            print(f"[clinical] Database not ready (attempt {attempt}/{retries}): {exc}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to Postgres after retries")


_wait_for_db()


# ----------------------------------------------------------------
# Prometheus
# ----------------------------------------------------------------

requests_total = Counter(
    "clinical_http_requests_total", "Total HTTP requests to clinical service"
)
records_served_total = Counter(
    "clinical_records_served_total",
    "Total clinical records returned",
    ["hospital_id", "department"],
)
auth_failures_total = Counter(
    "clinical_auth_failures_total", "Auth failures in clinical service"
)
ws_connections_total = Counter(
    "clinical_ws_connections_total",
    "Total WebSocket connections opened",
    ["hospital_id", "department"],
)


@app.middleware("http")
async def count_requests(request: Request, call_next):
    requests_total.inc()
    return await call_next(request)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type="text/plain")


# ----------------------------------------------------------------
# Auth helpers
# ----------------------------------------------------------------


def validate_token(request: Request) -> dict:
    """Validate Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        auth_failures_total.inc()
        raise HTTPException(status_code=401, detail="Missing or malformed token")
    token = auth_header.split(" ", 1)[1]
    return _call_validate(token)


def validate_token_str(token: str) -> dict:
    """Validate a raw token string — used by WebSocket endpoints."""
    if not token:
        auth_failures_total.inc()
        raise HTTPException(status_code=401, detail="Missing token")
    return _call_validate(token)


def _call_validate(token: str) -> dict:
    try:
        resp = http_requests.post(AUTH_VALIDATE_URL, json={"token": token}, timeout=3)
        if resp.status_code != 200:
            auth_failures_total.inc()
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        return resp.json()
    except HTTPException:
        raise
    except Exception as exc:
        auth_failures_total.inc()
        raise HTTPException(status_code=503, detail=f"Auth service unreachable: {exc}")


def require_hospital_access(identity: dict, hospital_id: str):
    if identity.get("hospital_id") != hospital_id:
        raise HTTPException(
            status_code=403,
            detail="Access denied — you may only access your own hospital's records",
        )


def _serialize_row(row: dict) -> dict:
    """Make a DB row JSON-serializable (convert datetime objects to ISO strings)."""
    out = dict(row)
    for k, v in out.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
    return out


# ----------------------------------------------------------------
# Health
# ----------------------------------------------------------------


@app.get("/health")
def health():
    try:
        conn = _get_conn()
        conn.close()
        return {"status": "ok", "database": "ok"}
    except Exception as exc:
        return {"status": "degraded", "database": str(exc)}


# ----------------------------------------------------------------
# Patients
# ----------------------------------------------------------------


@app.get("/patients")
def list_patients(request: Request):
    validate_token(request)
    with db() as cur:
        cur.execute("SELECT * FROM patients ORDER BY name")
        rows = cur.fetchall()
    return {"patients": [dict(r) for r in rows], "total": len(rows)}


@app.get("/patients/{patient_id}")
def get_patient(patient_id: str, request: Request):
    validate_token(request)
    with db() as cur:
        cur.execute("SELECT * FROM patients WHERE id = %s", (patient_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Patient not found")
    return dict(row)


@app.get("/patients/{patient_id}/records")
def get_patient_records(
    patient_id: str,
    request: Request,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
):
    identity = validate_token(request)
    with db() as cur:
        cur.execute(
            """
            SELECT id, hospital_id, department, patient_id, patient_name,
                   producer_id, message_type, sequence, urgent, recorded_at, payload
            FROM clinical_records
            WHERE patient_id = %s AND hospital_id = %s
            ORDER BY recorded_at DESC
            LIMIT %s OFFSET %s
            """,
            (patient_id, identity["hospital_id"], limit, offset),
        )
        rows = cur.fetchall()
        cur.execute(
            "SELECT COUNT(*) AS n FROM clinical_records WHERE patient_id = %s AND hospital_id = %s",
            (patient_id, identity["hospital_id"]),
        )
        total = cur.fetchone()["n"]

    records_served_total.labels(
        hospital_id=identity["hospital_id"], department="all"
    ).inc(len(rows))
    return {
        "patient_id": patient_id,
        "hospital_id": identity["hospital_id"],
        "records": [_serialize_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ----------------------------------------------------------------
# Records — hospital-wide (admin view)
# ----------------------------------------------------------------


@app.get("/records/{hospital_id}")
def get_hospital_records(
    hospital_id: str,
    request: Request,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
):
    identity = validate_token(request)
    require_hospital_access(identity, hospital_id)

    with db() as cur:
        cur.execute(
            """
            SELECT id, hospital_id, department, patient_id, patient_name,
                   producer_id, message_type, sequence, urgent, recorded_at, payload
            FROM clinical_records
            WHERE hospital_id = %s
            ORDER BY recorded_at DESC
            LIMIT %s OFFSET %s
            """,
            (hospital_id, limit, offset),
        )
        rows = cur.fetchall()
        cur.execute(
            "SELECT COUNT(*) AS n FROM clinical_records WHERE hospital_id = %s",
            (hospital_id,),
        )
        total = cur.fetchone()["n"]

    records_served_total.labels(hospital_id=hospital_id, department="all").inc(
        len(rows)
    )
    return {
        "hospital_id": hospital_id,
        "records": [_serialize_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ----------------------------------------------------------------
# Records — department feed
# ----------------------------------------------------------------


@app.get("/records/{hospital_id}/{department}")
def get_department_records(
    hospital_id: str,
    department: str,
    request: Request,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
):
    identity = validate_token(request)
    require_hospital_access(identity, hospital_id)

    with db() as cur:
        cur.execute(
            """
            SELECT id, hospital_id, department, patient_id, patient_name,
                   producer_id, message_type, sequence, urgent, recorded_at, payload
            FROM clinical_records
            WHERE hospital_id = %s AND department = %s
            ORDER BY recorded_at DESC
            LIMIT %s OFFSET %s
            """,
            (hospital_id, department, limit, offset),
        )
        rows = cur.fetchall()
        cur.execute(
            "SELECT COUNT(*) AS n FROM clinical_records WHERE hospital_id = %s AND department = %s",
            (hospital_id, department),
        )
        total = cur.fetchone()["n"]

    records_served_total.labels(hospital_id=hospital_id, department=department).inc(
        len(rows)
    )
    return {
        "hospital_id": hospital_id,
        "department": department,
        "records": [_serialize_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ----------------------------------------------------------------
# Records — urgent only
# ----------------------------------------------------------------


@app.get("/records/{hospital_id}/{department}/urgent")
def get_urgent_records(
    hospital_id: str,
    department: str,
    request: Request,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
):
    identity = validate_token(request)
    require_hospital_access(identity, hospital_id)

    with db() as cur:
        cur.execute(
            """
            SELECT id, hospital_id, department, patient_id, patient_name,
                   producer_id, message_type, sequence, urgent, recorded_at, payload
            FROM clinical_records
            WHERE hospital_id = %s AND department = %s AND urgent = TRUE
            ORDER BY recorded_at DESC
            LIMIT %s OFFSET %s
            """,
            (hospital_id, department, limit, offset),
        )
        rows = cur.fetchall()
        cur.execute(
            """
            SELECT COUNT(*) AS n FROM clinical_records
            WHERE hospital_id = %s AND department = %s AND urgent = TRUE
            """,
            (hospital_id, department),
        )
        total = cur.fetchone()["n"]

    records_served_total.labels(hospital_id=hospital_id, department=department).inc(
        len(rows)
    )
    return {
        "hospital_id": hospital_id,
        "department": department,
        "urgent_only": True,
        "records": [_serialize_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ----------------------------------------------------------------
# Records — single record by primary key
# ----------------------------------------------------------------


@app.get("/records/detail/{record_id}")
def get_record_detail(record_id: int, request: Request):
    identity = validate_token(request)

    with db() as cur:
        cur.execute(
            """
            SELECT id, hospital_id, department, patient_id, patient_name,
                   producer_id, message_type, sequence, urgent, recorded_at, payload
            FROM clinical_records
            WHERE id = %s
            """,
            (record_id,),
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Record not found")

    require_hospital_access(identity, row["hospital_id"])
    return _serialize_row(row)


# ----------------------------------------------------------------
# WebSocket — department feed
#
# ws://host:8003/ws/{hospital_id}/{department}?token=<token>
#
# On connect:
#   1. Validates token and hospital access — closes with 1008 if invalid
#   2. Sends the last 20 records immediately as a "snapshot" message
#   3. Polls every 2 seconds for rows newer than the last seen id
#   4. Pushes each new record individually as a "record" message
#
# Message format:
#   { "type": "snapshot", "records": [...] }
#   { "type": "record", "data": {...} }
#   { "type": "error", "detail": "..." }
# ----------------------------------------------------------------


@app.websocket("/ws/{hospital_id}/{department}")
async def ws_department_feed(
    websocket: WebSocket,
    hospital_id: str,
    department: str,
    token: str = "",
):
    await websocket.accept()

    # Authenticate
    try:
        identity = validate_token_str(token)
        require_hospital_access(identity, hospital_id)
    except HTTPException as exc:
        await websocket.send_text(json.dumps({"type": "error", "detail": exc.detail}))
        await websocket.close(code=1008)
        return

    ws_connections_total.labels(hospital_id=hospital_id, department=department).inc()

    # Send snapshot of last 20 records
    try:
        with db() as cur:
            cur.execute(
                """
                SELECT id, hospital_id, department, patient_id, patient_name,
                       producer_id, message_type, sequence, urgent, recorded_at, payload
                FROM clinical_records
                WHERE hospital_id = %s AND department = %s
                ORDER BY recorded_at DESC
                LIMIT 20
                """,
                (hospital_id, department),
            )
            snapshot = [_serialize_row(r) for r in cur.fetchall()]
            last_id = snapshot[0]["id"] if snapshot else 0

        await websocket.send_text(
            json.dumps(
                {
                    "type": "snapshot",
                    "records": list(reversed(snapshot)),  # chronological order
                }
            )
        )
    except Exception as exc:
        await websocket.send_text(json.dumps({"type": "error", "detail": str(exc)}))
        await websocket.close(code=1011)
        return

    # Poll loop
    try:
        while True:
            await asyncio.sleep(WS_POLL_INTERVAL)

            try:
                with db() as cur:
                    cur.execute(
                        """
                        SELECT id, hospital_id, department, patient_id, patient_name,
                               producer_id, message_type, sequence, urgent, recorded_at, payload
                        FROM clinical_records
                        WHERE hospital_id = %s AND department = %s AND id > %s
                        ORDER BY id ASC
                        """,
                        (hospital_id, department, last_id),
                    )
                    new_rows = cur.fetchall()

                for row in new_rows:
                    record = _serialize_row(row)
                    last_id = record["id"]
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "record",
                                "data": record,
                            }
                        )
                    )
                    records_served_total.labels(
                        hospital_id=hospital_id, department=department
                    ).inc()

            except Exception as exc:
                await websocket.send_text(
                    json.dumps({"type": "error", "detail": str(exc)})
                )

    except WebSocketDisconnect:
        pass  # Client disconnected cleanly


# ----------------------------------------------------------------
# WebSocket — hospital-wide feed (admin view)
#
# ws://host:8003/ws/{hospital_id}?token=<token>
# ----------------------------------------------------------------


@app.websocket("/ws/{hospital_id}")
async def ws_hospital_feed(
    websocket: WebSocket,
    hospital_id: str,
    token: str = "",
):
    await websocket.accept()

    try:
        identity = validate_token_str(token)
        require_hospital_access(identity, hospital_id)
    except HTTPException as exc:
        await websocket.send_text(json.dumps({"type": "error", "detail": exc.detail}))
        await websocket.close(code=1008)
        return

    ws_connections_total.labels(hospital_id=hospital_id, department="all").inc()

    # Send snapshot of last 50 records across all departments
    try:
        with db() as cur:
            cur.execute(
                """
                SELECT id, hospital_id, department, patient_id, patient_name,
                       producer_id, message_type, sequence, urgent, recorded_at, payload
                FROM clinical_records
                WHERE hospital_id = %s
                ORDER BY recorded_at DESC
                LIMIT 50
                """,
                (hospital_id,),
            )
            snapshot = [_serialize_row(r) for r in cur.fetchall()]
            last_id = snapshot[0]["id"] if snapshot else 0

        await websocket.send_text(
            json.dumps(
                {
                    "type": "snapshot",
                    "records": list(reversed(snapshot)),
                }
            )
        )
    except Exception as exc:
        await websocket.send_text(json.dumps({"type": "error", "detail": str(exc)}))
        await websocket.close(code=1011)
        return

    try:
        while True:
            await asyncio.sleep(WS_POLL_INTERVAL)

            try:
                with db() as cur:
                    cur.execute(
                        """
                        SELECT id, hospital_id, department, patient_id, patient_name,
                               producer_id, message_type, sequence, urgent, recorded_at, payload
                        FROM clinical_records
                        WHERE hospital_id = %s AND id > %s
                        ORDER BY id ASC
                        """,
                        (hospital_id, last_id),
                    )
                    new_rows = cur.fetchall()

                for row in new_rows:
                    record = _serialize_row(row)
                    last_id = record["id"]
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "record",
                                "data": record,
                            }
                        )
                    )
                    records_served_total.labels(
                        hospital_id=hospital_id, department="all"
                    ).inc()

            except Exception as exc:
                await websocket.send_text(
                    json.dumps({"type": "error", "detail": str(exc)})
                )

    except WebSocketDisconnect:
        pass
