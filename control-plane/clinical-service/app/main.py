"""
MedLock Clinical API Service
=============================
Performance fixes applied
--------------------------
1. Token validation cache  — avoids auth-service HTTP round-trip on every request.
   TOKEN_CACHE_TTL (default 30s, env-overridable).

2. KMS identity cache — avoids KMS HTTP call on every send.
   KMS_CACHE_TTL (default 300s, env-overridable).

3. DB pool tuned — connect_timeout=5 added.

Bug fix
-------
4. audit_logs INSERT — was passing time.time() (a Python float) into the
   `timestamp` column which is TIMESTAMPTZ in schema.sql. Postgres refuses
   to cast numeric → timestamptz, causing a 500 on every /messages/send:
     "column "timestamp" is of type timestamp with time zone but
      expression is of type numeric"
   Fix: removed `timestamp` from the INSERT column list entirely.
   The column has DEFAULT NOW() so Postgres sets it correctly with no
   application-side value needed.
"""

from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, generate_latest
from pydantic import BaseModel
from contextlib import contextmanager
import os, time, asyncio, json, hashlib, threading
import psycopg2, psycopg2.extras, psycopg2.pool
from datetime import datetime
import requests as http_requests

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
BROKER_URL = os.environ.get("BROKER_URL", "http://broker:9000")
KMS_URL = os.environ.get("KMS_URL", "http://kms-service:8000")
DEFAULT_PAGE_SIZE = 50
WS_POLL_INTERVAL = 2

TOKEN_CACHE_TTL = int(os.environ.get("TOKEN_CACHE_TTL", "30"))  # seconds
KMS_CACHE_TTL = int(os.environ.get("KMS_CACHE_TTL", "300"))  # seconds

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is not set")

# ----------------------------------------------------------------
# Role / permission tables
# ----------------------------------------------------------------

SEND_PERMISSIONS: dict[str, list[str]] = {
    "icu": ["doctor", "nurse"],
    "cardiology": ["doctor"],
    "radiology": ["doctor"],
    "neurology": ["doctor", "nurse"],
    "oncology": ["doctor"],
}

ROLE_MESSAGE_TYPES: dict[str, dict[str, list[str]]] = {
    "doctor": {
        "icu": ["ICU_VITALS", "CODE_ALERT", "PATIENT_OBSERVATION"],
        "cardiology": ["ECG_REPORT", "CARDIOLOGY_CONSULT"],
        "radiology": ["RADIOLOGY_REPORT", "IMAGING_REQUEST"],
        "neurology": ["NEURO_ASSESSMENT", "STROKE_ALERT"],
        "oncology": ["ONCOLOGY_TREATMENT_PLAN", "CHEMO_NOTE"],
    },
    "nurse": {
        "icu": ["ICU_VITALS", "PATIENT_OBSERVATION"],
        "neurology": ["NEURO_ASSESSMENT", "STROKE_ALERT"],
    },
    "admin": {},
}


def get_permitted_message_types(role: str, department: str) -> list[str]:
    return ROLE_MESSAGE_TYPES.get(role, {}).get(department, [])


def can_send(role: str, department: str) -> bool:
    return role in SEND_PERMISSIONS.get(department, [])


# ----------------------------------------------------------------
# Connection pool
# ----------------------------------------------------------------

_pool = None


def _init_pool(min_conn=4, max_conn=50, retries=10, delay=2.0):
    global _pool
    for attempt in range(1, retries + 1):
        try:
            _pool = psycopg2.pool.ThreadedConnectionPool(
                min_conn,
                max_conn,
                DATABASE_URL,
                connect_timeout=5,
            )
            print(f"[clinical] DB pool ready (attempt {attempt})")
            return
        except Exception as exc:
            print(f"[clinical] Not ready ({attempt}/{retries}): {exc}")
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


_init_pool()

# ----------------------------------------------------------------
# Token validation cache
# ----------------------------------------------------------------

_token_cache: dict[str, tuple[dict, float]] = {}
_token_cache_lock = threading.Lock()


def _cache_get_token(token: str) -> dict | None:
    with _token_cache_lock:
        entry = _token_cache.get(token)
        if entry is None:
            return None
        identity, expires_at = entry
        if time.time() > expires_at:
            del _token_cache[token]
            return None
        return identity


def _cache_set_token(token: str, identity: dict):
    with _token_cache_lock:
        _token_cache[token] = (identity, time.time() + TOKEN_CACHE_TTL)


# ----------------------------------------------------------------
# KMS identity cache
# ----------------------------------------------------------------

_kms_cache: dict[str, float] = {}
_kms_cache_lock = threading.Lock()


def _kms_cache_get(hospital: str, dept: str, staff_id: str) -> bool:
    key = f"{hospital}:{dept}:{staff_id}"
    with _kms_cache_lock:
        ts = _kms_cache.get(key)
        if ts is None:
            return False
        if time.time() - ts > KMS_CACHE_TTL:
            del _kms_cache[key]
            return False
        return True


def _kms_cache_set(hospital: str, dept: str, staff_id: str):
    with _kms_cache_lock:
        _kms_cache[f"{hospital}:{dept}:{staff_id}"] = time.time()


# ----------------------------------------------------------------
# Prometheus
# ----------------------------------------------------------------

requests_total = Counter("clinical_http_requests_total", "Total HTTP requests")
records_served_total = Counter(
    "clinical_records_served_total", "Records returned", ["hospital_id", "department"]
)
auth_failures_total = Counter("clinical_auth_failures_total", "Auth failures")
ws_connections_total = Counter(
    "clinical_ws_connections_total", "WS connections", ["hospital_id", "department"]
)
messages_sent_total = Counter(
    "clinical_messages_sent_total",
    "Messages sent",
    ["hospital_id", "department", "role"],
)
send_blocked_total = Counter(
    "clinical_send_blocked_total",
    "Sends blocked by RBAC",
    ["hospital_id", "role", "reason"],
)
token_cache_hits = Counter("clinical_token_cache_hits_total", "Token cache hits")
token_cache_misses = Counter("clinical_token_cache_misses_total", "Token cache misses")
kms_cache_hits = Counter("clinical_kms_cache_hits_total", "KMS cache hits")
kms_cache_misses = Counter("clinical_kms_cache_misses_total", "KMS cache misses")


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
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        auth_failures_total.inc()
        raise HTTPException(status_code=401, detail="Missing or malformed token")
    return _call_validate(auth_header.split(" ", 1)[1])


def validate_token_str(token: str) -> dict:
    if not token:
        auth_failures_total.inc()
        raise HTTPException(status_code=401, detail="Missing token")
    return _call_validate(token)


def _call_validate(token: str) -> dict:
    cached = _cache_get_token(token)
    if cached is not None:
        token_cache_hits.inc()
        return cached

    token_cache_misses.inc()
    try:
        resp = http_requests.post(AUTH_VALIDATE_URL, json={"token": token}, timeout=3)
        if resp.status_code != 200:
            auth_failures_total.inc()
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        identity = resp.json()
        _cache_set_token(token, identity)
        return identity
    except HTTPException:
        raise
    except Exception as exc:
        auth_failures_total.inc()
        raise HTTPException(status_code=503, detail=f"Auth service unreachable: {exc}")


def require_hospital_access(identity: dict, hospital_id: str):
    if identity.get("hospital_id") != hospital_id:
        raise HTTPException(
            status_code=403, detail="Access denied — hospital isolation violation"
        )


def _serialize_row(row: dict) -> dict:
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
# Permissions introspection
# ----------------------------------------------------------------


@app.get("/me/permissions")
def get_my_permissions(request: Request):
    identity = validate_token(request)
    role = identity.get("role", "")
    department = identity.get("department", "")
    return {
        "staff_id": identity.get("staff_id"),
        "hospital_id": identity.get("hospital_id"),
        "role": role,
        "department": department,
        "can_send": can_send(role, department),
        "message_types": get_permitted_message_types(role, department),
    }


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
        cur.execute("SELECT * FROM patients WHERE id=%s", (patient_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Patient not found")
    return dict(row)


@app.get("/patients/{patient_id}/records")
def get_patient_records(
    patient_id: str, request: Request, limit: int = DEFAULT_PAGE_SIZE, offset: int = 0
):
    identity = validate_token(request)
    with db() as cur:
        cur.execute(
            """
            SELECT id, hospital_id, department, patient_id, patient_name,
                   producer_id, message_type, sequence, urgent, recorded_at, payload
            FROM clinical_records
            WHERE patient_id=%s AND hospital_id=%s
            ORDER BY recorded_at DESC LIMIT %s OFFSET %s
            """,
            (patient_id, identity["hospital_id"], limit, offset),
        )
        rows = cur.fetchall()
        cur.execute(
            "SELECT COUNT(*) AS n FROM clinical_records WHERE patient_id=%s AND hospital_id=%s",
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
# Records
# ----------------------------------------------------------------


@app.get("/records/{hospital_id}")
def get_hospital_records(
    hospital_id: str, request: Request, limit: int = DEFAULT_PAGE_SIZE, offset: int = 0
):
    identity = validate_token(request)
    require_hospital_access(identity, hospital_id)
    with db() as cur:
        cur.execute(
            """
            SELECT id, hospital_id, department, patient_id, patient_name,
                   producer_id, message_type, sequence, urgent, recorded_at, payload
            FROM clinical_records WHERE hospital_id=%s
            ORDER BY recorded_at DESC LIMIT %s OFFSET %s
            """,
            (hospital_id, limit, offset),
        )
        rows = cur.fetchall()
        cur.execute(
            "SELECT COUNT(*) AS n FROM clinical_records WHERE hospital_id=%s",
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
            FROM clinical_records WHERE hospital_id=%s AND department=%s
            ORDER BY recorded_at DESC LIMIT %s OFFSET %s
            """,
            (hospital_id, department, limit, offset),
        )
        rows = cur.fetchall()
        cur.execute(
            "SELECT COUNT(*) AS n FROM clinical_records WHERE hospital_id=%s AND department=%s",
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
            FROM clinical_records WHERE hospital_id=%s AND department=%s AND urgent=TRUE
            ORDER BY recorded_at DESC LIMIT %s OFFSET %s
            """,
            (hospital_id, department, limit, offset),
        )
        rows = cur.fetchall()
        cur.execute(
            "SELECT COUNT(*) AS n FROM clinical_records WHERE hospital_id=%s AND department=%s AND urgent=TRUE",
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


@app.get("/records/detail/{record_id}")
def get_record_detail(record_id: int, request: Request):
    identity = validate_token(request)
    with db() as cur:
        cur.execute(
            """
            SELECT id, hospital_id, department, patient_id, patient_name,
                   producer_id, message_type, sequence, urgent, recorded_at, payload
            FROM clinical_records WHERE id=%s
            """,
            (record_id,),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Record not found")
    require_hospital_access(identity, row["hospital_id"])
    return _serialize_row(row)


# ----------------------------------------------------------------
# Send message — zero-trust enforced
# ----------------------------------------------------------------


class SendMessageRequest(BaseModel):
    department: str
    patient_id: str
    patient_name: str
    message_type: str
    payload: dict
    urgent: bool = False


@app.post("/messages/send")
def send_message(body: SendMessageRequest, request: Request):
    identity = validate_token(request)
    role = identity.get("role", "")
    hospital = identity.get("hospital_id", "")
    staff_id = identity.get("staff_id", "")
    dept = identity.get("department", "")

    if body.department != dept:
        send_blocked_total.labels(
            hospital_id=hospital, role=role, reason="department_mismatch"
        ).inc()
        raise HTTPException(
            status_code=403,
            detail=f"Department isolation violation — you are assigned to '{dept}', not '{body.department}'",
        )

    if not can_send(role, dept):
        send_blocked_total.labels(
            hospital_id=hospital, role=role, reason="role_not_permitted"
        ).inc()
        raise HTTPException(
            status_code=403,
            detail=f"Role '{role}' is not permitted to send messages in {dept}",
        )

    permitted = get_permitted_message_types(role, dept)
    if body.message_type not in permitted:
        send_blocked_total.labels(
            hospital_id=hospital, role=role, reason="message_type_not_permitted"
        ).inc()
        raise HTTPException(
            status_code=403,
            detail=f"Role '{role}' cannot send '{body.message_type}'. Permitted: {permitted}",
        )

    # KMS check — use cache, only call KMS on cache miss
    if _kms_cache_get(hospital, dept, staff_id):
        kms_cache_hits.inc()
    else:
        kms_cache_misses.inc()
        try:
            kms_resp = http_requests.get(
                f"{KMS_URL}/keys/{hospital}/{dept}/{staff_id}", timeout=3
            )
            if kms_resp.status_code != 200:
                raise HTTPException(
                    status_code=403,
                    detail="Sender not found in KMS — identity unverifiable",
                )
            _kms_cache_set(hospital, dept, staff_id)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"KMS unreachable: {exc}")

    full_payload = {
        "message_type": body.message_type,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hospital_id": hospital,
        "producer_id": staff_id,
        "patient": {"id": body.patient_id, "name": body.patient_name},
        "urgent": body.urgent,
        **body.payload,
    }

    payload_json = json.dumps(full_payload)
    payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()
    sequence = _get_next_sequence(hospital, staff_id)

    try:
        with db() as cur:
            cur.execute(
                """
                INSERT INTO clinical_records
                    (hospital_id, department, patient_id, patient_name,
                     producer_id, message_type, sequence, payload, urgent)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
                """,
                (
                    hospital,
                    dept,
                    body.patient_id,
                    body.patient_name,
                    staff_id,
                    body.message_type,
                    sequence,
                    payload_json,
                    body.urgent,
                ),
            )
            record_id = cur.fetchone()["id"]

            # FIX: removed `timestamp` from the INSERT column list.
            # schema.sql defines: timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
            # Passing time.time() (a Python float) caused Postgres to reject
            # the insert with:
            #   "column "timestamp" is of type timestamp with time zone
            #    but expression is of type numeric"
            # The DEFAULT NOW() handles it correctly with no app-side value.
            cur.execute(
                """
                INSERT INTO audit_logs
                    (producer_id, department, sequence, verified)
                VALUES (%s, %s, %s, %s)
                """,
                (staff_id, dept, sequence, True),
            )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store message: {exc}")

    messages_sent_total.labels(hospital_id=hospital, department=dept, role=role).inc()

    return {
        "status": "sent",
        "record_id": record_id,
        "sequence": sequence,
        "payload_hash": payload_hash,
        "message_type": body.message_type,
        "urgent": body.urgent,
        "zero_trust": {
            "department_isolation": "passed",
            "role_check": "passed",
            "message_type_check": "passed",
            "kms_identity_check": "passed",
        },
    }


def _get_next_sequence(hospital_id: str, producer_id: str) -> int:
    try:
        resp = http_requests.get(
            f"{BROKER_URL}/sequence/{hospital_id}/{producer_id}", timeout=3
        )
        if resp.status_code == 200:
            return resp.json().get("last_sequence", 0) + 1
    except Exception:
        pass
    try:
        with db() as cur:
            cur.execute(
                "SELECT COALESCE(MAX(sequence),0)+1 AS next FROM clinical_records WHERE producer_id=%s",
                (producer_id,),
            )
            return cur.fetchone()["next"]
    except Exception:
        return int(time.time())


# ----------------------------------------------------------------
# Audit log
# ----------------------------------------------------------------


@app.get("/audit/{hospital_id}")
def get_audit_log(
    hospital_id: str, request: Request, limit: int = 100, offset: int = 0
):
    identity = validate_token(request)
    require_hospital_access(identity, hospital_id)
    with db() as cur:
        cur.execute(
            """
            SELECT a.id, a.timestamp, a.producer_id, a.department,
                   a.sequence, a.verified,
                   cr.message_type, cr.patient_name, cr.urgent, cr.hospital_id
            FROM audit_logs a
            LEFT JOIN clinical_records cr
                ON  cr.producer_id = a.producer_id
                AND cr.sequence    = a.sequence
                AND cr.department  = a.department
            WHERE cr.hospital_id = %s
            ORDER BY a.timestamp DESC
            LIMIT %s OFFSET %s
            """,
            (hospital_id, limit, offset),
        )
        rows = cur.fetchall()
        cur.execute(
            """
            SELECT COUNT(*) AS n FROM audit_logs a
            LEFT JOIN clinical_records cr
                ON  cr.producer_id = a.producer_id
                AND cr.sequence    = a.sequence
                AND cr.department  = a.department
            WHERE cr.hospital_id = %s
            """,
            (hospital_id,),
        )
        total = cur.fetchone()["n"]
    return {
        "hospital_id": hospital_id,
        "entries": [_serialize_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "note": "Metadata only — no plaintext payloads stored in audit log",
    }


# ----------------------------------------------------------------
# WebSocket — department feed
# ----------------------------------------------------------------


@app.websocket("/ws/{hospital_id}/{department}")
async def ws_department_feed(
    websocket: WebSocket, hospital_id: str, department: str, token: str = ""
):
    await websocket.accept()
    try:
        identity = validate_token_str(token)
        require_hospital_access(identity, hospital_id)
    except HTTPException as exc:
        await websocket.send_text(json.dumps({"type": "error", "detail": exc.detail}))
        await websocket.close(code=1008)
        return

    ws_connections_total.labels(hospital_id=hospital_id, department=department).inc()

    try:
        with db() as cur:
            cur.execute(
                """
                SELECT id, hospital_id, department, patient_id, patient_name,
                       producer_id, message_type, sequence, urgent, recorded_at, payload
                FROM clinical_records
                WHERE hospital_id=%s AND department=%s
                ORDER BY recorded_at DESC LIMIT 20
                """,
                (hospital_id, department),
            )
            snapshot = [_serialize_row(r) for r in cur.fetchall()]
            last_id = snapshot[0]["id"] if snapshot else 0
        await websocket.send_text(
            json.dumps({"type": "snapshot", "records": list(reversed(snapshot))})
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
                        WHERE hospital_id=%s AND department=%s AND id>%s
                        ORDER BY id ASC
                        """,
                        (hospital_id, department, last_id),
                    )
                    new_rows = cur.fetchall()
                for row in new_rows:
                    record = _serialize_row(row)
                    last_id = record["id"]
                    await websocket.send_text(
                        json.dumps({"type": "record", "data": record})
                    )
                    records_served_total.labels(
                        hospital_id=hospital_id, department=department
                    ).inc()
            except Exception as exc:
                await websocket.send_text(
                    json.dumps({"type": "error", "detail": str(exc)})
                )
    except WebSocketDisconnect:
        pass


# ----------------------------------------------------------------
# WebSocket — hospital-wide feed
# ----------------------------------------------------------------


@app.websocket("/ws/{hospital_id}")
async def ws_hospital_feed(websocket: WebSocket, hospital_id: str, token: str = ""):
    await websocket.accept()
    try:
        identity = validate_token_str(token)
        require_hospital_access(identity, hospital_id)
    except HTTPException as exc:
        await websocket.send_text(json.dumps({"type": "error", "detail": exc.detail}))
        await websocket.close(code=1008)
        return

    ws_connections_total.labels(hospital_id=hospital_id, department="all").inc()

    try:
        with db() as cur:
            cur.execute(
                """
                SELECT id, hospital_id, department, patient_id, patient_name,
                       producer_id, message_type, sequence, urgent, recorded_at, payload
                FROM clinical_records WHERE hospital_id=%s
                ORDER BY recorded_at DESC LIMIT 50
                """,
                (hospital_id,),
            )
            snapshot = [_serialize_row(r) for r in cur.fetchall()]
            last_id = snapshot[0]["id"] if snapshot else 0
        await websocket.send_text(
            json.dumps({"type": "snapshot", "records": list(reversed(snapshot))})
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
                        FROM clinical_records WHERE hospital_id=%s AND id>%s
                        ORDER BY id ASC
                        """,
                        (hospital_id, last_id),
                    )
                    new_rows = cur.fetchall()
                for row in new_rows:
                    record = _serialize_row(row)
                    last_id = record["id"]
                    await websocket.send_text(
                        json.dumps({"type": "record", "data": record})
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
