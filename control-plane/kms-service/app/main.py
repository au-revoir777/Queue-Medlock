from fastapi import FastAPI, Response, HTTPException
from pydantic import BaseModel
from prometheus_client import Counter, Gauge, generate_latest
import time

app = FastAPI(title="MedLock KMS Service - Zero Trust Mode")

# -----------------------------
# In-memory key registry
# -----------------------------
# Structure:
# {(hospital_id, department_id): [
#     {
#         "staff_id": str,
#         "public_sign_key": str,
#         "public_kx_key": str,
#         "timestamp": float
#     }
# ]}
# -----------------------------

key_registry: dict[tuple[str, str], list[dict]] = {}

REPLAY_WINDOW_SECONDS = 5  # replay detection window

# -----------------------------
# Prometheus Metrics
# -----------------------------

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
    response = await call_next(request)
    return response


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type="text/plain")


# -----------------------------
# Models
# -----------------------------


class KeyExchangePayload(BaseModel):
    hospital_id: str
    department_id: str
    staff_id: str
    public_sign_key: str
    public_kx_key: str


# -----------------------------
# Routes
# -----------------------------


@app.get("/keys/{hospital_id}/{department_id}")
def get_keys(hospital_id: str, department_id: str):

    scope = (hospital_id, department_id)

    keys_fetched_total.labels(
        hospital_id=hospital_id, department_id=department_id
    ).inc()

    return {
        "hospital_id": hospital_id,
        "department_id": department_id,
        "total_keys": len(key_registry.get(scope, [])),
        "keys": key_registry.get(scope, []),
    }


@app.post("/exchange")
def exchange(payload: KeyExchangePayload):

    now = time.time()
    scope = (payload.hospital_id, payload.department_id)

    key_registry.setdefault(scope, [])

    # Check for existing staff key
    existing = next(
        (k for k in key_registry[scope] if k["staff_id"] == payload.staff_id), None
    )

    if existing:
        # Detect rapid re-registration (possible replay attack)
        if now - existing.get("timestamp", 0) < REPLAY_WINDOW_SECONDS:
            replay_attempts_total.inc()

        key_overwrites_total.inc()

        key_registry[scope] = [
            k for k in key_registry[scope] if k["staff_id"] != payload.staff_id
        ]

    key_registry[scope].append(
        {
            "staff_id": payload.staff_id,
            "public_sign_key": payload.public_sign_key,
            "public_kx_key": payload.public_kx_key,
            "timestamp": now,
        }
    )

    key_exchanges_total.labels(
        hospital_id=payload.hospital_id, department_id=payload.department_id
    ).inc()

    registered_staff_gauge.labels(
        hospital_id=payload.hospital_id, department_id=payload.department_id
    ).set(len(key_registry[scope]))

    return {
        "status": "registered",
        "hospital_id": payload.hospital_id,
        "department_id": payload.department_id,
        "staff_id": payload.staff_id,
        "total_staff_in_scope": len(key_registry[scope]),
    }


@app.get("/health")
def health():
    return {"status": "ok"}
