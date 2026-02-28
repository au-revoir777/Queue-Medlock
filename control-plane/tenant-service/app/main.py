from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from prometheus_client import Counter, Gauge, generate_latest
import time
import requests
import os

app = FastAPI(title="MedLock Tenant Service - Zero Trust Mode")

AUTH_URL = os.environ.get("AUTH_URL", "http://auth-service:8000/register")

# -----------------------------
# In-memory storage
# -----------------------------
hospitals: dict[str, dict] = {}
staff: dict[str, dict] = {}

# -----------------------------
# Metrics
# -----------------------------
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
    return {"status": "ok"}


# -----------------------------
# Models
# -----------------------------
class HospitalCreate(BaseModel):
    id: str
    name: str


class StaffRegister(BaseModel):
    id: str
    hospital_id: str
    role: str
    department: str  # added: required, forwarded to auth service
    public_sign_key: str
    public_kx_key: str


# -----------------------------
# Routes
# -----------------------------
@app.post("/hospitals")
def create_hospital(payload: HospitalCreate):

    if payload.id in hospitals:
        raise HTTPException(status_code=409, detail="Hospital already exists")

    hospitals[payload.id] = {
        "id": payload.id,
        "name": payload.name,
        "created_at": time.time(),
    }

    active_staff_gauge.labels(hospital_id=payload.id).set(0)
    hospitals_created_total.inc()

    return hospitals[payload.id]


@app.post("/staff/register")
def register_staff(payload: StaffRegister):

    if payload.hospital_id not in hospitals:
        raise HTTPException(status_code=404, detail="Hospital not found")

    auth_response = requests.post(
        AUTH_URL,
        json={
            "hospital_id": payload.hospital_id,
            "staff_id": payload.id,
            "password": "pass123",
            "department": payload.department,  # forwarded to auth
        },
        timeout=3,
    )

    if auth_response.status_code not in (200, 201, 409):
        raise HTTPException(status_code=500, detail="Auth service failed")

    staff[payload.id] = {**payload.model_dump(), "registered_at": time.time()}

    staff_registered_total.labels(
        hospital_id=payload.hospital_id, role=payload.role
    ).inc()

    count = len([s for s in staff.values() if s["hospital_id"] == payload.hospital_id])

    active_staff_gauge.labels(hospital_id=payload.hospital_id).set(count)

    return staff[payload.id]
