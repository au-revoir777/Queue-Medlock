from fastapi import FastAPI, Response, HTTPException
from pydantic import BaseModel
from prometheus_client import Counter, generate_latest
import hashlib
import time

app = FastAPI(title="MedLock Auth Service")

# -----------------------------
# In-memory registries
# -----------------------------
user_registry: dict[tuple[str, str], str] = {}
token_registry: dict[str, dict] = {}

# -----------------------------
# Prometheus Metrics
# -----------------------------
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
    return {"status": "ok"}


# -----------------------------
# Models
# -----------------------------
class RegisterPayload(BaseModel):
    hospital_id: str
    staff_id: str
    password: str


class LoginPayload(BaseModel):
    hospital_id: str
    staff_id: str
    password: str


class ValidatePayload(BaseModel):
    token: str


# -----------------------------
# Routes
# -----------------------------
@app.post("/register")
def register(payload: RegisterPayload):

    key = (payload.hospital_id, payload.staff_id)

    if key in user_registry:
        raise HTTPException(status_code=409, detail="User already exists")

    hashed = hashlib.sha256(payload.password.encode()).hexdigest()
    user_registry[key] = hashed

    registrations_total.labels(hospital_id=payload.hospital_id).inc()

    return {"status": "created"}


@app.post("/login")
def login(payload: LoginPayload):

    key = (payload.hospital_id, payload.staff_id)

    if key not in user_registry:
        login_failure_total.labels(hospital_id=payload.hospital_id).inc()
        raise HTTPException(status_code=404, detail="User not found")

    hashed_input = hashlib.sha256(payload.password.encode()).hexdigest()

    if user_registry[key] != hashed_input:
        login_failure_total.labels(hospital_id=payload.hospital_id).inc()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    login_success_total.labels(hospital_id=payload.hospital_id).inc()

    token_raw = f"{payload.hospital_id}{payload.staff_id}{time.time()}"
    token = hashlib.sha256(token_raw.encode()).hexdigest()

    token_registry[token] = {
        "hospital_id": payload.hospital_id,
        "staff_id": payload.staff_id,
        "issued_at": time.time(),
    }

    return {"access_token": token}


@app.post("/validate")
def validate(payload: ValidatePayload):

    if payload.token not in token_registry:
        raise HTTPException(status_code=401, detail="Invalid token")

    return token_registry[payload.token]
