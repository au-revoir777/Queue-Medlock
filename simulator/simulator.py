"""
MedLock Traffic Simulator — Hybrid Post-Quantum Cryptography
=============================================================
Key exchange  : X25519 (classical) + ML-KEM-768 (post-quantum) combined via HKDF
Signatures    : Ed25519 (classical) + ML-DSA-65 (post-quantum) both verified
Delivery      : Redis consumer groups (exactly-once, ACK after decrypt)
Resilience    : Sequence bootstrapped from broker on startup (survives restarts)
Key directory : KMS fetched at decrypt time (zero-trust — no local key trust)

Clinical data (Step 1a)
-----------------------
Each department produces structured, semi-realistic clinical JSON payloads.
  ICU        → vitals (HR, BP, SpO2, temperature, RR, GCS, alerts)
  Cardiology → ECG readings (rhythm, intervals, ST changes, interpretation)
  Radiology  → scan results (modality, body part, findings, impression)
  Neurology  → neurological assessments (GCS, pupils, motor, NIHSS)
  Oncology   → treatment plans (diagnosis, stage, protocol, medications)

Key persistence (Step 1b)
--------------------------
StaffMember key pairs persisted in simulator_keys table. Loaded on restart.

Clinical records (Step 2)
--------------------------
After every successful decrypt, the structured record is written to the
clinical_records table. Patients are seeded on startup from _PATIENTS list.
"""

import json
import os
import requests
import random
import time
import threading
import logging
import base64
import hashlib
from dataclasses import dataclass, field
from contextlib import contextmanager
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import psycopg2
import psycopg2.extras
import oqs  # liboqs-python — ML-KEM-768 and ML-DSA-65

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s",
)
log = logging.getLogger("simulator")

SIM_PASSWORD = os.environ.get("SIM_PASSWORD", "")
if not SIM_PASSWORD:
    raise RuntimeError("SIM_PASSWORD not set")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

AUTH_URL = os.environ.get("AUTH_URL", "http://auth-service:8000/login")
TENANT_URL = os.environ.get("TENANT_URL", "http://tenant-service:8000")
BROKER_URL = os.environ.get("BROKER_URL", "http://broker:9000")
KMS_URL = os.environ.get("KMS_URL", "http://kms-service:8000")

HOSPITALS = ["hospital1", "hospital2"]
DEPARTMENTS = ["cardiology", "radiology", "icu", "neurology", "oncology"]
ROLES = ["doctor", "nurse", "admin"]

PENDING_RECLAIM_IDLE_MS = 30_000

KEM_ALG = "ML-KEM-768"
DSA_ALG = "ML-DSA-65"


# ----------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------


def _get_sim_conn():
    return psycopg2.connect(DATABASE_URL)


@contextmanager
def _sim_db():
    conn = _get_sim_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _wait_for_sim_db(retries: int = 10, delay: float = 2.0):
    for attempt in range(1, retries + 1):
        try:
            conn = _get_sim_conn()
            conn.close()
            log.info("[sim-db] Database ready (attempt %d)", attempt)
            return
        except Exception as exc:
            log.warning("[sim-db] Not ready (attempt %d/%d): %s", attempt, retries, exc)
            time.sleep(delay)
    raise RuntimeError("Simulator could not connect to Postgres after retries")


def _create_sim_keys_table():
    with _sim_db() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS simulator_keys (
                staff_id         TEXT PRIMARY KEY,
                hospital_id      TEXT NOT NULL,
                department       TEXT NOT NULL,
                sign_private_b64 TEXT NOT NULL,
                kx_private_b64   TEXT NOT NULL,
                kem_private_b64  TEXT NOT NULL,
                kem_public_b64   TEXT NOT NULL,
                dsa_private_b64  TEXT NOT NULL,
                dsa_public_b64   TEXT NOT NULL,
                created_at       DOUBLE PRECISION NOT NULL
            )
        """
        )
    log.info("[sim-db] simulator_keys table ready")


# ----------------------------------------------------------------
# Clinical data generators — semi-realistic, clearly fake
# ----------------------------------------------------------------

_PATIENTS = [
    {"id": "P1001", "name": "Aisha Nair", "age": 45, "blood_type": "O+"},
    {"id": "P1002", "name": "Rahul Menon", "age": 62, "blood_type": "A+"},
    {"id": "P1003", "name": "Fatima Al-Sayed", "age": 38, "blood_type": "B-"},
    {"id": "P1004", "name": "Chen Wei", "age": 71, "blood_type": "AB+"},
    {"id": "P1005", "name": "Priya Sharma", "age": 55, "blood_type": "O-"},
    {"id": "P1006", "name": "Omar Hassan", "age": 49, "blood_type": "A-"},
    {"id": "P1007", "name": "Lindiwe Dube", "age": 33, "blood_type": "B+"},
    {"id": "P1008", "name": "Santiago Reyes", "age": 67, "blood_type": "AB-"},
]

_DOCTORS = [
    "Dr. Ahmed Khan",
    "Dr. Priya Patel",
    "Dr. Chen Wei",
    "Dr. Sara Okonkwo",
    "Dr. James Osei",
    "Dr. Leila Ahmadi",
]


def _patient() -> dict:
    return random.choice(_PATIENTS)


def _doctor() -> str:
    return random.choice(_DOCTORS)


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def generate_icu_message(hospital_id: str, producer_id: str) -> dict:
    p = _patient()
    hr = random.randint(55, 130)
    sbp = random.randint(90, 180)
    dbp = random.randint(60, 110)
    spo2 = random.randint(88, 100)
    temp = round(random.uniform(36.0, 39.5), 1)
    rr = random.randint(12, 30)
    gcs = random.randint(8, 15)

    alerts = []
    if hr > 110:
        alerts.append("TACHYCARDIA")
    if hr < 60:
        alerts.append("BRADYCARDIA")
    if spo2 < 92:
        alerts.append("HYPOXIA")
    if sbp > 160:
        alerts.append("HYPERTENSION")
    if sbp < 90:
        alerts.append("HYPOTENSION")
    if temp > 38.5:
        alerts.append("FEVER")
    if gcs < 13:
        alerts.append("ALTERED_CONSCIOUSNESS")

    return {
        "message_type": "ICU_VITALS",
        "timestamp": _timestamp(),
        "hospital_id": hospital_id,
        "producer_id": producer_id,
        "patient": p,
        "attending": _doctor(),
        "vitals": {
            "heart_rate": hr,
            "blood_pressure": f"{sbp}/{dbp}",
            "spo2_percent": spo2,
            "temperature_c": temp,
            "respiratory_rate": rr,
            "gcs": gcs,
        },
        "alerts": alerts,
        "status": "CRITICAL" if alerts else "STABLE",
    }


def generate_cardiology_message(hospital_id: str, producer_id: str) -> dict:
    p = _patient()
    rhythms = [
        "Normal sinus rhythm",
        "Sinus tachycardia",
        "Sinus bradycardia",
        "Atrial fibrillation",
        "Premature ventricular contractions",
        "First-degree AV block",
    ]
    interpretations = [
        "No acute changes",
        "Possible ischaemia — correlate clinically",
        "ST elevation in leads II, III, aVF — urgent review",
        "T-wave inversion in V1-V4",
        "Left ventricular hypertrophy pattern",
        "Normal ECG",
    ]
    return {
        "message_type": "ECG_REPORT",
        "timestamp": _timestamp(),
        "hospital_id": hospital_id,
        "producer_id": producer_id,
        "patient": p,
        "attending": _doctor(),
        "ecg": {
            "heart_rate": random.randint(45, 130),
            "rhythm": random.choice(rhythms),
            "pr_interval_ms": random.randint(120, 220),
            "qrs_duration_ms": random.randint(80, 130),
            "qt_interval_ms": random.randint(350, 480),
            "st_changes": random.choice(["None", "Elevation", "Depression"]),
            "axis": random.choice(["Normal", "Left deviation", "Right deviation"]),
        },
        "interpretation": random.choice(interpretations),
        "urgent": random.random() < 0.15,
    }


def generate_radiology_message(hospital_id: str, producer_id: str) -> dict:
    p = _patient()
    findings_pool = [
        "No acute intracranial abnormality identified.",
        "Mild cardiomegaly noted. No pleural effusion.",
        "Small consolidation in the right lower lobe, consistent with pneumonia.",
        "No evidence of fracture or dislocation.",
        "Hepatomegaly with no focal lesions identified.",
        "Mild degenerative changes at L4-L5.",
        "No significant abnormality detected.",
        "Soft tissue swelling noted. No bony injury.",
    ]
    impressions = [
        "Normal study.",
        "Findings consistent with pneumonia — clinical correlation advised.",
        "No acute pathology identified.",
        "Recommend follow-up MRI in 6 weeks.",
        "Urgent neurosurgical review recommended.",
        "Findings noted — clinical correlation required.",
    ]
    return {
        "message_type": "RADIOLOGY_REPORT",
        "timestamp": _timestamp(),
        "hospital_id": hospital_id,
        "producer_id": producer_id,
        "patient": p,
        "radiologist": _doctor(),
        "scan": {
            "modality": random.choice(["CT", "MRI", "X-Ray", "Ultrasound", "PET-CT"]),
            "body_part": random.choice(
                ["Chest", "Abdomen", "Brain", "Spine", "Pelvis", "Neck"]
            ),
            "contrast_used": random.choice([True, False]),
            "scan_duration": f"{random.randint(5, 45)} minutes",
        },
        "findings": random.choice(findings_pool),
        "impression": random.choice(impressions),
        "urgent": random.random() < 0.10,
    }


def generate_neurology_message(hospital_id: str, producer_id: str) -> dict:
    p = _patient()
    gcs_eye = random.randint(1, 4)
    gcs_verbal = random.randint(1, 5)
    gcs_motor = random.randint(1, 6)
    nihss = random.randint(0, 25)
    diagnoses = [
        "Ischaemic stroke — right MCA territory",
        "Transient ischaemic attack",
        "Seizure disorder — under investigation",
        "Migraine with aura",
        "Subarachnoid haemorrhage",
        "Peripheral neuropathy",
    ]
    return {
        "message_type": "NEURO_ASSESSMENT",
        "timestamp": _timestamp(),
        "hospital_id": hospital_id,
        "producer_id": producer_id,
        "patient": p,
        "neurologist": _doctor(),
        "gcs": {
            "eye": gcs_eye,
            "verbal": gcs_verbal,
            "motor": gcs_motor,
            "total": gcs_eye + gcs_verbal + gcs_motor,
        },
        "pupils": random.choice(
            [
                "Equal and reactive",
                "Right pupil dilated and sluggish",
                "Left pupil non-reactive",
                "Bilateral pinpoint pupils",
                "Equal and brisk",
            ]
        ),
        "motor_exam": random.choice(
            [
                "No focal deficit",
                "Left arm weakness (4/5)",
                "Right leg weakness (3/5)",
                "Normal power throughout",
            ]
        ),
        "nihss_score": nihss,
        "diagnosis": random.choice(diagnoses),
        "severity": "SEVERE" if nihss > 15 else "MODERATE" if nihss > 5 else "MILD",
    }


def generate_oncology_message(hospital_id: str, producer_id: str) -> dict:
    p = _patient()
    cancers = [
        ("Breast carcinoma", ["Stage I", "Stage II", "Stage III"]),
        ("Non-small cell lung CA", ["Stage II", "Stage III", "Stage IV"]),
        ("Colorectal carcinoma", ["Stage I", "Stage II", "Stage III"]),
        ("Diffuse large B-cell lymphoma", ["Stage II", "Stage III"]),
        ("Acute myeloid leukaemia", ["Newly diagnosed", "Relapsed"]),
        ("Glioblastoma multiforme", ["Stage IV"]),
    ]
    protocols = [
        "AC-T (Doxorubicin + Cyclophosphamide → Paclitaxel)",
        "FOLFOX (Oxaliplatin + Leucovorin + 5-Fluorouracil)",
        "R-CHOP (Rituximab + CHOP)",
        "Temozolomide + Radiotherapy",
        "Carboplatin + Pemetrexed",
        "Azacitidine monotherapy",
    ]
    cancer_name, stages = random.choice(cancers)
    meds = random.sample(
        [
            "Dexamethasone 4mg BD",
            "Ondansetron 8mg TDS",
            "Filgrastim 300mcg SC daily",
            "Aprepitant 125mg day 1",
            "Omeprazole 20mg OD",
            "Metoclopramide 10mg TDS PRN",
        ],
        k=random.randint(2, 4),
    )

    return {
        "message_type": "ONCOLOGY_TREATMENT_PLAN",
        "timestamp": _timestamp(),
        "hospital_id": hospital_id,
        "producer_id": producer_id,
        "patient": p,
        "oncologist": _doctor(),
        "diagnosis": cancer_name,
        "stage": random.choice(stages),
        "protocol": random.choice(protocols),
        "cycle": f"Cycle {random.randint(1, 6)} of {random.randint(6, 8)}",
        "medications": meds,
        "next_review": f"In {random.randint(2, 4)} weeks",
        "ecog_status": random.randint(0, 3),
    }


CLINICAL_GENERATORS = {
    "icu": generate_icu_message,
    "cardiology": generate_cardiology_message,
    "radiology": generate_radiology_message,
    "neurology": generate_neurology_message,
    "oncology": generate_oncology_message,
}


def generate_clinical_message(dept: str, hospital_id: str, producer_id: str) -> str:
    generator = CLINICAL_GENERATORS.get(dept)
    if generator is None:
        return json.dumps(
            {
                "message_type": "GENERIC",
                "timestamp": _timestamp(),
                "hospital_id": hospital_id,
                "producer_id": producer_id,
                "content": f"Message from {producer_id} in {dept}",
            }
        )
    return json.dumps(generator(hospital_id, producer_id))


# ----------------------------------------------------------------
# Patient seeding
# ----------------------------------------------------------------


def seed_patients():
    """Insert the fixed patient list into the patients table if not already present."""
    try:
        with _sim_db() as cur:
            for p in _PATIENTS:
                cur.execute(
                    """
                    INSERT INTO patients (id, name, age, blood_type)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """,
                    (p["id"], p["name"], p["age"], p["blood_type"]),
                )
        log.info("[sim-db] Patients seeded (%d rows)", len(_PATIENTS))
    except Exception as exc:
        log.warning("[sim-db] Patient seeding failed: %s", exc)


# ----------------------------------------------------------------
# Clinical record writer
# ----------------------------------------------------------------


def write_clinical_record(
    *,
    hospital_id: str,
    department: str,
    producer_id: str,
    sequence: int,
    record: dict,
):
    """Persist a decrypted clinical record to Postgres."""
    patient = record.get("patient", {})
    patient_id = patient.get("id")
    patient_name = patient.get("name")
    message_type = record.get("message_type", "UNKNOWN")
    urgent = bool(record.get("urgent", False))

    try:
        with _sim_db() as cur:
            cur.execute(
                """
                INSERT INTO clinical_records
                    (hospital_id, department, patient_id, patient_name,
                     producer_id, message_type, sequence, payload, urgent)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    hospital_id,
                    department,
                    patient_id,
                    patient_name,
                    producer_id,
                    message_type,
                    sequence,
                    json.dumps(record),
                    urgent,
                ),
            )
        log.info(
            "[clinical] Wrote %s for %s [%s/%s seq=%d]",
            message_type,
            patient_name,
            hospital_id,
            department,
            sequence,
        )
    except Exception as exc:
        log.warning(
            "[clinical] Write failed [%s/%s seq=%d]: %s",
            hospital_id,
            department,
            sequence,
            exc,
        )


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _d64(s: str) -> bytes:
    return base64.b64decode(s)


def safe_post(url: str, json: dict, retries: int = 5, timeout: float = 3.0):
    delay = 0.5
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(url, json=json, timeout=timeout)
            if resp.status_code < 500:
                return resp
        except Exception as exc:
            log.warning(
                "POST %s failed (attempt %d/%d): %s", url, attempt, retries, exc
            )
        time.sleep(delay)
        delay = min(delay * 2, 10)
    log.error("POST %s failed after %d attempts", url, retries)
    return None


def get_last_sequence(hospital_id: str, producer_id: str) -> int:
    try:
        resp = requests.get(
            f"{BROKER_URL}/sequence/{hospital_id}/{producer_id}", timeout=3
        )
        if resp.status_code == 200:
            seq = resp.json().get("last_sequence", 0)
            log.info(
                "Sequence bootstrap %s/%s → last_sequence=%d",
                hospital_id,
                producer_id,
                seq,
            )
            return seq
    except Exception as exc:
        log.warning(
            "Could not bootstrap sequence for %s/%s: %s", hospital_id, producer_id, exc
        )
    return 0


def fetch_producer_keys(hospital_id: str, department_id: str, producer_id: str) -> dict:
    resp = requests.get(
        f"{KMS_URL}/keys/{hospital_id}/{department_id}/{producer_id}", timeout=3
    )
    if resp.status_code != 200:
        raise ValueError(
            f"KMS key lookup failed for {producer_id}: HTTP {resp.status_code} {resp.text[:80]}"
        )
    return resp.json()


# ----------------------------------------------------------------
# Hybrid crypto
# ----------------------------------------------------------------

ENVELOPE_VERSION = "hybrid-v1"


@dataclass
class EncryptedPayload:
    nonce: str
    ciphertext: str
    envelope: dict


def build_encrypted_payload(
    *,
    hospital_id: str,
    department_id: str,
    producer_id: str,
    sequence: int,
    plaintext: str,
    consumer_kx_public_b64: str,
    producer_sign_private_obj: ed25519.Ed25519PrivateKey,
    consumer_kem_public_b64: str,
    producer_dsa_private_bytes: bytes,
) -> EncryptedPayload:

    consumer_kx_pub = x25519.X25519PublicKey.from_public_bytes(
        _d64(consumer_kx_public_b64)
    )
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared_x25519 = eph_priv.exchange(consumer_kx_pub)

    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, shared_kem = kem.encap_secret(_d64(consumer_kem_public_b64))

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"{hospital_id}:{department_id}".encode(),
    ).derive(shared_x25519 + shared_kem)

    nonce = os.urandom(12)
    aad = f"{producer_id}:{sequence}".encode()
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext.encode(), aad)
    digest = hashlib.sha256(ciphertext).hexdigest()

    signed_content = f"{producer_id}:{sequence}:{digest}".encode()
    sig_classical = producer_sign_private_obj.sign(signed_content)
    with oqs.Signature(DSA_ALG, secret_key=producer_dsa_private_bytes) as dsa:
        sig_pqc = dsa.sign(signed_content)

    return EncryptedPayload(
        nonce=_b64(nonce),
        ciphertext=_b64(ciphertext),
        envelope={
            "version": ENVELOPE_VERSION,
            "ephemeral_public_key": _b64(eph_pub_bytes),
            "kem_ciphertext": _b64(kem_ct),
            "signature_classical": _b64(sig_classical),
            "signature_pqc": _b64(sig_pqc),
            "cipher_hash": digest,
        },
    )


def decrypt_item(
    *,
    hospital_id: str,
    department_id: str,
    producer_id: str,
    sequence: int,
    nonce_b64: str,
    ciphertext_b64: str,
    envelope: dict,
    consumer_kx_private_obj: x25519.X25519PrivateKey,
    consumer_kem_private_bytes: bytes,
    producer_sign_public_obj: ed25519.Ed25519PublicKey,
    producer_dsa_public_bytes: bytes,
) -> str:

    ciphertext = _d64(ciphertext_b64)
    digest = hashlib.sha256(ciphertext).hexdigest()
    if digest != envelope.get("cipher_hash"):
        raise ValueError("Cipher hash mismatch — message tampered")

    signed_content = f"{producer_id}:{sequence}:{digest}".encode()
    producer_sign_public_obj.verify(
        _d64(envelope["signature_classical"]), signed_content
    )

    with oqs.Signature(DSA_ALG) as dsa:
        valid = dsa.verify(
            signed_content, _d64(envelope["signature_pqc"]), producer_dsa_public_bytes
        )
    if not valid:
        raise ValueError("ML-DSA-65 signature verification failed")

    eph_pub = x25519.X25519PublicKey.from_public_bytes(
        _d64(envelope["ephemeral_public_key"])
    )
    shared_x25519 = consumer_kx_private_obj.exchange(eph_pub)

    with oqs.KeyEncapsulation(KEM_ALG, secret_key=consumer_kem_private_bytes) as kem:
        shared_kem = kem.decap_secret(_d64(envelope["kem_ciphertext"]))

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"{hospital_id}:{department_id}".encode(),
    ).derive(shared_x25519 + shared_kem)

    return (
        AESGCM(session_key)
        .decrypt(_d64(nonce_b64), ciphertext, f"{producer_id}:{sequence}".encode())
        .decode()
    )


# ----------------------------------------------------------------
# Staff — with Postgres key persistence
# ----------------------------------------------------------------
@dataclass
class StaffMember:
    hospital_id: str
    staff_id: str
    role: str
    department: str
    token: str = None
    sequence: int = 1

    sign_key_obj: ed25519.Ed25519PrivateKey = field(default=None)
    kx_private_obj: x25519.X25519PrivateKey = field(default=None)

    kem_private_bytes: bytes = field(default=None, repr=False)
    kem_public_bytes: bytes = field(default=None, repr=False)
    dsa_private_bytes: bytes = field(default=None, repr=False)
    dsa_public_bytes: bytes = field(default=None, repr=False)

    sign_key: str = field(init=False, repr=False)
    kx_public: str = field(init=False, repr=False)
    kem_public: str = field(init=False, repr=False)
    dsa_public: str = field(init=False, repr=False)

    def __post_init__(self):
        row = self._load_keys_from_db()
        if row:
            log.info("[sim-keys] Loaded persisted keys for %s", self.staff_id)
            self.sign_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(
                _d64(row["sign_private_b64"])
            )
            self.kx_private_obj = x25519.X25519PrivateKey.from_private_bytes(
                _d64(row["kx_private_b64"])
            )
            self.kem_private_bytes = _d64(row["kem_private_b64"])
            self.kem_public_bytes = _d64(row["kem_public_b64"])
            self.dsa_private_bytes = _d64(row["dsa_private_b64"])
            self.dsa_public_bytes = _d64(row["dsa_public_b64"])
        else:
            log.info("[sim-keys] Generating new keys for %s", self.staff_id)
            self.sign_key_obj = ed25519.Ed25519PrivateKey.generate()
            self.kx_private_obj = x25519.X25519PrivateKey.generate()
            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                self.kem_public_bytes = kem.generate_keypair()
                self.kem_private_bytes = kem.export_secret_key()
            with oqs.Signature(DSA_ALG) as dsa:
                self.dsa_public_bytes = dsa.generate_keypair()
                self.dsa_private_bytes = dsa.export_secret_key()
            self._save_keys_to_db()

        self.sign_key = _b64(
            self.sign_key_obj.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
        self.kx_public = _b64(
            self.kx_private_obj.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
        self.kem_public = _b64(self.kem_public_bytes)
        self.dsa_public = _b64(self.dsa_public_bytes)

    def _load_keys_from_db(self):
        try:
            with _sim_db() as cur:
                cur.execute(
                    "SELECT * FROM simulator_keys WHERE staff_id = %s", (self.staff_id,)
                )
                return cur.fetchone()
        except Exception as exc:
            log.warning("[sim-keys] Load failed for %s: %s", self.staff_id, exc)
            return None

    def _save_keys_to_db(self):
        sign_priv = _b64(
            self.sign_key_obj.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        kx_priv = _b64(
            self.kx_private_obj.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        try:
            with _sim_db() as cur:
                cur.execute(
                    """
                    INSERT INTO simulator_keys
                        (staff_id, hospital_id, department,
                         sign_private_b64, kx_private_b64,
                         kem_private_b64,  kem_public_b64,
                         dsa_private_b64,  dsa_public_b64,
                         created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (staff_id) DO NOTHING
                """,
                    (
                        self.staff_id,
                        self.hospital_id,
                        self.department,
                        sign_priv,
                        kx_priv,
                        _b64(self.kem_private_bytes),
                        _b64(self.kem_public_bytes),
                        _b64(self.dsa_private_bytes),
                        _b64(self.dsa_public_bytes),
                        time.time(),
                    ),
                )
            log.info("[sim-keys] Saved keys for %s", self.staff_id)
        except Exception as exc:
            log.warning("[sim-keys] Save failed for %s: %s", self.staff_id, exc)


# ----------------------------------------------------------------
# Registration + auth
# ----------------------------------------------------------------
def register_staff_member(s: StaffMember) -> bool:
    resp = safe_post(
        f"{TENANT_URL}/staff/register",
        json={
            "id": s.staff_id,
            "hospital_id": s.hospital_id,
            "role": s.role,
            "department": s.department,
            "public_sign_key": s.sign_key,
            "public_kx_key": s.kx_public,
            "public_kem_key": s.kem_public,
            "public_dsa_key": s.dsa_public,
        },
    )
    if resp is None:
        log.error("Staff register %s → no response (timeout)", s.staff_id)
        return False
    if resp.status_code not in (200, 201, 409):
        log.error(
            "Staff register %s → HTTP %d %s",
            s.staff_id,
            resp.status_code,
            resp.text[:120],
        )
        return False
    log.info("Staff register %s → OK (HTTP %d)", s.staff_id, resp.status_code)
    return True


def authenticate_staff_member(s: StaffMember) -> bool:
    resp = safe_post(
        AUTH_URL,
        json={
            "hospital_id": s.hospital_id,
            "staff_id": s.staff_id,
            "password": "pass123",
        },
    )
    if resp is None:
        s.token = None
        return False
    if resp.status_code == 404:
        log.warning("Auth for %s → 404, re-registering", s.staff_id)
        s.token = None
        register_staff_member(s)
        return False
    if resp.status_code not in (200, 201):
        s.token = None
        return False
    s.token = resp.json().get("access_token")
    return True


# ----------------------------------------------------------------
# Consumer group helpers
# ----------------------------------------------------------------
def cg_dequeue(hospital_id: str, dept: str, consumer_id: str, token: str) -> list:
    try:
        resp = requests.get(
            f"{BROKER_URL}/cg-dequeue/{hospital_id}/{dept}",
            params={"consumer_id": consumer_id, "count": "10"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=3,
        )
        if resp.status_code == 200:
            return resp.json().get("items", [])
        log.warning("cg-dequeue failed: %d %s", resp.status_code, resp.text[:80])
    except Exception as exc:
        log.warning("cg-dequeue exception: %s", exc)
    return []


def cg_ack(
    hospital_id: str, dept: str, consumer_id: str, message_ids: list, token: str
) -> None:
    if not message_ids:
        return
    try:
        resp = requests.post(
            f"{BROKER_URL}/cg-ack/{hospital_id}/{dept}",
            json={"consumer_id": consumer_id, "message_ids": message_ids},
            headers={"Authorization": f"Bearer {token}"},
            timeout=3,
        )
        if resp.status_code != 200:
            log.warning("cg-ack failed: %d %s", resp.status_code, resp.text[:80])
    except Exception as exc:
        log.warning("cg-ack exception: %s", exc)


def cg_reclaim_pending(
    hospital_id: str, dept: str, consumer_id: str, token: str
) -> list:
    try:
        resp = requests.get(
            f"{BROKER_URL}/cg-pending/{hospital_id}/{dept}",
            params={
                "consumer_id": consumer_id,
                "min_idle_ms": str(PENDING_RECLAIM_IDLE_MS),
                "count": "10",
            },
            headers={"Authorization": f"Bearer {token}"},
            timeout=3,
        )
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            if items:
                log.warning(
                    "Reclaimed %d pending message(s) in %s/%s",
                    len(items),
                    hospital_id,
                    dept,
                )
            return items
    except Exception as exc:
        log.warning("cg-pending exception: %s", exc)
    return []


def process_items(items, *, hospital_id, dept, consumer_id, consumer):
    ack_ids = []
    for item in items:
        try:
            envelope = item.get("envelope", {})
            if envelope.get("version") != ENVELOPE_VERSION:
                log.warning(
                    "Skipping legacy message id=%s — ACKing to clear PEL", item["id"]
                )
                ack_ids.append(item["id"])
                continue

            producer_id = item["producer_id"]
            kms_keys = fetch_producer_keys(hospital_id, dept, producer_id)

            producer_sign_pub = ed25519.Ed25519PublicKey.from_public_bytes(
                _d64(kms_keys["public_sign_key"])
            )
            producer_dsa_pub_bytes = _d64(kms_keys["public_dsa_key"])

            plaintext = decrypt_item(
                hospital_id=hospital_id,
                department_id=dept,
                producer_id=producer_id,
                sequence=item["sequence"],
                nonce_b64=item["nonce"],
                ciphertext_b64=item["ciphertext"],
                envelope=envelope,
                consumer_kx_private_obj=consumer.kx_private_obj,
                consumer_kem_private_bytes=consumer.kem_private_bytes,
                producer_sign_public_obj=producer_sign_pub,
                producer_dsa_public_bytes=producer_dsa_pub_bytes,
            )

            try:
                record = json.loads(plaintext)
                msg_type = record.get("message_type", "UNKNOWN")
                patient = record.get("patient", {}).get("name", "unknown patient")
                log.info(
                    "Decrypted [%s/%s] %s — %s", hospital_id, dept, msg_type, patient
                )

                # ✅ Write decrypted record to Postgres
                write_clinical_record(
                    hospital_id=hospital_id,
                    department=dept,
                    producer_id=producer_id,
                    sequence=item["sequence"],
                    record=record,
                )
            except json.JSONDecodeError:
                log.info("Decrypted [%s/%s]: %s", hospital_id, dept, plaintext)

            ack_ids.append(item["id"])

        except Exception as exc:
            log.warning("Decryption failed id=%s: %s", item["id"], exc, exc_info=True)

    cg_ack(hospital_id, dept, consumer_id, ack_ids, consumer.token)


# ----------------------------------------------------------------
# Per-department simulation thread
# ----------------------------------------------------------------
def simulate_department(hospital_id: str, dept: str):
    producer = StaffMember(
        hospital_id=hospital_id,
        staff_id=f"{hospital_id}_{dept}_producer",
        role=random.choice(ROLES),
        department=dept,
    )
    consumer = StaffMember(
        hospital_id=hospital_id,
        staff_id=f"{hospital_id}_{dept}_consumer",
        role=random.choice(ROLES),
        department=dept,
    )
    consumer_id = consumer.staff_id

    for s in [producer, consumer]:
        if not register_staff_member(s):
            log.error(
                "Initial registration failed for %s — will retry on next cycle",
                s.staff_id,
            )

    producer.sequence = get_last_sequence(hospital_id, producer.staff_id) + 1
    log.info(
        "Producer %s starting at sequence %d", producer.staff_id, producer.sequence
    )

    while True:
        try:
            auth_ok = True
            for s in [producer, consumer]:
                if not authenticate_staff_member(s):
                    auth_ok = False

            if not auth_ok:
                log.warning(
                    "[%s/%s] Auth failed this cycle — skipping", hospital_id, dept
                )
                time.sleep(2)
                continue

            if not producer.token or not consumer.token:
                log.warning("[%s/%s] Token is None — skipping cycle", hospital_id, dept)
                time.sleep(2)
                continue

            # Enqueue 3 clinical messages per cycle
            for _ in range(3):
                msg_text = generate_clinical_message(
                    dept, hospital_id, producer.staff_id
                )
                payload = build_encrypted_payload(
                    hospital_id=producer.hospital_id,
                    department_id=dept,
                    producer_id=producer.staff_id,
                    sequence=producer.sequence,
                    plaintext=msg_text,
                    consumer_kx_public_b64=consumer.kx_public,
                    producer_sign_private_obj=producer.sign_key_obj,
                    consumer_kem_public_b64=consumer.kem_public,
                    producer_dsa_private_bytes=producer.dsa_private_bytes,
                )
                try:
                    resp = requests.post(
                        f"{BROKER_URL}/enqueue",
                        json={
                            "hospital": producer.hospital_id,
                            "department": dept,
                            "producer_id": producer.staff_id,
                            "sequence": producer.sequence,
                            "nonce": payload.nonce,
                            "ciphertext": payload.ciphertext,
                            "envelope": payload.envelope,
                        },
                        headers={"Authorization": f"Bearer {producer.token}"},
                        timeout=3,
                    )
                    if resp.status_code == 200:
                        try:
                            record = json.loads(msg_text)
                            msg_type = record.get("message_type", dept.upper())
                            patient = record.get("patient", {}).get("name", "")
                            log.info(
                                "Enqueued [%s/%s] %s — %s",
                                hospital_id,
                                dept,
                                msg_type,
                                patient,
                            )
                        except Exception:
                            log.info("Enqueued [%s/%s]", hospital_id, dept)
                        producer.sequence += 1
                    else:
                        log.warning(
                            "Enqueue failed: HTTP %d %s [%s/%s]",
                            resp.status_code,
                            resp.text[:120],
                            hospital_id,
                            dept,
                        )
                except requests.exceptions.Timeout:
                    log.warning("Enqueue timed out [%s/%s]", hospital_id, dept)
                except Exception as exc:
                    log.warning("Enqueue exception [%s/%s]: %s", hospital_id, dept, exc)

            pending = cg_reclaim_pending(hospital_id, dept, consumer_id, consumer.token)
            if pending:
                process_items(
                    pending,
                    hospital_id=hospital_id,
                    dept=dept,
                    consumer_id=consumer_id,
                    consumer=consumer,
                )

            new_items = cg_dequeue(hospital_id, dept, consumer_id, consumer.token)
            if new_items:
                process_items(
                    new_items,
                    hospital_id=hospital_id,
                    dept=dept,
                    consumer_id=consumer_id,
                    consumer=consumer,
                )

        except Exception as exc:
            log.exception(
                "Unhandled error in simulate_department(%s, %s): %s",
                hospital_id,
                dept,
                exc,
            )

        time.sleep(2)


# ----------------------------------------------------------------
# Startup
# ----------------------------------------------------------------
def create_hospitals():
    for hospital in HOSPITALS:
        for _ in range(5):
            try:
                resp = requests.post(
                    f"{TENANT_URL}/hospitals",
                    json={"id": hospital, "name": hospital},
                    timeout=3,
                )
                if resp.status_code in (200, 201, 409):
                    log.info("Hospital %s ready (HTTP %d)", hospital, resp.status_code)
                    break
            except Exception as exc:
                log.warning("Create hospital %s failed: %s", hospital, exc)
            time.sleep(1)


if __name__ == "__main__":
    log.info(
        "Simulator starting — hybrid PQC mode (ML-KEM-768 + X25519, ML-DSA-65 + Ed25519)"
    )

    _wait_for_sim_db()
    _create_sim_keys_table()
    seed_patients()

    create_hospitals()

    threads = []
    for hospital in HOSPITALS:
        for dept in DEPARTMENTS:
            t = threading.Thread(
                target=simulate_department,
                args=(hospital, dept),
                name=f"sim-{hospital}-{dept}",
                daemon=True,
            )
            t.start()
            threads.append(t)
            log.info("Started thread for %s/%s", hospital, dept)

    while True:
        time.sleep(5)
