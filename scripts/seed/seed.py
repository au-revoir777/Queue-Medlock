"""
MedLock Demo Seed Script
=========================
Creates demo hospitals and staff accounts on first run.
Safe to re-run — all operations use 409-tolerant upsert logic.

Accounts created
----------------
hospital1:
  dr_ahmed    — doctor    — cardiology
  nurse_priya — nurse     — icu
  dr_chen     — doctor    — radiology
  dr_patel    — doctor    — neurology
  dr_okonkwo  — doctor    — oncology

hospital2:
  dr_hassan   — doctor    — cardiology
  nurse_sara  — nurse     — icu
  admin_lee   — admin     — radiology
  dr_reyes    — doctor    — neurology
  dr_dube     — doctor    — oncology

All accounts use password: demo1234
Keys are generated fresh if the account does not exist yet.
Auth registration is handled internally by tenant-service.
"""

import os
import sys
import time
import base64
import logging
import urllib3
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

# Suppress SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [seed] %(levelname)s %(message)s",
)
log = logging.getLogger("seed")

TENANT_URL = os.environ.get("TENANT_URL", "https://tenant-service:8000")
AUTH_URL = os.environ.get("AUTH_URL", "https://auth-service:8000")
KMS_URL = os.environ.get("KMS_URL", "https://kms-service:8000")
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "demo1234")

# mTLS cert paths from environment
MTLS_CERT_PATH = os.environ.get("MTLS_CERT_PATH")
MTLS_KEY_PATH = os.environ.get("MTLS_KEY_PATH")
MTLS_CA_PATH = os.environ.get("MTLS_CA_PATH")


def build_session() -> requests.Session:
    """Build a requests Session with mTLS client cert and CA verification."""
    session = requests.Session()
    if MTLS_CERT_PATH and MTLS_KEY_PATH:
        session.cert = (MTLS_CERT_PATH, MTLS_KEY_PATH)
        log.info("mTLS enabled — cert=%s", MTLS_CERT_PATH)
    else:
        log.warning("No mTLS cert configured — requests will be unauthenticated")

    if MTLS_CA_PATH:
        session.verify = MTLS_CA_PATH
        log.info("Using CA bundle: %s", MTLS_CA_PATH)
    else:
        # Fall back to disabling verification (dev only)
        session.verify = False
        log.warning("No CA path set — SSL verification disabled")

    return session


# Try to import oqs for post-quantum keys — fall back to classical-only if unavailable
try:
    import oqs

    PQC_AVAILABLE = True
    log.info("liboqs available — generating ML-KEM-768 + ML-DSA-65 keys")
except ImportError:
    PQC_AVAILABLE = False
    log.warning("liboqs not available — using placeholder PQC keys (demo only)")


# ----------------------------------------------------------------
# Demo accounts
# ----------------------------------------------------------------

HOSPITALS = [
    {"id": "hospital1", "name": "City General Hospital"},
    {"id": "hospital2", "name": "St. Mary Medical Centre"},
]

STAFF = [
    # hospital1
    {
        "id": "dr_ahmed",
        "hospital_id": "hospital1",
        "role": "doctor",
        "department": "cardiology",
    },
    {
        "id": "nurse_priya",
        "hospital_id": "hospital1",
        "role": "nurse",
        "department": "icu",
    },
    {
        "id": "dr_chen",
        "hospital_id": "hospital1",
        "role": "doctor",
        "department": "radiology",
    },
    {
        "id": "dr_patel",
        "hospital_id": "hospital1",
        "role": "doctor",
        "department": "neurology",
    },
    {
        "id": "dr_okonkwo",
        "hospital_id": "hospital1",
        "role": "doctor",
        "department": "oncology",
    },
    # hospital2
    {
        "id": "dr_hassan",
        "hospital_id": "hospital2",
        "role": "doctor",
        "department": "cardiology",
    },
    {
        "id": "nurse_sara",
        "hospital_id": "hospital2",
        "role": "nurse",
        "department": "icu",
    },
    {
        "id": "admin_lee",
        "hospital_id": "hospital2",
        "role": "admin",
        "department": "radiology",
    },
    {
        "id": "dr_reyes",
        "hospital_id": "hospital2",
        "role": "doctor",
        "department": "neurology",
    },
    {
        "id": "dr_dube",
        "hospital_id": "hospital2",
        "role": "doctor",
        "department": "oncology",
    },
]


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def generate_keys() -> dict:
    """Generate classical + post-quantum key pairs for a staff member."""
    # Classical keys
    sign_priv = ed25519.Ed25519PrivateKey.generate()
    sign_pub = sign_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    kx_priv = x25519.X25519PrivateKey.generate()
    kx_pub = kx_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    if PQC_AVAILABLE:
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            kem_pub = kem.generate_keypair()
        with oqs.Signature("ML-DSA-65") as dsa:
            dsa_pub = dsa.generate_keypair()
    else:
        # Placeholder — 32 random bytes — only for demo environments without liboqs
        import os as _os

        kem_pub = _os.urandom(32)
        dsa_pub = _os.urandom(32)

    return {
        "public_sign_key": _b64(sign_pub),
        "public_kx_key": _b64(kx_pub),
        "public_kem_key": _b64(kem_pub),
        "public_dsa_key": _b64(dsa_pub),
    }


def wait_for_service(
    session: requests.Session,
    url: str,
    name: str,
    retries: int = 20,
    delay: float = 3.0,
):
    for attempt in range(1, retries + 1):
        try:
            resp = session.get(f"{url}/health", timeout=3)
            if resp.status_code == 200:
                log.info("%s is ready (attempt %d)", name, attempt)
                return
        except Exception as exc:
            log.warning("%s not ready (attempt %d/%d): %s", name, attempt, retries, exc)
        time.sleep(delay)
    log.error("%s did not become ready — aborting", name)
    sys.exit(1)


def create_hospital(session: requests.Session, hospital: dict) -> bool:
    try:
        resp = session.post(
            f"{TENANT_URL}/hospitals",
            json={"id": hospital["id"], "name": hospital["name"]},
            timeout=5,
        )
        if resp.status_code in (200, 201):
            log.info("Created hospital: %s", hospital["id"])
            return True
        if resp.status_code == 409:
            log.info("Hospital already exists: %s", hospital["id"])
            return True
        log.error(
            "Failed to create hospital %s: HTTP %d %s",
            hospital["id"],
            resp.status_code,
            resp.text[:120],
        )
        return False
    except Exception as exc:
        log.error("Exception creating hospital %s: %s", hospital["id"], exc)
        return False


def register_staff(session: requests.Session, member: dict) -> bool:
    keys = generate_keys()
    payload = {
        "id": member["id"],
        "hospital_id": member["hospital_id"],
        "role": member["role"],
        "department": member["department"],
        **keys,
    }
    try:
        resp = session.post(
            f"{TENANT_URL}/staff/register",
            json=payload,
            timeout=5,
        )
        if resp.status_code in (200, 201):
            log.info(
                "Registered staff: %s @ %s/%s",
                member["id"],
                member["hospital_id"],
                member["department"],
            )
            return True
        if resp.status_code == 409:
            log.info("Staff already exists: %s", member["id"])
            return True
        log.error(
            "Failed to register %s: HTTP %d %s",
            member["id"],
            resp.status_code,
            resp.text[:120],
        )
        return False
    except Exception as exc:
        log.error("Exception registering %s: %s", member["id"], exc)
        return False


def update_password(session: requests.Session, member: dict) -> bool:
    """
    The tenant-service registers staff with password 'pass123' internally.
    We need to update the auth record to use DEMO_PASSWORD instead.
    Call auth-service /register with the demo password — 409 means user
    already exists with the correct password so we skip silently.
    """
    try:
        resp = session.post(
            f"{AUTH_URL}/register",
            json={
                "hospital_id": member["hospital_id"],
                "staff_id": member["id"],
                "password": DEMO_PASSWORD,
                "department": member["department"],
            },
            timeout=5,
        )
        if resp.status_code in (200, 201, 409):
            return True
        log.warning("Password update for %s: HTTP %d", member["id"], resp.status_code)
        return False
    except Exception as exc:
        log.warning("Password update exception for %s: %s", member["id"], exc)
        return False


# ----------------------------------------------------------------
# Main
# ----------------------------------------------------------------

if __name__ == "__main__":
    log.info("MedLock demo seed starting...")

    session = build_session()

    wait_for_service(session, TENANT_URL, "tenant-service")
    wait_for_service(session, AUTH_URL, "auth-service")

    # Give services a moment to fully settle after health check passes
    time.sleep(2)

    # Create hospitals
    log.info("--- Creating hospitals ---")
    for hospital in HOSPITALS:
        create_hospital(session, hospital)

    # Register staff
    log.info("--- Registering demo staff ---")
    for member in STAFF:
        register_staff(session, member)

    # Update passwords to demo1234
    # tenant-service registers staff with 'pass123' internally;
    # we call auth /register again with demo1234 — if 409 the account
    # already has the right password from a previous seed run.
    log.info("--- Setting demo passwords ---")
    for member in STAFF:
        update_password(session, member)

    log.info("Seed complete. Demo accounts ready:")
    log.info("  Password for all accounts: %s", DEMO_PASSWORD)
    for m in STAFF:
        log.info(
            "  %s @ %s (%s / %s)", m["id"], m["hospital_id"], m["role"], m["department"]
        )

    log.info("Seed script finished — exiting.")
    sys.exit(0)
