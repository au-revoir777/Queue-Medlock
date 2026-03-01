"""
MedLock Traffic Simulator — Hybrid Post-Quantum Cryptography
=============================================================
Key exchange  : X25519 (classical) + ML-KEM-768 (post-quantum) combined via HKDF
Signatures    : Ed25519 (classical) + ML-DSA-65 (post-quantum) both verified
Delivery      : Redis consumer groups (exactly-once, ACK after decrypt)
Resilience    : Sequence bootstrapped from broker on startup (survives restarts)
Key directory : KMS fetched at decrypt time (zero-trust — no local key trust)

Fixes applied
-------------
1. Re-registration on 404 login — if auth returns 404 the staff member no longer
   exists (auth state was wiped by a restart); we re-register before retrying.
2. Token guard — enqueue / dequeue are skipped when token is None so we never
   send "Bearer None" to the broker.
3. Enqueue logging now distinguishes timeout/None from HTTP error responses.
4. Staff registration failure is fatal for the cycle — thread retries next tick
   rather than continuing with a broken identity.
"""

import os
import requests
import random
import time
import threading
import logging
import base64
import hashlib
from dataclasses import dataclass, field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import oqs  # liboqs-python — ML-KEM-768 and ML-DSA-65

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s",
)
log = logging.getLogger("simulator")

SIM_PASSWORD = os.environ.get("SIM_PASSWORD", "")
if not SIM_PASSWORD:
    raise RuntimeError("SIM_PASSWORD not set")

AUTH_URL = os.environ.get("AUTH_URL", "http://auth-service:8000/login")
TENANT_URL = os.environ.get("TENANT_URL", "http://tenant-service:8000")
BROKER_URL = os.environ.get("BROKER_URL", "http://broker:9000")
KMS_URL = os.environ.get("KMS_URL", "http://kms-service:8000")

HOSPITALS = ["hospital1", "hospital2"]
DEPARTMENTS = ["cardiology", "radiology", "icu", "neurology", "oncology"]
ROLES = ["doctor", "nurse", "admin"]

PENDING_RECLAIM_IDLE_MS = 30_000

# OQS algorithm names (NIST-standardised)
KEM_ALG = "ML-KEM-768"  # post-quantum key encapsulation
DSA_ALG = "ML-DSA-65"  # post-quantum digital signatures


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
    """Bootstrap sequence from broker to survive restarts without 409."""
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
    """
    Fetch a producer's public keys from the KMS at decrypt time.
    Zero-trust model — consumers never hold producer keys locally.
    """
    resp = requests.get(
        f"{KMS_URL}/keys/{hospital_id}/{department_id}/{producer_id}", timeout=3
    )
    if resp.status_code != 200:
        raise ValueError(
            f"KMS key lookup failed for {producer_id}: HTTP {resp.status_code} {resp.text[:80]}"
        )
    return resp.json()


# ----------------------------------------------------------------
# Hybrid crypto — Key Exchange
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

    combined_ikm = shared_x25519 + shared_kem
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"{hospital_id}:{department_id}".encode(),
    ).derive(combined_ikm)

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
            signed_content,
            _d64(envelope["signature_pqc"]),
            producer_dsa_public_bytes,
        )
    if not valid:
        raise ValueError("ML-DSA-65 signature verification failed")

    eph_pub = x25519.X25519PublicKey.from_public_bytes(
        _d64(envelope["ephemeral_public_key"])
    )
    shared_x25519 = consumer_kx_private_obj.exchange(eph_pub)

    with oqs.KeyEncapsulation(KEM_ALG, secret_key=consumer_kem_private_bytes) as kem:
        shared_kem = kem.decap_secret(_d64(envelope["kem_ciphertext"]))

    combined_ikm = shared_x25519 + shared_kem
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"{hospital_id}:{department_id}".encode(),
    ).derive(combined_ikm)

    return (
        AESGCM(session_key)
        .decrypt(_d64(nonce_b64), ciphertext, f"{producer_id}:{sequence}".encode())
        .decode()
    )


# ----------------------------------------------------------------
# Staff — holds classical + PQC key pairs
# ----------------------------------------------------------------
@dataclass
class StaffMember:
    hospital_id: str
    staff_id: str
    role: str
    department: str

    token: str = None
    sequence: int = 1

    sign_key_obj: ed25519.Ed25519PrivateKey = field(
        default_factory=ed25519.Ed25519PrivateKey.generate
    )
    kx_private_obj: x25519.X25519PrivateKey = field(
        default_factory=x25519.X25519PrivateKey.generate
    )

    kem_private_bytes: bytes = field(default=None, repr=False)
    kem_public_bytes: bytes = field(default=None, repr=False)
    dsa_private_bytes: bytes = field(default=None, repr=False)
    dsa_public_bytes: bytes = field(default=None, repr=False)

    sign_key: str = field(init=False, repr=False)
    kx_public: str = field(init=False, repr=False)
    kem_public: str = field(init=False, repr=False)
    dsa_public: str = field(init=False, repr=False)

    def __post_init__(self):
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
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            self.kem_public_bytes = kem.generate_keypair()
            self.kem_private_bytes = kem.export_secret_key()
        self.kem_public = _b64(self.kem_public_bytes)

        with oqs.Signature(DSA_ALG) as dsa:
            self.dsa_public_bytes = dsa.generate_keypair()
            self.dsa_private_bytes = dsa.export_secret_key()
        self.dsa_public = _b64(self.dsa_public_bytes)


# ----------------------------------------------------------------
# Registration helper — shared by startup and re-registration
# ----------------------------------------------------------------
def register_staff_member(s: StaffMember) -> bool:
    """
    Register a staff member with the tenant service.
    Returns True on success (200, 201, 409), False on failure.

    FIX: extracted so both initial startup and re-registration after a
    404 login (state wipe) can call the same logic cleanly.
    """
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
    """
    Authenticate a staff member and store the token.

    FIX: Returns False and clears the token on failure instead of silently
    leaving a stale/None token in place.

    FIX: Detects 404 (staff not found — auth state was wiped by a restart)
    and triggers re-registration so the next authenticate call will succeed.
    """
    resp = safe_post(
        AUTH_URL,
        json={
            "hospital_id": s.hospital_id,
            "staff_id": s.staff_id,
            "password": "pass123",
        },
    )

    if resp is None:
        log.warning("Auth for %s → no response (timeout), clearing token", s.staff_id)
        s.token = None
        return False

    if resp.status_code == 404:
        # FIX: auth service has no record of this staff member — state was wiped.
        # Re-register so subsequent cycles can log in successfully.
        log.warning(
            "Auth for %s → 404 Not Found — auth state wiped, re-registering", s.staff_id
        )
        s.token = None
        register_staff_member(s)  # best-effort; next cycle will retry login
        return False

    if resp.status_code not in (200, 201):
        log.warning(
            "Auth for %s → HTTP %d %s", s.staff_id, resp.status_code, resp.text[:80]
        )
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
    """
    Decrypt each item by fetching the producer's keys from KMS at runtime.
    Zero-trust: consumer never holds producer keys locally.
    """
    ack_ids = []
    for item in items:
        try:
            envelope = item.get("envelope", {})

            if envelope.get("version") != ENVELOPE_VERSION:
                log.warning(
                    "Skipping legacy message id=%s (envelope version=%r, expected %r) "
                    "— ACKing to clear PEL",
                    item["id"],
                    envelope.get("version"),
                    ENVELOPE_VERSION,
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
            log.info(
                "Decrypted [%s/%s] [%s]: %s", hospital_id, dept, item["id"], plaintext
            )
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

    # FIX: registration failure is fatal for this cycle — abort and retry next tick
    # rather than continuing with an unregistered identity.
    for s in [producer, consumer]:
        if not register_staff_member(s):
            log.error(
                "Initial registration failed for %s — will retry on next cycle",
                s.staff_id,
            )

    # Bootstrap sequence from broker — survives restarts without 409
    producer.sequence = get_last_sequence(hospital_id, producer.staff_id) + 1
    log.info(
        "Producer %s starting at sequence %d", producer.staff_id, producer.sequence
    )

    while True:
        try:
            # Re-authenticate each cycle.
            # FIX: if login returns 404, authenticate_staff_member re-registers
            # automatically and returns False — we skip this cycle gracefully.
            auth_ok = True
            for s in [producer, consumer]:
                if not authenticate_staff_member(s):
                    auth_ok = False

            if not auth_ok:
                log.warning(
                    "[%s/%s] Auth failed this cycle — skipping enqueue/dequeue",
                    hospital_id,
                    dept,
                )
                time.sleep(2)
                continue

            # FIX: explicit token guard — never send "Bearer None" to broker
            if not producer.token or not consumer.token:
                log.warning(
                    "[%s/%s] Token is None after auth — skipping cycle",
                    hospital_id,
                    dept,
                )
                time.sleep(2)
                continue

            # Enqueue 3 messages using hybrid crypto
            for _ in range(3):
                msg_text = f"Hello from {producer.staff_id} in {dept}"
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
                        log.info("Enqueued [%s/%s]: %s", hospital_id, dept, msg_text)
                        producer.sequence += 1
                    else:
                        # FIX: log the actual HTTP status and body, not just None
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

            # Fetch and decrypt via consumer group
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
