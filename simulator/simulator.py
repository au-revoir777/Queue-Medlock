"""
MedLock Traffic Simulator
=========================
- One thread per hospital/department pair (10 threads: 2 hospitals x 5 departments)
- Each thread owns one producer + one consumer, both fixed to that department
- Producers bootstrap their sequence from the broker on startup to survive restarts
- Messages are delivered via Redis consumer groups (exactly-once, ACK after decrypt)
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

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s"
)
log = logging.getLogger("simulator")

SIM_PASSWORD = os.environ.get("SIM_PASSWORD", "")
if not SIM_PASSWORD:
    raise RuntimeError("SIM_PASSWORD not set")

AUTH_URL = os.environ.get("AUTH_URL", "http://auth-service:8000/login")
TENANT_URL = os.environ.get("TENANT_URL", "http://tenant-service:8000")
BROKER_URL = os.environ.get("BROKER_URL", "http://broker:9000")

HOSPITALS = ["hospital1", "hospital2"]
DEPARTMENTS = ["cardiology", "radiology", "icu", "neurology", "oncology"]
ROLES = ["doctor", "nurse", "admin"]

PENDING_RECLAIM_IDLE_MS = 30_000


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


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
    """
    Ask the broker for the last sequence number it has seen for this producer.
    Returns 0 if never published before. Used to survive container restarts
    without hitting replay detection (409) on the first enqueue.
    """
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


# ----------------------------------------------------------------
# Crypto
# ----------------------------------------------------------------
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
    consumer_public_kx_b64: str,
    producer_signing_private_obj: ed25519.Ed25519PrivateKey,
) -> EncryptedPayload:
    consumer_pub = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(consumer_public_kx_b64)
    )
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = eph_priv.exchange(consumer_pub)

    session_key = HKDF(
        hashes.SHA256(), 32, None, f"{hospital_id}:{department_id}".encode()
    ).derive(shared)
    nonce = os.urandom(12)
    aad = f"{producer_id}:{sequence}".encode()
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext.encode(), aad)

    digest = hashlib.sha256(ciphertext).hexdigest()
    signature = producer_signing_private_obj.sign(
        f"{producer_id}:{sequence}:{digest}".encode()
    )

    return EncryptedPayload(
        nonce=_b64(nonce),
        ciphertext=_b64(ciphertext),
        envelope={
            "ephemeral_public_key": _b64(eph_pub_bytes),
            "signature": _b64(signature),
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
    consumer_private_kx_obj: x25519.X25519PrivateKey,
    producer_signing_public_obj: ed25519.Ed25519PublicKey,
) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    digest = hashlib.sha256(ciphertext).hexdigest()
    if digest != envelope.get("cipher_hash"):
        raise ValueError("Cipher hash mismatch")

    producer_signing_public_obj.verify(
        base64.b64decode(envelope["signature"]),
        f"{producer_id}:{sequence}:{digest}".encode(),
    )

    eph_pub = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(envelope["ephemeral_public_key"])
    )
    shared = consumer_private_kx_obj.exchange(eph_pub)
    session_key = HKDF(
        hashes.SHA256(), 32, None, f"{hospital_id}:{department_id}".encode()
    ).derive(shared)

    return (
        AESGCM(session_key)
        .decrypt(
            base64.b64decode(nonce_b64),
            ciphertext,
            f"{producer_id}:{sequence}".encode(),
        )
        .decode()
    )


# ----------------------------------------------------------------
# Staff
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
    sign_key: str = field(init=False)
    kx_public: str = field(init=False)

    def __post_init__(self):
        self.sign_key = _b64(
            self.sign_key_obj.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        self.kx_public = _b64(
            self.kx_private_obj.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )


# ----------------------------------------------------------------
# Consumer group helpers
# ----------------------------------------------------------------
def cg_dequeue(hospital_id: str, dept: str, consumer_id: str) -> list:
    try:
        resp = requests.get(
            f"{BROKER_URL}/cg-dequeue/{hospital_id}/{dept}",
            params={"consumer_id": consumer_id, "count": "10"},
            timeout=3,
        )
        if resp.status_code == 200:
            return resp.json().get("items", [])
        log.warning("cg-dequeue failed: %d %s", resp.status_code, resp.text[:80])
    except Exception as exc:
        log.warning("cg-dequeue exception: %s", exc)
    return []


def cg_ack(hospital_id: str, dept: str, consumer_id: str, message_ids: list) -> None:
    if not message_ids:
        return
    try:
        resp = requests.post(
            f"{BROKER_URL}/cg-ack/{hospital_id}/{dept}",
            json={"consumer_id": consumer_id, "message_ids": message_ids},
            timeout=3,
        )
        if resp.status_code != 200:
            log.warning("cg-ack failed: %d %s", resp.status_code, resp.text[:80])
    except Exception as exc:
        log.warning("cg-ack exception: %s", exc)


def cg_reclaim_pending(hospital_id: str, dept: str, consumer_id: str) -> list:
    try:
        resp = requests.get(
            f"{BROKER_URL}/cg-pending/{hospital_id}/{dept}",
            params={
                "consumer_id": consumer_id,
                "min_idle_ms": str(PENDING_RECLAIM_IDLE_MS),
                "count": "10",
            },
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


def process_items(items, *, hospital_id, dept, consumer_id, consumer, producer):
    ack_ids = []
    for item in items:
        try:
            plaintext = decrypt_item(
                hospital_id=hospital_id,
                department_id=dept,
                producer_id=item["producer_id"],
                sequence=item["sequence"],
                nonce_b64=item["nonce"],
                ciphertext_b64=item["ciphertext"],
                envelope=item.get("envelope", {}),
                consumer_private_kx_obj=consumer.kx_private_obj,
                producer_signing_public_obj=producer.sign_key_obj.public_key(),
            )
            log.info(
                "Decrypted [%s/%s] [%s]: %s", hospital_id, dept, item["id"], plaintext
            )
            ack_ids.append(item["id"])
        except Exception as exc:
            log.warning("Decryption failed id=%s: %s", item["id"], exc)
    cg_ack(hospital_id, dept, consumer_id, ack_ids)


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

    # Register both staff members
    for s in [producer, consumer]:
        resp = safe_post(
            f"{TENANT_URL}/staff/register",
            json={
                "id": s.staff_id,
                "hospital_id": s.hospital_id,
                "role": s.role,
                "department": s.department,
                "public_sign_key": s.sign_key,
                "public_kx_key": s.kx_public,
            },
        )
        if resp is not None and resp.status_code not in (200, 201, 409):
            log.warning(
                "Staff register %s → %d %s",
                s.staff_id,
                resp.status_code,
                resp.text[:80],
            )

    # Bootstrap producer sequence from broker — survives restarts without 409
    producer.sequence = get_last_sequence(hospital_id, producer.staff_id) + 1
    log.info(
        "Producer %s starting at sequence %d", producer.staff_id, producer.sequence
    )

    while True:
        try:
            # Re-authenticate each cycle (tokens may expire)
            for s in [producer, consumer]:
                resp = safe_post(
                    AUTH_URL,
                    json={
                        "hospital_id": s.hospital_id,
                        "staff_id": s.staff_id,
                        "password": "pass123",
                    },
                )
                if resp is not None and resp.status_code in (200, 201):
                    s.token = resp.json().get("access_token")

            # Enqueue 3 messages
            for _ in range(3):
                msg_text = f"Hello from {producer.staff_id} in {dept}"
                payload = build_encrypted_payload(
                    hospital_id=producer.hospital_id,
                    department_id=dept,
                    producer_id=producer.staff_id,
                    sequence=producer.sequence,
                    plaintext=msg_text,
                    consumer_public_kx_b64=consumer.kx_public,
                    producer_signing_private_obj=producer.sign_key_obj,
                )
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
                if resp is not None and resp.status_code == 200:
                    log.info("Enqueued [%s/%s]: %s", hospital_id, dept, msg_text)
                    producer.sequence += 1
                else:
                    log.warning(
                        "Enqueue failed: %s %s",
                        resp.status_code if resp else None,
                        resp.text[:80] if resp else "",
                    )

            # Fetch and decrypt via consumer group
            pending = cg_reclaim_pending(hospital_id, dept, consumer_id)
            if pending:
                process_items(
                    pending,
                    hospital_id=hospital_id,
                    dept=dept,
                    consumer_id=consumer_id,
                    consumer=consumer,
                    producer=producer,
                )

            new_items = cg_dequeue(hospital_id, dept, consumer_id)
            if new_items:
                process_items(
                    new_items,
                    hospital_id=hospital_id,
                    dept=dept,
                    consumer_id=consumer_id,
                    consumer=consumer,
                    producer=producer,
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
    log.info("Simulator starting...")
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
