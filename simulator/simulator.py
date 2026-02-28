"""
MedLock Traffic Simulator - Normal Messages Test (Fixed)
========================================================
- Registers hospitals and staff
- Sends encrypted messages to the broker
- Fetches and decrypts messages
- Logs decrypted messages reliably
"""

import os
import requests
import random
import string
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
SIM_PASSWORD = os.environ["SIM_PASSWORD"]

if not SIM_PASSWORD:
    raise RuntimeError("SIM_PASSWORD not set")

# ----------------------------------------------------------------
# Service URLs
# ----------------------------------------------------------------
AUTH_URL = os.environ.get("AUTH_URL", "http://auth-service:8000/login")
TENANT_URL = os.environ.get("TENANT_URL", "http://tenant-service:8000")
BROKER_URL = os.environ.get("BROKER_URL", "http://broker:9000")

HOSPITALS = ["hospital1", "hospital2"]
DEPARTMENTS = ["cardiology", "radiology", "icu"]
ROLES = ["doctor", "nurse", "admin"]


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


# ----------------------------------------------------------------
# Crypto classes
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
    consumer_public_key = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(consumer_public_kx_b64)
    )
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    shared_secret = ephemeral_private.exchange(consumer_public_key)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"{hospital_id}:{department_id}".encode(),
    ).derive(shared_secret)

    nonce = os.urandom(12)
    aad = f"{producer_id}:{sequence}".encode()
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext.encode(), aad)

    digest = hashlib.sha256(ciphertext).hexdigest()
    signature = producer_signing_private_obj.sign(
        f"{producer_id}:{sequence}:{digest}".encode()
    )

    envelope = {
        "ephemeral_public_key": _b64(ephemeral_public),
        "signature": _b64(signature),
        "cipher_hash": digest,
    }

    return EncryptedPayload(
        nonce=_b64(nonce), ciphertext=_b64(ciphertext), envelope=envelope
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

    signed_content = f"{producer_id}:{sequence}:{digest}".encode()
    producer_signing_public_obj.verify(
        base64.b64decode(envelope["signature"]), signed_content
    )

    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(envelope["ephemeral_public_key"])
    )
    shared_secret = consumer_private_kx_obj.exchange(ephemeral_public)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"{hospital_id}:{department_id}".encode(),
    ).derive(shared_secret)

    plaintext = AESGCM(session_key).decrypt(
        base64.b64decode(nonce_b64), ciphertext, f"{producer_id}:{sequence}".encode()
    )
    return plaintext.decode()


# ----------------------------------------------------------------
# Staff class
# ----------------------------------------------------------------
@dataclass
class StaffMember:
    hospital_id: str
    staff_id: str
    role: str
    token: str = None
    sequence: int = 1
    sign_key_obj: ed25519.Ed25519PrivateKey = field(
        default_factory=ed25519.Ed25519PrivateKey.generate
    )
    kx_private_obj: x25519.X25519PrivateKey = field(
        default_factory=x25519.X25519PrivateKey.generate
    )
    sign_key: str = field(init=False)
    kx_private: str = field(init=False)
    kx_public: str = field(init=False)

    def __post_init__(self):
        self.sign_key = _b64(
            self.sign_key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.kx_private = _b64(
            self.kx_private_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.kx_public = _b64(
            self.kx_private_obj.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )


# ----------------------------------------------------------------
# Simulator
# ----------------------------------------------------------------
def simulate_tenant(hospital_id: str):
    staff_list = []

    while True:
        try:
            # Create a single producer and consumer staff for this hospital
            if not staff_list:
                producer = StaffMember(
                    hospital_id, f"{hospital_id}_producer", random.choice(ROLES)
                )
                consumer = StaffMember(
                    hospital_id, f"{hospital_id}_consumer", random.choice(ROLES)
                )
                staff_list.extend([producer, consumer])

                # Register both
                for s in staff_list:
                    resp = safe_post(
                        f"{TENANT_URL}/staff/register",
                        json={
                            "id": s.staff_id,
                            "hospital_id": s.hospital_id,
                            "role": s.role,
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

            # Authenticate
            for s in staff_list:
                resp = safe_post(
                    AUTH_URL,
                    json={
                        "hospital_id": s.hospital_id,
                        "staff_id": s.staff_id,
                        "password": SIM_PASSWORD,
                    },
                )
                if resp is not None and resp.status_code in (200, 201):
                    s.token = resp.json().get("access_token")

            producer, consumer = staff_list

            # Send messages
            for _ in range(3):
                dept = random.choice(DEPARTMENTS)
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
                body = {
                    "hospital": producer.hospital_id,
                    "department": dept,
                    "producer_id": producer.staff_id,
                    "sequence": producer.sequence,
                    "nonce": payload.nonce,
                    "ciphertext": payload.ciphertext,
                    "envelope": payload.envelope,
                }
                headers = {"Authorization": f"Bearer {producer.token}"}
                resp = requests.post(
                    f"{BROKER_URL}/enqueue", json=body, headers=headers, timeout=3
                )
                if resp is not None and resp.status_code == 200:
                    log.info("Enqueued message: %s", msg_text)
                    producer.sequence += 1
                else:
                    log.warning(
                        "Broker enqueue failed: %s %s",
                        resp.status_code if resp else None,
                        resp.text[:80] if resp else "",
                    )

            # Fetch and decrypt messages
            for dept in DEPARTMENTS:
                resp = requests.get(
                    f"{BROKER_URL}/dequeue/{producer.hospital_id}/{dept}", timeout=3
                )
                if resp is not None and resp.status_code == 200:
                    items = resp.json().get("items", [])
                    for item in items:
                        try:
                            plaintext = decrypt_item(
                                hospital_id=producer.hospital_id,
                                department_id=dept,
                                producer_id=item["producer_id"],
                                sequence=item["sequence"],
                                nonce_b64=item["nonce"],
                                ciphertext_b64=item["ciphertext"],
                                envelope=item.get("envelope", {}),
                                consumer_private_kx_obj=consumer.kx_private_obj,
                                producer_signing_public_obj=producer.sign_key_obj.public_key(),
                            )
                            log.info("Decrypted message: %s", plaintext)
                        except Exception as exc:
                            log.warning("Decryption failed: %s", exc)

        except Exception as exc:
            log.exception(
                "Unhandled error in simulate_tenant(%s): %s", hospital_id, exc
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
        t = threading.Thread(
            target=simulate_tenant,
            args=(hospital,),
            name=f"sim-{hospital}",
            daemon=True,
        )
        t.start()
        threads.append(t)
        log.info("Started simulation for %s", hospital)

    while True:
        time.sleep(5)
