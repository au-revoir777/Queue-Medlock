import os
import time
import base64
import hashlib
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

from consumer_sdk.medlock_consumer.crypto import decrypt_item, ReplayCache
from producer_sdk.medlock_producer.crypto import build_encrypted_payload

# ----------------------------------------------------------------
# Service URLs (adjust if running on localhost)
# ----------------------------------------------------------------
AUTH_URL = os.environ.get("AUTH_URL", "http://localhost:8000")
TENANT_URL = os.environ.get("TENANT_URL", "http://localhost:8001")
BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:9000")

HOSPITALS = ["test-hospital1", "test-hospital2"]
DEPARTMENTS = ["cardiology", "radiology", "icu"]
ROLES = ["doctor", "nurse", "admin"]


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
def random_key() -> str:
    import string, random

    return "".join(random.choices(string.ascii_letters + string.digits, k=32))


# ----------------------------------------------------------------
# Tests
# ----------------------------------------------------------------
def test_random_key_length():
    key = random_key()
    assert isinstance(key, str)
    assert len(key) == 32


def test_replay_cache_blocks_old_sequences():
    cache = ReplayCache()
    key = "hospital:dept:staff"
    assert cache.check_and_update(key, 1) is True
    assert cache.check_and_update(key, 1) is False
    assert cache.check_and_update(key, 0) is False
    assert cache.check_and_update(key, 2) is True


# ----------------------------------------------------------------
# Crypto Roundtrip Test
# ----------------------------------------------------------------
def test_encryption_roundtrip():
    # Generate Ed25519 signing key for producer
    signing_key = ed25519.Ed25519PrivateKey.generate()
    producer_signing_private_b64 = base64.b64encode(
        signing_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode()
    producer_signing_public_b64 = base64.b64encode(
        signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()

    # Generate X25519 consumer key pair
    consumer_private = x25519.X25519PrivateKey.generate()
    consumer_public = consumer_private.public_key()
    consumer_private_b64 = base64.b64encode(
        consumer_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode()
    consumer_public_b64 = base64.b64encode(
        consumer_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()

    # Build encrypted payload
    payload = build_encrypted_payload(
        hospital_id="hospital1",
        department_id="cardiology",
        producer_id="staff1",
        sequence=1,
        plaintext="Hello World!",
        consumer_public_kx_b64=consumer_public_b64,
        producer_signing_private_b64=producer_signing_private_b64,
    )

    # Decrypt and verify
    plaintext = decrypt_item(
        hospital_id="hospital1",
        department_id="cardiology",
        producer_id="staff1",
        sequence=1,
        nonce_b64=payload.nonce,
        ciphertext_b64=payload.ciphertext,
        envelope=payload.envelope,
        consumer_private_kx_b64=consumer_private_b64,
        producer_signing_public_b64=producer_signing_public_b64,
    )
    assert plaintext == "Hello World!"


# ----------------------------------------------------------------
# Tenant & Staff Setup Tests
# ----------------------------------------------------------------
@pytest.mark.parametrize("hospital_id", HOSPITALS)
def test_hospital_creation(hospital_id):
    resp = requests.post(
        f"{TENANT_URL}/hospitals", json={"id": hospital_id, "name": hospital_id}
    )
    assert resp.status_code in (200, 201, 409)


@pytest.mark.parametrize("hospital_id", HOSPITALS)
def test_staff_registration_and_login(hospital_id):
    # Generate keys
    sign_key = ed25519.Ed25519PrivateKey.generate()
    public_sign_key = base64.b64encode(
        sign_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()
    kx_private = x25519.X25519PrivateKey.generate()
    kx_public = kx_private.public_key()
    public_kx_key = base64.b64encode(
        kx_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()

    staff_id = f"staff-{int(time.time())}"

    # Register staff
    register_payload = {
        "id": staff_id,
        "hospital_id": hospital_id,
        "role": "doctor",
        "public_sign_key": public_sign_key,
        "public_kx_key": public_kx_key,
    }
    resp = requests.post(f"{TENANT_URL}/staff/register", json=register_payload)
    assert resp.status_code in (200, 201, 409)

    # Login via auth service
    login_payload = {
        "hospital_id": hospital_id,
        "staff_id": staff_id,
        "password": "pass123",
    }
    login_resp = requests.post(f"{AUTH_URL}/login", json=login_payload)
    assert login_resp.status_code in (200, 201)
    token = login_resp.json()["access_token"]
    assert token is not None


# ----------------------------------------------------------------
# Broker Messaging Test
# ----------------------------------------------------------------
@pytest.mark.integration
def test_broker_enqueue_dequeue():
    hospital_id = HOSPITALS[0]
    department = DEPARTMENTS[0]
    producer_id = f"staff-{int(time.time())}"

    # Generate keys
    sign_key = ed25519.Ed25519PrivateKey.generate()
    producer_signing_private_b64 = base64.b64encode(
        sign_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode()
    producer_signing_public_b64 = base64.b64encode(
        sign_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()

    consumer_private = x25519.X25519PrivateKey.generate()
    consumer_public = consumer_private.public_key()
    consumer_private_b64 = base64.b64encode(
        consumer_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode()
    consumer_public_b64 = base64.b64encode(
        consumer_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()

    # Register hospital and staff
    requests.post(
        f"{TENANT_URL}/hospitals", json={"id": hospital_id, "name": hospital_id}
    )
    requests.post(
        f"{TENANT_URL}/staff/register",
        json={
            "id": producer_id,
            "hospital_id": hospital_id,
            "role": "doctor",
            "public_sign_key": producer_signing_public_b64,
            "public_kx_key": consumer_public_b64,
        },
    )

    # Login and get token
    login_resp = requests.post(
        f"{AUTH_URL}/login",
        json={
            "hospital_id": hospital_id,
            "staff_id": producer_id,
            "password": "pass123",
        },
    )
    token = login_resp.json()["access_token"]

    # Build payload and enqueue
    payload = build_encrypted_payload(
        hospital_id=hospital_id,
        department_id=department,
        producer_id=producer_id,
        sequence=1,
        plaintext="Test Message",
        consumer_public_kx_b64=consumer_public_b64,
        producer_signing_private_b64=producer_signing_private_b64,
    )
    body = {
        "hospital": hospital_id,
        "department": department,
        "producer_id": producer_id,
        "sequence": 1,
        "nonce": payload.nonce,
        "ciphertext": payload.ciphertext,
        "envelope": payload.envelope,
    }
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.post(f"{BROKER_URL}/enqueue", json=body, headers=headers)
    assert resp.status_code == 200

    # Dequeue and decrypt
    resp = requests.get(f"{BROKER_URL}/dequeue/{hospital_id}/{department}")
    assert resp.status_code == 200
    items = resp.json().get("items", [])
    assert len(items) > 0

    decrypted = decrypt_item(
        hospital_id=hospital_id,
        department_id=department,
        producer_id=producer_id,
        sequence=1,
        nonce_b64=items[0]["nonce"],
        ciphertext_b64=items[0]["ciphertext"],
        envelope=items[0]["envelope"],
        consumer_private_kx_b64=consumer_private_b64,
        producer_signing_public_b64=producer_signing_public_b64,
    )
    assert decrypted == "Test Message"
