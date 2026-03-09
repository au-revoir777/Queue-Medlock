# test_consumer.py

import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

# Correct imports for your folder structure
from producer_sdk.medlock_producer.crypto import build_encrypted_payload
from consumer_sdk.medlock_consumer.crypto import decrypt_item, ReplayCache


# -------------------------------
# Fixture: generate keys
# -------------------------------
@pytest.fixture
def keys():
    # Consumer
    consumer_private = x25519.X25519PrivateKey.generate()
    consumer_public = consumer_private.public_key()

    # Producer signing
    producer_private = ed25519.Ed25519PrivateKey.generate()
    producer_public = producer_private.public_key()

    # Encode keys in base64
    consumer_priv_b64 = base64.b64encode(
        consumer_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode()
    consumer_pub_b64 = base64.b64encode(
        consumer_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()

    producer_priv_b64 = base64.b64encode(
        producer_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode()
    producer_pub_b64 = base64.b64encode(
        producer_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()

    return {
        "consumer_private": consumer_private,
        "consumer_private_b64": consumer_priv_b64,
        "consumer_pub_b64": consumer_pub_b64,
        "producer_private": producer_private,
        "producer_private_b64": producer_priv_b64,
        "producer_pub_b64": producer_pub_b64,
    }


# -------------------------------
# Test: producer -> consumer encryption
# -------------------------------
def test_end_to_end_crypto(keys):
    plaintext = "Hello Zero-Trust!"
    payload = build_encrypted_payload(
        hospital_id="HOSP123",
        department_id="CARDIO",
        producer_id="PROD001",
        sequence=1,
        plaintext=plaintext,
        consumer_public_kx_b64=keys["consumer_pub_b64"],
        producer_signing_private_b64=keys["producer_private_b64"],
    )

    decrypted = decrypt_item(
        hospital_id="HOSP123",
        department_id="CARDIO",
        producer_id="PROD001",
        sequence=1,
        nonce_b64=payload.nonce,
        ciphertext_b64=payload.ciphertext,
        envelope=payload.envelope,
        consumer_private_kx_b64=keys["consumer_private_b64"],
        producer_signing_public_b64=keys["producer_pub_b64"],
    )

    assert decrypted == plaintext


# -------------------------------
# Test: replay detection
# -------------------------------
def test_replay_detection(keys):
    cache = ReplayCache()

    key = "HOSP123:CARDIO:PROD001"
    seq1 = 1
    seq2 = 2
    seq0 = 0

    # First time: should allow
    assert cache.check_and_update(key, seq1) is True
    # Same sequence: replay, should reject
    assert cache.check_and_update(key, seq1) is False
    # Lower sequence: should reject
    assert cache.check_and_update(key, seq0) is False
    # Higher sequence: should allow
    assert cache.check_and_update(key, seq2) is True
