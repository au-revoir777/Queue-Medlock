# test_producer.py

import base64
import pytest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

# Correct imports for your folder structure
from producer_sdk.medlock_producer.crypto import (
    build_encrypted_payload,
    EncryptedPayload,
)
from producer_sdk.medlock_producer.cli import main as producer_main


# -------------------------------
# Fixtures: generate keys
# -------------------------------
@pytest.fixture
def keys():
    consumer_private = x25519.X25519PrivateKey.generate()
    consumer_public = consumer_private.public_key()
    producer_private = ed25519.Ed25519PrivateKey.generate()

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

    return {
        "consumer_private": consumer_private,
        "consumer_pub_b64": consumer_pub_b64,
        "producer_private": producer_private,
        "producer_priv_b64": producer_priv_b64,
    }


# -------------------------------
# Unit test: crypto function
# -------------------------------
def test_build_encrypted_payload(keys):
    payload: EncryptedPayload = build_encrypted_payload(
        hospital_id="HOSP123",
        department_id="CARDIO",
        producer_id="PROD001",
        sequence=1,
        plaintext="Hello, world!",
        consumer_public_kx_b64=keys["consumer_pub_b64"],
        producer_signing_private_b64=keys["producer_priv_b64"],
    )

    assert isinstance(payload.nonce, str)
    assert isinstance(payload.ciphertext, str)
    assert isinstance(payload.envelope, dict)

    for key in ["ephemeral_public_key", "signature", "cipher_hash"]:
        assert key in payload.envelope


# -------------------------------
# CLI / Integration test
# -------------------------------
def test_cli_with_mocked_requests(monkeypatch, keys):
    test_args = [
        "prog",
        "--hospital",
        "HOSP123",
        "--department",
        "CARDIO",
        "--producer-id",
        "PROD001",
        "--consumer-pubkey",
        keys["consumer_pub_b64"],
        "--producer-signing-key",
        keys["producer_priv_b64"],
        "--broker-url",
        "http://fake-broker",
        "--sequence",
        "1",
        "--message",
        "Test message",
    ]

    monkeypatch.setattr("sys.argv", test_args)

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"status": "ok"}

    with patch(
        "producer_sdk.medlock_producer.cli.requests.post", return_value=MockResponse()
    ) as mock_post:
        producer_main()
        assert mock_post.called
        args, kwargs = mock_post.call_args
        assert args[0] == "http://fake-broker/enqueue"
        payload = kwargs["json"]
        assert payload["department"] == "CARDIO"
        assert payload["producer_id"] == "PROD001"
        assert payload["sequence"] == 1
        for key in ["nonce", "ciphertext", "envelope"]:
            assert key in payload


# -------------------------------
# Optional: check sequence / replay
# -------------------------------
def test_multiple_sequences(keys):
    payload1 = build_encrypted_payload(
        hospital_id="HOSP123",
        department_id="CARDIO",
        producer_id="PROD001",
        sequence=1,
        plaintext="First message",
        consumer_public_kx_b64=keys["consumer_pub_b64"],
        producer_signing_private_b64=keys["producer_priv_b64"],
    )
    payload2 = build_encrypted_payload(
        hospital_id="HOSP123",
        department_id="CARDIO",
        producer_id="PROD001",
        sequence=2,
        plaintext="Second message",
        consumer_public_kx_b64=keys["consumer_pub_b64"],
        producer_signing_private_b64=keys["producer_priv_b64"],
    )

    assert payload1.ciphertext != payload2.ciphertext
    assert payload1.nonce != payload2.nonce
