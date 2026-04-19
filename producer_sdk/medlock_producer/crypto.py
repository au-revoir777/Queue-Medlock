import base64
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class EncryptedPayload:
    nonce: str
    ciphertext: str
    envelope: dict


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def build_encrypted_payload(
    *,
    hospital_id: str,
    department_id: str,
    producer_id: str,
    sequence: int,
    plaintext: str,
    consumer_public_kx_b64: str,
    producer_signing_private_b64: str,
) -> EncryptedPayload:
    consumer_public_key = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(consumer_public_kx_b64)
    )
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared_secret = ephemeral_private.exchange(consumer_public_key)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"{hospital_id}:{department_id}".encode("utf-8"),
    ).derive(shared_secret)

    nonce = os.urandom(12)
    aad = f"{producer_id}:{sequence}".encode("utf-8")
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext.encode("utf-8"), aad)

    digest = hashlib.sha256(ciphertext).hexdigest()
    signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(producer_signing_private_b64)
    )
    signature = signing_key.sign(f"{producer_id}:{sequence}:{digest}".encode("utf-8"))

    envelope = {
        "ephemeral_public_key": _b64(ephemeral_public),
        "signature": _b64(signature),
        "cipher_hash": digest,
    }
    return EncryptedPayload(
        nonce=_b64(nonce), ciphertext=_b64(ciphertext), envelope=envelope
    )
