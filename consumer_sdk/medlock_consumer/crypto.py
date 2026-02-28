import base64
import hashlib
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class ReplayCache:
    state: dict[str, int] = field(default_factory=dict)

    def check_and_update(self, key: str, sequence: int) -> bool:
        previous = self.state.get(key, 0)
        if sequence <= previous:
            return False
        self.state[key] = sequence
        return True


def decrypt_item(
    *,
    hospital_id: str,
    department_id: str,
    producer_id: str,
    sequence: int,
    nonce_b64: str,
    ciphertext_b64: str,
    envelope: dict,
    consumer_private_kx_b64: str,
    producer_signing_public_b64: str,
) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    digest = hashlib.sha256(ciphertext).hexdigest()

    if digest != envelope.get("cipher_hash"):
        raise ValueError("Cipher hash mismatch")

    verify_key = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.b64decode(producer_signing_public_b64)
    )
    signed_content = f"{producer_id}:{sequence}:{digest}".encode("utf-8")
    try:
        verify_key.verify(base64.b64decode(envelope["signature"]), signed_content)
    except InvalidSignature as exc:
        raise ValueError("Signature verification failed") from exc

    consumer_private = x25519.X25519PrivateKey.from_private_bytes(
        base64.b64decode(consumer_private_kx_b64)
    )
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(envelope["ephemeral_public_key"])
    )
    shared_secret = consumer_private.exchange(ephemeral_public)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"{hospital_id}:{department_id}".encode("utf-8"),
    ).derive(shared_secret)

    plaintext = AESGCM(session_key).decrypt(
        base64.b64decode(nonce_b64),
        ciphertext,
        f"{producer_id}:{sequence}".encode("utf-8"),
    )
    return plaintext.decode("utf-8")
