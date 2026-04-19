import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def main() -> None:
    sign_private = ed25519.Ed25519PrivateKey.generate()
    kx_private = x25519.X25519PrivateKey.generate()

    print(
        "ed25519_private=",
        b64(
            sign_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ),
    )
    print(
        "ed25519_public=",
        b64(
            sign_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
    )
    print(
        "x25519_private=",
        b64(
            kx_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ),
    )
    print(
        "x25519_public=",
        b64(
            kx_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
    )


if __name__ == "__main__":
    main()
