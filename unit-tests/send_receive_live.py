import json
import base64
import redis
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

# Import your existing project modules
from producer_sdk.medlock_producer.crypto import (
    build_encrypted_payload,
    EncryptedPayload,
)
from consumer_sdk.medlock_consumer.crypto import decrypt_item, ReplayCache

# ------------------ Setup Keys ------------------
# Consumer X25519 key pair
consumer_private = x25519.X25519PrivateKey.generate()
consumer_public = consumer_private.public_key()

# Producer Ed25519 key pair
producer_private = ed25519.Ed25519PrivateKey.generate()
producer_public = producer_private.public_key()

keys = {
    "consumer_private_b64": base64.b64encode(
        consumer_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode(),
    "consumer_pub_b64": base64.b64encode(
        consumer_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode(),
    "producer_private_b64": base64.b64encode(
        producer_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode(),
    "producer_pub_b64": base64.b64encode(
        producer_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode(),
}

# ------------------ Connect to Broker ------------------
r = redis.Redis(host="localhost", port=6379, decode_responses=True)

department = "CARDIO"
hospital = "HOSP123"
producer_id = "PROD001"
sequence = 1
plaintext = "Hello from live broker!"

# ------------------ PRODUCER: Send Message ------------------
payload: EncryptedPayload = build_encrypted_payload(
    hospital_id=hospital,
    department_id=department,
    producer_id=producer_id,
    sequence=sequence,
    plaintext=plaintext,
    consumer_public_kx_b64=keys["consumer_pub_b64"],
    producer_signing_private_b64=keys["producer_private_b64"],
)

r.xadd(
    f"dept:{department}",
    {
        "ciphertext": payload.ciphertext,
        "nonce": payload.nonce,
        "producer_id": producer_id,
        "sequence": str(sequence),
        "envelope": json.dumps(payload.envelope),
    },
)
print("Message sent to broker!")

# ------------------ CONSUMER: Receive Message ------------------
response_items = r.xrevrange(f"dept:{department}", "+", "-", count=10)
items = []
for msg_id, fields in reversed(response_items):
    obj = {k: v for k, v in fields.items()}
    obj["sequence"] = int(obj["sequence"])
    obj["envelope"] = json.loads(obj.get("envelope", "{}"))
    items.append(obj)

item = items[0]
cache = ReplayCache()
replay_key = f"{hospital}:{department}:{item['producer_id']}"
if cache.check_and_update(replay_key, item["sequence"]):
    decrypted = decrypt_item(
        hospital_id=hospital,
        department_id=department,
        producer_id=item["producer_id"],
        sequence=item["sequence"],
        nonce_b64=item["nonce"],
        ciphertext_b64=item["ciphertext"],
        envelope=item["envelope"],
        consumer_private_kx_b64=keys["consumer_private_b64"],
        producer_signing_public_b64=keys["producer_pub_b64"],
    )
    print("Decrypted message:", decrypted)
else:
    print("Replay detected, message ignored.")
