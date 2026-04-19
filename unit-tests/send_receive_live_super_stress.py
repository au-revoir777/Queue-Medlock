import json
import base64
import random
import time
import redis
from producer_sdk.medlock_producer.crypto import build_encrypted_payload
from consumer_sdk.medlock_consumer.crypto import decrypt_item, ReplayCache
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

# ---------------- CONFIG ----------------
BROKER_URL = "redis://localhost:6379"
hospital = "HOSP123"
producer_id = "PROD001"

# Departments
departments = ["CARDIO", "NEURO", "ORTHO", "DERMA", "ENT"]

# Number of messages per department
NUM_MESSAGES = 50

# ---------------- KEYS ----------------
consumer_private = x25519.X25519PrivateKey.generate()
consumer_public = consumer_private.public_key()
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

# ---------------- CONNECT BROKER ----------------
r = redis.Redis.from_url(BROKER_URL)

# ---------------- REPLAY CACHE ----------------
cache = ReplayCache()

# ---------------- SUPER STRESS TEST ----------------
sequence = 1
replay_attempts = 0

all_messages = []

# Generate messages
for dept in departments:
    for i in range(NUM_MESSAGES):
        all_messages.append((dept, f"Stress msg {i+1} for {dept}"))

# Shuffle messages and inject some duplicates
random.shuffle(all_messages)
duplicates = random.sample(
    all_messages, k=int(0.1 * len(all_messages))
)  # 10% duplicates
all_messages += duplicates
random.shuffle(all_messages)

start_time = time.time()

for dept, msg in all_messages:
    # ---------- PRODUCER ----------
    payload = build_encrypted_payload(
        hospital_id=hospital,
        department_id=dept,
        producer_id=producer_id,
        sequence=sequence,
        plaintext=msg,
        consumer_public_kx_b64=keys["consumer_pub_b64"],
        producer_signing_private_b64=keys["producer_private_b64"],
    )

    r.xadd(
        f"dept:{dept}",
        {
            "ciphertext": payload.ciphertext,
            "nonce": payload.nonce,
            "producer_id": producer_id,
            "sequence": str(sequence),
            "envelope": json.dumps(payload.envelope),
        },
    )
    print(f"Sent: {msg} to {dept}")

    # ---------- CONSUMER ----------
    items = r.xrevrange(f"dept:{dept}", "+", "-", count=1)
    for msg_id, fields in items:
        obj = {k.decode(): v.decode() for k, v in fields.items()}
        obj["sequence"] = int(obj["sequence"])
        obj["envelope"] = json.loads(obj["envelope"])

        # Replay protection
        replay_key = f"{hospital}:{dept}:{obj['producer_id']}"
        if not cache.check_and_update(replay_key, obj["sequence"]):
            replay_attempts += 1
            print(f"Replay detected for {dept}, seq={obj['sequence']}")
            continue

        # Decrypt
        decrypted = decrypt_item(
            hospital_id=hospital,
            department_id=dept,
            producer_id=obj["producer_id"],
            sequence=obj["sequence"],
            nonce_b64=obj["nonce"],
            ciphertext_b64=obj["ciphertext"],
            envelope=obj["envelope"],
            consumer_private_kx_b64=keys["consumer_private_b64"],
            producer_signing_public_b64=keys["producer_pub_b64"],
        )
        print(f"Decrypted for {dept}: {decrypted}")

    sequence += 1

end_time = time.time()
print("\nSuper stress test completed!")
print(f"Total messages processed: {len(all_messages)}")
print(f"Replay attempts detected: {replay_attempts}")
print(f"Total time: {end_time - start_time:.2f}s")
