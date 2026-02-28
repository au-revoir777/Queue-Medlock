import argparse

import requests

from .crypto import ReplayCache, decrypt_item


def main():
    parser = argparse.ArgumentParser(description="MedLock consumer CLI")
    parser.add_argument("--hospital", required=True)
    parser.add_argument("--department", required=True)
    parser.add_argument("--consumer-id", required=True)
    parser.add_argument("--consumer-kx-private-key", required=True)
    parser.add_argument("--producer-signing-public-key", required=True)
    parser.add_argument("--broker-url", required=True)
    args = parser.parse_args()

    cache = ReplayCache()
    response = requests.get(f"{args.broker_url}/dequeue/{args.department}", timeout=10)
    response.raise_for_status()

    for item in response.json().get("items", []):
        replay_key = f"{args.hospital}:{args.department}:{item['producer_id']}"
        if not cache.check_and_update(replay_key, item["sequence"]):
            print(
                f"REPLAY DETECTED: producer={item['producer_id']} seq={item['sequence']}"
            )
            continue

        plaintext = decrypt_item(
            hospital_id=args.hospital,
            department_id=args.department,
            producer_id=item["producer_id"],
            sequence=item["sequence"],
            nonce_b64=item["nonce"],
            ciphertext_b64=item["ciphertext"],
            envelope=item.get("envelope", {}),
            consumer_private_kx_b64=args.consumer_kx_private_key,
            producer_signing_public_b64=args.producer_signing_public_key,
        )
        print(f"{item['producer_id']}#{item['sequence']}: {plaintext}")


if __name__ == "__main__":
    main()
