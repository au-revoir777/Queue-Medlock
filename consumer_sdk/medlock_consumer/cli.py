import argparse
import requests
from .crypto import ReplayCache, decrypt_item


def fetch_producer_signing_key(
    broker_url: str, hospital: str, department: str, producer_id: str
) -> str:
    """Fetch the current signing public key for a producer from KMS via broker."""
    resp = requests.get(
        f"{broker_url}/keys/{hospital}/{department}/{producer_id}",
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()[
        "public_sign_key"
    ]  # adjust field name to match your KMS response


def main():
    parser = argparse.ArgumentParser(description="MedLock consumer CLI")
    parser.add_argument("--hospital", required=True)
    parser.add_argument("--department", required=True)
    parser.add_argument("--consumer-id", required=True)
    parser.add_argument("--consumer-kx-private-key", required=True)
    # REMOVED: --producer-signing-public-key
    parser.add_argument("--broker-url", required=True)
    parser.add_argument(
        "--use-consumer-group",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()

    if args.use_consumer_group:
        _run_consumer_group(args)
    else:
        _run_legacy(args)


def _run_legacy(args):
    cache = ReplayCache()
    response = requests.get(
        f"{args.broker_url}/dequeue/{args.hospital}/{args.department}", timeout=10
    )
    response.raise_for_status()

    for item in response.json().get("items", []):
        replay_key = f"{args.hospital}:{args.department}:{item['producer_id']}"
        if not cache.check_and_update(replay_key, item["sequence"]):
            print(
                f"REPLAY DETECTED: producer={item['producer_id']} seq={item['sequence']}"
            )
            continue

        # ✅ Fetch the correct key for THIS producer dynamically
        try:
            signing_key = fetch_producer_signing_key(
                args.broker_url, args.hospital, args.department, item["producer_id"]
            )
        except Exception as exc:
            print(f"KEY FETCH FAILED producer={item['producer_id']}: {exc}")
            continue

        try:
            plaintext = decrypt_item(
                hospital_id=args.hospital,
                department_id=args.department,
                producer_id=item["producer_id"],
                sequence=item["sequence"],
                nonce_b64=item["nonce"],
                ciphertext_b64=item["ciphertext"],
                envelope=item.get("envelope", {}),
                consumer_private_kx_b64=args.consumer_kx_private_key,
                producer_signing_public_b64=signing_key,  # ✅ per-producer key
            )
            print(f"{item['producer_id']}#{item['sequence']}: {plaintext}")
        except Exception as exc:
            print(
                f"DECRYPT FAILED producer={item['producer_id']} seq={item['sequence']}: {exc}"
            )


def _run_consumer_group(args):
    response = requests.get(
        f"{args.broker_url}/cg-dequeue/{args.hospital}/{args.department}",
        params={"consumer_id": args.consumer_id, "count": "10"},
        timeout=10,
    )
    response.raise_for_status()

    items = response.json().get("items", [])
    ack_ids = []

    for item in items:
        # ✅ Fetch the correct key for THIS producer dynamically
        try:
            signing_key = fetch_producer_signing_key(
                args.broker_url, args.hospital, args.department, item["producer_id"]
            )
        except Exception as exc:
            print(
                f"KEY FETCH FAILED id={item['id']} producer={item['producer_id']}: {exc}"
            )
            continue  # Leave in PEL — will retry on next run

        try:
            plaintext = decrypt_item(
                hospital_id=args.hospital,
                department_id=args.department,
                producer_id=item["producer_id"],
                sequence=item["sequence"],
                nonce_b64=item["nonce"],
                ciphertext_b64=item["ciphertext"],
                envelope=item.get("envelope", {}),
                consumer_private_kx_b64=args.consumer_kx_private_key,
                producer_signing_public_b64=signing_key,  # ✅ per-producer key
            )
            print(f"{item['producer_id']}#{item['sequence']}: {plaintext}")
            ack_ids.append(item["id"])
        except Exception as exc:
            print(f"DECRYPTION FAILED id={item['id']}: {exc}")

    if ack_ids:
        ack_resp = requests.post(
            f"{args.broker_url}/cg-ack/{args.hospital}/{args.department}",
            json={"consumer_id": args.consumer_id, "message_ids": ack_ids},
            timeout=10,
        )
        ack_resp.raise_for_status()
        print(f"ACKed {ack_resp.json().get('acked')} message(s)")


if __name__ == "__main__":
    main()
