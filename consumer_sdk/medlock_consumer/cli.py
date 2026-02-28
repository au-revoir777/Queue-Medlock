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
    # New: opt-in to consumer group mode (default: legacy mode)
    parser.add_argument(
        "--use-consumer-group",
        action="store_true",
        default=False,
        help="Use Redis consumer group delivery (recommended). "
        "Falls back to legacy full-stream scan if not set.",
    )
    args = parser.parse_args()

    if args.use_consumer_group:
        _run_consumer_group(args)
    else:
        _run_legacy(args)


# ----------------------------------------------------------------
# Legacy mode — full stream scan, no ACK, kept for backward compat
# ----------------------------------------------------------------
def _run_legacy(args):
    cache = ReplayCache()
    # NOTE: legacy endpoint includes hospital in path, old CLI had a bug
    # where it used /dequeue/<department> without hospital — kept as-is
    # to avoid breaking existing scripts.
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


# ----------------------------------------------------------------
# Consumer group mode — fetch-decrypt-ACK, exactly-once delivery
# ----------------------------------------------------------------
def _run_consumer_group(args):
    # Step 1: fetch new messages assigned to this consumer
    response = requests.get(
        f"{args.broker_url}/cg-dequeue/{args.hospital}/{args.department}",
        params={"consumer_id": args.consumer_id, "count": "10"},
        timeout=10,
    )
    response.raise_for_status()

    items = response.json().get("items", [])
    ack_ids = []

    for item in items:
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
                producer_signing_public_b64=args.producer_signing_public_key,
            )
            print(f"{item['producer_id']}#{item['sequence']}: {plaintext}")
            # Only ACK after successful decryption
            ack_ids.append(item["id"])
        except Exception as exc:
            # Leave in PEL — will be reclaimed on next run
            print(f"DECRYPTION FAILED id={item['id']}: {exc}")

    # Step 2: ACK successfully processed messages
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
