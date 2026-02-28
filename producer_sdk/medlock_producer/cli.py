import argparse

import requests

from .crypto import build_encrypted_payload


def main():
    parser = argparse.ArgumentParser(description="MedLock producer CLI")
    parser.add_argument("--hospital", required=True)
    parser.add_argument("--department", required=True)
    parser.add_argument("--producer-id", required=True)
    parser.add_argument("--consumer-pubkey", required=True)
    parser.add_argument("--producer-signing-key", required=True)
    parser.add_argument("--broker-url", required=True)
    parser.add_argument("--sequence", type=int, default=1)
    parser.add_argument("--message", required=True)
    args = parser.parse_args()

    payload = build_encrypted_payload(
        hospital_id=args.hospital,
        department_id=args.department,
        producer_id=args.producer_id,
        sequence=args.sequence,
        plaintext=args.message,
        consumer_public_kx_b64=args.consumer_pubkey,
        producer_signing_private_b64=args.producer_signing_key,
    )

    body = {
        "department": args.department,
        "producer_id": args.producer_id,
        "sequence": args.sequence,
        "nonce": payload.nonce,
        "ciphertext": payload.ciphertext,
        "envelope": payload.envelope,
    }
    response = requests.post(f"{args.broker_url}/enqueue", json=body, timeout=10)
    response.raise_for_status()
    print(response.json())


if __name__ == "__main__":
    main()
