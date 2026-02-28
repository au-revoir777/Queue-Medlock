# MedLock Mesh

Zero-Trust Multi-Tenant Clinical Messaging platform for secure hospital collaboration across untrusted infrastructure.

## Core Principles

- **Broker is untrusted**: no key handling, no plaintext processing.
- **Cryptographic tenant isolation**: keys are scoped with `hospital_id + department_id` in HKDF info.
- **Device identity assurance**: staff devices use Ed25519 signing keys and X25519 key-exchange keys.
- **Replay resistance**: consumers track producer sequence numbers and reject stale messages.

## Monorepo Layout

```text
medlock-mesh/
├── frontend/                 # React + TypeScript dashboard
├── control-plane/
│   ├── auth-service/         # FastAPI JWT auth
│   ├── tenant-service/       # FastAPI hospital/department/staff lifecycle
│   └── kms-service/          # FastAPI key registration/discovery/exchange metadata
├── broker/                   # Node + Express + Redis Streams message relay
├── producer-sdk/             # Python CLI + library for signing/encrypting messages
├── consumer-sdk/             # Python CLI + library for dequeue/verify/decrypt/replay guard
├── mobile-client/            # Flutter starter shell
├── infra/                    # Nginx gateway and SQL schema
├── docker-compose.yml
└── scripts/                  # Local helper scripts
```

## Crypto Flow

1. Producer creates an ephemeral X25519 key pair.
2. Producer computes shared secret with consumer static X25519 public key.
3. Session key is derived via HKDF-SHA256 with `hospital_id:department_id` context.
4. Message plaintext is encrypted with AES-GCM.
5. Producer signs message envelope (including sequence + nonce + ciphertext hash) with Ed25519.
6. Consumer verifies signature, derives the same session key, decrypts, and checks replay cache.

## Services

### Control Plane

- `auth-service`
  - `POST /login`
  - `POST /refresh`
- `tenant-service`
  - `POST /hospitals`
  - `POST /hospitals/{id}/departments`
  - `POST /staff/register`
- `kms-service`
  - `GET /keys/{hospital}/{department}`
  - `POST /exchange`

### Broker

- `POST /enqueue`
- `GET /dequeue/{department}`

Only opaque payload components are persisted in Redis Streams:

```json
{
  "ciphertext": "...",
  "nonce": "...",
  "producer_id": "...",
  "sequence": 42
}
```

## Quickstart

```bash
docker compose up --build
```

Endpoints:

- Frontend: `http://localhost:3000`
- Gateway: `http://localhost:8080`
- Auth API: `http://localhost:8001`
- Tenant API: `http://localhost:8002`
- KMS API: `http://localhost:8003`
- Broker API: `http://localhost:9000`

## CLI Demo

1. Register staff public keys with tenant + KMS service.
2. Produce encrypted message:

```bash
python -m medlock_producer.cli \
  --hospital apollo \
  --department radiology \
  --producer-id doc-1 \
  --consumer-pubkey <base64-x25519-public-key> \
  --producer-signing-key <base64-ed25519-private-key> \
  --broker-url http://localhost:9000 \
  --message "MRI complete"
```

3. Consume and decrypt:

```bash
python -m medlock_consumer.cli \
  --hospital apollo \
  --department radiology \
  --consumer-id lab-1 \
  --consumer-kx-private-key <base64-x25519-private-key> \
  --producer-signing-public-key <base64-ed25519-public-key> \
  --broker-url http://localhost:9000
```

## Security Notes

- Session keys are never persisted in any service.
- Broker never receives identity private keys or plaintext.
- Replay cache is maintained client-side per producer per tenant/department.
- This scaffold is intentionally minimal; harden for production (mTLS, HSM-backed KMS, full auditing, key rotation).
