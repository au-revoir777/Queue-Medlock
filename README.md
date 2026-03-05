# MedLock — Zero Trust Clinical Platform

MedLock is a secure, multi-tenant clinical messaging platform built on a **Zero Trust** architecture. It enables hospital staff across departments (Cardiology, ICU, Neurology, Oncology, Radiology, etc.) to exchange end-to-end encrypted clinical records in real time, with every service-to-service call authenticated via mutual TLS (mTLS).

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Services](#services)
- [Security Model](#security-model)
- [Database Schema](#database-schema)
- [Frontend](#frontend)
- [Observability](#observability)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Developer Tooling](#developer-tooling)
- [Testing & Simulation](#testing--simulation)
- [Key Design Decisions](#key-design-decisions)

---

## Architecture Overview

### System Topology

```
┌──────────────────────────────────────────────────────────────────┐
│   Browser (React SPA, :3000)  /  Mobile Client (Flutter)         │
└────────────────────┬─────────────────────────────────────────────┘
                     │  HTTP / WebSocket
                     ▼
           ┌──────────────────┐
           │   Nginx Gateway  │  :8080 (HTTP) / :8443 (HTTPS)
           │  (reverse proxy) │  TLS termination
           └────────┬─────────┘
                    │  mTLS  (all internal calls over private CA)
      ┌─────────────┼──────────────────────────────┬────────────┐
      ▼             ▼             ▼                 ▼            ▼
  Auth Svc     Tenant Svc     KMS Svc        Clinical Svc   Policy Svc
  :8000        :8001          :8002          :8003           :8004
  (FastAPI)    (FastAPI)      (FastAPI)      (FastAPI)       (FastAPI)
      │             │             │                │
      └─────────────┴─────────────┴────────────────┘
                          │
                     PostgreSQL 16
                          │
                     ┌────┴────┐
                     │ Broker  │  :9000  (Node.js / Express)
                     │  mTLS   │  validates tokens → Auth Svc on every call
                     └────┬────┘
                          │
                       Redis 7
                    (Streams / PubSub)

Observability:  Prometheus (:9090)  →  Grafana (:3100)
```

---

### Request & Message Flow

**1. Staff Registration (one-time)**

```
Client  →  Tenant Service  /staff/register
               ├──►  Auth Service   /register    (create login credentials)
               └──►  KMS Service    /exchange    (store 4 public keys:
                                                  Ed25519, X25519,
                                                  ML-KEM-768, ML-DSA-65)
```

**2. Login**

```
Client  →  Auth Service  /login
        ←  access_token  (opaque SHA-256 token, 1 hr TTL, pre-warmed in cache)
```

**3. Producing a Clinical Record**

```
Producer (browser / simulator)
  1. Fetch consumer's public keys  ──►  KMS Service  /keys/{hospital}/{dept}/{id}
  2. Encrypt payload locally
       X25519 ephemeral DH        ┐
       ML-KEM-768 encapsulation   ├──  HKDF-SHA256  →  session key  →  AES-256-GCM
       Ed25519 + ML-DSA-65 sigs   ┘
  3. POST /enqueue  →  Broker  (Bearer token)
          Broker  →  Auth Service  /validate   (token check + identity binding)
          Broker  →  Redis Stream              (ciphertext + envelope only;
                                               plaintext never leaves the client)
```

**4. Consuming a Clinical Record**

```
Consumer (browser via WebSocket / simulator thread)
  1. GET /cg-dequeue  or  WebSocket subscription  →  Broker / Clinical Service
          Broker  →  Auth Service  /validate   (token check)
  2. For each message: fetch producer's public keys  →  KMS Service
  3. Decrypt locally
       Reconstruct session key  (X25519 private + ephemeral pub + ML-KEM-768 decap)
       Verify Ed25519 signature  +  ML-DSA-65 signature  (both must pass)
       AES-256-GCM decrypt  +  AAD check  (producer_id:sequence)
  4. ACK message  →  POST /cg-ack  →  Broker
  5. Persist decrypted record  →  Clinical Service  →  PostgreSQL
```

**5. Frontend Live Feed**

```
Browser  →  WebSocket  →  Clinical Service  (token in query param)
         ←  snapshot of recent records on connect
         ←  incremental "record" push events as new records arrive
```

> All internal service-to-service calls use mTLS. No service trusts another based on network position alone.

---

## Project Structure

```
.
├── control-plane/
│   ├── auth-service/
│   │   └── app/main.py             # FastAPI auth service
│   ├── tenant-service/
│   │   └── app/main.py             # Hospital & staff provisioning
│   ├── kms-service/
│   │   └── app/main.py             # Key Management Service
│   ├── clinical-service/
│   │   └── app/main.py             # Clinical record CRUD + WebSocket feed
│   └── policy-service/
│       └── app/main.py             # Attribute-Based Access Control
├── broker/
│   └── src/
│       ├── index.js                # Node.js Redis Streams message broker
│       └── mtlsClient.js           # mTLS-aware Node.js HTTP client
├── frontend/
│   └── src/
│       ├── App.tsx                 # Root component & routing
│       ├── api.ts                  # Typed API + WebSocket client helpers
│       ├── main.tsx                # Entry point
│       ├── components/
│       │   ├── Layout.tsx          # App shell & sidebar navigation
│       │   ├── PageHeader.tsx      # Consistent page header
│       │   └── RecordFeed.tsx      # Paginated decrypted record list
│       ├── context/
│       │   └── AuthContext.tsx     # Global auth state (token + identity)
│       ├── hooks/
│       │   └── useWebSocket.ts     # Live record feed WebSocket hook
│       └── pages/
│           ├── Login.tsx           # Authentication UI
│           ├── Dashboard.tsx       # Overview & stats
│           ├── Compose.tsx         # Encrypt & publish clinical records
│           ├── AuditLog.tsx        # Tamper-evident audit log viewer
│           ├── Admin.tsx           # Admin-only panel
│           ├── DeptPages.tsx       # Reusable department record feed
│           ├── Cardiology.tsx      # Department page wrappers
│           ├── ICU.tsx
│           ├── Neurology.tsx
│           ├── Oncology.tsx
│           └── Radiology.tsx
├── consumer_sdk/
│   └── medlock_consumer/
│       ├── cli.py                  # Consumer CLI (dequeue + decrypt)
│       └── crypto.py               # Classical decryption primitives (X25519 + Ed25519)
├── producer_sdk/
│   └── medlock_producer/
│       ├── cli.py                  # Producer CLI (encrypt + enqueue)
│       └── crypto.py               # Classical encryption primitives
├── simulator/
│   └── simulator.py                # Full hybrid-PQC clinical data simulator
├── scripts/
│   ├── gen_keys.py                 # Key pair generation utility
│   └── seed/
│       └── seed.py                 # Demo hospital/staff/patient seed script
├── infra/
│   ├── schema.sql                  # Shared Postgres schema (run at DB init)
│   ├── certs/
│   │   ├── gen-certs.sh            # CA + per-service cert generation
│   │   └── verify-certs.sh         # Cert verification helper
│   ├── nginx/
│   │   └── default.conf            # Gateway reverse proxy config
│   ├── prometheus.yml              # Prometheus scrape config
│   └── grafana/
│       └── provisioning/
│           ├── dashboards/
│           │   ├── medlock.json    # Pre-built Grafana dashboard
│           │   └── provider.yml    # Dashboard provider config
│           └── datasources/
│               └── prometheus.yml  # Grafana → Prometheus datasource
├── mtls/
│   └── mtls_requests.py            # mTLS-aware Python requests wrapper (shared)
├── mobile-client/
│   └── lib/main.dart               # Flutter mobile client
├── unit-tests/                     # Pytest suites + live send/receive scripts
├── attacker.py                     # Red-team security simulation
├── stress_test.py                  # Load & latency testing
├── openapi.json                    # OpenAPI specification
└── docker-compose.yml              # Full-stack container orchestration
```

---

## Services

### Auth Service — `control-plane/auth-service`

Python FastAPI service responsible for staff authentication. Sits at the centre of the trust model — every other service calls `/validate` on every incoming request.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | Create a new staff account |
| `POST` | `/login` | Authenticate and receive an opaque access token |
| `POST` | `/validate` | Validate a Bearer token (called by all services) |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |

**Performance notes:**
- PostgreSQL connection pool (min 8, max 50 connections, pre-opened at startup)
- In-memory token cache with configurable TTL (`TOKEN_CACHE_TTL`, default 120 s); tokens are pre-warmed at login
- `/validate` is `async def` — runs directly on the uvicorn event loop with lock-free dict reads; cache hits complete in < 0.1 ms
- Cache misses dispatch the blocking DB call via `run_in_executor` to avoid blocking the event loop

---

### Tenant Service — `control-plane/tenant-service`

Handles hospital and staff provisioning. On staff registration it fans out to both the Auth service (create credentials) and the KMS service (register public keys). Maintains the authoritative `tenant_hospitals` and `tenant_staff` tables.

---

### KMS Service — `control-plane/kms-service`

Manages cryptographic key registration and retrieval. Each staff member registers four public keys: `Ed25519` (classical signing), `X25519` (classical key exchange), `ML-KEM-768` (post-quantum KEM), and `ML-DSA-65` (post-quantum signing). Keys are namespaced by `(hospital_id, department_id, staff_id)` and looked up at decrypt time — never cached client-side.

---

### Clinical Service — `control-plane/clinical-service`

Persists decrypted clinical records from the simulator into PostgreSQL and exposes a WebSocket feed to the frontend. Validates every request through the Auth service. Pushes `snapshot` and incremental `record` events over WebSocket to connected browser clients.

---

### Policy Service — `control-plane/policy-service`

Attribute-Based Access Control engine. Evaluates whether a given identity (hospital, department, role) is permitted to access a specific resource or record type.

---

### Broker — `broker/src/index.js`

Node.js / Express HTTPS server wrapping **Redis Streams** as the clinical message bus. All endpoints validate the Bearer token against the Auth service and cross-check the token identity against the request body before accepting data.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/sequence/:hospital/:producer_id` | Bootstrap last known sequence number |
| `POST` | `/enqueue` | Publish an encrypted clinical record |
| `GET` | `/dequeue/:hospital/:department` | Legacy polling dequeue (last 10 messages) |
| `GET` | `/cg-dequeue/:hospital/:department` | Consumer-group dequeue |
| `POST` | `/cg-ack/:hospital/:department` | Acknowledge processed messages |
| `GET` | `/cg-pending/:hospital/:department` | Reclaim unacknowledged messages via `XAUTOCLAIM` |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |

---

## Security Model

### End-to-End Encryption — Hybrid Post-Quantum (`hybrid-v1`)

All clinical records are encrypted at the producer before transmission. The full simulator uses a **hybrid classical + post-quantum** scheme so that breaking either layer alone is not sufficient to compromise a message.

**Key Exchange — both secrets combined via HKDF:**

| Layer | Algorithm | Notes |
|-------|-----------|-------|
| Classical | X25519 ephemeral ECDH | Per-message ephemeral key pair |
| Post-Quantum | ML-KEM-768 | NIST PQC Key Encapsulation Mechanism |

Both shared secrets are concatenated and passed through **HKDF-SHA256** (info = `hospital_id:department_id`) to derive a 32-byte AES session key.

**Encryption:** AES-256-GCM — AAD = `producer_id:sequence`

**Dual Signatures — both verified on decrypt:**

| Layer | Algorithm | Signed content |
|-------|-----------|----------------|
| Classical | Ed25519 | `producer_id:sequence:sha256(ciphertext)` |
| Post-Quantum | ML-DSA-65 | same |

The **envelope** stored in the broker contains: `ephemeral_public_key`, `kem_ciphertext`, `signature_classical`, `signature_pqc`, `cipher_hash`, `version`. The broker and PostgreSQL **never see plaintext**.

The consumer SDK (`consumer_sdk/medlock_consumer/crypto.py`) provides a classical-only path (X25519 + Ed25519) for lightweight consumers.

---

### Mutual TLS (mTLS)

All service-to-service communication requires a client certificate signed by the project's private CA (`infra/certs/ca.crt`). The broker's HTTPS server is configured with `requestCert: true` and `rejectUnauthorized: true`. All Python services use `mtls/mtls_requests.py` — a drop-in wrapper around `requests` — to automatically attach the service certificate on every outbound call.

---

### Replay Protection

The broker tracks a monotonically increasing sequence number per `(hospital_id, producer_id)` in Redis. Any enqueue with `sequence ≤ last_seen` is rejected with HTTP 409. On a 409, producers automatically re-sync their sequence counter from `/sequence/:hospital/:producer_id` before retrying.

---

### Token Validation

Every service independently validates the Bearer token against the Auth service on every request. There is no implicit inter-service trust based on network position. The Auth service hot path (cache hit) completes in < 0.1 ms.

---

## Database Schema

All tables are defined in `infra/schema.sql` and initialised by Postgres at startup. Individual services must **not** re-create these tables in their own startup routines.

| Table | Owner | Description |
|-------|-------|-------------|
| `hospitals` | Shared | Hospital registry |
| `departments` | Shared | Department registry |
| `staff` | Shared | Staff public keys |
| `audit_logs` | Clinical | Tamper-evident audit trail |
| `patients` | Clinical | Patient registry |
| `clinical_records` | Clinical | Persisted decrypted records (written post-decrypt) |
| `auth_users` | Auth | Staff credentials (hashed passwords) |
| `auth_tokens` | Auth | Active session tokens with expiry |
| `kms_keys` | KMS | Staff cryptographic public keys (all 4 algorithms) |
| `tenant_hospitals` | Tenant | Tenant-scoped hospital records |
| `tenant_staff` | Tenant | Tenant staff records including all 4 public keys |
| `simulator_keys` | Simulator | Persisted simulator key pairs (survive restarts) |

Indexes are provided on token lookup, token expiry sweep, patient records, and department-scoped record queries.

---

## Frontend

React + TypeScript SPA (Vite) served on port 3000.

| File | Responsibility |
|------|----------------|
| `context/AuthContext.tsx` | Global auth state (`token`, `identity`) persisted in `sessionStorage` |
| `hooks/useWebSocket.ts` | WebSocket hook — connects to Clinical Service, handles `snapshot` + `record` events, auto-reconnects |
| `api.ts` | Typed HTTP and WebSocket client helpers for all backend services |
| `components/Layout.tsx` | App shell, sidebar navigation, role-based route guards |
| `pages/Login.tsx` | Login form — calls Auth service, populates `AuthContext` |
| `pages/Compose.tsx` | Compose, sign, encrypt, and publish a clinical record to the Broker |
| `pages/Dashboard.tsx` | Hospital-wide overview with recent records and stats |
| `pages/AuditLog.tsx` | Tamper-evident audit log viewer with signature verification |
| `pages/Admin.tsx` | Admin-only management panel |
| `pages/DeptPages.tsx` | Reusable department record feed (used by all dept pages) |
| `pages/Cardiology` / `ICU` / `Neurology` / `Oncology` / `Radiology` | Thin wrappers over `DeptPages` |
| `components/RecordFeed.tsx` | Paginated, decrypted clinical record list |
| `components/PageHeader.tsx` | Consistent page header |

---

## Observability

**Prometheus** (`infra/prometheus.yml`) scrapes metrics from all services. **Grafana** (`infra/grafana/provisioning/dashboards/medlock.json`) ships a pre-built dashboard covering:

- Auth service: request rate, login success/failure counters, token cache hit ratio
- Clinical service: request rate, error rate
- Broker: enqueue / dequeue / ack throughput, per-hospital message volume
- Security counters: replay attack detections, validation failures

Access Grafana at `http://localhost:3100` — credentials `admin / medlock`. Anonymous viewer access is enabled by default.

---

## Getting Started

### Prerequisites

- Docker + Docker Compose v2
- `openssl` (for certificate generation)

### 1. Generate mTLS Certificates

```bash
bash infra/certs/gen-certs.sh
```

Creates a private CA and per-service signed certificates under `infra/certs/`.

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your values
```

See [Environment Variables](#environment-variables) for required keys.

### 3. Start the Stack

```bash
# Full stack
docker compose up --build

# With red-team attacker enabled
docker compose --profile attack up --build
```

The `seed` container runs automatically on first boot and populates demo hospitals, staff accounts, and patients.

### 4. Access

| Service | URL |
|---------|-----|
| Frontend | `http://localhost:3000` |
| Gateway HTTP | `http://localhost:8080` |
| Gateway HTTPS | `https://localhost:8443` |
| Auth Service | `https://localhost:8000` |
| Tenant Service | `https://localhost:8001` |
| KMS Service | `https://localhost:8002` |
| Clinical Service | `https://localhost:8003` |
| Policy Service | `https://localhost:8004` |
| Broker | `https://localhost:9000` |
| Prometheus | `http://localhost:9090` |
| Grafana | `http://localhost:3100` |

Demo credentials are seeded with the password set by `DEMO_PASSWORD` (default: `demo1234`).

---

## Environment Variables

| Variable | Service | Description |
|----------|---------|-------------|
| `POSTGRES_USER` | postgres | Database username |
| `POSTGRES_PASSWORD` | postgres | Database password |
| `POSTGRES_DB` | postgres | Database name |
| `JWT_SECRET` | auth | Token signing secret |
| `DEMO_PASSWORD` | seed | Demo account password (default: `demo1234`) |
| `SIM_PASSWORD` | simulator | Simulator account password |
| `MTLS_CERT_PATH` | all services | Path to the service's TLS certificate |
| `MTLS_KEY_PATH` | all services | Path to the service's TLS private key |
| `MTLS_CA_PATH` | all services | Path to the shared CA certificate |
| `MTLS_REQUIRED` | all services | Enforce mTLS — `"true"` or `"false"` |
| `TOKEN_CACHE_TTL` | auth | In-memory token cache TTL in seconds (default: `120`) |

---

## Developer Tooling

### Producer & Consumer SDKs

MedLock ships two Python SDKs with CLIs for direct interaction with the platform.

**Producer SDK** — encrypt and publish clinical records:

```bash
python -m medlock_producer.cli \
  --hospital hospital1 \
  --department cardiology \
  --producer-id staff_id \
  --broker-url https://localhost:9000 \
  --token <access_token>
```

**Consumer SDK** — fetch and decrypt records from the broker:

```bash
# Legacy dequeue
python -m medlock_consumer.cli \
  --hospital hospital1 \
  --department cardiology \
  --consumer-id staff_id \
  --consumer-kx-private-key <base64_key> \
  --broker-url https://localhost:9000

# Consumer-group mode (at-least-once delivery, with ACK)
python -m medlock_consumer.cli ... --use-consumer-group
```

### Key Generation

```bash
python scripts/gen_keys.py
```

Generates Ed25519, X25519, ML-KEM-768, and ML-DSA-65 key pairs for staff registration.

### mTLS Wrappers

- **Python** — `mtls/mtls_requests.py`: drop-in replacement for `requests`, auto-attaches the service certificate from env vars. Imported as `import mtls_requests as requests` in all control-plane services.
- **Node.js** — `broker/src/mtlsClient.js`: wraps `https` with cert/key/CA loaded from env vars. Used by `broker/src/index.js` for outbound calls to the Auth service.

---

## Testing & Simulation

### Simulator — `simulator/simulator.py`

Continuously generates realistic clinical events (ICU vitals, cardiology ECGs, radiology scans, neurology assessments, oncology treatment plans) across multiple hospitals and departments using the full hybrid post-quantum crypto stack. Runs as the `medlock_simulator` Docker container.

```bash
python simulator/simulator.py
```

### Stress Test — `stress_test.py`

Measures p50 / p95 / p99 latency for the login and validate endpoints under concurrent load. Validates the auth service SLA targets: login p95 < 200 ms, validate p95 < 50 ms.

```bash
python stress_test.py
```

### Attacker — `attacker.py`

Red-team simulation that exercises the platform's security controls: replay attacks, sequence manipulation, identity mismatch attempts, token forgery, and cross-tenant access. Activated via the `attack` Docker Compose profile.

```bash
docker compose --profile attack up attacker
```

### Unit & Integration Tests — `unit-tests/`

```bash
pytest unit-tests/test_full_flow.py
pytest unit-tests/test_producer.py
pytest unit-tests/test_consumer.py
pytest unit-tests/test_simulator.py
```

Live end-to-end scripts (`send_receive_live.py`, `send_receive_live_multi.py`, `send_receive_live_stress.py`, `send_receive_live_super_stress.py`) are also available for manual validation against a running stack.

---

## Key Design Decisions

**Why Redis Streams for the broker?**
Streams provide persistent, ordered, consumer-group semantics with at-least-once delivery and `XAUTOCLAIM`-based pending message reclaim. No clinical record is silently dropped even if a consumer crashes mid-processing.

**Why `async def` for `/validate`?**
The validate endpoint is on the hot path of every service call. Converting from `sync def` (threadpool dispatch, GIL contention across concurrent threads) to `async def` (runs directly on the event loop) reduced p95 latency from ~140 ms to well under 50 ms on cache hits.

**Why hybrid post-quantum cryptography?**
Classical X25519 / Ed25519 alone is vulnerable to "harvest now, decrypt later" attacks — an adversary captures ciphertext today and decrypts it once quantum hardware matures. Combining X25519 with ML-KEM-768 and Ed25519 with ML-DSA-65 requires breaking **both** schemes simultaneously, providing long-term confidentiality for sensitive patient data.

**Why client-side encryption?**
The broker, Redis, and PostgreSQL never hold plaintext. Compromising any storage or transport layer does not expose patient data. Only the intended recipient holding the private X25519 and ML-KEM-768 keys can decrypt a record.

**Why mTLS everywhere?**
Network-level mutual authentication eliminates the implicit trust that flat internal networks create. An attacker with internal network access cannot impersonate a service without a CA-signed certificate.

**Why live KMS key lookup at decrypt time?**
Staff public keys are fetched from the KMS on each consume cycle rather than cached locally. This is a zero-trust decision: a locally cached key could be stale or revoked. Live lookup ensures key revocation takes effect on the very next message.
