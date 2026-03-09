#!/usr/bin/env bash
# =============================================================================
# MedLock mTLS Certificate Generator
# =============================================================================
# Creates a private CA and issues certificates for every internal service.
# Run this once locally. Commit only ca.crt (never ca.key or *.key).
# On cloud, load the generated files into your secret manager and mount them.
#
# Usage:
#   cd infra/certs && bash gen-certs.sh
#
# Output (per service):
#   <service>/ca.crt       — shared trust root  (safe to commit)
#   <service>/<svc>.crt    — service certificate
#   <service>/<svc>.key    — service private key (NEVER COMMIT)
#
# The flat ca.crt at infra/certs/ca.crt is the one all services mount.
# =============================================================================

set -euo pipefail

DAYS_CA=3650     # 10 years — rotate on breach
DAYS_SVC=825     # ~2.25 years — rotate annually in prod
KEY_BITS=4096
SUBJ_BASE="/C=US/ST=CA/L=MedLock/O=MedLock"

# ✅ FIX: Added 'seed' so the seed service gets a client cert
SERVICES=(
  auth-service
  tenant-service
  kms-service
  broker
  clinical-service
  simulator
  gateway
  seed
  prometheus
)

OUT="$(cd "$(dirname "$0")" && pwd)"

echo "==> Generating CA key and certificate..."
openssl genrsa -out "$OUT/ca.key" $KEY_BITS 2>/dev/null
openssl req -new -x509 \
  -key "$OUT/ca.key" \
  -out "$OUT/ca.crt" \
  -days $DAYS_CA \
  -subj "$SUBJ_BASE/CN=MedLock-Internal-CA"

echo "==> CA certificate generated: $OUT/ca.crt"

for SVC in "${SERVICES[@]}"; do
  DIR="$OUT/$SVC"
  mkdir -p "$DIR"

  echo ""
  echo "==> Generating cert for: $SVC"

  # Per-service private key
  openssl genrsa -out "$DIR/$SVC.key" $KEY_BITS 2>/dev/null

  # CSR with SAN so Go/Python TLS stacks accept it without hostname warnings
  openssl req -new \
    -key "$DIR/$SVC.key" \
    -out "$DIR/$SVC.csr" \
    -subj "$SUBJ_BASE/CN=$SVC" \
    -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C  = US
ST = CA
L  = MedLock
O  = MedLock
CN = $SVC

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SVC
DNS.2 = localhost
DNS.3 = 127.0.0.1
IP.1  = 127.0.0.1
EOF
)

  # Sign with our CA, embedding SANs
  openssl x509 -req \
    -in "$DIR/$SVC.csr" \
    -CA "$OUT/ca.crt" \
    -CAkey "$OUT/ca.key" \
    -CAcreateserial \
    -out "$DIR/$SVC.crt" \
    -days $DAYS_SVC \
    -extensions v3_req \
    -extfile <(cat <<EOF
[v3_req]
subjectAltName = DNS:$SVC, DNS:localhost, IP:127.0.0.1
EOF
)

  # Copy shared CA cert into per-service dir for convenience
  cp "$OUT/ca.crt" "$DIR/ca.crt"

  # Clean up CSR — not needed after signing
  rm "$DIR/$SVC.csr"

  echo "    Key : $DIR/$SVC.key"
  echo "    Cert: $DIR/$SVC.crt"
done

echo ""
echo "==> All certificates generated."
echo ""
echo "IMPORTANT:"
echo "  - Add infra/certs/**/*.key to .gitignore"
echo "  - Add infra/certs/ca.key to .gitignore"
echo "  - Only ca.crt is safe to commit"
echo ""
echo "Verify a cert:"
echo "  openssl verify -CAfile infra/certs/ca.crt infra/certs/broker/broker.crt"
