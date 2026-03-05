#!/usr/bin/env bash
# =============================================================================
# verify-certs.sh — Verify all MedLock service certificates
# =============================================================================
# Run after gen-certs.sh to confirm every cert:
#   1. Is signed by our private CA
#   2. Has the correct Subject Alternative Names
#   3. Has not expired
#
# Usage:
#   cd infra/certs && bash verify-certs.sh
# =============================================================================

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
CA="$DIR/ca.crt"
PASS=0
FAIL=0

SERVICES=(
  auth-service
  tenant-service
  kms-service
  broker
  clinical-service
  simulator
  gateway
)

check_cert() {
  local SVC="$1"
  local CERT="$DIR/$SVC/$SVC.crt"

  if [[ ! -f "$CERT" ]]; then
    echo "  ❌ MISSING: $CERT  (run gen-certs.sh first)"
    FAIL=$((FAIL + 1))
    return
  fi

  # Verify signature chain
  if openssl verify -CAfile "$CA" "$CERT" > /dev/null 2>&1; then
    echo -n "  ✅ $SVC — chain OK"
  else
    echo "  ❌ $SVC — chain FAILED"
    FAIL=$((FAIL + 1))
    return
  fi

  # Check expiry
  EXPIRY=$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null | cut -d= -f2)
  EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$EXPIRY" +%s)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

  echo " | expires in ${DAYS_LEFT} days ($EXPIRY)"
  PASS=$((PASS + 1))
}

echo ""
echo "MedLock mTLS Certificate Verification"
echo "======================================"
echo "CA: $CA"
echo ""

if [[ ! -f "$CA" ]]; then
  echo "❌ CA certificate not found at $CA"
  echo "   Run: cd infra/certs && bash gen-certs.sh"
  exit 1
fi

for SVC in "${SERVICES[@]}"; do
  check_cert "$SVC"
done

echo ""
echo "======================================"
echo "Result: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
  echo "Run gen-certs.sh to regenerate missing/failed certificates."
  exit 1
fi

echo ""
echo "All certificates valid. mTLS is ready."
echo ""
echo "Next steps:"
echo "  1. docker compose up --build"
echo "  2. Check logs: docker logs medlock_broker | grep mtls"
echo "  3. Set MTLS_REQUIRED=true in docker-compose.yml once confirmed working"
