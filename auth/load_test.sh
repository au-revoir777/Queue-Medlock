#!/usr/bin/env bash
# ============================================================
# MedLock Rate Limiter — Load Test Script
# ============================================================
# Sends 120 sequential requests to /auth/validate to demonstrate
# that the token-bucket rate limiter correctly rejects requests
# after the 100-request capacity (+5 burst) is exhausted.
#
# Usage:
#   chmod +x auth/load_test.sh
#   ./auth/load_test.sh
#
# Prerequisites:
#   - Redis running on localhost:6379
#   - Auth service running on localhost:8000
# ============================================================

set -euo pipefail

BASE_URL="${AUTH_URL:-http://localhost:8000}"
ENDPOINT="${BASE_URL}/auth/validate"
TOTAL_REQUESTS=120
TOKEN="test-token-for-load-test"

# Counters
SUCCESS=0
REJECTED=0
ERRORS=0

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  MedLock Rate Limiter — Load Test                           ║"
echo "║  Target : ${ENDPOINT}                                       "
echo "║  Requests: ${TOTAL_REQUESTS}                                ║"
echo "║  Expected: ~105 allowed, ~15 rejected (429)                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

for i in $(seq 1 ${TOTAL_REQUESTS}); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${ENDPOINT}" \
        -H "Content-Type: application/json" \
        -d "{\"token\": \"${TOKEN}\", \"hospital_id\": \"hospital1\", \"department\": \"cardiology\", \"staff_id\": \"nurse_001\"}")

    if [ "${HTTP_CODE}" == "429" ]; then
        REJECTED=$((REJECTED + 1))
        STATUS="🚫 429 RATE LIMITED"
    elif [ "${HTTP_CODE}" == "200" ] || [ "${HTTP_CODE}" == "401" ]; then
        SUCCESS=$((SUCCESS + 1))
        STATUS="✅ ${HTTP_CODE} OK"
    else
        ERRORS=$((ERRORS + 1))
        STATUS="⚠️  ${HTTP_CODE} ERROR"
    fi

    # Print every 10th request or when rate-limited
    if [ $((i % 10)) -eq 0 ] || [ "${HTTP_CODE}" == "429" ]; then
        printf "  [%3d/%d] %s\n" "${i}" "${TOTAL_REQUESTS}" "${STATUS}"
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  RESULTS"
echo "═══════════════════════════════════════════════════════════════"
echo "  Total requests : ${TOTAL_REQUESTS}"
echo "  Allowed        : ${SUCCESS}"
echo "  Rate-limited   : ${REJECTED}"
echo "  Errors         : ${ERRORS}"
echo "═══════════════════════════════════════════════════════════════"

if [ "${REJECTED}" -gt 0 ]; then
    echo ""
    echo "  ✅ Rate limiter is WORKING — ${REJECTED} requests correctly rejected."
else
    echo ""
    echo "  ⚠️  No 429 responses detected. Verify Redis and middleware are running."
fi
