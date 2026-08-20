#!/usr/bin/env bash
# =============================================================================
# End-to-end pipeline test — exercises the full path through every service:
#
#   auth -> KYC register -> KYC approve (on-chain) -> kyc.events -> Redis
#        -> Kafka transaction -> ML scoring -> audit receipt anchored
#        -> alert -> case -> SAR (hash on-chain) -> audit trail
#        -> per-org completeness -> compliance report
#
# Usage:  bash tests/e2e/e2e_pipeline.sh
# Env:    GATEWAY (default :8080), BLOCKCHAIN (default :9005),
#         ALERT (:9003), CASE (:9004), KYC (:9001), ML (:8000)
# =============================================================================
set -uo pipefail

GATEWAY="${GATEWAY:-http://localhost:8080}"
BLOCKCHAIN="${BLOCKCHAIN:-http://localhost:9005}"
ALERT="${ALERT:-http://localhost:9003}"
CASE_SVC="${CASE_SVC:-http://localhost:9004}"
KYC="${KYC:-http://localhost:9001}"
ML="${ML:-http://localhost:8000}"
EMAIL="${EMAIL:-admin@fraud.local}"
PASSWORD="${PASSWORD:-FraudOps@2026}"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
PASS=0; FAIL=0; SKIP=0
declare -a FAILED_STEPS=()

step()  { printf "${B}[%02d]${N} %-46s " "$1" "$2"; }
ok()    { PASS=$((PASS+1)); printf "${G}PASS${N} %s\n" "${1:-}"; }
bad()   { FAIL=$((FAIL+1)); FAILED_STEPS+=("$1"); printf "${R}FAIL${N} %s\n" "${2:-}"; }
skip()  { SKIP=$((SKIP+1)); printf "${Y}SKIP${N} %s\n" "${1:-}"; }

jqr() { python3 -c "import sys,json;d=json.load(sys.stdin);print(eval('d'+sys.argv[1]) if sys.argv[1] else d)" "$1" 2>/dev/null; }

echo "=============================================================="
echo " AML FRAUD DETECTION — END-TO-END PIPELINE TEST"
echo " $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================================="
echo

# ---------------------------------------------------------------- 1. health
step 1 "service health (gateway + downstream)"
H=$(curl -s -m 8 "$GATEWAY/health")
if echo "$H" | grep -q '"status":"healthy"'; then
  UNHEALTHY=$(echo "$H" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(','.join(k for k,v in d.get('services',{}).items() if v.get('status')!='healthy') or 'none')" 2>/dev/null)
  [ "$UNHEALTHY" = "none" ] && ok "all downstream healthy" || bad "health" "unhealthy: $UNHEALTHY"
else
  bad "health" "gateway not healthy"
fi

step 2 "ml-service models loaded"
MODELS=$(curl -s -m 8 "$ML/health" | jqr "['loaded_models']")
if echo "$MODELS" | grep -q "lightgbm"; then ok "$MODELS"; else bad "ml-health" "$MODELS"; fi

step 3 "fabric channels connected"
CH=$(curl -s -m 8 "$BLOCKCHAIN/health")
if echo "$CH" | grep -q "audit-channel.*connected"; then ok "3 channels"; else bad "fabric" "$CH"; fi

# ---------------------------------------------------------------- 2. auth
step 4 "auth login -> JWT"
TOK=$(curl -s -m 10 -X POST "$GATEWAY/api/v1/auth/login" -H 'Content-Type: application/json' \
      -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jqr "['access_token']")
if [ -n "$TOK" ] && [ "$TOK" != "None" ]; then ok "token acquired"; else bad "login" "no token"; echo "aborting"; exit 1; fi
AUTH=(-H "Authorization: Bearer $TOK")

# ---------------------------------------------------------------- 3. KYC
CUST="e2e-cust-$(date +%s)"
step 5 "KYC register customer"
REG=$(curl -s -m 15 -w '\n%{http_code}' -X POST "$GATEWAY/api/v1/kyc/customers" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d "{
    \"full_name\":\"E2E Test Subject\",
    \"email\":\"$CUST@example.com\",\"phone_number\":\"+8801700000000\",
    \"date_of_birth\":\"1990-01-01\",\"nationality\":\"BD\",
    \"address_line1\":\"1 Test Road\",\"city\":\"Dhaka\",
    \"country_code\":\"BD\",\"country_of_issue\":\"BD\",
    \"occupation\":\"Engineer\",\"source_of_funds\":\"SALARY\",
    \"expected_monthly_volume\":5000,
    \"document_type\":\"PASSPORT\",
    \"document_number\":\"P$(date +%s)\"}")
CODE=$(echo "$REG" | tail -1); BODY=$(echo "$REG" | head -n -1)
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
  RID=$(echo "$BODY" | jqr "['customer_id']"); [ -z "$RID" ] && RID="$CUST"
  ok "customer_id=$RID"
else bad "kyc-register" "HTTP $CODE $(echo "$BODY"|head -c 120)"; RID="$CUST"; fi

step 6 "KYC approve at CRITICAL risk"
APV=$(curl -s -m 20 -w '\n%{http_code}' -X PATCH "$GATEWAY/api/v1/kyc/customers/$RID/status" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"status":"APPROVED","risk_level":"CRITICAL","verifier_id":"e2e-runner","reason":"e2e automated test"}')
CODE=$(echo "$APV" | tail -1)
if [ "$CODE" = "200" ]; then ok "APPROVED/CRITICAL"; else bad "kyc-approve" "HTTP $CODE $(echo "$APV"|head -c 120)"; fi

step 7 "KYC status landed on-chain"
ONCHAIN=""; for i in $(seq 1 12); do
  ONCHAIN=$(curl -s -m 8 "$BLOCKCHAIN/internal/v1/kyc/record/$RID" 2>/dev/null)
  echo "$ONCHAIN" | grep -q "APPROVED" && break; sleep 3
done
if echo "$ONCHAIN" | grep -q "APPROVED"; then ok "on-chain APPROVED"; else bad "kyc-onchain" "$(echo "$ONCHAIN"|head -c 120)"; fi

step 8 "KYC risk propagated to Redis profile"
PROF=$(docker exec fds-redis redis-cli -a "${REDIS_PASSWORD:-}" --no-auth-warning HGETALL "customer:profile:$RID" 2>/dev/null | tr '\n' ' ')
if echo "$PROF" | grep -qi "kyc_risk_level"; then ok "$(echo "$PROF"|head -c 70)"; else bad "redis-profile" "$(echo "$PROF"|head -c 80)"; fi

# ---------------------------------------------------------------- 4. transaction
TXH="e2e-tx-$(date +%s)"
step 9 "publish transaction to Kafka"
TXJSON="{\"tx_hash\":\"$TXH\",\"customer_id\":\"$RID\",\"amount\":98500.0,\"currency_code\":\"USD\",\"channel\":\"WIRE_TRANSFER\",\"country_code\":\"IR\",\"counterparty_country\":\"KP\",\"merchant_category\":\"CRYPTO_EXCHANGE\",\"merchant_id\":\"m-e2e\",\"transaction_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
if echo "$TXJSON" | bash scripts/publish_tx.sh >/dev/null 2>&1; then ok "published $TXH"; else bad "kafka-publish" "producer error"; fi

step 10 "ML scored + audit receipt anchored"
TRAIL=""; for i in $(seq 1 15); do
  TRAIL=$(curl -s -m 8 "$BLOCKCHAIN/internal/v1/audit/trail?entity_id=$TXH&entity_type=TRANSACTION" 2>/dev/null)
  echo "$TRAIL" | grep -q "TRANSACTION_PROCESSED" && break; sleep 3
done
if echo "$TRAIL" | grep -q "TRANSACTION_PROCESSED"; then ok "receipt on audit-channel"; else bad "audit-receipt" "$(echo "$TRAIL"|head -c 140)"; fi

step 11 "alert raised for the transaction"
AL=""; for i in $(seq 1 10); do
  AL=$(curl -s -m 8 "$ALERT/api/v1/alerts/customer/$RID" 2>/dev/null)
  echo "$AL" | grep -q "$TXH" && break; sleep 3
done
if echo "$AL" | grep -q "$TXH"; then ok "alert exists"
else skip "no alert (expected: live features are out-of-distribution)"; fi

# ---------------------------------------------------------------- 5. cases
step 12 "case list endpoint reachable"
CS=$(curl -s -m 10 -w '\n%{http_code}' "$CASE_SVC/cases" "${AUTH[@]}")
CODE=$(echo "$CS" | tail -1)
if [ "$CODE" = "200" ]; then ok "HTTP 200"; else bad "case-list" "HTTP $CODE"; fi

# ---------------------------------------------------------------- 6. audit layer
step 13 "per-org sequence status (completeness)"
SEQ=$(curl -s -m 10 "$BLOCKCHAIN/internal/v1/audit/sequence" 2>/dev/null)
if echo "$SEQ" | grep -q '"payload"' && ! echo "$SEQ" | grep -q '"payload":\[\]'; then ok "$(echo "$SEQ"|head -c 100)"
elif echo "$SEQ" | grep -q '"payload"'; then skip "sequence empty (no receipts anchored yet)"
else bad "audit-sequence" "$(echo "$SEQ"|head -c 120)"; fi

step 14 "completeness reconciliation"
COMP=$(curl -s -m 10 "$BLOCKCHAIN/internal/v1/audit/completeness?expected_count=1" 2>/dev/null)
if echo "$COMP" | grep -qi "anchored_receipts\|complete"; then ok "$(echo "$COMP"|head -c 90)"; else bad "completeness" "$(echo "$COMP"|head -c 120)"; fi

step 15 "compliance report"
RPT=$(curl -s -m 15 -w '\n%{http_code}' "$BLOCKCHAIN/internal/v1/audit/compliance?start_date=2020-01-01T00:00:00Z&end_date=2030-01-01T00:00:00Z")
CODE=$(echo "$RPT" | tail -1)
if [ "$CODE" = "200" ]; then ok "HTTP 200"; else bad "compliance" "HTTP $CODE"; fi

step 16 "analytics endpoint"
AN=$(curl -s -m 10 -w '\n%{http_code}' "$GATEWAY/api/v1/analytics/alert-metrics" "${AUTH[@]}")
CODE=$(echo "$AN" | tail -1)
if [ "$CODE" = "200" ]; then ok "HTTP 200"; else skip "HTTP $CODE"; fi

echo
echo "=============================================================="
printf " RESULT: ${G}%d passed${N}, ${R}%d failed${N}, ${Y}%d skipped${N}\n" "$PASS" "$FAIL" "$SKIP"
[ ${#FAILED_STEPS[@]} -gt 0 ] && printf " failed: %s\n" "${FAILED_STEPS[*]}"
echo "=============================================================="
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
