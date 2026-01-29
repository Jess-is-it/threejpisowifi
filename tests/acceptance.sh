#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=".env.acceptance"
cat > "$ENV_FILE" <<'EOF'
CW_ENV=production
CW_PUBLIC_BASE_URL=http://127.0.0.1
CW_DOMAIN=:80

POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=centralwifi
POSTGRES_USER=centralwifi
POSTGRES_PASSWORD=centralwifi
DATABASE_URL=postgresql+psycopg2://centralwifi:centralwifi@postgres:5432/centralwifi

REDIS_URL=redis://redis:6379/0

API_PORT=8000
JWT_ISSUER=centralwifi
JWT_SECRET=test-jwt-secret
JWT_EXPIRES_SECONDS=86400

ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin

RADIUS_SHARED_SECRET=testing123
ACTIVE_SESSION_GRACE_SECONDS=180

VENDO_SECONDS_PER_COIN=300
VENDO_EVENT_TOLERANCE_SECONDS=600
DEVICE_TOKEN_ENC_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

SMS_PROVIDER=mock
PAYMENT_PROVIDER=mock
EOF

export CW_ENV_FILE="$ENV_FILE"
DC="docker compose --env-file $ENV_FILE"

chmod +x deploy/install.sh || true

echo "[test] Starting stack..."
$DC up -d --build

echo "[test] Waiting for healthy services..."
timeout 300 bash -lc "until $DC ps | awk 'NR>2 {print}' | grep -q 'api'; do sleep 1; done"

BASE="http://127.0.0.1"

echo "[test] Admin login..."
TOKEN="$(curl -fsS -X POST "$BASE/api/v1/admin/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')"

RUN_ID="$(date +%s)-$RANDOM"
# Use a unique E.164 phone per run so tests are idempotent across reruns (no stale sessions/webhooks).
PHONE="+1555$(printf '%07d' "$((RANDOM % 10000000))")"
PW="pw12345678"

echo "[test] Create user..."
RESP="$(curl -sS -X POST "$BASE/api/v1/admin/users" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"phone\":\"$PHONE\",\"password\":\"$PW\"}" -w '\n%{http_code}')"
BODY="$(echo "$RESP" | head -n 1)"
CODE="$(echo "$RESP" | tail -n 1)"
if [[ "$CODE" == "200" ]]; then
  USER_ID="$(python3 -c 'import sys,json; print(json.loads(sys.argv[1])["id"])' "$BODY")"
elif [[ "$CODE" == "409" ]]; then
  USERS_JSON="$(curl -fsS "$BASE/api/v1/admin/users" -H "Authorization: Bearer $TOKEN")"
  USER_ID="$(python3 - <<'PY' "$USERS_JSON" "$PHONE"
import sys,json
rows=json.loads(sys.argv[1])
phone=sys.argv[2]
for r in rows:
  if r.get("phone")==phone:
    print(r["id"])
    raise SystemExit(0)
raise SystemExit(2)
PY
)"
else
  echo "Create user failed (HTTP $CODE): $BODY" >&2
  exit 1
fi

echo "[test] Ensure known WiFi password..."
RESET="$(curl -fsS -X POST "$BASE/api/v1/admin/users/$USER_ID/reset-password" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}' )"
PW="$(python3 -c 'import sys,json; print(json.load(sys.stdin)["new_password"])' <<<"$RESET")"

echo "[test] Credit wallet..."
curl -fsS -X POST "$BASE/api/v1/admin/wallet/credit" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"user_id\":$USER_ID,\"source\":\"ADMIN\",\"amount_seconds\":120}" >/dev/null

echo "[test] RADIUS auth ACCEPT..."
$DC exec -T radius bash -lc "printf 'User-Name = $PHONE\nUser-Password = $PW\nCalling-Station-Id = AA-BB-CC-DD-EE-FF\n' | (radclient -x 127.0.0.1:1812 auth \"\$RADIUS_SHARED_SECRET\" || true) | grep -q 'Access-Accept'"

echo "[test] RADIUS auth REJECT on 2nd device..."
$DC exec -T radius bash -lc "printf 'User-Name = $PHONE\nUser-Password = $PW\nCalling-Station-Id = 11-22-33-44-55-66\n' | (radclient -x 127.0.0.1:1812 auth \"\$RADIUS_SHARED_SECRET\" || true) | grep -q 'Access-Reject'"

echo "[test] Interim-Update decrements wallet..."
WALLET_BEFORE_DEBIT="$(curl -fsS "$BASE/api/v1/admin/users/$USER_ID/wallet" -H "Authorization: Bearer $TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["time_remaining_seconds"])')"
sleep 2
$DC exec -T radius bash -lc "printf 'User-Name = $PHONE\nAcct-Status-Type = Interim-Update\nCalling-Station-Id = AA-BB-CC-DD-EE-FF\nAcct-Session-Id = test-$RUN_ID\n' | (radclient -x 127.0.0.1:1813 acct \"\$RADIUS_SHARED_SECRET\" || true) >/dev/null"

WALLET_AFTER="$(curl -fsS "$BASE/api/v1/admin/users/$USER_ID/wallet" -H "Authorization: Bearer $TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["time_remaining_seconds"])')"
if [[ "${WALLET_AFTER}" -ge "${WALLET_BEFORE_DEBIT}" ]]; then
  echo "Expected wallet to decrement after Interim-Update; before=${WALLET_BEFORE_DEBIT} after=${WALLET_AFTER}" >&2
  exit 1
fi

echo "[test] Mock payment credits once..."
PAY1_KEY="pay1-$RUN_ID"
PAY2_KEY="pay2-$RUN_ID"
curl -fsS -X POST "$BASE/api/v1/payments/webhook/mock" \
  -H 'Content-Type: application/json' -H "Idempotency-Key: $PAY1_KEY" \
  -d "{\"phone\":\"$PHONE\",\"amount_seconds\":60,\"amount_money\":10,\"ref\":\"$PAY1_KEY\",\"status\":\"paid\"}" >/dev/null
curl -fsS -X POST "$BASE/api/v1/payments/webhook/mock" \
  -H 'Content-Type: application/json' -H "Idempotency-Key: $PAY1_KEY" \
  -d "{\"phone\":\"$PHONE\",\"amount_seconds\":60,\"amount_money\":10,\"ref\":\"$PAY1_KEY\",\"status\":\"paid\"}" >/dev/null

W1="$(curl -fsS "$BASE/api/v1/admin/users/$USER_ID/wallet" -H "Authorization: Bearer $TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["time_remaining_seconds"])')"
curl -fsS -X POST "$BASE/api/v1/payments/webhook/mock" \
  -H 'Content-Type: application/json' -H "Idempotency-Key: $PAY2_KEY" \
  -d "{\"phone\":\"$PHONE\",\"amount_seconds\":60,\"amount_money\":10,\"ref\":\"$PAY2_KEY\",\"status\":\"paid\"}" >/dev/null
W2="$(curl -fsS "$BASE/api/v1/admin/users/$USER_ID/wallet" -H "Authorization: Bearer $TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["time_remaining_seconds"])')"
if [[ "$((W2 - W1))" -ne 60 ]]; then
  echo "Expected exactly +60s from pay-2; got delta=$((W2 - W1))" >&2
  exit 1
fi

echo "[test] Mock SMS logs..."
curl -fsS -X POST "$BASE/api/v1/sms/test" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"to_phone\":\"$PHONE\",\"message\":\"hello\"}" >/dev/null
SMS_LOGS_JSON="$(curl -fsS "$BASE/api/v1/sms/logs" -H "Authorization: Bearer $TOKEN")"
python3 - <<'PY' "$SMS_LOGS_JSON" "$PHONE"
import sys, json
rows = json.loads(sys.argv[1])
phone = sys.argv[2]
assert isinstance(rows, list)
assert any(r.get("to_phone") == phone and r.get("message") == "hello" for r in rows)
PY

echo "[test] Vendo credit event updates wallet..."
VENDO_DEVICE_ID="vendo-$RUN_ID"
DEV_CREATE="$(curl -fsS -X POST "$BASE/api/v1/admin/devices" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"device_id\":\"$VENDO_DEVICE_ID\",\"wallet_user_id\":$USER_ID}")"
DEV_TOKEN="$(python3 -c 'import sys,json; print(json.loads(sys.argv[1])["device_token"])' "$DEV_CREATE")"
TS="$(python3 -c 'import time; print(int(time.time()))')"
NONCE="n-$(python3 -c 'import os; print(os.urandom(6).hex())')"
SIG="$(python3 - <<PY
import hmac,hashlib
device_id='$VENDO_DEVICE_ID'
coin_amount=2
timestamp=int('$TS')
nonce='$NONCE'
token='$DEV_TOKEN'.encode()
msg=f"{device_id}:{coin_amount}:{timestamp}:{nonce}".encode()
print(hmac.new(token,msg,hashlib.sha256).hexdigest())
PY
)"
W_BEFORE="$(curl -fsS "$BASE/api/v1/admin/users/$USER_ID/wallet" -H "Authorization: Bearer $TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["time_remaining_seconds"])')"
curl -fsS -X POST "$BASE/api/v1/vendo/credit" -H 'Content-Type: application/json' \
  -d "{\"device_id\":\"$VENDO_DEVICE_ID\",\"coin_amount\":2,\"timestamp\":$TS,\"nonce\":\"$NONCE\",\"hmac_signature\":\"$SIG\",\"target_phone\":\"$PHONE\"}" >/dev/null
W_AFTER="$(curl -fsS "$BASE/api/v1/admin/users/$USER_ID/wallet" -H "Authorization: Bearer $TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["time_remaining_seconds"])')"
if [[ "$((W_AFTER - W_BEFORE))" -ne 600 ]]; then
  echo "Expected +600s from 2 coins at 300s/coin; got delta=$((W_AFTER - W_BEFORE))" >&2
  exit 1
fi

echo "[test] OK"
