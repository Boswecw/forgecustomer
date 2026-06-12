#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DB_NAME="${DB_NAME:-fc}"
PSQL_CMD="${PSQL:-psql -v ON_ERROR_STOP=1}"
SMOKE_HOST="${SMOKE_HOST:-127.0.0.1}"
SMOKE_PORT="${SMOKE_PORT:-19133}"
ARTIFACT_BASE_URL="${RELEASE_ARTIFACT_BASE_URL:-https://downloads.example.test/authorforge}"
JWT_SECRET="${SUPABASE_JWT_SECRET:-update-http-smoke-supabase-secret}"
JWT_ISSUER="${SUPABASE_JWT_ISSUER:-https://proj.supabase.co/auth/v1}"
JWT_AUDIENCE="${SUPABASE_JWT_AUDIENCE:-authenticated}"
ROLLOUT_SECRET="${UPDATE_ROLLOUT_SECRET:-update-http-smoke-rollout-secret}"

AUTH_USER_ID="00000000-0000-4000-8000-000000000911"
INSTALLATION_ID="00000000-0000-4000-8000-000000000903"
RELEASE_ID="00000000-0000-4000-8000-000000000904"
CAMPAIGN_ID="00000000-0000-4000-8000-000000000906"
ARTIFACT_STORAGE_KEY="authorforge/http-smoke/authorforge-updater-linux-x86_64.appimage"
EXPECTED_URL="${ARTIFACT_BASE_URL%/}/$ARTIFACT_STORAGE_KEY"

tmp_dir="$(mktemp -d)"
api_pid=""

cleanup() {
  if [[ -n "$api_pid" ]] && kill -0 "$api_pid" 2>/dev/null; then
    kill "$api_pid" 2>/dev/null || true
    wait "$api_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

$PSQL_CMD -d "$DB_NAME" -f supabase/tests/update_campaign_http_smoke.sql

if [[ -z "${DATABASE_URL:-}" ]]; then
  if [[ -n "${PGHOST:-}" ]]; then
    export DATABASE_URL="postgres:///${DB_NAME}?host=${PGHOST}&port=${PGPORT:-5432}"
  else
    export DATABASE_URL="postgres://localhost/${DB_NAME}"
  fi
fi

export HOST="$SMOKE_HOST"
export PORT="$SMOKE_PORT"
export RELEASE_ARTIFACT_BASE_URL="$ARTIFACT_BASE_URL"
export SUPABASE_JWT_ISSUER="$JWT_ISSUER"
export SUPABASE_JWT_AUDIENCE="$JWT_AUDIENCE"
export SUPABASE_JWT_SECRET="$JWT_SECRET"
export ADMIN_JWT_ISSUER="${ADMIN_JWT_ISSUER:-https://operators.local}"
export ADMIN_JWT_AUDIENCE="${ADMIN_JWT_AUDIENCE:-forgecustomer-admin}"
export ADMIN_JWT_PUBLIC_KEY="${ADMIN_JWT_PUBLIC_KEY:-}"
export ENTITLEMENT_SIGNING_PRIVATE_KEY="${ENTITLEMENT_SIGNING_PRIVATE_KEY:-AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=}"
export ENTITLEMENT_SIGNING_KEY_ID="${ENTITLEMENT_SIGNING_KEY_ID:-update-http-smoke-entitlement-key}"
export UPDATE_ROLLOUT_SECRET="$ROLLOUT_SECRET"
export DATABASE_ACQUIRE_TIMEOUT_SECS="${DATABASE_ACQUIRE_TIMEOUT_SECS:-5}"
export REQUEST_TIMEOUT_SECS="${REQUEST_TIMEOUT_SECS:-10}"
export RATE_LIMIT_PER_MINUTE="${RATE_LIMIT_PER_MINUTE:-0}"

token="$(
  AUTH_USER_ID="$AUTH_USER_ID" JWT_SECRET="$JWT_SECRET" JWT_ISSUER="$JWT_ISSUER" JWT_AUDIENCE="$JWT_AUDIENCE" python3 - <<'PY'
import base64
import hashlib
import hmac
import json
import os
import time

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

header = {"alg": "HS256", "typ": "JWT"}
claims = {
    "sub": os.environ["AUTH_USER_ID"],
    "iss": os.environ["JWT_ISSUER"],
    "aud": os.environ["JWT_AUDIENCE"],
    "exp": int(time.time()) + 3600,
}
head = b64url(json.dumps(header, separators=(",", ":")).encode())
body = b64url(json.dumps(claims, separators=(",", ":")).encode())
signature = hmac.new(os.environ["JWT_SECRET"].encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
print(f"{head}.{body}.{b64url(signature)}")
PY
)"

read -r rollout_bucket block_rollout allow_rollout < <(
  ROLLOUT_SECRET="$ROLLOUT_SECRET" CAMPAIGN_ID="$CAMPAIGN_ID" INSTALLATION_ID="$INSTALLATION_ID" python3 - <<'PY'
import hashlib
import hmac
import os

message = f"{os.environ['CAMPAIGN_ID']}:{os.environ['INSTALLATION_ID']}".encode()
digest = hmac.new(os.environ["ROLLOUT_SECRET"].encode(), message, hashlib.sha256).digest()
bucket = int.from_bytes(digest[:8], "big") % 10000
block = bucket // 100
allow = min(100, block + 1)
print(bucket, block, allow)
PY
)

cargo run -p forgecustomer-api > "$tmp_dir/api.log" 2>&1 &
api_pid="$!"

ready=0
for _ in $(seq 1 180); do
  if ! kill -0 "$api_pid" 2>/dev/null; then
    echo "forgecustomer-api exited during update smoke startup" >&2
    cat "$tmp_dir/api.log" >&2
    exit 1
  fi
  if curl -fsS "http://$SMOKE_HOST:$SMOKE_PORT/v1/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "forgecustomer-api did not become healthy during update smoke startup" >&2
  cat "$tmp_dir/api.log" >&2
  exit 1
fi

set_release_gate() {
  local minimum_supported_version="$1"
  local minimum_updater_version="$2"
  $PSQL_CMD -d "$DB_NAME" -c "
    update public.product_releases
    set minimum_supported_version = '$minimum_supported_version',
        minimum_updater_version = '$minimum_updater_version'
    where id = '$RELEASE_ID';
  " >/dev/null
}

set_rollout() {
  local rollout="$1"
  $PSQL_CMD -d "$DB_NAME" -c "
    update public.update_campaigns
    set rollout_percentage = $rollout
    where id = '$CAMPAIGN_ID';
  " >/dev/null
}

request_update() {
  local current_version="$1"
  local build_id="$2"
  local updater_version="$3"
  local body_file="$4"

  curl -sS \
    -o "$body_file" \
    -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    -H "X-Forge-Installation-ID: $INSTALLATION_ID" \
    -H "X-Forge-Build-ID: $build_id" \
    -H "X-Forge-Updater-Version: $updater_version" \
    -H "X-Forge-Package-Format: appimage" \
    "http://$SMOKE_HOST:$SMOKE_PORT/v1/updates/authorforge/linux/x86_64/$current_version"
}

expect_status() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  local body_file="$4"
  if [[ "$actual" != "$expected" ]]; then
    echo "$label expected HTTP $expected, got $actual" >&2
    cat "$body_file" >&2
    exit 1
  fi
}

body="$tmp_dir/update.json"

status="$(request_update "1.0.0" "20260612.previous" "1.0.0" "$body")"
expect_status "baseline update offer" "200" "$status" "$body"
EXPECTED_URL="$EXPECTED_URL" python3 - "$body" <<'PY'
import json
import os
import sys

body = json.load(open(sys.argv[1]))
assert body["version"] == "1.2.0", body
assert body["url"] == os.environ["EXPECTED_URL"], body
assert body["signature"] == "ci-tauri-http-smoke-signature", body
assert body["notes"] == "HTTP update smoke release notes", body
assert body["pub_date"], body
PY

status="$(request_update "1.2.0" "20260612.previous" "1.0.0" "$body")"
expect_status "same-version request" "204" "$status" "$body"

status="$(request_update "1.0.0" "20260612.http-smoke" "1.0.0" "$body")"
expect_status "same-build request" "204" "$status" "$body"

set_release_gate "1.1.0" "1.0.0"
status="$(request_update "1.0.0" "20260612.previous" "1.0.0" "$body")"
expect_status "minimum-supported-version gate" "204" "$status" "$body"
status="$(request_update "1.1.0" "20260612.previous" "1.0.0" "$body")"
expect_status "minimum-supported-version satisfied" "200" "$status" "$body"

set_release_gate "1.0.0" "2.0.0"
status="$(request_update "1.0.0" "20260612.previous" "1.0.0" "$body")"
expect_status "minimum-updater-version gate" "204" "$status" "$body"
status="$(request_update "1.0.0" "20260612.previous" "2.0.0" "$body")"
expect_status "minimum-updater-version satisfied" "200" "$status" "$body"

set_release_gate "1.0.0" "1.0.0"
set_rollout "$block_rollout"
status="$(request_update "1.0.0" "20260612.previous" "1.0.0" "$body")"
expect_status "deterministic rollout bucket blocked" "204" "$status" "$body"

set_rollout "$allow_rollout"
status="$(request_update "1.0.0" "20260612.previous" "1.0.0" "$body")"
expect_status "deterministic rollout bucket allowed" "200" "$status" "$body"

echo "update campaign HTTP smoke passed: bucket=$rollout_bucket blocked_at=$block_rollout allowed_at=$allow_rollout"
