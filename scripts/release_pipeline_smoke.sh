#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DB_NAME="${DB_NAME:-fc}"
PSQL_CMD="${PSQL:-psql -v ON_ERROR_STOP=1}"
SMOKE_HOST="${SMOKE_HOST:-127.0.0.1}"
SMOKE_PORT="${SMOKE_PORT:-19131}"
ARTIFACT_BASE_URL="${RELEASE_ARTIFACT_BASE_URL:-https://downloads.example.test/authorforge}"

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

upload_root="$tmp_dir/upload"
mkdir -p "$upload_root/authorforge/smoke"

bootstrap_file="$tmp_dir/authorforge-bootstrap-linux-x86_64.appimage"
updater_file="$tmp_dir/authorforge-updater-linux-x86_64.appimage"
bootstrap_storage_key="authorforge/smoke/authorforge-bootstrap-linux-x86_64.appimage"
updater_storage_key="authorforge/smoke/authorforge-updater-linux-x86_64.appimage"

printf 'AuthorForge bootstrap smoke package\nversion=9.9.901\nbuild=20260612.release-smoke\n' > "$bootstrap_file"
printf 'AuthorForge updater smoke package\nversion=9.9.901\nbuild=20260612.release-smoke\n' > "$updater_file"

upload_immutable() {
  local source="$1"
  local storage_key="$2"
  local target="$upload_root/$storage_key"

  if [[ -e "$target" ]]; then
    echo "immutable upload target already exists: $storage_key" >&2
    return 1
  fi

  mkdir -p "$(dirname "$target")"
  cp "$source" "$target"
  cmp -s "$source" "$target"
}

upload_immutable "$bootstrap_file" "$bootstrap_storage_key"
upload_immutable "$updater_file" "$updater_storage_key"

bootstrap_sha256="$(sha256sum "$upload_root/$bootstrap_storage_key" | awk '{print $1}')"
updater_sha256="$(sha256sum "$upload_root/$updater_storage_key" | awk '{print $1}')"
bootstrap_size_bytes="$(wc -c < "$upload_root/$bootstrap_storage_key" | tr -d ' ')"
updater_size_bytes="$(wc -c < "$upload_root/$updater_storage_key" | tr -d ' ')"

$PSQL_CMD -d "$DB_NAME" \
  -v bootstrap_storage_key="$bootstrap_storage_key" \
  -v bootstrap_size_bytes="$bootstrap_size_bytes" \
  -v bootstrap_sha256="$bootstrap_sha256" \
  -v updater_storage_key="$updater_storage_key" \
  -v updater_size_bytes="$updater_size_bytes" \
  -v updater_sha256="$updater_sha256" \
  -f supabase/tests/release_pipeline_smoke.sql

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
export SUPABASE_JWT_ISSUER="${SUPABASE_JWT_ISSUER:-https://proj.supabase.co/auth/v1}"
export SUPABASE_JWT_AUDIENCE="${SUPABASE_JWT_AUDIENCE:-authenticated}"
export SUPABASE_JWT_SECRET="${SUPABASE_JWT_SECRET:-release-smoke-supabase-secret}"
export ADMIN_JWT_ISSUER="${ADMIN_JWT_ISSUER:-https://operators.local}"
export ADMIN_JWT_AUDIENCE="${ADMIN_JWT_AUDIENCE:-forgecustomer-admin}"
export ADMIN_JWT_PUBLIC_KEY="${ADMIN_JWT_PUBLIC_KEY:-}"
export ENTITLEMENT_SIGNING_PRIVATE_KEY="${ENTITLEMENT_SIGNING_PRIVATE_KEY:-AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=}"
export ENTITLEMENT_SIGNING_KEY_ID="${ENTITLEMENT_SIGNING_KEY_ID:-release-smoke-entitlement-key}"
export UPDATE_ROLLOUT_SECRET="${UPDATE_ROLLOUT_SECRET:-release-smoke-rollout-secret}"
export DATABASE_ACQUIRE_TIMEOUT_SECS="${DATABASE_ACQUIRE_TIMEOUT_SECS:-5}"
export REQUEST_TIMEOUT_SECS="${REQUEST_TIMEOUT_SECS:-10}"
export RATE_LIMIT_PER_MINUTE="${RATE_LIMIT_PER_MINUTE:-0}"

cargo run -p forgecustomer-api > "$tmp_dir/api.log" 2>&1 &
api_pid="$!"

ready=0
for _ in $(seq 1 180); do
  if ! kill -0 "$api_pid" 2>/dev/null; then
    echo "forgecustomer-api exited during release smoke startup" >&2
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
  echo "forgecustomer-api did not become healthy during release smoke startup" >&2
  cat "$tmp_dir/api.log" >&2
  exit 1
fi

latest_json="$(curl -fsS "http://$SMOKE_HOST:$SMOKE_PORT/v1/products/authorforge/releases/latest?channel=stable")"
download_json="$(curl -fsS "http://$SMOKE_HOST:$SMOKE_PORT/v1/products/authorforge/downloads?platform=linux&arch=x86_64&channel=stable&package_format=appimage")"

export LATEST_JSON="$latest_json"
export DOWNLOAD_JSON="$download_json"
export EXPECTED_VERSION="9.9.901"
export EXPECTED_BUILD_ID="20260612.release-smoke"
export EXPECTED_BOOTSTRAP_URL="${ARTIFACT_BASE_URL%/}/$bootstrap_storage_key"
export EXPECTED_BOOTSTRAP_SHA256="$bootstrap_sha256"
export EXPECTED_BOOTSTRAP_SIZE="$bootstrap_size_bytes"

python3 - <<'PY'
import json
import os

latest = json.loads(os.environ["LATEST_JSON"])
download = json.loads(os.environ["DOWNLOAD_JSON"])
release = latest["release"]

expected = {
    "version": os.environ["EXPECTED_VERSION"],
    "build_id": os.environ["EXPECTED_BUILD_ID"],
    "download_url": os.environ["EXPECTED_BOOTSTRAP_URL"],
    "sha256": os.environ["EXPECTED_BOOTSTRAP_SHA256"],
    "size_bytes": int(os.environ["EXPECTED_BOOTSTRAP_SIZE"]),
}

assert release["version"] == expected["version"], release
assert release["build_id"] == expected["build_id"], release
assert release["release_channel_key"] == "stable", release

assert download["version"] == expected["version"], download
assert download["build_id"] == expected["build_id"], download
assert download["release_channel"] == "stable", download
assert download["platform"] == "linux", download
assert download["architecture"] == "x86_64", download
assert download["package_format"] == "appimage", download
assert download["download_url"] == expected["download_url"], download
assert download["sha256"] == expected["sha256"], download
assert download["size_bytes"] == expected["size_bytes"], download
PY

echo "release pipeline smoke passed: $EXPECTED_BOOTSTRAP_URL"
