#!/usr/bin/env bash
set -euo pipefail

PARTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$PARTS_DIR/../.." && pwd)"
ASSEMBLED_OUTPUT="${1:-$ROOT_DIR/doc/FOCSYSTEM.md}"

require_contains() {
  local file="$1"
  local needle="$2"
  local label="$3"
  if ! grep -Fq -- "$needle" "$file"; then
    echo "snapshot validation failed: $label missing in $file" >&2
    echo "expected: $needle" >&2
    exit 1
  fi
}

require_absent() {
  local file="$1"
  local needle="$2"
  local label="$3"
  if grep -Fq -- "$needle" "$file"; then
    echo "snapshot validation failed: $label still present in $file" >&2
    echo "unexpected: $needle" >&2
    exit 1
  fi
}

test -f "$ASSEMBLED_OUTPUT"

require_contains "$PARTS_DIR/_index.md" 'Primary output: `doc/FOCSYSTEM.md`' "index primary output"
require_contains "$ASSEMBLED_OUTPUT" "Document version" "assembled document version header"
require_contains "$ASSEMBLED_OUTPUT" 'Primary output: `doc/FOCSYSTEM.md`' "assembled primary output"
require_contains "$ASSEMBLED_OUTPUT" "ForgeCustomer PostgreSQL is the customer and commercial source of truth." "authority doctrine"
require_contains "$ASSEMBLED_OUTPUT" "DataForge is a sink, not a source of truth." "dataforge doctrine"
require_contains "$ASSEMBLED_OUTPUT" "NOT_IMPLEMENTED" "current MVP gap transparency"
require_absent "$ASSEMBLED_OUTPUT" 'Primary output: `doc/SYSTEM.md`' "legacy system output"

echo "snapshot validation passed: $ASSEMBLED_OUTPUT"
