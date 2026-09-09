#!/usr/bin/env bash
# Validate kibana_export_ko.ndjson by importing it into the local Kibana instance.
#
# Prerequisites:
#   docker compose -f integration-tests/docker-compose.yml up  (kibana must be healthy)
#
# Usage:
#   bash integration-tests/verify_kibana_import.sh [--kibana http://127.0.0.1:15601]
set -euo pipefail

KIBANA="${KIBANA:-http://127.0.0.1:15601}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NDJSON="$SCRIPT_DIR/../tpot-fork/docker/tpotinit/dist/etc/objects/kibana_export_ko.ndjson"

if [[ ! -f "$NDJSON" ]]; then
  echo "ERROR: ndjson not found: $NDJSON" >&2
  exit 1
fi

echo "=== Waiting for Kibana to be available at $KIBANA ==="
for i in $(seq 1 60); do
  if curl -fsS "$KIBANA/api/status" 2>/dev/null | grep -q '"level":"available"'; then
    echo "Kibana ready (attempt $i)"
    break
  fi
  if [[ $i -eq 60 ]]; then
    echo "ERROR: Kibana not ready after 60 attempts" >&2
    exit 1
  fi
  echo "  waiting... ($i/60)"
  sleep 5
done

echo
echo "=== Importing kibana_export_ko.ndjson ==="
RESPONSE=$(curl -sS -X POST \
  "$KIBANA/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -F "file=@$NDJSON" \
)

echo "Raw response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

# Parse counts
SUCCESS=$(echo "$RESPONSE" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('successCount', 0))
" 2>/dev/null || echo "0")

ERRORS=$(echo "$RESPONSE" | python3 -c "
import json, sys
d = json.load(sys.stdin)
errs = d.get('errors', [])
print(len(errs))
if errs:
    for e in errs[:5]:
        print(f\"  ERROR: {e.get('type')} / {e.get('id')} — {e.get('error', {}).get('message')}\", file=sys.stderr)
" 2>&1 | tail -n +2 || echo "?")

echo
echo "=== Result ==="
echo "  successCount : $SUCCESS"
echo "  errors       : $ERRORS"

if [[ "$ERRORS" == "0" || "$ERRORS" == "" ]]; then
  echo "PASS: all objects imported successfully"
  exit 0
else
  echo "WARN: $ERRORS error(s) during import (check output above)"
  exit 1
fi
