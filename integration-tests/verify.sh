#!/usr/bin/env bash
# Quick post-run sanity checks for the ml-classifier pipeline.
set -euo pipefail

ES="${ES:-http://127.0.0.1:19200}"

echo "=== indices ==="
curl -s "$ES/_cat/indices?v&s=index" | grep -E "logstash-|ml-analysis-" || echo "(no matching indices yet)"

echo
echo "=== ml-analysis sample (last 5) ==="
curl -s "$ES/ml-analysis-*/_search?pretty&size=5&sort=@timestamp:desc"

echo
echo "=== label distribution ==="
curl -s "$ES/ml-analysis-*/_search?size=0&pretty" \
  -H 'Content-Type: application/json' \
  -d '{"aggs":{"by_label":{"terms":{"field":"ml_label.keyword","size":10}}}}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); [print(f\"{b['key']:>15}  {b['doc_count']}\") for b in d.get('aggregations',{}).get('by_label',{}).get('buckets',[])]"
