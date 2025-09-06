#!/usr/bin/env bash
set -euo pipefail
BASE="${1:-https://YOUR-PROJECT.deno.dev}"

echo "## Health"
curl -s "$BASE/api/health" | jq .

echo "## Login (owner@local / przyjazn)"
curl -s -X POST "$BASE/api/auth/login" -H 'content-type: application/json' \
  -d '{"email":"owner@local","password":"przyjazn"}' | jq .

echo "## GA4"
curl -s -X POST "$BASE/api/ga4/collect" -H 'content-type: application/json' \
  -d '{"client_id":"555.666","events":[{"name":"page_view","params":{"page_location":"'$BASE'","page_title":"QEHS"}}]}' | jq .

echo "## TikTok (wymaga env i tokenów)"
curl -s -X POST "$BASE/api/tiktok/track" -H 'content-type: application/json' \
  -d '{"event":"CompletePayment","event_id":"123","timestamp":1690000000,"context":{"page":{"url":"'$BASE'"},"user":{"external_id":"user_1"}},"properties":{"value":9.99,"currency":"USD"}}' | jq .
