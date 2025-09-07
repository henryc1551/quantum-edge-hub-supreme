#!/usr/bin/env bash
set -euo pipefail
URL="${1:-https://qehs.example.com/api/health}"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$URL" || echo "000")
if [ "$HTTP" = "200" ]; then
  echo "OK $URL"
  exit 0
else
  echo "FAIL $URL ($HTTP)"
  exit 1
fi
