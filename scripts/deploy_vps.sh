#!/usr/bin/env bash
set -euo pipefail

# 1) Zbuduj i odpal
docker compose -f docker-compose.prod.yml up -d --build

# 2) Jeżeli nie masz certu → pozyskaj
if [ ! -f "./certbot/conf/live/${DOMAIN:-_}/fullchain.pem" ]; then
  ./scripts/obtain_cert.sh
fi

# 3) Reload nginx po starcie całości
docker compose -f docker-compose.prod.yml exec -T nginx nginx -t && docker compose -f docker-compose.prod.yml exec -T nginx nginx -s reload || true

echo "Deploy zakończony."
