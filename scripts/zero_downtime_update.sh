#!/usr/bin/env bash
set -euo pipefail
git pull --rebase
docker compose -f docker-compose.prod.yml build qehs
docker compose -f docker-compose.prod.yml up -d qehs
docker compose -f docker-compose.prod.yml exec -T nginx nginx -s reload || true
echo "Aplikacja zaktualizowana bez przestoju."
