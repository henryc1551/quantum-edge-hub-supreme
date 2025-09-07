#!/usr/bin/env bash
set -euo pipefail
# Odpalane przez cron raz dziennie (albo użyj kontenera certbot z compose)
docker compose -f docker-compose.prod.yml run --rm certbot certbot renew --webroot -w /var/www/certbot
docker compose -f docker-compose.prod.yml exec -T nginx nginx -s reload || true
