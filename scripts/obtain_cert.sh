#!/usr/bin/env bash
set -euo pipefail

# Wczytaj domenę i email z .env.vps
if [ -f ".env.vps" ]; then
  export $(grep -E '^(DOMAIN|EMAIL)=' .env.vps | xargs)
fi

if [ -z "${DOMAIN:-}" ] || [ -z "${EMAIL:-}" ]; then
  echo "Ustaw DOMAIN i EMAIL w .env.vps"
  exit 1
fi

# Start nginx w trybie tylko HTTP (80), żeby serwować ACME webroot
docker compose -f docker-compose.prod.yml up -d nginx

# Utwórz katalogi
mkdir -p certbot/www certbot/conf

# Uzyskaj certyfikat (webroot)
docker run --rm \
  -v "$(pwd)/certbot/www:/var/www/certbot" \
  -v "$(pwd)/certbot/conf:/etc/letsencrypt" \
  certbot/certbot:v2.11.0 certonly --webroot -w /var/www/certbot \
  -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive

# Przeładuj nginx z certami
docker compose -f docker-compose.prod.yml exec nginx nginx -s reload || true

echo "Certyfikaty pozyskane dla $DOMAIN"
