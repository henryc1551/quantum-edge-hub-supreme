# Backupy

- Kod: GitHub (zabezpiecz 2FA)
- Konfiguracja serwera: `.env.vps`, `nginx/`, `docker-compose.prod.yml`
- Certy: `certbot/conf` (Let’s Encrypt – odnawiane automatycznie)
- Deno KV (Deploy): zarządzane przez platformę (brak bezpośredniego snapshotu); logikę przenieś na własny store jeśli wymagane (np. Postgres).
