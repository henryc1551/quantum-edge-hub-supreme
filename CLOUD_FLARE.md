# Cloudflare – rekomendowane ustawienia

## DNS
- Proxy: ON (chmura pomarańczowa) dla domeny i subdomen.

## SSL/TLS
- Mode: Full (strict) – jeśli VPS z certem Let's Encrypt; dla Deno Deploy – użyj domeny *.deno.dev lub niestandardowej z certem Deno.
- Minimum TLS: 1.2
- TLS 1.3: ON
- HSTS: ON (preload po weryfikacji)

## Security/WAF
- WAF: ON (managed rules)
- Bot Fight Mode: ON
- Rate limiting: 20 req/s na /api/* (jeśli używasz CF zamiast Nginx limit_req)
- Firewall Rules (przykład):
  - Block Country (opcjonalnie wg potrzeb)
  - Challenge ASN „agresywne hostingi” (opcjonalnie)
- Turnstile (opcjonalnie): wymuś token dla /api/public-endpoints

## Performance
- Brotli: ON
- Early Hints: ON
- Caching: Respect existing headers; Dla statyków: Edge Cache TTL 1d
