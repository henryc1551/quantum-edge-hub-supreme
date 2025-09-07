# Frontend – szybki start

- Statyki w `/public`
- Dodawanie dashboardów:
  - Wrzucaj SPA do `/public/dashboards/<nazwa>/index.html`
  - Backendowe API → własne endpointy w `main.ts` (prefiks `/api/<twoje>`)
- CORS: `ALLOWED_ORIGINS` w ENV (Deno / VPS)
- CSP: aktualizuj w `main.ts` i `nginx/snippets/security_headers.conf` jeśli korzystasz z zewn. zasobów
