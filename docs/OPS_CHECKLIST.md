# QEHS – OPS Checklist (Prod)

- [ ] DNS → domena wskazuje na Deno Deploy / VPS
- [ ] HTTPS → cert ok (Deno / Let's Encrypt)
- [ ] ENV ustawione (OpenAI, Eleven, GA4, TikTok, Stripe)
- [ ] /admin/bootstrap wykonany (owner@local)
- [ ] ADMIN_REQUIRE_PASSKEY = true (po dodaniu passkey)
- [ ] WAF/RateLimit włączone (Cloudflare/Nginx)
- [ ] Backupy repo (GitHub), backup konfiguracji `.env.vps`
- [ ] Monitoring `/api/health`
- [ ] CI (GitHub Actions) przechodzi
