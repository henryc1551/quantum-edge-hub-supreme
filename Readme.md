# Quantum Edge Hub Supreme (QEHS)

**QEHS** to globalna, kwantowa platforma stworzona jako połączenie:
- **Backend (Deno)** – `main.ts` obsługujący API, logowanie, webhooki, GA4, TikTok, Stripe, OpenAI, ElevenLabs.
- **Frontend (public/)** – panel admin, auth, PWA (offline + instalacja mobilna).
- **DevOps** – Docker, Nginx, Let’s Encrypt, systemd, backupy, monitoring.
- **Bezpieczeństwo** – HSTS, CSP, rate-limit, passkeys, audyt.

---

## 🚀 Uruchomienie na Deno Deploy

1. **GitHub**
   - Wgraj wszystkie pliki do repo.
   - Struktura zgodna z katalogami podanymi w repo.

2. **Deno Deploy**
   - Wejdź na [https://dash.deno.com](https://dash.deno.com).
   - **New Project → Import from GitHub**.
   - Entrypoint: `main.ts`.
   - Deploy.

3. **Zmienne środowiskowe**
   - W Deno Deploy → **Settings → Environment Variables**.
   - Skopiuj z `env.example` i uzupełnij swoimi kluczami:
     - `OPENAI_API_KEY`, `ELEVEN_API_KEY`, `STRIPE_WEBHOOK_SECRET`,
     - `GA4_MEASUREMENT_ID`, `GA4_API_SECRET`,
     - `TIKTOK_PIXEL_ID`, `TIKTOK_ACCESS_TOKEN`.

4. **Pierwsze logowanie**
   - Wejdź w `/admin/bootstrap`.
   - Konto startowe: `owner@local / przyjazn`.
   - Zmień hasło, dodaj passkey.

---

## 🖥 Uruchomienie na VPS (Docker + Nginx)

1. `git clone <TwojeRepo>`
2. `cd quantum-edge-hub-supreme`
3. `cp env.example .env.vps` i uzupełnij wartości.
4. `docker compose -f docker-compose.prod.yml up -d --build`
5. `./scripts/obtain_cert.sh` → pierwszy cert SSL.
6. Strona działa na `https://twoja-domena/`.

---

## 🔐 Zabezpieczenia

- HTTPS (Deno Deploy lub Let’s Encrypt).
- Nagłówki bezpieczeństwa (HSTS, CSP, X-Frame-Options, Referrer-Policy).
- Rate-limit `/api` (Nginx / Cloudflare).
- Passkeys + blokady logowania.
- Podpisane webhooki (HMAC/Stripe).
- Pliki `.well-known` (security.txt, assetlinks.json, Apple association).

---

## 📱 PWA i Mobile

- **Service Worker** → offline + cache.
- **Manifest** → instalacja jako aplikacja.
- **Offline.html** → działa bez internetu.
- Passkeys kompatybilne z Android/iOS.

---

## 📂 Ważne katalogi

- `main.ts` → serwer (Deno).
- `public/` → frontend, admin, auth, PWA.
- `scripts/` → deploy, certy, backup, monitoring.
- `nginx/` → reverse proxy i zabezpieczenia.
- `docs/` → instrukcje i checklisty.

---

## ✅ Checklist przed produkcją

- [ ] DNS → domena wskazuje na Deno Deploy / VPS.
- [ ] ENV → klucze ustawione w Deno Deploy / `.env.vps`.
- [ ] `/admin/bootstrap` wykonany.
- [ ] Włączone passkeys.
- [ ] Rate-limit włączony.
- [ ] Certyfikaty HTTPS aktywne.
- [ ] Backup i monitoring skonfigurowany.

---

© Henryk – Quantum Edge Hub Supreme
