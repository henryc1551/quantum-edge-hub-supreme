// ===================== Quantum Edge Hub Supreme — main.ts =====================
// ALL-IN-ONE ultra setup (Deno Deploy friendly)
//
// REQUIREMENTS (Environment Variables):
//   FORCE_HTTPS=true
//   ALLOWED_ORIGINS=https://yourdomain.com,https://*.deno.dev
//   ADMIN_REQUIRE_PASSKEY=true
//   BIND_SESSION_UA=true
//   BIND_SESSION_IP=false
//   ALLOW_ADMIN_IPS= (optional, comma-separated IPs)
//
//   JWT_SECRET=change-me-very-strong  (used for optional JWT issues)
//   LOGIN_MAX_FAILS=7
//   LOGIN_LOCKOUT_MINUTES=20
//
//   // Webhooks
//   WEBHOOK_HMAC_SECRET=please-change
//   STRIPE_WEBHOOK_SECRET= (when using Stripe webhooks)
//
//   // GA4 Measurement Protocol
//   GA4_MEASUREMENT_ID=G-XXXXXXX
//   GA4_API_SECRET=xxxxxxxx
//
//   // TikTok Events API (server-to-server)
//   TIKTOK_PIXEL_ID=xxxxxxxxxxxx
//   TIKTOK_ACCESS_TOKEN=xxxxxxxxxxxxxxxx
//
//   // Google Ads (reports) - requires OAuth 2.0 bearer token and developer token
//   GOOGLE_ADS_DEVELOPER_TOKEN=xxxxxxxxxxxx
//   GOOGLE_ADS_LOGIN_CUSTOMER_ID= (optional manager CID, digits only)
//
//   // OpenAI
//   OPENAI_API_KEY=sk-...
//
//   // ElevenLabs
//   ELEVEN_API_KEY=...    (tts)
//   ELEVEN_VOICE_ID=...   (default voice)
//
// =============================================================================

/** ——— Imports ——— **/
const kv = await Deno.openKv();

/** ——— Config ——— **/
const CFG = {
  FORCE_HTTPS: (Deno.env.get("FORCE_HTTPS") ?? "true").toLowerCase() === "true",
  ADMIN_REQUIRE_PASSKEY:
    (Deno.env.get("ADMIN_REQUIRE_PASSKEY") ?? "true").toLowerCase() === "true",
  BIND_SESSION_UA:
    (Deno.env.get("BIND_SESSION_UA") ?? "true").toLowerCase() === "true",
  BIND_SESSION_IP:
    (Deno.env.get("BIND_SESSION_IP") ?? "false").toLowerCase() === "true",
  ALLOWED_ORIGINS: (Deno.env.get("ALLOWED_ORIGINS") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),

  ALLOW_ADMIN_IPS: (Deno.env.get("ALLOW_ADMIN_IPS") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),

  JWT_SECRET: Deno.env.get("JWT_SECRET") ?? "change-me",
  LOGIN_MAX_FAILS: Number(Deno.env.get("LOGIN_MAX_FAILS") ?? "7"),
  LOGIN_LOCKOUT_MINUTES: Number(Deno.env.get("LOGIN_LOCKOUT_MINUTES") ?? "20"),

  WEBHOOK_HMAC_SECRET: Deno.env.get("WEBHOOK_HMAC_SECRET") ?? "",
  STRIPE_WEBHOOK_SECRET: Deno.env.get("STRIPE_WEBHOOK_SECRET") ?? "",

  GA4_MEASUREMENT_ID: Deno.env.get("GA4_MEASUREMENT_ID") ?? "",
  GA4_API_SECRET: Deno.env.get("GA4_API_SECRET") ?? "",

  TIKTOK_PIXEL_ID: Deno.env.get("TIKTOK_PIXEL_ID") ?? "",
  TIKTOK_ACCESS_TOKEN: Deno.env.get("TIKTOK_ACCESS_TOKEN") ?? "",

  GOOGLE_ADS_DEVELOPER_TOKEN: Deno.env.get("GOOGLE_ADS_DEVELOPER_TOKEN") ?? "",
  GOOGLE_ADS_LOGIN_CUSTOMER_ID:
    Deno.env.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID") ?? "",

  OPENAI_API_KEY: Deno.env.get("OPENAI_API_KEY") ?? "",
  ELEVEN_API_KEY: Deno.env.get("ELEVEN_API_KEY") ?? "",
  ELEVEN_VOICE_ID: Deno.env.get("ELEVEN_VOICE_ID") ?? "21m00Tcm4TlvDq8ikWAM", // Rachel
};

const enc = new TextEncoder();
const dec = new TextDecoder();

/** ——— Utilities ——— **/
function addSecHeaders(h: Headers) {
  h.set("x-content-type-options", "nosniff");
  h.set("referrer-policy", "strict-origin-when-cross-origin");
  h.set("permissions-policy", "geolocation=(), microphone=(), camera=()");
  h.set("cross-origin-opener-policy", "same-origin");
  h.set("cross-origin-resource-policy", "same-origin");
  h.set(
    "content-security-policy",
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
  );
  if (CFG.FORCE_HTTPS) {
    h.set("strict-transport-security", "max-age=63072000; includeSubDomains; preload");
  }
}

function json(data: unknown, status = 200, extra?: HeadersInit) {
  const h = new Headers(extra);
  addSecHeaders(h);
  h.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers: h });
}

function text(body: string, status = 200, extra?: HeadersInit) {
  const h = new Headers(extra);
  addSecHeaders(h);
  h.set("content-type", "text/plain; charset=utf-8");
  return new Response(body, { status, headers: h });
}

function ipOf(req: Request) {
  return req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for") ||
    "0.0.0.0";
}

function originOk(req: Request) {
  const origin = req.headers.get("origin") ?? "";
  if (!origin) return true; // GET on same-origin
  if (CFG.ALLOWED_ORIGINS.length === 0) return true;
  return CFG.ALLOWED_ORIGINS.some((o) => matchOrigin(origin, o));
}
function matchOrigin(actual: string, rule: string) {
  if (rule.includes("*")) {
    // wildcard: https://*.deno.dev
    const r = new URL(actual);
    const want = rule.replace("https://", "").replace("http://", "");
    const parts = want.split("*");
    return r.host.endsWith(parts.pop() || "");
  }
  return actual === rule;
}

function corsHeaders(req: Request) {
  const h = new Headers();
  const origin = req.headers.get("origin") ?? "";
  if (originOk(req)) {
    h.set("access-control-allow-origin", origin || "*");
    h.set("vary", "Origin");
  }
  h.set("access-control-allow-credentials", "true");
  h.set(
    "access-control-allow-headers",
    "content-type,authorization,x-csrf,x-qehs-signature",
  );
  h.set("access-control-allow-methods", "GET,POST,OPTIONS");
  return h;
}

function getContentType(path: string) {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    html: "text/html; charset=utf-8",
    css: "text/css; charset=utf-8",
    js: "application/javascript; charset=utf-8",
    json: "application/json; charset=utf-8",
    svg: "image/svg+xml",
    png: "image/png",
    webmanifest: "application/manifest+json",
    txt: "text/plain; charset=utf-8",
    xml: "application/xml; charset=utf-8",
  };
  return map[ext] ?? "application/octet-stream";
}

async function sha256Hex(s: string) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** ——— Audit ——— **/
async function logAudit(req: Request, action: string, meta: Record<string, unknown> = {}, email?: string) {
  try {
    const rec = {
      id: crypto.randomUUID(),
      at: Date.now(),
      ip: ipOf(req),
      email,
      action,
      meta,
    };
    await kv.set(["audit", rec.at, rec.id], rec, { expireIn: 365 * 24 * 3600 * 1000 });
  } catch {}
}

async function listAudits(limit = 200) {
  const out: any[] = [];
  for await (const it of kv.list({ prefix: ["audit"] })) out.push(it.value);
  out.sort((a, b) => b.at - a.at);
  return out.slice(0, limit);
}

async function queryAudits({ email, action, ip }: { email?: string; action?: string; ip?: string }, limit = 500) {
  const all = await listAudits(3000);
  return all.filter((ev) =>
    (!email || ev.email === email) &&
    (!action || ev.action === action) &&
    (!ip || ev.ip === ip)
  ).slice(0, limit);
}

/** ——— Rate limit ——— **/
async function ratelimit(req: Request, key: string, limit = 20, windowSec = 60) {
  const ip = ipOf(req);
  const k = ["rl", key, ip];
  const now = Date.now();
  const rec = (await kv.get<{ c: number; t: number }>(k)).value || { c: 0, t: now };
  if (now - rec.t > windowSec * 1000) {
    rec.c = 0;
    rec.t = now;
  }
  rec.c++;
  await kv.set(k, rec, { expireIn: windowSec * 1000 });
  return rec.c <= limit;
}

/** ——— CSRF ——— **/
async function csrfToken() {
  return crypto.randomUUID().replace(/-/g, "");
}

/** ——— Session & Users ——— **/
type User = { email: string; pass: string; role: "owner" | "user"; createdAt: number; totp?: { enabled?: boolean } };
function getCookie(req: Request, name: string) {
  const c = req.headers.get("cookie") || "";
  const m = c.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : null;
}
function setCookie(h: Headers, name: string, val: string, days = 30) {
  const exp = new Date(Date.now() + days * 864e5).toUTCString();
  h.append(
    "set-cookie",
    `${name}=${encodeURIComponent(val)}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${exp}`,
  );
}

async function getUser(email: string) {
  return (await kv.get<User>(["user", email])).value || null;
}
async function saveUser(u: User) {
  await kv.set(["user", u.email], u);
}
function requireOwner(s: { user: User }) {
  return s.user.role === "owner";
}

async function sessionFromReq(req: Request) {
  const t = getCookie(req, "token");
  if (!t) return null;
  const s = (await kv.get<{ email: string; createdAt: number; authn?: string; uaHash?: string; ip?: string }>(["session", t])).value;
  if (!s) return null;
  const user = await getUser(s.email);
  if (!user) return null;
  if (CFG.BIND_SESSION_UA) {
    const ua = req.headers.get("user-agent") || "";
    const uaHash = await sha256Hex(ua);
    if (s.uaHash && s.uaHash !== uaHash) return null;
  }
  if (CFG.BIND_SESSION_IP) {
    const ip = ipOf(req);
    if (s.ip && s.ip !== ip) return null;
  }
  return { user, token: t, session: s };
}

async function authFailKey(email: string) {
  return ["auth-fails", email];
}
async function noteAuthFail(email: string) {
  const rec = (await kv.get<{ c: number; t: number }>(await authFailKey(email))).value || { c: 0, t: 0 };
  rec.c = (rec.c || 0) + 1;
  rec.t = Date.now();
  await kv.set(await authFailKey(email), rec, { expireIn: 24 * 3600 * 1000 });
}
async function resetAuthFail(email: string) {
  await kv.delete(await authFailKey(email));
}
async function isLocked(email: string) {
  const rec = (await kv.get<{ c: number; t: number }>(await authFailKey(email))).value;
  if (!rec) return false;
  if (rec.c < CFG.LOGIN_MAX_FAILS) return false;
  const until = rec.t + CFG.LOGIN_LOCKOUT_MINUTES * 60 * 1000;
  return Date.now() < until;
}

/** ——— WebAuthn (simplified, SPKI provided by client) ——— **/
type CredRec = {
  email: string;
  credIdB64u: string;
  publicKeySpkiB64: string;
  alg: number; // -7 ECDSA P-256, -257 RSA
  signCount: number;
  transports?: string[];
  aaguidHex?: string;
};
function b64uToU8(s: string) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s + pad);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function u8ToB64u(u: Uint8Array) {
  const bin = Array.from(u).map((b) => String.fromCharCode(b)).join("");
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function credKeyById(credIdB64u: string) {
  return ["webauthn", "credById", credIdB64u];
}
async function listUserCreds(email: string) {
  const ids: string[] = [];
  for await (const it of kv.list({ prefix: ["webauthn", "cred", email] })) {
    const id = (it.key as string[]).slice(-1)[0] as string;
    ids.push(id);
  }
  return ids;
}
async function putCred(rec: CredRec) {
  await kv.set(await credKeyById(rec.credIdB64u), rec);
  await kv.set(["webauthn", "cred", rec.email, rec.credIdB64u], { ok: true });
}
async function getCredById(credIdB64u: string) {
  return (await kv.get<CredRec>(await credKeyById(credIdB64u))).value || null;
}
async function setChallenge(emailOrAny: string, kind: "register" | "login", challenge: string, rpId: string) {
  await kv.set(["webauthn", "challenge", kind, emailOrAny], { challenge, rpId, at: Date.now() }, { expireIn: 10 * 60 * 1000 });
}
async function getChallenge(emailOrAny: string, kind: "register" | "login") {
  return (await kv.get<{ challenge: string; rpId: string; at: number }>(["webauthn", "challenge", kind, emailOrAny])).value;
}
async function delChallenge(emailOrAny: string, kind: "register" | "login") {
  await kv.delete(["webauthn", "challenge", kind, emailOrAny]);
}
function rpIdFromURL(u: URL) {
  return u.hostname;
}
function originFromURL(u: URL) {
  return `${u.protocol}//${u.host}`;
}
async function importPubKey(spkiDer: Uint8Array, alg: number) {
  if (alg === -7) {
    return await crypto.subtle.importKey("spki", spkiDer, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  }
  if (alg === -257) {
    return await crypto.subtle.importKey("spki", spkiDer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  }
  throw new Error("Unsupported alg");
}
async function sha256(buf: Uint8Array | string) {
  const b = typeof buf === "string" ? enc.encode(buf) : buf;
  const d = await crypto.subtle.digest("SHA-256", b);
  return new Uint8Array(d);
}
async function verifyAssertion(alg: number, spki: Uint8Array, authenticatorData: Uint8Array, clientDataJSON: Uint8Array, signature: Uint8Array) {
  const pub = await importPubKey(spki, alg);
  const clientHash = await sha256(clientDataJSON);
  const data = new Uint8Array(authenticatorData.length + clientHash.length);
  data.set(authenticatorData, 0);
  data.set(clientHash, authenticatorData.length);
  if (alg === -7) {
    return await crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, pub, signature, data);
  } else {
    return await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, pub, signature, data);
  }
}

/** ——— Webhooks verify ——— **/
function subtleEq(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a[i] ^ b[i];
  return v === 0;
}
async function hmacSHA256B64(key: string, msg: string) {
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}
async function verifyGeneric(secret: string, payload: string, signatureB64: string) {
  const macB64 = await hmacSHA256B64(secret, payload);
  return macB64 === signatureB64;
}
function parseStripeSigHeader(h: string) {
  const map: Record<string, string> = {};
  (h || "").split(",").forEach((p) => {
    const [k, v] = p.split("=");
    if (k && v) map[k] = v;
  });
  return map;
}
async function verifyStripe(sigHeader: string, payload: string, secret: string, toleranceSec = 300) {
  const map = parseStripeSigHeader(sigHeader || "");
  const t = map["t"]; const v1 = map["v1"];
  if (!t || !v1) return false;
  const now = Math.floor(Date.now() / 1000);
  const ts = Number(t);
  if (!Number.isFinite(ts) || Math.abs(now - ts) > toleranceSec) return false;
  const signed = `${t}.${payload}`;
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(signed)));
  const given = Uint8Array.from(v1.match(/.{1,2}/g)!.map((h) => parseInt(h, 16)));
  return subtleEq(sig, given);
}

/** ——— GA4 / TikTok / Google Ads / OpenAI / ElevenLabs ——— **/
async function ga4Collect(payload: any) {
  if (!CFG.GA4_MEASUREMENT_ID || !CFG.GA4_API_SECRET) {
    throw new Error("GA4 env not set");
  }
  const url = `https://www.google-analytics.com/mp/collect?measurement_id=${encodeURIComponent(CFG.GA4_MEASUREMENT_ID)}&api_secret=${encodeURIComponent(CFG.GA4_API_SECRET)}`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(`GA4 error ${r.status}`);
  return { ok: true };
}

async function tiktokTrack(body: any) {
  if (!CFG.TIKTOK_PIXEL_ID || !CFG.TIKTOK_ACCESS_TOKEN) {
    throw new Error("TikTok env not set");
  }
  const url = "https://business-api.tiktok.com/open_api/v1.3/event/track/";
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "access-token": CFG.TIKTOK_ACCESS_TOKEN,
    },
    body: JSON.stringify({
      pixel_code: CFG.TIKTOK_PIXEL_ID,
      ...body,
    }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`TikTok error ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

async function googleAdsReport(accessToken: string, customerId: string, gaql: string) {
  // Requires: GOOGLE_ADS_DEVELOPER_TOKEN (+ optionally manager login CID)
  const devToken = CFG.GOOGLE_ADS_DEVELOPER_TOKEN;
  if (!devToken) throw new Error("GOOGLE_ADS_DEVELOPER_TOKEN missing");
  const loginCustomerId = CFG.GOOGLE_ADS_LOGIN_CUSTOMER_ID;
  const url = `https://googleads.googleapis.com/v16/customers/${customerId}/googleAds:searchStream`;
  const headers: HeadersInit = {
    "content-type": "application/json",
    "developer-token": devToken,
    "authorization": `Bearer ${accessToken}`,
  };
  if (loginCustomerId) headers["login-customer-id"] = loginCustomerId;
  const r = await fetch(url, { method: "POST", headers, body: JSON.stringify({ query: gaql }) });
  const text = await r.text();
  if (!r.ok) throw new Error(`Google Ads error ${r.status}: ${text}`);
  // API returns NDJSON-like chunks; try to parse array of results:
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function openaiChat(messages: Array<{ role: string; content: string }>, model = "gpt-4o-mini") {
  if (!CFG.OPENAI_API_KEY) throw new Error("OPENAI_API_KEY missing");
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${CFG.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({ model, messages }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(`OpenAI error ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

async function elevenTTS(textInput: string, voiceId = CFG.ELEVEN_VOICE_ID) {
  if (!CFG.ELEVEN_API_KEY) throw new Error("ELEVEN_API_KEY missing");
  const url = `https://api.elevenlabs.io/v1/text-to-speech/${voiceId}`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "xi-api-key": CFG.ELEVEN_API_KEY,
      "content-type": "application/json",
      "accept": "audio/mpeg",
    },
    body: JSON.stringify({ text: textInput, model_id: "eleven_multilingual_v2" }),
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`Eleven error ${r.status}: ${t}`);
  }
  const buf = new Uint8Array(await r.arrayBuffer());
  return new Response(buf, {
    headers: {
      "content-type": "audio/mpeg",
      "content-length": String(buf.byteLength),
    },
  });
}

/** ——— Bootstrap ——— **/
async function handleBootstrap(_req: Request) {
  const u = await getUser("owner@local");
  if (u) return text("Already bootstrapped");
  await saveUser({
    email: "owner@local",
    pass: await sha256Hex("przyjazn"),
    role: "owner",
    createdAt: Date.now(),
    totp: { enabled: false },
  });
  return text("Bootstrap OK (owner@local / przyjazn)");
}

/** ——— Handler ——— **/
Deno.serve(async (req) => {
  try {
    // HTTPS enforce
    const url = new URL(req.url);
    const headers = new Headers(corsHeaders(req));
    addSecHeaders(headers);

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    if (CFG.FORCE_HTTPS && req.headers.get("x-forwarded-proto") === "http") {
      headers.set("location", url.toString().replace("http://", "https://"));
      return new Response(null, { status: 301, headers });
    }

    // Health
    if (url.pathname === "/api/health") {
      return json({ ok: true, service: "QEHS", ts: Date.now() }, 200, headers);
    }

    // CSRF token (simple)
    if (url.pathname === "/api/csrf" && req.method === "GET") {
      return json({ token: await csrfToken() }, 200, headers);
    }

    // Bootstrap owner
    if (url.pathname === "/admin/bootstrap") {
      return await handleBootstrap(req);
    }

    // Auth: login/password (with lockout + sessions)
    if (url.pathname === "/api/auth/login" && req.method === "POST") {
      if (!(await ratelimit(req, "login", 12, 60))) {
        await logAudit(req, "auth.login.ratelimit", { ip: ipOf(req) });
        return json({ ok: false, error: "rate-limited" }, 429, headers);
      }
      const b = await req.json().catch(() => ({}));
      const email = String(b?.email || "").toLowerCase().trim();
      const pw = String(b?.password || "");

      if (await isLocked(email)) {
        await logAudit(req, "auth.login.locked", { email });
        return json({ ok: false, error: "locked" }, 423, headers);
      }
      const u = await getUser(email);
      if (!u || u.pass !== await sha256Hex(pw)) {
        await noteAuthFail(email);
        await logAudit(req, "auth.login.fail", { email });
        return json({ ok: false, error: "invalid creds" }, 401, headers);
      }
      await resetAuthFail(email);
      const t = crypto.randomUUID();
      const ua = req.headers.get("user-agent") || "";
      const uaHash = await sha256Hex(ua);
      const ipAddr = ipOf(req);
      await kv.set(["session", t], {
        email,
        createdAt: Date.now(),
        authn: "password",
        uaHash,
        ip: ipAddr,
      }, { expireIn: 30 * 864e5 });
      headers.append(
        "set-cookie",
        `token=${encodeURIComponent(t)}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${new Date(Date.now() + 30 * 864e5).toUTCString()}`,
      );
      await logAudit(req, "auth.login.ok", { email, method: "password" });
      return json({ ok: true, user: { email, role: u.role } }, 200, headers);
    }

    if (url.pathname === "/api/auth/logout" && req.method === "POST") {
      const t = getCookie(req, "token");
      if (t) await kv.delete(["session", t]);
      headers.append("set-cookie", "token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax");
      return text("OK", 200, headers);
    }

    // Backup codes
    if (url.pathname === "/api/auth/backup/generate" && req.method === "POST") {
      const s = await sessionFromReq(req);
      if (!s || !requireOwner(s)) return json({ ok: false, error: "forbidden" }, 403, headers);
      const codes: string[] = [];
      for (let i = 0; i < 10; i++) {
        const raw = crypto.randomUUID().replace(/-/g, "").slice(0, 10).toUpperCase();
        codes.push(raw.slice(0, 5) + "-" + raw.slice(5));
      }
      const hashed = await Promise.all(codes.map((c) => sha256Hex(c)));
      await kv.set(["backup-codes", s.user.email], { hashed, at: Date.now() });
      await logAudit(req, "auth.backup.generate", { email: s.user.email, count: 10 });
      return json({ ok: true, codes }, 200, headers);
    }
    if (url.pathname === "/api/auth/backup/count" && req.method === "GET") {
      const s = await sessionFromReq(req);
      if (!s) return json({ ok: false, error: "unauthorized" }, 401, headers);
      const rec = (await kv.get<{ hashed: string[] }>(["backup-codes", s.user.email])).value;
      return json({ ok: true, left: rec?.hashed?.length ?? 0 }, 200, headers);
    }

    // WebAuthn: register
    if (url.pathname === "/api/webauthn/register/options" && req.method === "POST") {
      const s = await sessionFromReq(req);
      if (!s) return json({ ok: false, error: "unauthorized" }, 401, headers);
      const rpId = rpIdFromURL(url);
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      await setChallenge(s.user.email, "register", u8ToB64u(challenge), rpId);
      const userId = u8ToB64u((await sha256(s.user.email)).slice(0, 16));
      return json({
        ok: true,
        options: {
          publicKey: {
            rp: { name: "Quantum Edge Hub Supreme", id: rpId },
            user: { id: b64ToU8(userId), name: s.user.email, displayName: s.user.email },
            challenge,
            pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
            timeout: 120000,
            authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
            attestation: "none",
          },
        },
      }, 200, headers);
    }
    if (url.pathname === "/api/webauthn/register/verify" && req.method === "POST") {
      const s = await sessionFromReq(req);
      if (!s) return json({ ok: false, error: "unauthorized" }, 401, headers);
      const body = await req.json().catch(() => ({}));
      const credIdB64u = String(body?.id || "");
      const clientDataB64u = String(body?.response?.clientDataJSON || "");
      const attestationB64u = String(body?.response?.attestationObject || "");
      const alg = Number(body?.alg || -7);
      const publicKeySpkiB64 = String(body?.publicKeySpkiB64 || "");
      if (!credIdB64u || !clientDataB64u || !attestationB64u || !publicKeySpkiB64) {
        return json({ ok: false, error: "invalid payload" }, 400, headers);
      }
      const chal = await getChallenge(s.user.email, "register");
      if (!chal) return json({ ok: false, error: "no challenge" }, 400, headers);
      const client = JSON.parse(dec.decode(b64uToU8(clientDataB64u)));
      const expectedOrigin = originFromURL(url);
      if (client.type !== "webauthn.create" || client.origin !== expectedOrigin || client.challenge !== chal.challenge) {
        return json({ ok: false, error: "client mismatch" }, 400, headers);
      }
      await putCred({ email: s.user.email, credIdB64u, publicKeySpkiB64, alg: (alg === -7 || alg === -257) ? alg : -7, signCount: 0 });
      await delChallenge(s.user.email, "register");
      return json({ ok: true, added: true }, 200, headers);
    }

    // WebAuthn: login
    if (url.pathname === "/api/webauthn/login/options" && req.method === "POST") {
      const b = await req.json().catch(() => ({}));
      const email = String(b?.email || "");
      const rpId = rpIdFromURL(url);
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      await setChallenge(email || "any", "login", u8ToB64u(challenge), rpId);
      let allow: any[] = [];
      if (email) {
        const ids = await listUserCreds(email);
        allow = ids.map((id) => ({ type: "public-key", id: b64ToU8(id) }));
      }
      return json({
        ok: true,
        options: { publicKey: { rpId, challenge, allowCredentials: allow, userVerification: "preferred", timeout: 120000 }, mediation: "optional" },
      }, 200, headers);
    }
    if (url.pathname === "/api/webauthn/login/verify" && req.method === "POST") {
      const body = await req.json().catch(() => ({}));
      const credIdB64u = String(body?.id || "");
      const clientDataB64u = String(body?.response?.clientDataJSON || "");
      const authenticatorDataB64u = String(body?.response?.authenticatorData || "");
      const signatureB64u = String(body?.response?.signature || "");
      if (!credIdB64u || !clientDataB64u || !authenticatorDataB64u || !signatureB64u) {
        return json({ ok: false, error: "invalid payload" }, 400, headers);
      }
      const cred = await getCredById(credIdB64u);
      if (!cred) return json({ ok: false, error: "unknown credential" }, 404, headers);
      const chal = await getChallenge(cred.email, "login") || await getChallenge("any", "login");
      if (!chal) return json({ ok: false, error: "no challenge" }, 400, headers);
      const clientDataU8 = b64uToU8(clientDataB64u);
      const client = JSON.parse(dec.decode(clientDataU8));
      const expectedOrigin = originFromURL(url);
      if (client.type !== "webauthn.get" || client.origin !== expectedOrigin || client.challenge !== chal.challenge) {
        return json({ ok: false, error: "client mismatch" }, 400, headers);
      }
      const authData = b64uToU8(authenticatorDataB64u);
      const okSig = await verifyAssertion(cred.alg, b64uToU8(cred.publicKeySpkiB64), authData, clientDataU8, b64uToU8(signatureB64u));
      if (!okSig) return json({ ok: false, error: "bad signature" }, 401, headers);

      await delChallenge(cred.email, "login"); await delChallenge("any", "login");
      const t = crypto.randomUUID();
      const ua = req.headers.get("user-agent") || "";
      const uaHash = await sha256Hex(ua);
      const ipAddr = ipOf(req);
      await kv.set(["session", t], {
        email: cred.email,
        createdAt: Date.now(),
        authn: "passkey",
        uaHash,
        ip: ipAddr,
      }, { expireIn: 30 * 864e5 });
      headers.append(
        "set-cookie",
        `token=${encodeURIComponent(t)}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${new Date(Date.now() + 30 * 864e5).toUTCString()}`,
      );
      return json({ ok: true, email: cred.email }, 200, headers);
    }

    // Audit browse (owner only; requires passkey if enabled)
    if (url.pathname === "/api/audit/list" && req.method === "GET") {
      const s = await sessionFromReq(req);
      if (!s || !requireOwner(s)) return json({ ok: false, error: "forbidden" }, 403, headers);
      if (CFG.ADMIN_REQUIRE_PASSKEY && s.session?.authn !== "passkey") {
        return json({ ok: false, error: "passkey required" }, 403, headers);
      }
      const limit = Math.min(1000, Number(url.searchParams.get("limit") ?? "200"));
      const items = await listAudits(limit);
      return json({ ok: true, items }, 200, headers);
    }
    if (url.pathname === "/api/audit/search" && req.method === "GET") {
      const s = await sessionFromReq(req);
      if (!s || !requireOwner(s)) return json({ ok: false, error: "forbidden" }, 403, headers);
      if (CFG.ADMIN_REQUIRE_PASSKEY && s.session?.authn !== "passkey") {
        return json({ ok: false, error: "passkey required" }, 403, headers);
      }
      const email = url.searchParams.get("email") || undefined;
      const action = url.searchParams.get("action") || undefined;
      const ip = url.searchParams.get("ip") || undefined;
      const limit = Math.min(2000, Number(url.searchParams.get("limit") ?? "500"));
      const items = await queryAudits({ email, action, ip }, limit);
      return json({ ok: true, items }, 200, headers);
    }

    // Webhooks ingest (generic HMAC / Stripe)
    if (url.pathname === "/api/webhooks/ingest" && req.method === "POST") {
      const raw = await req.text();
      const provider = (url.searchParams.get("provider") || "generic").toLowerCase();
      let verified = false;
      if (provider === "stripe") {
        if (!CFG.STRIPE_WEBHOOK_SECRET) {
          return json({ ok: false, error: "stripe secret missing" }, 400, headers);
        }
        const sig = req.headers.get("stripe-signature") || "";
        verified = await verifyStripe(sig, raw, CFG.STRIPE_WEBHOOK_SECRET);
      } else {
        if (!CFG.WEBHOOK_HMAC_SECRET) {
          return json({ ok: false, error: "generic secret missing" }, 400, headers);
        }
        const sig = req.headers.get("x-qehs-signature") || "";
        verified = await verifyGeneric(CFG.WEBHOOK_HMAC_SECRET, raw, sig);
      }
      await logAudit(req, verified ? "webhook.verified" : "webhook.failed", { provider });
      if (!verified) return json({ ok: false, verified: false }, 401, headers);
      const id = crypto.randomUUID();
      await kv.set(["webhook", provider, id], { id, provider, at: Date.now(), raw }, { expireIn: 30 * 24 * 3600 * 1000 });
      return json({ ok: true, verified: true, id }, 200, headers);
    }

    // GA4 proxy
    if (url.pathname === "/api/ga4/collect" && req.method === "POST") {
      const payload = await req.json().catch(() => ({}));
      const ok = await ga4Collect(payload).catch((e) => ({ error: String(e) }));
      if ((ok as any).error) return json({ ok: false, error: (ok as any).error }, 400, headers);
      return json({ ok: true }, 200, headers);
    }

    // TikTok Events API
    if (url.pathname === "/api/tiktok/track" && req.method === "POST") {
      const body = await req.json().catch(() => ({}));
      try {
        const res = await tiktokTrack(body);
        return json({ ok: true, res }, 200, headers);
      } catch (e) {
        return json({ ok: false, error: String(e) }, 400, headers);
      }
    }

    // Google Ads (reports) — provide accessToken via Authorization Bearer on client or body
    if (url.pathname === "/api/google-ads/report" && req.method === "POST") {
      const body = await req.json().catch(() => ({}));
      const gaql = String(body?.gaql || "SELECT customer.id FROM customer LIMIT 1");
      const customerId = String(body?.customerId || "").replace(/-/g, "");
      const authHeader = req.headers.get("authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : String(body?.accessToken || "");
      if (!token || !customerId) return json({ ok: false, error: "accessToken or customerId missing" }, 400, headers);
      try {
        const res = await googleAdsReport(token, customerId, gaql);
        return json({ ok: true, res }, 200, headers);
      } catch (e) {
        return json({ ok: false, error: String(e) }, 400, headers);
      }
    }

    // OpenAI proxy
    if (url.pathname === "/api/openai/chat" && req.method === "POST") {
      const body = await req.json().catch(() => ({}));
      const messages = Array.isArray(body?.messages) ? body.messages : [{ role: "user", content: "Hello" }];
      const model = String(body?.model || "gpt-4o-mini");
      try {
        const res = await openaiChat(messages, model);
        return json({ ok: true, res }, 200, headers);
      } catch (e) {
        return json({ ok: false, error: String(e) }, 400, headers);
      }
    }

    // ElevenLabs TTS
    if (url.pathname === "/api/tts/eleven" && req.method === "POST") {
      const body = await req.json().catch(() => ({}));
      const textInput = String(body?.text || "");
      const voiceId = String(body?.voiceId || CFG.ELEVEN_VOICE_ID);
      if (!textInput) return json({ ok: false, error: "text required" }, 400, headers);
      try {
        return await elevenTTS(textInput, voiceId);
      } catch (e) {
        return json({ ok: false, error: String(e) }, 400, headers);
      }
    }

    // Admin gate for static /admin/*
    if (url.pathname === "/admin" || url.pathname.startsWith("/admin/")) {
      const s = await sessionFromReq(req);
      const ipAddr = ipOf(req);
      if (!s || !requireOwner(s)) return text("Forbidden (owner only)", 403, headers);
      if (CFG.ALLOW_ADMIN_IPS.length && !CFG.ALLOW_ADMIN_IPS.includes(ipAddr)) return text("Forbidden (ip)", 403, headers);
      if (CFG.ADMIN_REQUIRE_PASSKEY && s.session?.authn !== "passkey") return text("Passkey required for admin", 403, headers);
      const r = await servePublic(url.pathname === "/admin" ? "/admin/index.html" : url.pathname);
      return r ?? text("Not Found", 404, headers);
    }

    // Static files
    const r = await servePublic(url.pathname === "/" ? "/index.html" : url.pathname);
    if (r) return r;

    return text("Not Found", 404, headers);
  } catch (e) {
    await logAudit(req, "server.error", { error: String(e) });
    return json({ ok: false, error: "server_error", detail: String(e) }, 500);
  }
});

/** ——— Static serving ——— **/
async function servePublic(pathname: string) {
  try {
    const fp = new URL(`./public${pathname}`, import.meta.url);
    const file = await Deno.readFile(fp);
    const h = new Headers();
    addSecHeaders(h);
    h.set("content-type", getContentType(pathname));
    return new Response(file, { headers: h });
  } catch {
    return null;
  }
}

/** helpers **/
function b64ToU8(s: string) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s + pad);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
