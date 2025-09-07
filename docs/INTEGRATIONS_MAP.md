# Mapowanie integracji

- GA4 MP → POST /api/ga4/collect
- TikTok Events → POST /api/tiktok/track
- Stripe Webhooks → POST /api/webhooks/ingest?provider=stripe
- Generic HMAC Webhooks → POST /api/webhooks/ingest?provider=generic (header: x-qehs-signature: base64 HMAC)
- OpenAI → POST /api/openai/chat
- ElevenLabs (TTS) → POST /api/tts/eleven
- Google Ads Reports → POST /api/google-ads/report (Bearer accessToken, customerId, GAQL)
