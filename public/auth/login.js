const $ = (s)=>document.querySelector(s);

$('#btnLogin')?.addEventListener('click', async ()=>{
  const email = $('#email').value.trim();
  const password = $('#password').value;
  const r = await fetch('/api/auth/login', {
    method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify({ email, password })
  });
  $('#out').textContent = await r.text();
});

$('#btnGen')?.addEventListener('click', async ()=>{
  const r = await fetch('/api/auth/backup/generate', { method:'POST' });
  $('#outCodes').textContent = await r.text();
});

// GA4 test
$('#btnGA4')?.addEventListener('click', async ()=>{
  const payload = {
    client_id: '555.666', // przykładowy cid
    events: [{ name:'page_view', params:{ page_location: location.href, page_title: document.title } }]
  };
  const r = await fetch('/api/ga4/collect', {
    method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload)
  });
  $('#outAPI').textContent = await r.text();
});

// TikTok test
$('#btnTT')?.addEventListener('click', async ()=>{
  const body = {
    event: "CompletePayment",
    event_id: crypto.randomUUID(),
    timestamp: Math.floor(Date.now()/1000),
    context: { ad: {}, page:{ url: location.href }, user: { external_id: "user_1" } },
    properties: { value: 9.99, currency: "USD" }
  };
  const r = await fetch('/api/tiktok/track', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body) });
  $('#outAPI').textContent = await r.text();
});

// OpenAI test
$('#btnAI')?.addEventListener('click', async ()=>{
  const r = await fetch('/api/openai/chat', {
    method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify({ messages:[{role:'user', content:'Say hello from QEHS'}] })
  });
  $('#outAPI').textContent = await r.text();
});

// ElevenLabs TTS
$('#btnTTS')?.addEventListener('click', async ()=>{
  const r = await fetch('/api/tts/eleven', {
    method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify({ text: 'Witaj, QEHS – jedziemy!' })
  });
  if (r.headers.get('content-type')?.includes('audio')) {
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const audio = new Audio(url);
    audio.play();
    $('#outAPI').textContent = 'Audio odebrane i odtworzone.';
  } else {
    $('#outAPI').textContent = await r.text();
  }
});
