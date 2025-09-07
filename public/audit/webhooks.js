const $=(s)=>document.querySelector(s);
const out = (id)=>document.getElementById(id);

document.getElementById('btnSend')?.addEventListener('click', async ()=>{
  const body = document.getElementById('body').value;
  const sig = document.getElementById('sig').value.trim();
  const r = await fetch('/api/webhooks/ingest?provider=generic',{
    method:'POST',
    headers:{'content-type':'application/json','x-qehs-signature':sig},
    body
  });
  out('out').textContent = await r.text();
});

document.getElementById('btnSendS')?.addEventListener('click', async ()=>{
  const body = document.getElementById('bodyS').value;
  const sig = document.getElementById('sigS').value.trim();
  const r = await fetch('/api/webhooks/ingest?provider=stripe',{
    method:'POST',
    headers:{'content-type':'application/json','stripe-signature':sig},
    body
  });
  out('outS').textContent = await r.text();
});
