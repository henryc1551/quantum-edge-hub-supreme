const $ = (s)=>document.querySelector(s);
const out = $("#out"); const out2 = $("#out2");

async function jget(u){
  const r = await fetch(u, { credentials:"include" });
  const t = await r.text(); try{ return JSON.parse(t) } catch { return t }
}
document.getElementById('btnLoad')?.addEventListener('click', async ()=>{
  const data = await jget('/api/audit/list?limit=200');
  out.textContent = JSON.stringify(data, null, 2);
});
document.getElementById('btnSearch')?.addEventListener('click', async ()=>{
  const qs = new URLSearchParams({
    email: document.getElementById('email').value,
    action: document.getElementById('action').value,
    ip: document.getElementById('ip').value,
    limit: '500'
  });
  const data = await jget('/api/audit/search?'+qs.toString());
  out2.textContent = JSON.stringify(data, null, 2);
});
