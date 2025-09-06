// Czyści wszystkie klucze w Deno KV (uwaga: usuwa sesje i użytkowników!)
const kv = await Deno.openKv();
let n = 0;
for await (const e of kv.list({ prefix: [] })) {
  await kv.delete(e.key);
  n++;
}
console.log("KV cleared, entries:", n);
