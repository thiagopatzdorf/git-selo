// Sobe o Worker do rastro num servidor HTTP local, com D1 em memória e o Resend trocado por um arquivo:
// cada e-mail "enviado" vira uma linha JSON em $RASTRO_EMAILS. Uso: node servidor-local.mjs (imprime a porta).
import http from 'node:http';
import fs from 'node:fs';
import worker from './worker.js';
import { d1 } from './d1-sqlite.mjs';
const caixa = process.env.RASTRO_EMAILS;
const real = globalThis.fetch;
globalThis.fetch = async (u, i) => {
  if (String(u).startsWith('https://api.resend.com/')) { if (caixa) fs.appendFileSync(caixa, i.body + '\n'); return new Response(JSON.stringify({ id: 'teste' })); }
  return real(u, i);
};
const env = { DB: d1(), RESEND_API_KEY: 'teste' };
const s = http.createServer(async (q, r) => {
  const partes = []; for await (const c of q) partes.push(c);
  const corpo = Buffer.concat(partes);
  const h = { ...q.headers, 'cf-connecting-ip': q.headers['x-teste-ip'] || '203.0.113.7' };
  const res = await worker.fetch(new Request(`http://${q.headers.host}${q.url}`, { method: q.method, headers: h, body: ['GET', 'HEAD'].includes(q.method) ? undefined : corpo }), env);
  r.writeHead(res.status, Object.fromEntries(res.headers)); r.end(Buffer.from(await res.arrayBuffer()));
});
s.listen(0, '127.0.0.1', () => console.log(s.address().port));
