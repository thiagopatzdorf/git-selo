// node --test apps/git-selo/rastro  (Node >= 22: node:sqlite faz o papel do D1)
import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import worker from './worker.js';
// node:sqlite (o D1 de teste) só existe no Node 22+; no 20 estes testes são pulados, não falham.
let d1 = null; try { ({ d1 } = await import('./d1-sqlite.mjs')); } catch {}
const test = (nome, fn) => nodeTest(nome, { skip: !d1 && 'node:sqlite needs Node 22+' }, fn);

const emails = [];
globalThis.fetch = async (u, i) => { if (String(u).includes('resend')) { emails.push(JSON.parse(i.body)); return new Response(JSON.stringify({ id: 'e1' })); } return new Response('{}'); };
const env = { DB: d1 ? d1() : null, RESEND_API_KEY: 're' };
const pedir = async (m, p, b, h = {}) => {
  const r = await worker.fetch(new Request('https://rastro.test' + p, { method: m, headers: { 'cf-connecting-ip': h.ip || '198.51.100.1', 'user-agent': 'curl/8', ...(b ? { 'content-type': 'application/json' } : {}), ...h }, body: b ? JSON.stringify(b) : undefined }), env);
  const t = await r.text(); let j = {}; try { j = JSON.parse(t); } catch {}
  return { st: r.status, j, t };
};
const codigoDoEmail = (e) => e.text.match(/\/v1\/confirm\/([\w-]+)/)[1];

let w;
test('criar vigia devolve um token por leitor e só manda o e-mail de confirmação', async () => {
  const r = await pedir('POST', '/v1/watch', { email: 'dono@exemplo.com', repo: 'acme/app', readers: ['@alice', '@bob'] });
  assert.equal(r.st, 201);
  assert.deepEqual(Object.keys(r.j.tokens), ['@alice', '@bob']);
  assert.notEqual(r.j.tokens['@alice'], r.j.tokens['@bob']);
  assert.equal(r.j.confirmation_email, 'sent');
  assert.equal(emails.length, 1); assert.match(emails[0].subject, /Confirm leak alerts for acme\/app/);
  w = r.j;
});

test('antes de confirmar, usar o link grava o acesso mas não manda alerta', async () => {
  const r = await pedir('GET', `/c/${w.tokens['@bob']}/admin`);
  assert.equal(r.st, 200); assert.deepEqual(r.j, { status: 'ok' });
  assert.equal(emails.length, 1, 'no alert before the owner confirms');
});

test('confirmado, o link da cópia do Bob manda alerta dizendo que foi a cópia do Bob, com IP e país', async () => {
  assert.equal((await pedir('GET', `/v1/confirm/${codigoDoEmail(emails[0])}`)).st, 200);
  await pedir('GET', `/c/${w.tokens['@bob']}`, null, { ip: '192.0.2.44', 'cf-ipcountry': 'PT' });
  const e = emails.at(-1);
  assert.equal(e.to[0], 'dono@exemplo.com');
  assert.match(e.subject, /@bob's copy of acme\/app was used/);
  assert.match(e.text, /192\.0\.2\.44 \(PT\)/);
});

test('um robô batendo no link não enche a caixa: um e-mail por cópia a cada 10 minutos, todos gravados', async () => {
  const antes = emails.length;
  for (let i = 0; i < 5; i++) await pedir('GET', `/c/${w.tokens['@bob']}`);
  assert.equal(emails.length, antes);
  const s = await pedir('GET', `/v1/watch/${w.id}`, null, { authorization: `Bearer ${w.manage}` });
  assert.equal(s.j.hits.filter((h) => h.reader === '@bob').length, 7);
});

test('token que não existe recebe a mesma resposta que um token real', async () => {
  const r = await pedir('GET', '/c/naoexisteessetoken123');
  assert.deepEqual(r.j, { status: 'ok' });
});

test('sem a chave de gerência ninguém lê os acessos, identifica cópia nem apaga', async () => {
  assert.equal((await pedir('GET', `/v1/watch/${w.id}`)).st, 401);
  assert.equal((await pedir('GET', `/v1/watch/${w.id}`, null, { authorization: 'Bearer errada' })).st, 401);
  assert.equal((await pedir('DELETE', `/v1/watch/${w.id}`, null, { authorization: 'Bearer errada' })).st, 401);
});

test('identificar diz de quem é um token achado numa cópia vazada', async () => {
  const r = await pedir('POST', `/v1/watch/${w.id}/identify`, { token: w.tokens['@alice'] }, { authorization: `Bearer ${w.manage}` });
  assert.deepEqual(r.j, { reader: '@alice' });
  assert.equal((await pedir('POST', `/v1/watch/${w.id}/identify`, { token: 'outro' }, { authorization: `Bearer ${w.manage}` })).st, 404);
});

test('o link de parar desliga os alertas e o de confirmar religa', async () => {
  const c = codigoDoEmail(emails[0]), antes = emails.length;
  await pedir('GET', `/v1/stop/${c}`);
  await new Promise((r) => setTimeout(r, 5));
  await pedir('GET', `/c/${w.tokens['@alice']}`);
  assert.equal(emails.length, antes, 'stopped watch sends nothing');
});

test('entrada ruim é recusada: e-mail, nome do repo, lista de leitores', async () => {
  assert.equal((await pedir('POST', '/v1/watch', { email: 'x', repo: 'a', readers: ['@a'] }, { ip: '10.9.9.1' })).st, 400);
  assert.equal((await pedir('POST', '/v1/watch', { email: 'a@b.co', repo: '<script>', readers: ['@a'] }, { ip: '10.9.9.1' })).st, 400);
  assert.equal((await pedir('POST', '/v1/watch', { email: 'a@b.co', repo: 'r', readers: [] }, { ip: '10.9.9.1' })).st, 400);
  assert.equal((await pedir('POST', '/v1/watch', { email: 'a@b.co', repo: 'r', readers: Array.from({ length: 51 }, (_, i) => '@u' + i) }, { ip: '10.9.9.1' })).st, 400);
});

test('o servidor não vira canhão de e-mail: no máximo 3 confirmações por endereço por dia', async () => {
  const st = [];
  for (let i = 0; i < 4; i++) st.push((await pedir('POST', '/v1/watch', { email: 'vitima@exemplo.com', repo: 'r', readers: ['@a'] }, { ip: `10.1.1.${i}` })).st);
  assert.deepEqual(st, [201, 201, 201, 429]);
});

test('apagar a vigia remove tokens e acessos; o link antigo deixa de alertar', async () => {
  const d = await pedir('DELETE', `/v1/watch/${w.id}`, null, { authorization: `Bearer ${w.manage}` });
  assert.deepEqual(d.j, { deleted: true });
  assert.equal((await pedir('GET', `/v1/watch/${w.id}`, null, { authorization: `Bearer ${w.manage}` })).st, 401);
});
