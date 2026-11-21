// Rastro de vazamento de ponta a ponta: o servidor do rastro de verdade (rastro/worker.js num HTTP local,
// D1 em node:sqlite, e-mails num arquivo), Git de verdade, três pessoas.
import { test as nodeTest, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sshKeypair, keyServer } from './helpers.mjs';
import * as age from '../age.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, '..', 'git-selo.mjs');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selo-trace-'));
const people = { alice: sshKeypair('ed25519', 'alice'), bob: sshKeypair('rsa', 'bob'), carol: sshKeypair('ed25519', 'carol') };
const REMOTE = path.join(tmp, 'remote.git'), CAIXA = path.join(tmp, 'emails.jsonl');
const ENV = 'STRIPE_KEY=sk_live_not_a_real_key_123\nDATABASE_URL=postgres://prod'; // sem quebra de linha final, de propósito
const CODIGO = 'export const PRECO_SECRETO = 42;\n';
let keys, rastro, rastroProc;
// O servidor de teste usa node:sqlite (Node 22+). No Node 20 o rastro é pulado, com o motivo.
const temSqlite = await import('node:sqlite').then(() => true, () => false);
const test = (nome, fn) => nodeTest(nome, { skip: !temSqlite && 'node:sqlite needs Node 22+' }, fn);

function env(name) {
  const h = path.join(tmp, 'home-' + name);
  if (!fs.existsSync(h)) {
    fs.mkdirSync(path.join(h, '.ssh'), { recursive: true });
    fs.writeFileSync(path.join(h, '.ssh', name === 'bob' ? 'id_rsa' : 'id_ed25519'), people[name].private, { mode: 0o600 });
    fs.mkdirSync(path.join(h, 'bin'));
    fs.symlinkSync(BIN, path.join(h, 'bin', 'git-selo'));
  }
  return { ...process.env, HOME: h, XDG_CONFIG_HOME: path.join(h, '.config'), PATH: `${path.join(h, 'bin')}:${process.env.PATH}`,
    SELO_GITHUB_URL: keys.url, SELO_TRACE_SERVER: rastro, GIT_AUTHOR_NAME: name, GIT_AUTHOR_EMAIL: `${name}@x`,
    GIT_COMMITTER_NAME: name, GIT_COMMITTER_EMAIL: `${name}@x`, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
}
const run = (who, cwd, cmd, args) => {
  const r = spawnSync(cmd, args, { cwd, env: env(who), encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`${who}: ${cmd} ${args.join(' ')} -> ${r.status}\n${r.stderr}`);
  return r.stdout;
};
const g = (who, cwd, ...a) => run(who, cwd, 'git', a);
const selo = (who, cwd, ...a) => run(who, cwd, 'git', ['selo', ...a]);
const dir = (n) => path.join(tmp, n);
const emails = () => (fs.existsSync(CAIXA) ? fs.readFileSync(CAIXA, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : []);
const owner = () => JSON.parse(fs.readFileSync(path.join(dir('alice'), '.git', 'selo', 'trace-owner.json'), 'utf8'));
const objetos = () => execFileSync('git', ['--git-dir', REMOTE, 'cat-file', '--batch-all-objects', '--batch'], { maxBuffer: 1 << 26 });
const MARCA_URL = /^BACKUP_ADMIN_URL=http:\/\/127\.0\.0\.1:\d+\/c\/([\w-]+)‍?$/m;

before(async () => {
  if (!temSqlite) return;
  fs.chmodSync(BIN, 0o755);
  const kd = path.join(tmp, 'keys'); fs.mkdirSync(kd);
  for (const [n, k] of Object.entries(people)) fs.writeFileSync(path.join(kd, `${n}.keys`), k.public.split(' ').slice(0, 2).join(' ') + '\n');
  keys = await keyServer(kd);
  rastroProc = spawn(process.execPath, [path.join(HERE, '..', 'rastro', 'servidor-local.mjs')], { env: { ...process.env, RASTRO_EMAILS: CAIXA }, stdio: ['ignore', 'pipe', 'inherit'] });
  rastro = `http://127.0.0.1:${await new Promise((r) => rastroProc.stdout.once('data', (d) => r(String(d).trim())))}`;
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', REMOTE]);
  const a = dir('alice');
  g('alice', tmp, 'init', '-q', '-b', 'main', a);
  selo('alice', a, 'init');
  selo('alice', a, 'add', '@alice', '@bob');
  fs.mkdirSync(path.join(a, 'src'));
  fs.writeFileSync(path.join(a, '.env'), ENV);
  fs.writeFileSync(path.join(a, 'src', 'preco.js'), CODIGO);
  selo('alice', a, 'protect', 'src/preco.js');
  g('alice', a, 'add', '-A'); g('alice', a, 'commit', '-qm', 'init');
  g('alice', a, 'remote', 'add', 'origin', REMOTE); g('alice', a, 'push', '-q', '-u', 'origin', 'main');
});
after(() => { keys?.close(); rastroProc?.kill(); fs.rmSync(tmp, { recursive: true, force: true }); });

test('trace on marca a cópia de cada leitor e manda só o e-mail de confirmação', () => {
  const a = dir('alice');
  const out = selo('alice', a, 'trace', 'on', '--email', 'dono@exemplo.com');
  assert.match(out, /2 reader copies marked \(@alice, @bob\)/);
  assert.equal(fs.readdirSync(path.join(a, '.selo-trace')).length, 2);
  // A cópia da Alice já tem a marca dela: o link no .env e o token invisível no código.
  const tokA = owner().tokens['@alice'];
  assert.equal(fs.readFileSync(path.join(a, '.env'), 'utf8').match(MARCA_URL)[1], tokA);
  assert.match(fs.readFileSync(path.join(a, 'src', 'preco.js'), 'utf8'), /^\/\/ [​‌]+$/m);
  // O Git vê só a política e os tokens cifrados mudando, nunca o .env marcado.
  const mudou = g('alice', a, 'status', '--porcelain', '-uall').trim().split('\n').map((l) => l.slice(3));
  assert.ok(mudou.includes('.selo.json') && mudou.some((f) => f.startsWith('.selo-trace/')));
  assert.ok(!mudou.includes('.env') && !mudou.includes('src/preco.js'), `marked files must look unchanged: ${mudou}`);
  assert.equal(emails().length, 1);
  assert.match(emails()[0].subject, /Confirm leak alerts/);
  g('alice', a, 'commit', '-qm', 'trace on'); g('alice', a, 'push', '-q');
  assert.equal(g('alice', a, 'status', '--porcelain'), '');
});

test('o repositório nunca guarda token nenhum: o .env cifrado no remoto é o texto original', () => {
  const tudo = objetos();
  for (const t of Object.values(owner().tokens)) assert.ok(!tudo.includes(t), 'a token leaked into git objects');
  const ct = execFileSync('git', ['--git-dir', REMOTE, 'cat-file', 'blob', 'main:.env']);
  assert.equal(age.decrypt(ct, age.parseIdentities(people.alice.private)).toString(), ENV);
});

test('o Bob recebe a cópia dele, com outro token; a Carol, fora da lista, não recebe marca', () => {
  const b = dir('bob'), c = dir('carol');
  g('bob', tmp, 'clone', '-q', REMOTE, b); selo('bob', b, 'unlock');
  const envB = fs.readFileSync(path.join(b, '.env'), 'utf8');
  assert.equal(envB.match(MARCA_URL)[1], owner().tokens['@bob']);
  assert.notEqual(owner().tokens['@bob'], owner().tokens['@alice']);
  assert.equal(g('bob', b, 'status', '--porcelain'), '', 'the mark must not make git status dirty');
  g('carol', tmp, 'clone', '-q', REMOTE, c); selo('carol', c, 'unlock');
  assert.ok(fs.readFileSync(path.join(c, '.env'), 'latin1').startsWith('age-encryption'));
  assert.ok(!fs.existsSync(path.join(c, '.git', 'selo', 'trace.json')));
});

test('alguém usa o link da cópia do Bob: o dono recebe o e-mail dizendo que foi a cópia do Bob', async () => {
  const conf = emails()[0].text.match(/(http:\/\/\S+\/v1\/confirm\/[\w-]+)/)[1];
  assert.equal((await fetch(conf)).status, 200);
  const url = fs.readFileSync(path.join(dir('bob'), '.env'), 'utf8').match(/^BACKUP_ADMIN_URL=(\S+?)‍?$/m)[1];
  await fetch(url, { headers: { 'user-agent': 'scanner-de-vazamento/1' } });
  const e = emails().at(-1);
  assert.equal(e.to[0], 'dono@exemplo.com');
  assert.match(e.subject, /@bob's copy of alice was used/);
  assert.match(selo('alice', dir('alice'), 'trace', 'status'), /alerts ON[\s\S]*@bob .*scanner-de-vazamento/);
});

test('um arquivo vazado sem o .env ainda diz de quem é a cópia, pelo token invisível no código', () => {
  const vazado = path.join(tmp, 'vazado.js');
  fs.copyFileSync(path.join(dir('bob'), 'src', 'preco.js'), vazado);
  assert.match(selo('alice', dir('alice'), 'trace', 'identify', vazado), /this copy came from @bob/);
});

test('o Bob edita e empurra: a marca dele não vai junto, e a Alice continua com a dela', () => {
  const b = dir('bob'), a = dir('alice');
  fs.appendFileSync(path.join(b, '.env'), 'NOVA=1\n');
  g('bob', b, 'commit', '-qam', 'bob edita'); g('bob', b, 'push', '-q');
  const tudo = objetos();
  assert.ok(!tudo.includes(owner().tokens['@bob']), "bob's token must never reach the remote");
  g('alice', a, 'pull', '-q');
  const envA = fs.readFileSync(path.join(a, '.env'), 'utf8');
  assert.match(envA, /NOVA=1/);
  assert.equal(envA.match(MARCA_URL)[1], owner().tokens['@alice']);
  assert.ok(!envA.includes(owner().tokens['@bob']));
});

test('trace off apaga a vigia no servidor e tira as marcas do disco', async () => {
  const a = dir('alice'), o = owner();
  const out = selo('alice', a, 'trace', 'off');
  assert.match(out, /trace off: watch deleted/);
  assert.equal((await fetch(`${rastro}/v1/watch/${o.id}`, { headers: { authorization: `Bearer ${o.manage}` } })).status, 401);
  assert.doesNotMatch(fs.readFileSync(path.join(a, '.env'), 'utf8'), /BACKUP_ADMIN_URL/);
  assert.doesNotMatch(fs.readFileSync(path.join(a, 'src', 'preco.js'), 'utf8'), /[​‌]/);
  assert.ok(!fs.existsSync(path.join(a, '.selo-trace')));
  g('alice', a, 'commit', '-qm', 'trace off'); g('alice', a, 'push', '-q');
  assert.equal(g('alice', a, 'status', '--porcelain'), '');
  assert.match(selo('alice', a, 'check'), /ok \(2 protected/);
  // O Bob puxa o trace off com a marca antiga ainda no disco: nada aparece como mudança, nada do token sobe.
  const b = dir('bob');
  g('bob', b, 'pull', '-q');
  assert.equal(g('bob', b, 'status', '--porcelain'), '');
  fs.appendFileSync(path.join(b, '.env'), 'OUTRA=2\n');
  g('bob', b, 'commit', '-qam', 'depois do off'); g('bob', b, 'push', '-q');
  // O token iria cifrado, então procurar nos objetos não basta: abre o .env do remoto e confere o texto.
  const envRemoto = age.decrypt(execFileSync('git', ['--git-dir', REMOTE, 'cat-file', 'blob', 'main:.env']), age.parseIdentities(people.alice.private)).toString();
  assert.doesNotMatch(envRemoto, /BACKUP_ADMIN_URL/, "bob's mark went into the commit");
  assert.match(envRemoto, /OUTRA=2/);
});
