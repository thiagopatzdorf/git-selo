// Caso real: as chaves que pessoas de verdade publicam em github.com/<usuario>.keys,
// copiadas em 2026-11-20 (test/fixtures/github-keys). Prova que o formato do mundo real passa,
// não só as chaves que o próprio teste gera.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as age from '../age.mjs';
import { keyServer } from './helpers.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, '..', 'git-selo.mjs');
const FIX = path.join(HERE, 'fixtures', 'github-keys');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selo-real-'));
const hasAge = spawnSync('age', ['--version']).status === 0;
let srv;
const env = () => ({ ...process.env, HOME: tmp, XDG_CONFIG_HOME: path.join(tmp, '.config'), SELO_GITHUB_URL: srv.url, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' });
const selo = (cwd, ...a) => spawnSync(process.execPath, [BIN, ...a], { cwd, env: env(), encoding: 'utf8' });

before(async () => { srv = await keyServer(FIX); });
after(() => { srv.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

test('as 21 chaves reais do @t3dotgg (RSA 4096 e ed25519) viram 21 destinatários', () => {
  const lines = fs.readFileSync(path.join(FIX, 't3dotgg.keys'), 'utf8').trim().split('\n');
  const recips = lines.map(age.parseRecipient);
  assert.equal(recips.length, 21);
  assert.deepEqual([...new Set(recips.map((r) => r.type))].sort(), ['ssh-ed25519', 'ssh-rsa']);
  const ct = age.encrypt(Buffer.from('hello theo\n'), recips);
  assert.equal(age.headerRecipients(ct).length, 21);
  if (hasAge) {
    // O age oficial tem de ler o cabeçalho e recusar só por não ter a chave: erro de formato reprova.
    const k = path.join(tmp, 'k.txt'), f = path.join(tmp, 'theo.age');
    fs.writeFileSync(k, age.generateIdentity().secret + '\n'); fs.writeFileSync(f, ct);
    const r = spawnSync('age', ['-d', '-i', k, f], { encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /no identity matched/);
  }
});

test('git selo add @usuario fixa no .selo.json exatamente as chaves publicadas', () => {
  const d = path.join(tmp, 'repo'); fs.mkdirSync(d);
  execFileSync('git', ['init', '-q'], { cwd: d, env: env() });
  assert.equal(selo(d, 'init').status, 0);
  const r = selo(d, 'add', '@thiagopatzdorf', '@t3dotgg');
  assert.equal(r.status, 0, r.stderr);
  const pol = JSON.parse(fs.readFileSync(path.join(d, '.selo.json'), 'utf8'));
  assert.equal(pol.keys['@thiagopatzdorf'].length, 2);
  assert.equal(pol.keys['@t3dotgg'].length, 21);
  assert.deepEqual(pol.groups.team, ['@thiagopatzdorf', '@t3dotgg']);
  fs.writeFileSync(path.join(d, '.env'), 'X=1\n');
  execFileSync('git', ['add', '-A'], { cwd: d, env: env() });
  const blob = execFileSync('git', ['cat-file', 'blob', ':.env'], { cwd: d, env: env() });
  assert.equal(age.headerRecipients(blob).length, 23);
  assert.equal(selo(d, 'check').status, 0);
});

test('quem só tem chave ECDSA no GitHub (o @FiloSottile) recebe o caminho, não um erro mudo', () => {
  const d = path.join(tmp, 'repo');
  const r = selo(d, 'add', '@FiloSottile');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /no ssh-ed25519 or ssh-rsa key on GitHub/);
  assert.match(r.stderr, /git selo key/);
});

test('usuário que não existe no GitHub falha com o status HTTP', () => {
  const r = selo(path.join(tmp, 'repo'), 'add', '@nao-existe-xyz');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /could not fetch keys for @nao-existe-xyz \(404\)/);
});
