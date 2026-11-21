// O caso inteiro, de ponta a ponta, com Git de verdade: três pessoas, um remoto, chaves SSH
// servidas como o GitHub serve (github.com/<user>.keys). É a costura: cada peça testada sozinha
// não prova que o fluxo funciona.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sshKeypair, keyServer } from './helpers.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, '..', 'git-selo.mjs');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selo-'));
const people = { alice: sshKeypair('ed25519', 'alice'), bob: sshKeypair('rsa', 'bob'), carol: sshKeypair('ed25519', 'carol') };
let server, base;
const SECRET = 'STRIPE_KEY=sk_live_not_a_real_key_123\nDATABASE_URL=postgres://prod\n';

function home(name) {
  const h = path.join(tmp, 'home-' + name);
  fs.mkdirSync(path.join(h, '.ssh'), { recursive: true });
  fs.writeFileSync(path.join(h, '.ssh', name === 'bob' ? 'id_rsa' : 'id_ed25519'), people[name].private, { mode: 0o600 });
  // `git selo` como subcomando do Git: basta um executável git-selo no PATH.
  const bin = path.join(h, 'bin'); fs.mkdirSync(bin, { recursive: true });
  try { fs.symlinkSync(BIN, path.join(bin, 'git-selo')); } catch {}
  return h;
}
function env(name) {
  return { ...process.env, HOME: home(name), XDG_CONFIG_HOME: path.join(tmp, 'home-' + name, '.config'), PATH: `${path.join(tmp, 'home-' + name, 'bin')}:${process.env.PATH}`,
    SELO_GITHUB_URL: base, GIT_AUTHOR_NAME: name, GIT_AUTHOR_EMAIL: `${name}@x`, GIT_COMMITTER_NAME: name, GIT_COMMITTER_EMAIL: `${name}@x`, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
}
const run = (who, cwd, cmd, args) => {
  const r = spawnSync(cmd, args, { cwd, env: env(who), encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`${who}: ${cmd} ${args.join(' ')} -> ${r.status}\n${r.stderr}`);
  return r.stdout;
};
const selo = (who, cwd, ...a) => run(who, cwd, 'git', ['selo', ...a]);
const gitc = (who, cwd, ...a) => run(who, cwd, 'git', a);
const clone = (who) => { const d = path.join(tmp, who); gitc(who, tmp, 'clone', '-q', path.join(tmp, 'remote.git'), d); return d; };

before(async () => {
  fs.chmodSync(BIN, 0o755);
  const keysDir = path.join(tmp, 'keys'); fs.mkdirSync(keysDir);
  for (const [n, k] of Object.entries(people)) fs.writeFileSync(path.join(keysDir, `${n}.keys`), k.public.split(' ').slice(0, 2).join(' ') + '\n');
  server = await keyServer(keysDir);
  base = server.url;
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', path.join(tmp, 'remote.git')]);
});
after(() => { server.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

test('o .env que o junior empurra chega cifrado no remoto e legível só para o time', () => {
  const a = path.join(tmp, 'alice');
  gitc('alice', tmp, 'init', '-q', '-b', 'main', a);
  selo('alice', a, 'init');
  selo('alice', a, 'add', '@alice', '@bob');
  fs.writeFileSync(path.join(a, '.env'), SECRET);
  fs.writeFileSync(path.join(a, 'README.md'), 'public\n');
  gitc('alice', a, 'add', '-A');
  gitc('alice', a, 'commit', '-qm', 'init');
  gitc('alice', a, 'remote', 'add', 'origin', path.join(tmp, 'remote.git'));
  gitc('alice', a, 'push', '-q', '-u', 'origin', 'main');

  const blob = execFileSync('git', ['--git-dir', path.join(tmp, 'remote.git'), 'cat-file', 'blob', 'main:.env']);
  assert.ok(blob.toString('latin1').startsWith('age-encryption.org/v1\n'), 'remote must hold ciphertext');
  assert.ok(!blob.includes('sk_live'), 'secret must not appear in the remote');
  assert.equal(fs.readFileSync(path.join(a, '.env'), 'utf8'), SECRET, 'author keeps plaintext locally');
  assert.equal(gitc('alice', a, 'status', '--porcelain'), '', 'git status must not flap after commit');
});

test('quem está na lista clona, roda unlock e lê; o status continua limpo', () => {
  const b = clone('bob');
  assert.ok(fs.readFileSync(path.join(b, '.env'), 'latin1').startsWith('age-encryption'), 'before unlock it is ciphertext');
  selo('bob', b, 'unlock');
  assert.equal(fs.readFileSync(path.join(b, '.env'), 'utf8'), SECRET);
  assert.equal(gitc('bob', b, 'status', '--porcelain'), '');
  assert.match(selo('bob', b, 'status'), /you can read/);
});

test('quem não está na lista vê só o cifrado e o checkout não quebra', () => {
  const c = clone('carol');
  selo('carol', c, 'unlock');
  assert.ok(fs.readFileSync(path.join(c, '.env'), 'latin1').startsWith('age-encryption'));
  assert.equal(gitc('carol', c, 'status', '--porcelain'), '');
  assert.match(selo('carol', c, 'status'), /not for you/);
  const r = spawnSync('git', ['selo', 'cat', '.env'], { cwd: c, env: env('carol'), encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not a reader/);
  assert.match(selo('carol', c, 'check'), /ok \(1 protected/);
});

test('o leitor edita, o diff mostra texto claro e o remoto continua cifrado', () => {
  const b = path.join(tmp, 'bob');
  fs.appendFileSync(path.join(b, '.env'), 'NEW=1\n');
  assert.match(gitc('bob', b, 'diff'), /\+NEW=1/);
  gitc('bob', b, 'commit', '-qam', 'add NEW');
  gitc('bob', b, 'push', '-q');
  const blob = execFileSync('git', ['--git-dir', path.join(tmp, 'remote.git'), 'cat-file', 'blob', 'main:.env']);
  assert.ok(!blob.includes('NEW=1'));
  gitc('alice', path.join(tmp, 'alice'), 'pull', '-q');
  assert.match(fs.readFileSync(path.join(tmp, 'alice', '.env'), 'utf8'), /NEW=1/);
});

test('remover alguém recifra e a pessoa deixa de ler as versões novas', () => {
  const a = path.join(tmp, 'alice');
  const out = selo('alice', a, 'remove', '@bob');
  assert.match(out, /Rotate the secrets/);
  assert.ok(!JSON.parse(fs.readFileSync(path.join(a, '.selo.json'), 'utf8')).keys['@bob'], 'bob keys unpinned');
  gitc('alice', a, 'commit', '-qam', 'revoke bob');
  gitc('alice', a, 'push', '-q');
  const b = path.join(tmp, 'bob');
  gitc('bob', b, 'pull', '-q');
  assert.ok(fs.readFileSync(path.join(b, '.env'), 'latin1').startsWith('age-encryption'), 'bob now sees ciphertext');
  assert.match(selo('alice', a, 'check'), /ok/);
});

test('o check do CI reprova segredo commitado em texto claro por quem não tem o git selo', () => {
  const d = path.join(tmp, 'sem-selo');
  gitc('carol', tmp, 'clone', '-q', path.join(tmp, 'remote.git'), d);
  // Sem `unlock` o filtro não está configurado neste clone: o Git commita o que vier.
  fs.writeFileSync(path.join(d, '.env.local'), 'TOKEN=abc\n');
  fs.writeFileSync(path.join(d, 'server.pem'), 'x\n');
  gitc('carol', d, 'add', '-A');
  const r = spawnSync('git', ['selo', 'check'], { cwd: d, env: env('carol'), encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /\.env\.local is committed in PLAINTEXT/);
  assert.match(r.stderr, /server\.pem looks like a secret/);
});

test('arquivo cifrado com destinatários diferentes da política reprova o check', () => {
  const a = path.join(tmp, 'alice');
  const pol = JSON.parse(fs.readFileSync(path.join(a, '.selo.json'), 'utf8'));
  pol.groups.team.push('@carol');
  pol.keys['@carol'] = [people.carol.public.split(' ').slice(0, 2).join(' ')];
  fs.writeFileSync(path.join(a, '.selo.json'), JSON.stringify(pol));
  // Alguém mexeu na lista à mão sem recifrar: o check tem de pegar.
  const r = spawnSync('git', ['selo', 'check'], { cwd: a, env: env('alice'), encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /different set of readers/);
  gitc('alice', a, 'checkout', '--', '.selo.json');
});

test('lock devolve o cifrado ao disco e unlock volta ao texto claro, mesmo com o índice ambíguo', () => {
  const a = path.join(tmp, 'alice');
  // Regravar o arquivo e o índice no mesmo segundo força o Git a comparar conteúdo ("racy git"):
  // era aí que o lock acusava mudança falsa.
  fs.rmSync(path.join(a, '.env')); gitc('alice', a, 'checkout', '--', '.env');
  selo('alice', a, 'lock');
  assert.ok(fs.readFileSync(path.join(a, '.env'), 'latin1').startsWith('age-encryption'));
  selo('alice', a, 'unlock');
  assert.match(fs.readFileSync(path.join(a, '.env'), 'utf8'), /STRIPE_KEY/);
  assert.equal(gitc('alice', a, 'status', '--porcelain'), '');
});

test('--version mostra a versão do package.json, a mesma que o npm publica', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'package.json'), 'utf8'));
  const r = spawnSync(process.execPath, [BIN, '--version'], { encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), pkg.version);
});
