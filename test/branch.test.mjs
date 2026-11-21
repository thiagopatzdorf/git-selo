// Branch privada de ponta a ponta: uma branch inteira (commits, mensagens, arquivos) vai cifrada
// para o mesmo remoto e só quem está na lista a recebe de volta como branch Git comum.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sshKeypair, keyServer } from './helpers.mjs';
import * as age from '../age.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, '..', 'git-selo.mjs');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selo-br-'));
const people = { alice: sshKeypair('ed25519', 'alice'), bob: sshKeypair('rsa', 'bob'), carol: sshKeypair('ed25519', 'carol') };
const REMOTE = path.join(tmp, 'remote.git');
const SEGREDO = 'export const LAUNCH_DATE = "2027-03-01"; // codinome: aurora-boreal';
let srv;

function env(name) {
  const h = path.join(tmp, 'home-' + name);
  if (!fs.existsSync(h)) {
    fs.mkdirSync(path.join(h, '.ssh'), { recursive: true });
    fs.writeFileSync(path.join(h, '.ssh', name === 'bob' ? 'id_rsa' : 'id_ed25519'), people[name].private, { mode: 0o600 });
    fs.mkdirSync(path.join(h, 'bin'));
    fs.symlinkSync(BIN, path.join(h, 'bin', 'git-selo'));
  }
  return { ...process.env, HOME: h, XDG_CONFIG_HOME: path.join(h, '.config'), PATH: `${path.join(h, 'bin')}:${process.env.PATH}`,
    SELO_GITHUB_URL: srv.url, GIT_AUTHOR_NAME: name, GIT_AUTHOR_EMAIL: `${name}@x`, GIT_COMMITTER_NAME: name, GIT_COMMITTER_EMAIL: `${name}@x`,
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
}
const run = (who, cwd, cmd, args) => {
  const r = spawnSync(cmd, args, { cwd, env: env(who), encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`${who}: ${cmd} ${args.join(' ')} -> ${r.status}\n${r.stderr}`);
  return r.stdout;
};
const g = (who, cwd, ...a) => run(who, cwd, 'git', a);
const selo = (who, cwd, ...a) => run(who, cwd, 'git', ['selo', ...a]);
const tenta = (who, cwd, ...a) => spawnSync('git', a, { cwd, env: env(who), encoding: 'utf8' });
const dir = (n) => path.join(tmp, n);

before(async () => {
  fs.chmodSync(BIN, 0o755);
  const keys = path.join(tmp, 'keys'); fs.mkdirSync(keys);
  for (const [n, k] of Object.entries(people)) fs.writeFileSync(path.join(keys, `${n}.keys`), k.public.split(' ').slice(0, 2).join(' ') + '\n');
  srv = await keyServer(keys);
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', REMOTE]);
  const a = dir('alice');
  g('alice', tmp, 'init', '-q', '-b', 'main', a);
  selo('alice', a, 'init');
  selo('alice', a, 'add', '@alice', '@bob', '--to', 'core');
  fs.writeFileSync(path.join(a, 'README.md'), 'public\n');
  g('alice', a, 'add', '-A'); g('alice', a, 'commit', '-qm', 'public base');
  g('alice', a, 'remote', 'add', 'origin', REMOTE); g('alice', a, 'push', '-q', '-u', 'origin', 'main');
});
after(() => { srv.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

test('a branch inteira sobe cifrada: nenhum commit, arquivo ou mensagem dela aparece no remoto', () => {
  const a = dir('alice');
  g('alice', a, 'checkout', '-q', '-b', 'launch');
  fs.writeFileSync(path.join(a, 'launch.js'), SEGREDO + '\n');
  g('alice', a, 'add', 'launch.js'); g('alice', a, 'commit', '-qm', 'aurora-boreal: data secreta');
  const out = selo('alice', a, 'branch', 'push', 'launch', '--for', 'core');
  assert.match(out, /pushed private branch "launch" \(1 commit\(s\), @alice, @bob\)/);
  // A política nova entra no .selo.json, para revisão em PR.
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(a, '.selo.json'), 'utf8')).branches, { launch: ['core'] });

  const todos = execFileSync('git', ['--git-dir', REMOTE, 'cat-file', '--batch-all-objects', '--batch'], { maxBuffer: 1 << 26 });
  assert.ok(!todos.includes('aurora-boreal'), 'commit message leaked');
  assert.ok(!todos.includes('LAUNCH_DATE'), 'file content leaked');
  const refs = execFileSync('git', ['--git-dir', REMOTE, 'for-each-ref', '--format=%(refname)'], { encoding: 'utf8' });
  assert.match(refs, /refs\/selo\/launch/);
  assert.doesNotMatch(refs, /refs\/heads\/launch/);
});

test('o hook barra o git push por hábito da branch privada em texto claro', () => {
  const a = dir('alice');
  const r = tenta('alice', a, 'push', 'origin', 'launch');
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /refusing to push private branch\(es\) in plaintext: launch/);
  const refs = execFileSync('git', ['--git-dir', REMOTE, 'for-each-ref', '--format=%(refname)'], { encoding: 'utf8' });
  assert.doesNotMatch(refs, /refs\/heads\/launch/);
  g('alice', a, 'checkout', '-q', 'main');
  g('alice', a, 'add', '.selo.json'); g('alice', a, 'commit', '-qm', 'policy: launch is private');
  g('alice', a, 'push', '-q'); // push normal da main continua passando
});

test('um clone comum nem baixa a branch privada', () => {
  const c = dir('carol');
  g('carol', tmp, 'clone', '-q', REMOTE, c);
  const refs = g('carol', c, 'for-each-ref', '--format=%(refname)');
  assert.doesNotMatch(refs, /selo|launch/);
});

test('quem está na lista recebe uma branch Git comum, com histórico e arquivos', () => {
  const b = dir('bob');
  g('bob', tmp, 'clone', '-q', REMOTE, b);
  selo('bob', b, 'unlock');
  assert.match(selo('bob', b, 'branch', 'list'), /launch\n {2}readers: @alice, @bob\n {2}you can read/);
  selo('bob', b, 'branch', 'pull', 'launch');
  g('bob', b, 'checkout', '-q', 'launch');
  assert.equal(fs.readFileSync(path.join(b, 'launch.js'), 'utf8'), SEGREDO + '\n');
  assert.match(g('bob', b, 'log', '--format=%s', '-1'), /aurora-boreal: data secreta/);
});

test('quem não está na lista vê que existe, mas não consegue abrir', () => {
  const c = dir('carol');
  selo('carol', c, 'unlock');
  assert.match(selo('carol', c, 'branch', 'list'), /launch\n {2}readers: @alice, @bob\n {2}encrypted \(not for you\)/);
  const r = tenta('carol', c, 'selo', 'branch', 'pull', 'launch');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /you are not a reader of private branch "launch"/);
  assert.equal(tenta('carol', c, 'rev-parse', '--verify', '--quiet', 'refs/heads/launch').status, 1);
});

test('o time continua trabalhando: commit do Bob chega na Alice, inclusive com a branch em uso', () => {
  const b = dir('bob'), a = dir('alice');
  fs.appendFileSync(path.join(b, 'launch.js'), '// revisado pelo bob\n');
  g('bob', b, 'commit', '-qam', 'bob revisa');
  assert.match(selo('bob', b, 'branch', 'push', 'launch'), /pushed private branch "launch" \(2 commit\(s\)/);
  // O Bob está dentro da branch, cujo .selo.json é anterior à política: a guarda vem da main do remoto.
  const r = tenta('bob', b, 'push', 'origin', 'launch');
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /refusing to push private branch/);
  g('alice', a, 'checkout', '-q', 'launch');
  selo('alice', a, 'branch', 'pull', 'launch');
  assert.match(fs.readFileSync(path.join(a, 'launch.js'), 'utf8'), /revisado pelo bob/);
  assert.equal(g('alice', a, 'status', '--porcelain'), '');
  g('alice', a, 'checkout', '-q', 'main');
});

test('o pacote da branch é age padrão: o age oficial abre e o git reconhece o bundle', { skip: spawnSync('age', ['--version']).status !== 0 && 'age not installed' }, () => {
  const b = dir('bob');
  const ct = execFileSync('git', ['cat-file', 'blob', 'refs/selo/launch:bundle.age'], { cwd: b });
  assert.equal(age.headerRecipients(ct).length, 2);
  const f = path.join(tmp, 'launch.age'), key = path.join(tmp, 'home-bob', '.ssh', 'id_rsa');
  fs.writeFileSync(f, ct);
  const bundle = path.join(tmp, 'launch.bundle');
  execFileSync('age', ['-d', '-i', key, '-o', bundle, f]);
  assert.match(execFileSync('git', ['bundle', 'list-heads', bundle], { cwd: b, encoding: 'utf8' }), /refs\/heads\/launch/);
});

test('nome de branch que quebraria a ref é recusado antes de qualquer coisa', () => {
  const a = dir('alice');
  for (const ruim of ['../fora', 'a..b', '-x']) {
    const r = tenta('alice', a, 'selo', 'branch', 'push', ruim, '--for', 'core');
    assert.equal(r.status, 1, ruim);
    assert.match(r.stderr, /invalid branch name/, ruim);
  }
});
