// Revisão de branch privada: a sala (repositório privado temporário com exatamente os leitores e um PR
// de verdade), a revisão local e o merge que publica. A API do GitHub é falsa (helpers.githubApi), o Git
// é de verdade, e o "repositório no GitHub" da sala é um bare local.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sshKeypair, keyServer, githubApi } from './helpers.mjs';
import * as age from '../age.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, '..', 'git-selo.mjs');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selo-room-'));
const people = { alice: sshKeypair('ed25519', 'alice'), bob: sshKeypair('rsa', 'bob'), carol: sshKeypair('ed25519', 'carol') };
const REMOTE = path.join(tmp, 'remote.git'), ROOMS = path.join(tmp, 'gh');
const SEGREDO = 'export const LAUNCH_DATE = "2027-03-01"; // codinome: aurora-boreal';
const TOKEN = 'token-de-teste-da-sala';
const COMENTARIO = 'parece bom, só renomeia a constante';
let keys, api;

function env(name) {
  const h = path.join(tmp, 'home-' + name);
  if (!fs.existsSync(h)) {
    fs.mkdirSync(path.join(h, '.ssh'), { recursive: true });
    fs.writeFileSync(path.join(h, '.ssh', name === 'bob' ? 'id_rsa' : 'id_ed25519'), people[name].private, { mode: 0o600 });
    fs.mkdirSync(path.join(h, 'bin'));
    fs.symlinkSync(BIN, path.join(h, 'bin', 'git-selo'));
  }
  return { ...process.env, HOME: h, XDG_CONFIG_HOME: path.join(h, '.config'), PATH: `${path.join(h, 'bin')}:${process.env.PATH}`,
    SELO_GITHUB_URL: keys.url, SELO_GITHUB_API: api.url, SELO_GITHUB_TOKEN: TOKEN, SELO_ROOM_GIT_URL: path.join(ROOMS, '{repo}.git'),
    GIT_AUTHOR_NAME: name, GIT_AUTHOR_EMAIL: `${name}@x`, GIT_COMMITTER_NAME: name, GIT_COMMITTER_EMAIL: `${name}@x`,
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
const objetos = (gitDir) => execFileSync('git', ['--git-dir', gitDir, 'cat-file', '--batch-all-objects', '--batch'], { maxBuffer: 1 << 26 });
const refs = (gitDir) => execFileSync('git', ['--git-dir', gitDir, 'for-each-ref', '--format=%(refname)'], { encoding: 'utf8' });

before(async () => {
  fs.chmodSync(BIN, 0o755);
  const kd = path.join(tmp, 'keys'); fs.mkdirSync(kd); fs.mkdirSync(ROOMS);
  for (const [n, k] of Object.entries(people)) fs.writeFileSync(path.join(kd, `${n}.keys`), k.public.split(' ').slice(0, 2).join(' ') + '\n');
  keys = await keyServer(kd);
  api = await githubApi(ROOMS, { login: 'alice', token: TOKEN,
    reviews: [{ user: { login: 'bob' }, state: 'APPROVED', body: 'aprovado', submitted_at: '2026-11-21T10:00:00Z' }],
    comments: [{ user: { login: 'bob' }, path: 'launch.js', line: 1, body: COMENTARIO, created_at: '2026-11-21T09:59:00Z' }],
    conversation: [], deleteFailures: 1 });
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', REMOTE]);
  const a = dir('alice');
  g('alice', tmp, 'init', '-q', '-b', 'main', a);
  selo('alice', a, 'init');
  selo('alice', a, 'add', '@alice', '@bob', '--to', 'core');
  fs.writeFileSync(path.join(a, 'README.md'), 'public\n');
  g('alice', a, 'add', '-A'); g('alice', a, 'commit', '-qm', 'public base');
  g('alice', a, 'remote', 'add', 'origin', REMOTE); g('alice', a, 'push', '-q', '-u', 'origin', 'main');
  g('alice', a, 'checkout', '-q', '-b', 'launch');
  fs.writeFileSync(path.join(a, 'launch.js'), SEGREDO + '\n');
  g('alice', a, 'add', 'launch.js'); g('alice', a, 'commit', '-qm', 'aurora-boreal: data secreta');
  selo('alice', a, 'branch', 'push', 'launch', '--for', 'core');
  g('alice', a, 'checkout', '-q', 'main');
  g('alice', a, 'add', '.selo.json'); g('alice', a, 'commit', '-qm', 'policy: launch is private'); g('alice', a, 'push', '-q');
});
after(() => { keys.close(); api.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

test('a sala abre um repositório privado só com os leitores e um PR de verdade, sem tocar o remoto comum', () => {
  const a = dir('alice');
  const out = selo('alice', a, 'room', 'open', 'launch');
  assert.match(out, /review room open: https:\/\/github\.com\/alice\/selo-room-alice-launch-[0-9a-f]{6}\/pull\/1/);
  const s = api.state();
  const [full] = Object.keys(s.repos);
  assert.equal(s.repos[full].private, true, 'the room must be private');
  // Só o Bob é convidado: a Alice é a dona da sala e a Carol não é leitora.
  assert.deepEqual(s.collaborators.map((c) => c.user), ['bob']);
  assert.equal(s.pulls[0].head, 'launch'); assert.equal(s.pulls[0].base, 'main');
  assert.match(s.pulls[0].body, /@alice, @bob/);
  assert.equal(s.badAuth, 0, 'every API call carries the token');
  // A branch está na sala, com o conteúdo de verdade, e continua fora do remoto comum.
  const room = path.join(ROOMS, full + '.git');
  assert.match(execFileSync('git', ['--git-dir', room, 'log', '--format=%s', '-1', 'launch'], { encoding: 'utf8' }), /aurora-boreal/);
  assert.doesNotMatch(refs(REMOTE), /refs\/heads\/launch/);
  assert.ok(!objetos(REMOTE).includes('aurora-boreal'));
});

test('abrir a mesma sala duas vezes é recusado', () => {
  const r = tenta('alice', dir('alice'), 'selo', 'room', 'open', 'launch');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /already open/);
});

test('fechar traz o commit do revisor e a conversa cifrada, e apaga a sala', () => {
  const a = dir('alice'), full = Object.keys(api.state().repos)[0], room = path.join(ROOMS, full + '.git');
  // O Bob revisa na sala: clona, corrige e empurra para a branch do PR.
  const br = dir('bob-na-sala');
  g('bob', tmp, 'clone', '-q', '-b', 'launch', room, br);
  fs.appendFileSync(path.join(br, 'launch.js'), '// sugestão do bob\n');
  g('bob', br, 'commit', '-qam', 'bob: sugestão da revisão'); g('bob', br, 'push', '-q');

  // 1ª tentativa: o token não pode apagar repositório. A revisão fica salva e a sala, de pé.
  const r1 = tenta('alice', a, 'selo', 'room', 'close', 'launch');
  assert.equal(r1.status, 1);
  assert.match(r1.stdout, /saved 2 review item\(s\), encrypted/);
  assert.match(r1.stderr, /delete_repo/);
  assert.ok(fs.existsSync(room));
  // 2ª tentativa: só apaga, sem salvar a revisão de novo.
  const out = selo('alice', a, 'room', 'close', 'launch');
  assert.doesNotMatch(out, /saved/);
  assert.equal(g('alice', a, 'ls-tree', '--name-only', 'refs/selo/launch').split('\n').filter((n) => n.startsWith('review-')).length, 1, 'review saved once');
  assert.match(out, /room alice\/.* deleted/);
  assert.deepEqual(api.state().deleted, [full]);
  assert.ok(!fs.existsSync(room));
  assert.match(g('alice', a, 'log', '--format=%s', '-1', 'launch'), /bob: sugestão da revisão/);

  // No remoto comum só há cifrado: nem o commit do Bob nem o comentário aparecem.
  const tudo = objetos(REMOTE);
  assert.ok(!tudo.includes('sugestão do bob'), 'commit leaked');
  assert.ok(!tudo.includes(COMENTARIO), 'review comment leaked');
  const tree = g('alice', a, 'ls-tree', '--name-only', 'refs/selo/launch');
  assert.match(tree, /bundle\.age\nreview-.*\.json\.age/);
  assert.equal(tenta('alice', a, 'config', '--get', 'selo.room.launch.repo').status, 1, 'room config removed');
});

test('a revisão salva aparece para o leitor e é ilegível para quem não está na lista', () => {
  const b = dir('bob');
  g('bob', tmp, 'clone', '-q', REMOTE, b);
  selo('bob', b, 'unlock');
  selo('bob', b, 'branch', 'pull', 'launch');
  const out = selo('bob', b, 'branch', 'review', 'launch');
  assert.match(out, /## commits\n.*bob: sugestão da revisão/);
  assert.match(out, /- bob launch\.js:1: parece bom/);
  assert.match(out, /- bob \[APPROVED\]: aprovado/);
  assert.match(out, /\+export const LAUNCH_DATE/);

  const name = g('bob', b, 'ls-tree', '--name-only', 'refs/selo/launch').split('\n').find((n) => n.startsWith('review-'));
  const ct = execFileSync('git', ['cat-file', 'blob', `refs/selo/launch:${name}`], { cwd: b });
  assert.equal(age.decrypt(ct, age.parseIdentities(people.carol.private)), null, 'carol must not read the review');
  assert.ok(age.decrypt(ct, age.parseIdentities(people.bob.private)), 'bob reads it');
});

test('a revisão em HTML é local, escapa o código e fica só para o dono do arquivo', () => {
  const b = dir('bob'), f = path.join(tmp, 'review.html');
  fs.writeFileSync(path.join(b, 'evil.html'), '<script>alert(1)</script>\n');
  g('bob', b, 'checkout', '-q', 'launch'); g('bob', b, 'add', 'evil.html'); g('bob', b, 'commit', '-qm', 'html no diff');
  selo('bob', b, 'branch', 'review', 'launch', '--html', f);
  const html = fs.readFileSync(f, 'utf8');
  assert.match(html, /LAUNCH_DATE/);
  assert.ok(!html.includes('<script>alert'), 'diff content must be escaped');
  assert.match(html, /&lt;script&gt;alert/);
  assert.equal(fs.statSync(f).mode & 0o777, 0o600);
  g('bob', b, 'reset', '-q', '--hard', 'HEAD~1'); g('bob', b, 'checkout', '-q', 'main');
});

test('o merge publica a branch, apaga refs/selo e os arquivos protegidos seguem cifrados na main', () => {
  const a = dir('alice');
  // Dentro da branch, um arquivo que nem depois de publicado pode ser legível.
  g('alice', a, 'checkout', '-q', 'launch');
  fs.mkdirSync(path.join(a, 'config'));
  fs.writeFileSync(path.join(a, 'config', 'prod.env'), 'LAUNCH_API_KEY=nao-e-chave-real\n');
  selo('alice', a, 'protect', 'config/*.env', '--for', 'core');
  g('alice', a, 'add', '-A'); g('alice', a, 'commit', '-qm', 'config protegida');
  g('alice', a, 'checkout', '-q', 'main');

  const out = selo('alice', a, 'branch', 'merge', 'launch');
  assert.match(out, /merged "launch" into main and pushed it; refs\/selo\/launch removed\. 1 protected file\(s\) stay encrypted/);
  // A branch virou pública na main, como é para ser...
  assert.match(execFileSync('git', ['--git-dir', REMOTE, 'show', 'main:launch.js'], { encoding: 'utf8' }), /LAUNCH_DATE/);
  // ...mas o arquivo protegido continua cifrado no remoto.
  const blob = execFileSync('git', ['--git-dir', REMOTE, 'cat-file', 'blob', 'main:config/prod.env']);
  assert.ok(blob.toString('latin1').startsWith('age-encryption.org/v1\n'));
  assert.ok(!blob.includes('LAUNCH_API_KEY'));
  assert.doesNotMatch(refs(REMOTE), /refs\/selo\/launch/);
  const pol = JSON.parse(execFileSync('git', ['--git-dir', REMOTE, 'show', 'main:.selo.json'], { encoding: 'utf8' }));
  assert.equal(pol.branches, undefined, 'the branch is no longer private');
  assert.deepEqual(pol.files['config/*.env'], ['core']);
  assert.match(selo('alice', a, 'check'), /ok \(1 protected/);
  // Agora é uma branch comum: o hook deixa empurrar.
  g('alice', a, 'push', '-q', 'origin', 'launch');
});

test('a sala recusa branch que não é privada', () => {
  const a = dir('alice');
  g('alice', a, 'checkout', '-q', '-b', 'publica');
  const r = tenta('alice', a, 'selo', 'room', 'open', 'publica');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not private/);
  g('alice', a, 'checkout', '-q', 'main');
});

test('se a main e a branch mudaram a mesma lista de leitores, o merge une as duas sem pedir ajuda', () => {
  const a = dir('alice');
  g('alice', a, 'checkout', '-q', '-b', 'launch2');
  fs.writeFileSync(path.join(a, 'x.js'), 'x\n'); g('alice', a, 'add', 'x.js'); g('alice', a, 'commit', '-qm', 'x');
  selo('alice', a, 'add', '@bob', '--to', 'ops'); g('alice', a, 'commit', '-qam', 'ops: bob');
  selo('alice', a, 'branch', 'push', 'launch2', '--for', 'core'); g('alice', a, 'commit', '-qam', 'launch2 privada');
  selo('alice', a, 'branch', 'push', 'launch2');
  g('alice', a, 'checkout', '-q', 'main');
  // Na main, o mesmo grupo nasce com outra pessoa: as mesmas linhas do .selo.json, conteúdo diferente.
  selo('alice', a, 'add', '@carol', '--to', 'ops'); g('alice', a, 'commit', '-qam', 'ops: carol'); g('alice', a, 'push', '-q');

  const out = selo('alice', a, 'branch', 'merge', 'launch2');
  assert.match(out, /\.selo\.json.*both sides changed the reader list/);
  const pol = JSON.parse(fs.readFileSync(path.join(a, '.selo.json'), 'utf8'));
  assert.deepEqual([...pol.groups.ops].sort(), ['@bob', '@carol']);
  assert.ok(pol.keys['@bob'] && pol.keys['@carol']);
  assert.equal(pol.branches?.launch2, undefined);
  assert.equal(g('alice', a, 'status', '--porcelain'), '');
  assert.match(selo('alice', a, 'check'), /ok/);
});
