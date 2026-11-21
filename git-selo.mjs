#!/usr/bin/env node
// git selo: arquivos privados dentro de um repositório Git comum.
// O arquivo vai cifrado (formato age) para as chaves SSH que cada pessoa já tem no GitHub;
// quem está na lista lê em texto claro, quem não está vê só o cifrado. Quem pode ler
// fica em .selo.json, revisado em PR como qualquer código.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as age from './age.mjs';

const POLICY = '.selo.json';
const BEGIN = '# >>> git-selo (generated from .selo.json by `git selo sync`; do not edit)';
const END = '# <<< git-selo';
const SECRETISH = [/(^|\/)\.env(\..+)?$/, /\.pem$/, /\.key$/, /(^|\/)id_(rsa|ed25519|ecdsa)$/, /\.p12$/, /(^|\/)credentials\.json$/, /\.tfvars$/];

const SELF = fileURLToPath(import.meta.url);
const say = (m) => process.stderr.write(`git-selo: ${m}\n`);
class UserError extends Error {}
const fail = (m) => { throw new UserError(m); };

// ---------- git ----------
function git(args, opts = {}) {
  return execFileSync('git', args, { encoding: opts.raw ? null : 'utf8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1 << 30, ...opts });
}
const root = () => git(['rev-parse', '--show-toplevel']).trim();
const gitDir = () => path.resolve(git(['rev-parse', '--git-dir']).trim());
const readStdin = () => { const parts = []; let n; const b = Buffer.alloc(1 << 16); try { while ((n = fs.readSync(0, b)) > 0) parts.push(Buffer.from(b.subarray(0, n))); } catch (e) { if (e.code !== 'EOF') throw e; } return Buffer.concat(parts); };

// ---------- política ----------
function loadPolicy(dir = root(), text) {
  const file = path.join(dir, POLICY);
  if (text === undefined) { if (!fs.existsSync(file)) fail(`no ${POLICY} here. Run \`git selo init\` first.`); text = fs.readFileSync(file, 'utf8'); }
  const p = JSON.parse(text);
  return { groups: p.groups || {}, files: p.files || {}, branches: p.branches || {}, keys: p.keys || {} };
}
function savePolicy(p, dir = root()) {
  const sorted = { groups: p.groups, files: p.files, ...(Object.keys(p.branches || {}).length ? { branches: p.branches } : {}), keys: Object.fromEntries(Object.entries(p.keys).sort()) };
  fs.writeFileSync(path.join(dir, POLICY), JSON.stringify(sorted, null, 2) + '\n');
}

// Padrões com a mesma semântica do .gitattributes, para o filtro do Git e o `check` concordarem.
export function globToRegex(pat) {
  let p = pat.replace(/^\//, '');
  const anchored = pat.startsWith('/') || p.replace(/\/$/, '').includes('/');
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '*' && p[i + 1] === '*') {
      if (p[i + 2] === '/') { re += '(?:.*/)?'; i += 2; } else { re += '.*'; i += 1; }
    } else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(anchored ? `^${re}$` : `(?:^|/)${re}$`);
}
// A última regra que casa vence, como no .gitattributes.
function readersOf(policy, file) {
  let hit = null;
  for (const [pat, who] of Object.entries(policy.files)) if (globToRegex(pat).test(file)) hit = who;
  return hit;
}
function expand(policy, names, seen = new Set()) {
  const out = [];
  for (const n of names) {
    if (policy.groups[n]) { if (seen.has(n)) fail(`group cycle at "${n}"`); out.push(...expand(policy, policy.groups[n], new Set([...seen, n]))); }
    else out.push(n);
  }
  return [...new Set(out)];
}
// Nome -> chaves públicas. "@usuario" usa as chaves fixadas em .selo.json (nunca a rede na hora
// de cifrar: chave trocada no GitHub não pode mudar quem lê sem passar por um PR).
function recipientsFor(policy, file) {
  const who = readersOf(policy, file);
  return who ? resolveReaders(policy, who) : null;
}
// Branch privada: mesmos grupos e chaves dos arquivos. Padrão ancorado na raiz do nome
// ("feat/*" casa "feat/x", nunca "outra/feat/x"), porque nome de branch não é caminho.
function branchReaders(policy, name) {
  let hit = null;
  for (const [pat, who] of Object.entries(policy.branches)) if (globToRegex('/' + pat).test(name)) hit = who;
  return hit;
}
function resolveReaders(policy, who) {
  const people = expand(policy, who), recips = [];
  for (const p of people) {
    if (p.startsWith('@')) {
      const ks = policy.keys[p];
      if (!ks || !ks.length) fail(`${p} has no pinned keys. Run \`git selo add ${p}\`.`);
      recips.push(...ks.map(age.parseRecipient));
    } else if (p.startsWith('age1') || p.startsWith('ssh-')) recips.push(age.parseRecipient(p));
    else fail(`unknown group or person "${p}" in ${POLICY}`);
  }
  const uniq = [...new Map(recips.map((r) => [r.id, r])).values()];
  return { people, recips: uniq };
}
const recipsId = (recips) => crypto.createHash('sha256').update(recips.map((r) => r.id).sort().join('\n')).digest('hex');

// O cabeçalho age diz o tipo de cada destinatário e, nas chaves SSH, a etiqueta da chave.
// Comparar isso com a política responde "esse arquivo foi cifrado para quem devia?" sem decifrar.
function matchesPolicy(ct, recips) {
  const have = age.headerRecipients(ct).filter((s) => ['X25519', 'ssh-ed25519', 'ssh-rsa'].includes(s.type));
  const key = (s) => `${s.type}:${s.tag || ''}`;
  return JSON.stringify(have.map(key).sort()) === JSON.stringify(recips.map(key).sort());
}

// ---------- identidades ----------
function loadIdentities(quiet) {
  const warn = quiet ? () => {} : say;
  const home = os.homedir();
  const sources = [];
  if (process.env.SELO_IDENTITY) sources.push(process.env.SELO_IDENTITY);
  const files = [process.env.SELO_IDENTITY_FILE, path.join(process.env.XDG_CONFIG_HOME || path.join(home, '.config'), 'selo', 'identity.txt'),
    path.join(home, '.ssh', 'id_ed25519'), path.join(home, '.ssh', 'id_rsa')].filter(Boolean);
  for (const f of files) if (fs.existsSync(f)) sources.push(fs.readFileSync(f, 'utf8'));
  return sources.flatMap((s) => age.parseIdentities(s, warn));
}

// ---------- cache: cifra estável para o `git status` não acusar mudança a cada leitura ----------
const cacheFile = (file) => path.join(gitDir(), 'selo', crypto.createHash('sha256').update(file).digest('hex'));
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
function cacheGet(file, pt, rid) {
  try { const c = JSON.parse(fs.readFileSync(cacheFile(file), 'utf8')); if (c.pt === sha(pt) && c.r === rid) return Buffer.from(c.ct, 'base64'); } catch {}
  return null;
}
function cachePut(file, pt, rid, ct) {
  const f = cacheFile(file);
  fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o700 });
  fs.writeFileSync(f, JSON.stringify({ pt: sha(pt), r: rid, ct: ct.toString('base64') }), { mode: 0o600 });
}

// ---------- filtros do Git ----------
function clean(file) {
  const input = readStdin();
  if (age.isAge(input)) return process.stdout.write(input); // sem acesso: o arquivo já está cifrado, passa intacto
  const r = recipientsFor(loadPolicy(process.cwd()), file);
  // Recusar é melhor que commitar em claro: o `git add` falha e nada sai cifrado para ninguém.
  if (!r || !r.recips.length) fail(`${file} is protected but has no readers in ${POLICY}; refusing to commit it in plaintext`);
  const rid = recipsId(r.recips);
  let ct = cacheGet(file, input, rid);
  if (!ct) { ct = age.encrypt(input, r.recips); cachePut(file, input, rid, ct); }
  process.stdout.write(ct);
}
function smudge(file) {
  const input = readStdin();
  if (!age.isAge(input)) return process.stdout.write(input);
  let pt = null;
  try { pt = age.decrypt(input, loadIdentities(true)); } catch (e) { say(`${file}: ${e.message}`); }
  if (!pt) return process.stdout.write(input); // sem chave: fica cifrado no disco, o checkout não quebra
  try {
    const r = recipientsFor(loadPolicy(process.cwd()), file);
    if (r && matchesPolicy(input, r.recips)) cachePut(file, pt, recipsId(r.recips), input);
  } catch {}
  process.stdout.write(pt);
}
function textconv(tmp) {
  const buf = fs.readFileSync(tmp);
  if (!age.isAge(buf)) return process.stdout.write(buf);
  const pt = age.decrypt(buf, loadIdentities(true));
  process.stdout.write(pt || '[git-selo: encrypted, you are not a reader]\n');
}

// ---------- comandos ----------
function configureFilters() {
  const cmd = `"${process.execPath}" "${SELF}"`;
  git(['config', 'filter.selo.clean', `${cmd} clean %f`]);
  git(['config', 'filter.selo.smudge', `${cmd} smudge %f`]);
  git(['config', 'filter.selo.required', 'true']);
  git(['config', 'diff.selo.textconv', `${cmd} textconv`]);
  installHook(cmd);
}
// O vazamento mais provável de uma branch privada é o hábito: `git push origin feature`. O hook
// recusa empurrar em texto claro qualquer branch que o .selo.json declara privada.
const HOOK_MARK = '# git-selo pre-push (generated)';
function hookPath() { return path.resolve(root(), git(['rev-parse', '--git-path', 'hooks/pre-push']).trim()); }
function installHook(cmd) {
  const f = hookPath();
  if (fs.existsSync(f) && !fs.readFileSync(f, 'utf8').includes(HOOK_MARK)) { say(`not touching your existing ${path.basename(f)} hook: private branches are not guarded on push`); return; }
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, `#!/bin/sh\n${HOOK_MARK}\nexec ${cmd} pre-push "$@"\n`, { mode: 0o755 });
}
function removeHook() {
  const f = hookPath();
  if (fs.existsSync(f) && fs.readFileSync(f, 'utf8').includes(HOOK_MARK)) fs.rmSync(f);
}
function prePush() {
  const policy = branchPolicy(process.argv[3] || 'origin');
  const bad = [];
  for (const line of readStdin().toString().split('\n')) {
    const [, , remoteRef] = line.trim().split(/\s+/);
    if (remoteRef && remoteRef.startsWith('refs/heads/')) {
      const name = remoteRef.slice('refs/heads/'.length);
      if (branchReaders(policy, name)) bad.push(name);
    }
  }
  if (bad.length) fail(`refusing to push private branch(es) in plaintext: ${bad.join(', ')}. Use \`git selo branch push ${bad[0]}\`.`);
}

// ---------- branches privadas ----------
// A política de uma branch vale a da branch principal do remoto (a revisada em PR), somada à da cópia
// local, que tem prioridade. Sem isso, quem está DENTRO de uma branch privada criada antes da política
// lê um .selo.json velho, que não sabe que a branch é privada (medido no teste do time).
function branchPolicy(remote = 'origin') {
  const local = loadPolicy(root());
  for (const ref of [`refs/remotes/${remote}/HEAD`, `refs/remotes/${remote}/main`, `refs/remotes/${remote}/master`]) {
    let text;
    try { text = git(['show', `${ref}:${POLICY}`], { cwd: root() }); } catch { continue; }
    const base = loadPolicy(root(), text);
    return { groups: { ...base.groups, ...local.groups }, files: local.files,
      branches: { ...base.branches, ...local.branches }, keys: { ...base.keys, ...local.keys } };
  }
  return local;
}
// A branch inteira vira um git bundle (só os commits que o remoto ainda não tem), cifrado em age para
// os leitores e guardado em refs/selo/<nome>: uma ref que `git clone` não baixa e que, para quem não
// está na lista, é um blob ilegível. Quem está na lista recebe de volta uma branch Git comum.
const seloRef = (n) => `refs/selo/${n}`;
function checkBranchName(n) {
  try { git(['check-ref-format', '--branch', n]); } catch { fail(`invalid branch name "${n}"`); }
  if (n.startsWith('-')) fail(`invalid branch name "${n}"`);
}
const BOT = { GIT_AUTHOR_NAME: 'git-selo', GIT_AUTHOR_EMAIL: 'git-selo@localhost', GIT_COMMITTER_NAME: 'git-selo', GIT_COMMITTER_EMAIL: 'git-selo@localhost' };
function branchPush(name, remote, groups) {
  checkBranchName(name);
  const dir = root(), policy = branchPolicy(remote);
  if (groups.length) { const p = loadPolicy(dir); p.branches[name] = groups; savePolicy(p, dir); policy.branches[name] = groups; say(`${POLICY}: branch "${name}" readable by ${groups.join(', ')} (commit this file)`); }
  const who = branchReaders(policy, name);
  if (!who) fail(`branch "${name}" has no readers in ${POLICY}. Use \`git selo branch push ${name} --for <group>\`.`);
  try { git(['rev-parse', '--verify', '--quiet', `refs/heads/${name}`]); } catch { fail(`no local branch "${name}"`); }
  const r = resolveReaders(policy, who);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selo-b-')), file = path.join(tmp, 'b.bundle');
  try {
    try { git(['bundle', 'create', file, `refs/heads/${name}`, '--not', `--remotes=${remote}`]); }
    catch (e) { if (/empty bundle/i.test(String(e.stderr))) fail(`every commit of "${name}" is already on ${remote}: nothing private to push`); throw e; }
    const ct = age.encrypt(fs.readFileSync(file), r.recips);
    const blob = git(['hash-object', '-w', '--stdin'], { input: ct }).trim();
    const tree = git(['mktree'], { input: `100644 blob ${blob}\tbundle.age\n` }).trim();
    const commit = git(['commit-tree', tree, '-m', `git-selo private branch ${name}`], { env: { ...process.env, ...BOT } }).trim();
    git(['update-ref', seloRef(name), commit]);
    git(['push', '--quiet', remote, `+${seloRef(name)}:${seloRef(name)}`], { cwd: dir });
    const n = git(['rev-list', '--count', `refs/heads/${name}`, '--not', `--remotes=${remote}`]).trim();
    console.log(`pushed private branch "${name}" (${n} commit(s), ${r.people.join(', ')}) as ${seloRef(name)}`);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}
function fetchSelo(remote, name = '*') {
  try { git(['fetch', '--quiet', remote, `+${seloRef(name)}:${seloRef(name)}`], { cwd: root() }); }
  catch (e) { if (name !== '*') fail(`no private branch "${name}" on ${remote}`); }
}
function branchPull(name, remote, force) {
  checkBranchName(name);
  fetchSelo(remote, name);
  const ct = git(['cat-file', 'blob', `${seloRef(name)}:bundle.age`], { raw: true });
  const pt = age.decrypt(ct, loadIdentities());
  if (!pt) fail(`you are not a reader of private branch "${name}"`);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'selo-b-')), file = path.join(tmp, 'b.bundle');
  try {
    fs.writeFileSync(file, pt);
    try { git(['bundle', 'verify', '--quiet', file]); }
    catch { fail(`missing the public history this branch builds on: run \`git fetch ${remote}\` and try again`); }
    const current = (() => { try { return git(['symbolic-ref', '--quiet', '--short', 'HEAD']).trim(); } catch { return ''; } })();
    if (current === name) {
      // Branch em uso: busca para uma ref temporária e avança só se for fast-forward.
      git(['fetch', '--quiet', file, `+refs/heads/${name}:refs/selo-pull/${name}`]);
      git(['merge', '--ff-only', '--quiet', `refs/selo-pull/${name}`], { cwd: root() });
      git(['update-ref', '-d', `refs/selo-pull/${name}`]);
    } else {
      git(['fetch', '--quiet', file, `${force ? '+' : ''}refs/heads/${name}:refs/heads/${name}`]);
    }
    console.log(`private branch "${name}" is now local (${git(['rev-parse', '--short', `refs/heads/${name}`]).trim()})`);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}
function branchList(remote) {
  fetchSelo(remote);
  const names = git(['for-each-ref', '--format=%(refname:strip=2)', 'refs/selo/']).split('\n').filter(Boolean);
  if (!names.length) { console.log(`no private branches on ${remote}`); return; }
  const ids = loadIdentities(true), policy = branchPolicy(remote);
  for (const n of names) {
    const ct = git(['cat-file', 'blob', `${seloRef(n)}:bundle.age`], { raw: true });
    let can = false; try { can = !!age.decrypt(ct, ids); } catch {}
    const who = branchReaders(policy, n);
    console.log(`${n}\n  readers: ${who ? resolveReaders(policy, who).people.join(', ') : '(not in .selo.json)'}\n  ${can ? 'you can read' : 'encrypted (not for you)'}`);
  }
}
function syncAttributes(policy, dir = root()) {
  const file = path.join(dir, '.gitattributes');
  const old = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  const kept = old.replace(new RegExp(`\\n?${BEGIN.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[\\s\\S]*?${END}\\n?`), '\n').replace(/^\n+/, '');
  for (const pat of Object.keys(policy.files)) if (/\s/.test(pat)) fail(`pattern "${pat}" has whitespace; not supported`);
  const block = [BEGIN, ...Object.keys(policy.files).map((p) => `${p} filter=selo diff=selo`), END].join('\n') + '\n';
  const next = (kept.trim() ? kept.replace(/\n*$/, '\n\n') : '') + block;
  if (next !== old) fs.writeFileSync(file, next);
  return next;
}
const tracked = () => git(['ls-files', '-z']).split('\0').filter(Boolean);
const protectedFiles = (policy) => tracked().filter((f) => readersOf(policy, f));

// Recifra os arquivos protegidos para a lista de leitores atual (o `clean` refaz o cifrado
// quando a lista muda). Precisa de quem tem acesso: sem o texto claro não há o que recifrar.
function rekey(policy) {
  const files = protectedFiles(policy), stuck = [];
  for (const f of files) {
    const p = path.join(root(), f);
    if (fs.existsSync(p) && age.isAge(fs.readFileSync(p))) stuck.push(f);
  }
  const ok = files.filter((f) => !stuck.includes(f));
  if (ok.length) git(['add', '--renormalize', '--', ...ok], { cwd: root() });
  if (stuck.length) say(`could not re-encrypt (you are not a reader): ${stuck.join(', ')}`);
  return { ok, stuck };
}

async function fetchKeys(user) {
  const base = process.env.SELO_GITHUB_URL || 'https://github.com';
  const res = await fetch(`${base}/${encodeURIComponent(user)}.keys`);
  if (!res.ok) fail(`could not fetch keys for @${user} (${res.status})`);
  const keys = (await res.text()).split('\n').map((l) => l.trim()).filter((l) => /^ssh-(ed25519|rsa) /.test(l)).map((l) => l.split(/\s+/).slice(0, 2).join(' '));
  if (!keys.length) fail(`@${user} has no ssh-ed25519 or ssh-rsa key on GitHub. They can run \`git selo key\` and send you the age1… key instead.`);
  return keys;
}

const HELP = `git selo — private files inside a normal Git repo

  git selo init                        create .selo.json, protect .env*, set up this clone
  git selo add @user [--to group]      give a GitHub user (their SSH keys) read access
  git selo add age1… [--to group]      same, with an age key (CI, or no SSH key)
  git selo remove @user [--from group] revoke and re-encrypt
  git selo protect <pattern> [--for group]   encrypt files matching a .gitattributes pattern
  git selo status                      who can read what, and can you
  git selo check [--strict]            CI gate: fail if a protected file is in plaintext or
                                       encrypted for the wrong people
  git selo unlock / lock               decrypt this clone / put the ciphertext back
  git selo key                         make a dedicated key (~/.config/selo/identity.txt)
  git selo --version                   print the installed version
  git selo cat <file> [--rev REV]      print a protected file from any revision
  git selo branch push <b> [--for g]   push a whole branch encrypted (refs/selo/<b>)
  git selo branch pull <b>             get a private branch back as a normal branch
  git selo branch list                 private branches on the remote, and which you can read

Readers decrypt with ~/.ssh/id_ed25519 or id_rsa, $SELO_IDENTITY, or the selo key.
Files are standard age (https://age-encryption.org): \`age -d -i ~/.ssh/id_ed25519 file\` works too.`;

function flag(args, name) { const i = args.indexOf(name); if (i < 0) return null; const v = args[i + 1]; args.splice(i, 2); return v; }

async function main(argv) {
  const [cmd, ...args] = argv;
  switch (cmd) {
    case 'clean': return clean(args[0]);
    case 'smudge': return smudge(args[0]);
    case 'textconv': return textconv(args[0]);
    case 'pre-push': return prePush();
    case 'branch': {
      const [sub, name] = args;
      const remote = flag(args, '--remote') || 'origin';
      if (sub === 'push') { const groups = []; let g; while ((g = flag(args, '--for'))) groups.push(g); return branchPush(args[1], remote, groups); }
      if (sub === 'pull') return branchPull(name, remote, args.includes('--force'));
      if (sub === 'list') return branchList(remote);
      fail('usage: git selo branch push <name> [--for group] | pull <name> [--force] | list   [--remote R]');
    }
    case 'init': {
      const dir = root(), file = path.join(dir, POLICY);
      if (!fs.existsSync(file)) savePolicy({ groups: { team: [] }, files: { '.env*': ['team'] }, keys: {} }, dir);
      syncAttributes(loadPolicy(dir), dir);
      configureFilters();
      console.log(`Ready. Next:\n  git selo add @your-github-user\n  git selo add @teammate\n  git add .selo.json .gitattributes .env && git commit -m "chore: private .env with git selo"`);
      return;
    }
    case 'add': case 'remove': {
      const group = flag(args, cmd === 'add' ? '--to' : '--from') || 'team';
      if (!args.length) fail(`usage: git selo ${cmd} @user|age1… [${cmd === 'add' ? '--to' : '--from'} group]`);
      const p = loadPolicy();
      for (const who of args) {
        if (cmd === 'add') {
          if (who.startsWith('@')) { p.keys[who] = await fetchKeys(who.slice(1)); console.log(`${who}: pinned ${p.keys[who].length} key(s)`); }
          else age.parseRecipient(who);
          p.groups[group] = [...new Set([...(p.groups[group] || []), who])];
        } else {
          p.groups[group] = (p.groups[group] || []).filter((x) => x !== who);
          if (who.startsWith('@') && !Object.values(p.groups).some((g) => g.includes(who)) && !Object.values(p.files).some((g) => g.includes(who))) delete p.keys[who];
        }
      }
      savePolicy(p); syncAttributes(p); configureFilters();
      const { ok } = rekey(p);
      console.log(`${ok.length} file(s) re-encrypted and staged. Review with \`git selo status\`, then commit.`);
      if (cmd === 'remove') console.log('Note: they can still read old commits they already had. Rotate the secrets themselves (new API keys, new passwords).');
      return;
    }
    case 'protect': {
      const group = flag(args, '--for') || 'team';
      if (!args.length) fail('usage: git selo protect <pattern> [--for group]');
      const p = loadPolicy();
      for (const pat of args) p.files[pat] = [group];
      savePolicy(p); syncAttributes(p); configureFilters();
      const { ok } = rekey(p);
      console.log(`${ok.length} file(s) encrypted and staged.`);
      return;
    }
    case 'status': {
      const p = loadPolicy(), ids = loadIdentities(true);
      const mine = new Set(ids.map((i) => (i.type === 'X25519' ? `X25519:` : `${i.type}:${i.tag}`)));
      const files = protectedFiles(p);
      if (!files.length) console.log('No protected files tracked yet.');
      for (const f of files) {
        const ct = git(['cat-file', 'blob', `:${f}`], { raw: true, cwd: root() });
        const r = recipientsFor(p, f);
        let state;
        if (!age.isAge(ct)) state = 'PLAINTEXT in index (!)';
        else if (!matchesPolicy(ct, r.recips)) state = 'stale: run `git selo unlock` then re-add, or ask a reader';
        else state = age.headerRecipients(ct).some((s) => mine.has(`${s.type}:${s.tag || ''}`)) && age.decrypt(ct, ids) ? 'you can read' : 'encrypted (not for you)';
        console.log(`${f}\n  readers: ${r.people.join(', ')}\n  ${state}`);
      }
      return;
    }
    case 'check': {
      const strict = args.includes('--strict');
      const dir = root(), p = loadPolicy(dir), problems = [], warnings = [];
      const attrs = fs.existsSync(path.join(dir, '.gitattributes')) ? fs.readFileSync(path.join(dir, '.gitattributes'), 'utf8') : '';
      for (const pat of Object.keys(p.files)) if (!attrs.includes(`${pat} filter=selo`)) problems.push(`.gitattributes is missing "${pat}": run \`git selo sync\``);
      for (const f of tracked()) {
        const who = readersOf(p, f);
        if (!who) { if (SECRETISH.some((re) => re.test(f))) (strict ? problems : warnings).push(`${f} looks like a secret but is not protected (git selo protect ${f})`); continue; }
        const blob = git(['cat-file', 'blob', `:${f}`], { raw: true, cwd: dir });
        if (!age.isAge(blob)) { problems.push(`${f} is committed in PLAINTEXT`); continue; }
        const r = recipientsFor(p, f);
        if (!matchesPolicy(blob, r.recips)) problems.push(`${f} is encrypted for a different set of readers than ${POLICY} says (a reader must run \`git selo add\`/\`remove\` again)`);
      }
      warnings.forEach((w) => say(`warning: ${w}`));
      if (problems.length) { problems.forEach((m) => say(`FAIL: ${m}`)); process.exitCode = 1; return; }
      console.log(`git-selo: ok (${protectedFiles(p).length} protected file(s) encrypted for the right readers)`);
      return;
    }
    case 'sync': { syncAttributes(loadPolicy()); configureFilters(); console.log('.gitattributes in sync'); return; }
    case 'unlock': case 'lock': {
      const dir = root(), files = protectedFiles(loadPolicy(dir));
      // Conferir antes de mexer nos filtros: sem o filtro, o Git compara texto claro com o
      // cifrado do índice e acusa mudança que não existe (só quando o mtime é ambíguo, por isso intermitente).
      const dirty = files.length ? git(['status', '--porcelain', '--', ...files], { cwd: dir }).trim() : '';
      if (dirty) fail(`commit or stash changes to protected files first:\n${dirty}`);
      if (cmd === 'unlock') configureFilters();
      else for (const k of ['filter.selo.clean', 'filter.selo.smudge', 'filter.selo.required', 'diff.selo.textconv']) try { git(['config', '--unset', k]); } catch {}
      for (const f of files) fs.rmSync(path.join(dir, f), { force: true });
      if (files.length) git(['checkout', '--', ...files], { cwd: dir });
      if (cmd === 'lock') { for (const f of files) fs.rmSync(cacheFile(f), { force: true }); removeHook(); }
      console.log(cmd === 'unlock' ? `${files.length} protected file(s) checked out (decrypted where you are a reader)` : `${files.length} file(s) back to ciphertext; filters removed from this clone`);
      return;
    }
    case 'key': {
      const f = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'selo', 'identity.txt');
      if (!fs.existsSync(f)) {
        const id = age.generateIdentity();
        fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o700 });
        fs.writeFileSync(f, `# git-selo identity, public key: ${id.recipient}\n${id.secret}\n`, { mode: 0o600 });
        say(`created ${f}`);
      }
      const pub = age.parseIdentities(fs.readFileSync(f, 'utf8'))[0].recipient;
      console.log(pub);
      return;
    }
    case 'cat': {
      const rev = flag(args, '--rev');
      const blob = git(['cat-file', 'blob', rev ? `${rev}:${args[0]}` : `:${args[0]}`], { raw: true, cwd: root() });
      const pt = age.isAge(blob) ? age.decrypt(blob, loadIdentities()) : blob;
      if (!pt) fail(`you are not a reader of ${args[0]}`);
      process.stdout.write(pt);
      return;
    }
    case '-v': case '--version': case 'version': {
      // Lido do package.json ao lado: um número só, o mesmo que o npm publica.
      console.log(JSON.parse(fs.readFileSync(path.join(path.dirname(SELF), 'package.json'), 'utf8')).version);
      return;
    }
    case undefined: case '-h': case '--help': case 'help': console.log(HELP); return;
    default: fail(`unknown command "${cmd}". See \`git selo help\`.`);
  }
}

main(process.argv.slice(2)).catch((e) => {
  if (e instanceof UserError) say(e.message);
  else if (e.stderr) say(String(e.stderr).trim() || e.message);
  else say(e.stack || e.message);
  process.exit(1);
});
