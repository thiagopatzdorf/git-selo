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
  return { groups: p.groups || {}, files: p.files || {}, branches: p.branches || {}, keys: p.keys || {}, ...(p.trace ? { trace: p.trace } : {}) };
}
function savePolicy(p, dir = root()) {
  const sorted = { groups: p.groups, files: p.files, ...(Object.keys(p.branches || {}).length ? { branches: p.branches } : {}), ...(p.trace ? { trace: p.trace } : {}), keys: Object.fromEntries(Object.entries(p.keys).sort()) };
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
  let input = readStdin();
  if (age.isAge(input)) return process.stdout.write(input); // sem acesso: o arquivo já está cifrado, passa intacto
  const policy = loadPolicy(process.cwd());
  // A marca do leitor nunca entra no repositório. A regra lembrada no clone cobre quem puxou um `trace off`
  // e ainda tem a marca antiga no disco: sem ela, o próximo commit levaria o token junto.
  for (const t of [policy.trace, localTrace().trace]) if (t) input = traceUnmark(input, t);
  const r = recipientsFor(policy, file);
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
  let out = pt;
  try {
    const policy = loadPolicy(process.cwd());
    const r = recipientsFor(policy, file);
    if (r && matchesPolicy(input, r.recips)) cachePut(file, pt, recipsId(r.recips), input);
    const token = policy.trace && myTraceToken();
    if (token) out = traceMark(file, pt, policy.trace, token);
  } catch {}
  process.stdout.write(out);
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
// `extras` são arquivos já cifrados que viajam junto do bundle (ex.: a revisão trazida da sala).
// O que já estava na ref além do bundle é mantido, para um push não apagar a revisão de outro.
function branchPush(name, remote, groups, extras = []) {
  checkBranchName(name);
  try { git(['fetch', '--quiet', remote, `+${seloRef(name)}:${seloRef(name)}`], { cwd: root() }); } catch {}
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
    let kept = [];
    try { kept = git(['ls-tree', seloRef(name)]).split('\n').filter((l) => l && !l.endsWith('\tbundle.age')); } catch {}
    const added = extras.map((e) => `100644 blob ${git(['hash-object', '-w', '--stdin'], { input: e.data }).trim()}\t${e.name}`);
    const tree = git(['mktree'], { input: [`100644 blob ${blob}\tbundle.age`, ...kept, ...added].join('\n') + '\n' }).trim();
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
// ---------- revisão, sala e merge ----------
// A base da revisão é a branch principal do remoto: a mesma que a política usa.
function baseRef(remote, base) {
  const cands = base ? [base] : [`refs/remotes/${remote}/HEAD`, `refs/remotes/${remote}/main`, `refs/remotes/${remote}/master`, 'refs/heads/main', 'refs/heads/master'];
  for (const c of cands) {
    try {
      git(['rev-parse', '--verify', '--quiet', `${c}^{commit}`]);
      const full = git(['rev-parse', '--symbolic-full-name', c]).trim() || c;
      return { ref: c, name: full.replace(/^refs\/(remotes\/[^/]+|heads)\//, '') };
    } catch {}
  }
  fail(base ? `no such base "${base}"` : 'could not find the base branch; pass --base <branch>');
}
function needLocal(name) {
  checkBranchName(name);
  try { git(['rev-parse', '--verify', '--quiet', `refs/heads/${name}`]); } catch { fail(`no local branch "${name}": run \`git selo branch pull ${name}\` first`); }
}
// As revisões trazidas da sala ficam em refs/selo/<b> como review-*.json.age, cifradas para os leitores.
function savedReviews(name) {
  let lines = [];
  try { lines = git(['ls-tree', seloRef(name)]).split('\n').filter((l) => /\treview-[^/]+\.json\.age$/.test(l)); } catch { return []; }
  const ids = loadIdentities(true), out = [];
  for (const l of lines) {
    const pt = age.decrypt(git(['cat-file', 'blob', l.split(/\s+/)[2]], { raw: true }), ids);
    if (pt) out.push(JSON.parse(pt.toString('utf8')));
  }
  return out.sort((a, b) => String(a.closedAt).localeCompare(String(b.closedAt)));
}
const esc = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
function branchReview(name, remote, base, html) {
  needLocal(name);
  const b = baseRef(remote, base), head = `refs/heads/${name}`;
  const log = git(['log', '--format=%h %an: %s', `${b.ref}..${head}`]).trim();
  const stat = git(['diff', '--no-color', '--stat', `${b.ref}...${head}`]).trim();
  // O diff passa pelo textconv do selo: quem é leitor vê os arquivos protegidos em texto claro.
  const diff = git(['diff', '--no-color', `${b.ref}...${head}`]);
  const reviews = savedReviews(name);
  if (html) {
    const cls = (l) => (/^(diff |index |--- |\+\+\+ )/.test(l) ? 'h' : l.startsWith('@@') ? 'k' : l.startsWith('+') ? 'a' : l.startsWith('-') ? 'd' : '');
    const lines = diff.split('\n').map((l) => `<span class="${cls(l)}">${esc(l)}</span>`).join('\n');
    const rv = reviews.map((r) => `<h2>Review from ${esc(r.room)} (${esc(r.closedAt)})</h2><ul>${[...r.reviews, ...r.comments, ...r.conversation].map((c) => `<li><b>${esc(c.user)}</b>${c.path ? ` <code>${esc(c.path)}${c.line ? ':' + esc(c.line) : ''}</code>` : ''}${c.state ? ` [${esc(c.state)}]` : ''}: ${esc(c.body)}</li>`).join('')}</ul>`).join('');
    fs.writeFileSync(html, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(name)} vs ${esc(b.name)}</title>
<style>:root{color-scheme:light dark;--bg:#fff;--fg:#1f2328;--a:#dafbe1;--d:#ffebe9;--k:#ddf4ff;--m:#59636e}@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--a:#12361f;--d:#4b1619;--k:#0c2d6b;--m:#9198a1}}body{background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:16px}pre{font:12px ui-monospace,monospace;overflow-x:auto}pre span{display:block;white-space:pre}.a{background:var(--a)}.d{background:var(--d)}.k{background:var(--k)}.h{font-weight:700}small{color:var(--m)}</style>
<h1>${esc(name)} <small>vs ${esc(b.name)}</small></h1><p><small>Private branch, rendered locally by git selo. This file holds plaintext: don't commit or share it.</small></p>
<h2>Commits</h2><pre>${esc(log || '(none)')}</pre><h2>Files</h2><pre>${esc(stat)}</pre>${rv}<h2>Diff</h2><pre>${lines}</pre>\n`, { mode: 0o600 });
    console.log(`wrote ${html} (plaintext; open it in your browser, don't commit it)`);
    return;
  }
  console.log(`# ${name} vs ${b.name}\n\n## commits\n${log || '(none)'}\n\n## files\n${stat}\n`);
  for (const r of reviews) {
    console.log(`## review from ${r.room} (${r.closedAt})`);
    for (const c of [...r.reviews, ...r.comments, ...r.conversation]) console.log(`- ${c.user}${c.path ? ` ${c.path}${c.line ? ':' + c.line : ''}` : ''}${c.state ? ` [${c.state}]` : ''}: ${c.body}`);
    console.log('');
  }
  process.stdout.write(diff);
}

// Sala de revisão: um repositório PRIVADO temporário no GitHub com exatamente os leitores da branch,
// para ter a tela de PR de verdade. Fecha trazendo de volta os commits e a conversa, cifrados, e apaga.
function ghToken() {
  const t = process.env.SELO_GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (t) return t;
  try { return execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
  catch { fail('the review room needs a GitHub token: run `gh auth login`, or set GITHUB_TOKEN'); }
}
async function gh(method, url, body) {
  const api = process.env.SELO_GITHUB_API || 'https://api.github.com';
  const res = await fetch(api + url, { method, body: body ? JSON.stringify(body) : undefined,
    headers: { authorization: `Bearer ${ghToken()}`, accept: 'application/vnd.github+json', 'user-agent': 'git-selo', 'x-github-api-version': '2022-11-28', ...(body ? { 'content-type': 'application/json' } : {}) } });
  const text = await res.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch {}
  return { status: res.status, data };
}
const roomUrl = (full) => (process.env.SELO_ROOM_GIT_URL || 'https://github.com/{repo}.git').replace('{repo}', full);
// O token vai para o git por variável de ambiente (GIT_CONFIG_*), nunca na linha de comando nem na URL.
function roomGit(full, args) {
  const url = roomUrl(full), env = { ...process.env };
  if (url.startsWith('https://github.com/')) {
    Object.assign(env, { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
      GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${ghToken()}`).toString('base64')}` });
  }
  return git(args.map((a) => (a === '{url}' ? url : a)), { cwd: root(), env });
}
const roomCfg = (name, key) => { try { return git(['config', '--get', `selo.room.${name}.${key}`]).trim(); } catch { return ''; } };
async function roomOpen(name, remote, base, owner) {
  needLocal(name);
  if (roomCfg(name, 'repo')) fail(`a review room for "${name}" is already open: ${roomCfg(name, 'url')}`);
  const policy = branchPolicy(remote), who = branchReaders(policy, name);
  if (!who) fail(`branch "${name}" is not private in ${POLICY}: there is nobody to invite`);
  const people = resolveReaders(policy, who).people, b = baseRef(remote, base);
  const me = await gh('GET', '/user');
  if (me.status !== 200) fail(`GitHub said ${me.status} to /user: check your token`);
  const login = me.data.login;
  const slug = (s) => s.replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 40);
  const repoName = `selo-room-${slug(path.basename(root()))}-${slug(name)}-${crypto.randomBytes(3).toString('hex')}`;
  const spec = { name: repoName, private: true, has_issues: false, has_wiki: false, has_projects: false, auto_init: false,
    description: `Temporary git-selo review room for a private branch. Deleted by \`git selo room close\`.` };
  const made = owner && owner !== login ? await gh('POST', `/orgs/${encodeURIComponent(owner)}/repos`, spec) : await gh('POST', '/user/repos', spec);
  if (made.status !== 201) fail(`could not create the room (${made.status}: ${made.data?.message || ''})`);
  if (made.data.private !== true) { await gh('DELETE', `/repos/${made.data.full_name}`); fail('GitHub created the room as public; deleted it'); }
  const full = made.data.full_name;
  git(['config', `selo.room.${name}.repo`, full]);
  const invited = [], skipped = [];
  for (const p of people) {
    if (!p.startsWith('@')) { skipped.push(p); continue; }
    const u = p.slice(1);
    if (u.toLowerCase() === login.toLowerCase()) continue;
    const r = await gh('PUT', `/repos/${full}/collaborators/${encodeURIComponent(u)}`, { permission: 'push' });
    if (r.status === 201 || r.status === 204) invited.push(p); else skipped.push(`${p} (${r.status})`);
  }
  // --no-verify: o hook barra branch privada indo para qualquer remoto; a sala é o único lugar onde ela pode ir.
  roomGit(full, ['push', '--quiet', '--no-verify', '{url}', `${b.ref}:refs/heads/${b.name}`, `refs/heads/${name}:refs/heads/${name}`]);
  const pr = await gh('POST', `/repos/${full}/pulls`, { title: `${name} → ${b.name}`, head: name, base: b.name,
    body: `Private review room made by [git selo](https://github.com/thiagopatzdorf/git-selo).\n\nOnly the readers of \`${name}\` are here: ${people.join(', ')}.\n\nReview as usual and push commits to \`${name}\`. **Don't click Merge**: when you're done, the author runs \`git selo room close ${name}\`, which brings the commits and this conversation back encrypted and deletes this repository.` });
  if (pr.status !== 201) fail(`room ${full} created, but the pull request failed (${pr.status}: ${pr.data?.message || ''}). Close it with \`git selo room close ${name}\``);
  git(['config', `selo.room.${name}.pr`, String(pr.data.number)]);
  git(['config', `selo.room.${name}.base`, b.name]);
  git(['config', `selo.room.${name}.url`, pr.data.html_url]);
  console.log(`review room open: ${pr.data.html_url}\n  private repo ${full}, invited: ${invited.join(', ') || '(only you)'}`);
  if (skipped.length) say(`not invited (no GitHub user or the invite failed): ${skipped.join(', ')}`);
  console.log(`invitees accept the invite from GitHub's email or https://github.com/${full}/invitations\nwhen done: git selo room close ${name}`);
}
async function roomClose(name, remote, keep) {
  checkBranchName(name);
  const full = roomCfg(name, 'repo'), number = roomCfg(name, 'pr');
  if (!full) fail(`no review room open for "${name}"`);
  // Revisão já guardada numa tentativa anterior (a exclusão falhou): só falta apagar, sem duplicar.
  if (roomCfg(name, 'saved') !== 'true') await roomSave(name, remote, full, number);
  if (keep) { console.log(`room kept open: ${roomCfg(name, 'url')}`); return; }
  const del = await gh('DELETE', `/repos/${full}`);
  if (del.status === 204 || del.status === 404) {
    try { git(['config', '--remove-section', `selo.room.${name}`]); } catch {}
    console.log(`room ${full} deleted`);
  } else {
    git(['config', `selo.room.${name}.saved`, 'true']);
    fail(`could not delete ${full} (${del.status}${del.status === 403 ? ': the token needs the delete_repo scope, `gh auth refresh -s delete_repo`' : ''}). The review is saved; delete it at https://github.com/${full}/settings or run \`git selo room close ${name}\` again`);
  }
}
async function roomSave(name, remote, full, number) {
  const tmpRef = `refs/selo-room/${name}`;
  roomGit(full, ['fetch', '--quiet', '{url}', `+refs/heads/${name}:${tmpRef}`]);
  const local = git(['rev-parse', `refs/heads/${name}`]).trim(), there = git(['rev-parse', tmpRef]).trim();
  const isAnc = (a, b2) => { try { git(['merge-base', '--is-ancestor', a, b2]); return true; } catch { return false; } };
  if (local !== there) {
    if (isAnc(local, there)) {
      const current = (() => { try { return git(['symbolic-ref', '--quiet', '--short', 'HEAD']).trim(); } catch { return ''; } })();
      if (current === name) git(['merge', '--ff-only', '--quiet', tmpRef], { cwd: root() });
      else git(['update-ref', `refs/heads/${name}`, there, local]);
      say(`brought back ${git(['rev-list', '--count', `${local}..${there}`]).trim()} commit(s) from the room`);
    } else if (!isAnc(there, local)) {
      fail(`"${name}" changed both here and in the room. Merge ${tmpRef} into it, then run \`git selo room close ${name}\` again`);
    }
  }
  const conv = { room: full, pr: Number(number) || null, closedAt: new Date().toISOString(), reviews: [], comments: [], conversation: [] };
  if (number) {
    const list = async (u) => { const r = await gh('GET', `${u}?per_page=100`); return Array.isArray(r.data) ? r.data : []; };
    conv.reviews = (await list(`/repos/${full}/pulls/${number}/reviews`)).filter((r) => r.body || r.state !== 'COMMENTED').map((r) => ({ user: r.user?.login, state: r.state, body: r.body || '', at: r.submitted_at }));
    conv.comments = (await list(`/repos/${full}/pulls/${number}/comments`)).map((c) => ({ user: c.user?.login, path: c.path, line: c.line ?? c.original_line ?? null, body: c.body, at: c.created_at }));
    conv.conversation = (await list(`/repos/${full}/issues/${number}/comments`)).map((c) => ({ user: c.user?.login, body: c.body, at: c.created_at }));
  }
  const policy = branchPolicy(remote), r = resolveReaders(policy, branchReaders(policy, name) || fail(`branch "${name}" is not private in ${POLICY}`));
  const stamp = conv.closedAt.replace(/[:.]/g, '-');
  branchPush(name, remote, [], [{ name: `review-${stamp}.json.age`, data: age.encrypt(Buffer.from(JSON.stringify(conv, null, 2)), r.recips) }]);
  git(['update-ref', '-d', tmpRef]);
  const n = conv.reviews.length + conv.comments.length + conv.conversation.length;
  console.log(`saved ${n} review item(s), encrypted, in ${seloRef(name)} (read them with \`git selo branch review ${name}\`)`);
}

// Publicar: o merge na branch principal é o momento de revelar a branch. Os arquivos protegidos pela
// camada de arquivos ("files" no .selo.json) continuam cifrados, porque o Git guarda o cifrado.
function mergePolicies(ours, theirs, drop) {
  const groups = { ...ours.groups };
  for (const [g, m] of Object.entries(theirs.groups)) groups[g] = [...new Set([...(groups[g] || []), ...m])];
  const branches = { ...ours.branches, ...theirs.branches }; delete branches[drop];
  return { groups, files: { ...ours.files, ...theirs.files }, branches, keys: { ...ours.keys, ...theirs.keys } };
}
function branchMerge(name, remote, into, noPush) {
  needLocal(name);
  const dir = root();
  if (git(['status', '--porcelain', '--untracked-files=no'], { cwd: dir }).trim()) fail('commit or stash your changes first');
  const target = into || baseRef(remote).name;
  git(['checkout', '--quiet', target], { cwd: dir });
  const msg = `Merge private branch '${name}' into ${target}`;
  let conflicted = [];
  try { git(['merge', '--no-ff', '--no-commit', '--quiet', `refs/heads/${name}`], { cwd: dir }); }
  catch { conflicted = git(['diff', '--name-only', '--diff-filter=U'], { cwd: dir }).split('\n').filter(Boolean); if (!conflicted.length) throw new Error('merge failed'); }
  // A lista de quem lê é gerada: se só ela conflita, a união é determinística e não precisa de gente.
  if (conflicted.some((f) => f !== POLICY && f !== '.gitattributes')) {
    git(['merge', '--abort'], { cwd: dir });
    fail(`conflicts in ${conflicted.join(', ')}: merge "${name}" by hand, then run \`git selo branch merge ${name}\` again (or delete ${seloRef(name)} yourself)`);
  }
  const stage = (n, f) => { try { return git(['show', `:${n}:${f}`], { cwd: dir }); } catch { return undefined; } };
  const ours = conflicted.includes(POLICY) ? loadPolicy(dir, stage(2, POLICY)) : loadPolicy(dir);
  const theirs = conflicted.includes(POLICY) ? loadPolicy(dir, stage(3, POLICY)) : ours;
  if (conflicted.includes('.gitattributes')) fs.writeFileSync(path.join(dir, '.gitattributes'), stage(2, '.gitattributes') || '');
  const merged = mergePolicies(ours, theirs, name);
  savePolicy(merged, dir); syncAttributes(merged, dir);
  git(['add', POLICY, '.gitattributes'], { cwd: dir });
  if (conflicted.length) console.log(`${conflicted.join(' and ')}: both sides changed the reader list; merged them (union, ${name} no longer private)`);
  git(['commit', '--quiet', '--no-verify', '-m', msg], { cwd: dir });
  if (noPush) { console.log(`merged "${name}" into ${target} locally. Push ${target}, then: git push ${remote} :${seloRef(name)}`); return; }
  git(['push', '--quiet', remote, `refs/heads/${target}:refs/heads/${target}`], { cwd: dir });
  try { git(['push', '--quiet', remote, `:${seloRef(name)}`], { cwd: dir }); } catch {}
  try { git(['update-ref', '-d', seloRef(name)]); } catch {}
  const kept = protectedFiles(merged).length;
  console.log(`merged "${name}" into ${target} and pushed it; ${seloRef(name)} removed. ${kept} protected file(s) stay encrypted.`);
}
// ---------- rastro: uma marca por leitor dentro da cópia decifrada ----------
// Quem decifra recebe os arquivos com uma marca que só a cópia dele tem: nos .env, uma linha com um
// link-isca (quem abrir o link dispara um e-mail ao dono); no código, uma linha de comentário com o
// token em caracteres de largura zero. O `clean` tira a marca antes de cifrar, então o repositório
// nunca guarda token nenhum e o `git status` continua limpo.
export const TRACE_DEFAULT_SERVER = 'https://rastro.genesisinnovation.io';
const TRACE_DIR = '.selo-trace';
const COMMENT = { '//': ['js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'go', 'rs', 'java', 'kt', 'c', 'h', 'cc', 'cpp', 'hpp', 'cs', 'swift', 'php', 'scss', 'dart'],
  '#': ['py', 'rb', 'sh', 'bash', 'zsh', 'yml', 'yaml', 'toml', 'conf', 'ini', 'pl', 'r', 'tf', 'tfvars'], '--': ['sql', 'lua', 'hs'] };
const ZW0 = '\u200B', ZW1 = '\u200C', ZWNL = '\u200D'; // 0, 1, e "a marca acrescentou a quebra de linha final"
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const isEnv = (f) => /(^|\/)\.env(\..+)?$|\.env$/.test(f);
const commentOf = (f) => { const ext = path.extname(f).slice(1).toLowerCase(); return Object.keys(COMMENT).find((k) => COMMENT[k].includes(ext)) || null; };
export const zwEncode = (t) => [...t].map((c) => B64.indexOf(c).toString(2).padStart(6, '0')).join('').replace(/0/g, ZW0).replace(/1/g, ZW1);
export const zwDecode = (z) => { const bits = z.replace(new RegExp(ZW0, 'g'), '0').replace(new RegExp(ZW1, 'g'), '1'); let o = ''; for (let i = 0; i + 6 <= bits.length; i += 6) o += B64[parseInt(bits.slice(i, i + 6), 2)]; return o; };
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
function markRegexes(trace) {
  return [new RegExp(`^${escRe(trace.var)}=\\S*/c/([\\w-]{8,64})(${ZWNL})?$`, 'm'), new RegExp(`^(?://|#|--) ([${ZW0}${ZW1}]{48,384})(${ZWNL})?$`, 'm')];
}
export function traceMark(file, pt, trace, token) {
  if (pt.includes(0)) return pt; // binário não leva marca
  let line;
  if (isEnv(file)) line = `${trace.var}=${trace.server.replace(/\/$/, '')}/c/${token}`;
  else if (commentOf(file)) line = `${commentOf(file)} ${zwEncode(token)}`;
  else return pt;
  const s = pt.toString('utf8'), nl = s.length && !s.endsWith('\n');
  return Buffer.from(s + (nl ? '\n' : '') + line + (nl ? ZWNL : '') + '\n');
}
export function traceUnmark(pt, trace) {
  if (pt.includes(0)) return pt;
  let s = pt.toString('utf8');
  for (const re of markRegexes(trace)) {
    const m = s.match(re);
    if (!m) continue;
    const start = m.index, end = start + m[0].length + (s[start + m[0].length] === '\n' ? 1 : 0);
    // A marca acrescentou a quebra de linha que o arquivo não tinha: tira as duas, para o conteúdo voltar idêntico.
    s = m[2] && end === s.length && start > 0 ? s.slice(0, start - 1) : s.slice(0, start) + s.slice(end);
  }
  return Buffer.from(s);
}
export function traceTokenIn(text, trace) {
  const s = text.toString('utf8');
  const [env, zw] = markRegexes(trace);
  const a = s.match(env); if (a) return a[1];
  const b = s.match(zw); if (b) return zwDecode(b[1]);
  const c = s.match(/\/c\/([\w-]{16,64})/); return c ? c[1] : null;
}
const traceFile = () => path.join(gitDir(), 'selo', 'trace.json');
const ownerFile = () => path.join(gitDir(), 'selo', 'trace-owner.json');
const localTrace = () => { try { return JSON.parse(fs.readFileSync(traceFile(), 'utf8')); } catch { return {}; } };
const myTraceToken = () => localTrace().token || null;
const personId = (p) => crypto.createHash('sha256').update(p).digest('hex').slice(0, 16);
const personLabel = (p) => (p.startsWith('@') || p.startsWith('age1') ? p : `key:${personId(p)}`);
function allReaders(policy) { return [...new Set(Object.values(policy.files).flatMap((who) => expand(policy, who)))]; }
// Descobre qual dos arquivos de .selo-trace/ é o meu (o único que a minha chave abre) e guarda o token
// em .git/selo/trace.json, de onde o smudge lê. Sem rastro na política, apaga o que houver.
function refreshTrace(policy, dir = root()) {
  fs.rmSync(traceFile(), { force: true });
  if (!policy.trace) return null;
  const save = (token) => { fs.mkdirSync(path.dirname(traceFile()), { recursive: true, mode: 0o700 }); fs.writeFileSync(traceFile(), JSON.stringify({ token, trace: policy.trace }), { mode: 0o600 }); };
  const d = path.join(dir, TRACE_DIR);
  if (!fs.existsSync(d)) return null;
  const ids = loadIdentities(true);
  for (const f of fs.readdirSync(d).filter((x) => x.endsWith('.age'))) {
    let pt = null; try { pt = age.decrypt(fs.readFileSync(path.join(d, f)), ids); } catch {}
    if (pt) { save(pt.toString('utf8').trim()); return pt.toString('utf8').trim(); }
  }
  return null;
}
// Regrava no disco os arquivos protegidos pelo filtro, para a marca entrar (ou sair) já.
// A conferência vem ANTES de mudar a política: depois, o clean já usa a regra nova e a marca antiga
// pareceria uma alteração do usuário (medido no primeiro `trace off`).
function assertClean(dir, files) {
  const dirty = files.length ? git(['status', '--porcelain', '--', ...files], { cwd: dir }).trim() : '';
  if (dirty) fail(`commit or stash changes to protected files first:\n${dirty}`);
}
function recheckout(dir, files) {
  if (!files.length) return;
  for (const f of files) fs.rmSync(path.join(dir, f), { force: true });
  git(['checkout', '--', ...files], { cwd: dir });
}
async function traceApi(server, method, p, body, manage) {
  const res = await fetch(server.replace(/\/$/, '') + p, { method, body: body ? JSON.stringify(body) : undefined,
    headers: { 'user-agent': 'git-selo', ...(body ? { 'content-type': 'application/json' } : {}), ...(manage ? { authorization: `Bearer ${manage}` } : {}) } });
  let data = null; try { data = await res.json(); } catch {}
  return { status: res.status, data };
}
const loadOwner = () => { try { return JSON.parse(fs.readFileSync(ownerFile(), 'utf8')); } catch { fail(`no ${path.relative(root(), ownerFile())}: only the clone that ran \`git selo trace on\` can do this`); } };

async function traceOn(email, server, varName) {
  const dir = root(), p = loadPolicy(dir);
  if (p.trace) fail('trace is already on. To change readers or settings: `git selo trace off`, then `git selo trace on` again');
  if (!email) fail('usage: git selo trace on --email you@example.com [--server URL] [--var NAME]');
  const people = allReaders(p);
  if (!people.length) fail('nobody reads protected files yet: `git selo add @user` first');
  assertClean(dir, protectedFiles(p));
  const labels = Object.fromEntries(people.map((x) => [personLabel(x), x]));
  const repo = (path.basename(dir) || 'repo').replace(/[^\w.\-/ ]/g, '-').slice(0, 120);
  const r = await traceApi(server, 'POST', '/v1/watch', { email, repo, readers: Object.keys(labels) });
  if (r.status !== 201) fail(`trace server said ${r.status}: ${r.data?.error || 'no answer'}`);
  const d = path.join(dir, TRACE_DIR);
  fs.mkdirSync(d, { recursive: true });
  for (const [label, token] of Object.entries(r.data.tokens)) {
    // Cada token vai cifrado só para o próprio leitor: ninguém vê o token do outro (e não tem como incriminar o colega).
    fs.writeFileSync(path.join(d, personId(labels[label]) + '.age'), age.encrypt(Buffer.from(token + '\n'), resolveReaders(p, [labels[label]]).recips));
  }
  fs.mkdirSync(path.dirname(ownerFile()), { recursive: true, mode: 0o700 });
  fs.writeFileSync(ownerFile(), JSON.stringify({ server, id: r.data.id, manage: r.data.manage, tokens: r.data.tokens }, null, 2), { mode: 0o600 });
  p.trace = { server, watch: r.data.id, var: varName };
  savePolicy(p, dir);
  git(['add', POLICY, TRACE_DIR], { cwd: dir });
  refreshTrace(p, dir);
  recheckout(dir, protectedFiles(p));
  console.log(`trace on: ${people.length} reader copies marked (${Object.keys(labels).join(', ')}).
${r.data.confirmation_email === 'sent' ? `Check ${email} and click "Confirm alerts": nothing is sent until you do.` : 'The server could not send the confirmation email.'}
Commit ${POLICY} and ${TRACE_DIR}/. Readers get their mark on their next \`git selo unlock\` or checkout.
The manage key is in ${path.relative(dir, ownerFile())} (this clone only).`);
}
async function traceStatus() {
  const o = loadOwner(), r = await traceApi(o.server, 'GET', `/v1/watch/${o.id}`, null, o.manage);
  if (r.status !== 200) fail(`trace server said ${r.status}: ${r.data?.error || ''}`);
  console.log(`${r.data.repo}: alerts ${r.data.active ? 'ON' : 'OFF (confirm the email)'}; readers ${r.data.readers.join(', ')}`);
  if (!r.data.hits.length) console.log('no hits');
  for (const h of r.data.hits) console.log(`${h.at}  ${h.reader}  ${h.ip || '?'}${h.country ? ` (${h.country})` : ''}  ${h.client || ''}`);
}
async function traceIdentify(file) {
  const p = loadPolicy(), o = loadOwner();
  if (!p.trace) fail('trace is off in this repo');
  const text = file === '-' ? readStdin() : fs.readFileSync(file);
  const token = traceTokenIn(text, p.trace);
  if (!token) { console.log('no git selo mark found in this file (it may have been stripped)'); process.exitCode = 1; return; }
  const r = await traceApi(o.server, 'POST', `/v1/watch/${o.id}/identify`, { token }, o.manage);
  if (r.status === 200) console.log(`this copy came from ${r.data.reader}`);
  else { console.log(`a git selo mark, but not from this repo's watch (${r.status})`); process.exitCode = 1; }
}
async function traceScan() {
  const o = loadOwner(), found = [];
  for (const [reader, token] of Object.entries(o.tokens)) {
    const r = await gh('GET', `/search/code?q=${encodeURIComponent(`"${token}"`)}`);
    if (r.status !== 200) fail(`GitHub code search said ${r.status}: ${r.data?.message || ''}`);
    for (const it of r.data.items || []) found.push(`${reader}: ${it.html_url}`);
  }
  console.log(found.length ? `found on GitHub:\n${found.join('\n')}` : `no copy found on GitHub code search (${Object.keys(o.tokens).length} marks checked)`);
  if (found.length) process.exitCode = 1;
}
async function traceOff() {
  const dir = root(), p = loadPolicy(dir);
  if (!p.trace) fail('trace is already off');
  const files = protectedFiles(p);
  assertClean(dir, files);
  let o = null; try { o = JSON.parse(fs.readFileSync(ownerFile(), 'utf8')); } catch {}
  if (o) {
    const r = await traceApi(o.server, 'DELETE', `/v1/watch/${o.id}`, null, o.manage);
    if (r.status !== 200 && r.status !== 401) fail(`trace server said ${r.status}: ${r.data?.error || ''}`);
  } else say('no manage key in this clone: the watch stays on the server until you use the stop link in its email');
  delete p.trace; savePolicy(p, dir);
  try { git(['rm', '-r', '-q', '--cached', '--ignore-unmatch', TRACE_DIR], { cwd: dir }); } catch {}
  fs.rmSync(path.join(dir, TRACE_DIR), { recursive: true, force: true });
  fs.rmSync(ownerFile(), { force: true });
  refreshTrace(p, dir);
  git(['add', POLICY], { cwd: dir });
  recheckout(dir, files);
  console.log(`trace off: watch deleted${o ? '' : ' (not on the server: no manage key here)'}, marks removed. Commit ${POLICY} and the removal of ${TRACE_DIR}/.`);
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
  git selo branch review <b> [--html F]  commits and diff against main, locally (plus saved reviews)
  git selo branch merge <b> [--into B] publish: merge into main, push, drop refs/selo/<b>
                                       (files under "files" stay encrypted)
  git selo room open <b>               temporary PRIVATE GitHub repo with exactly the readers,
                                       and a real pull request to review in
  git selo room close <b> [--keep]     bring commits and comments back encrypted, delete the room
  git selo trace on --email E          mark each reader's decrypted copy (leak alert by email)
  git selo trace status | scan | off   hits on the trace links / search GitHub for the marks / undo
  git selo trace identify <file>       whose copy a leaked file came from

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
      if (sub === 'review') { const base = flag(args, '--base'), html = flag(args, '--html'); return branchReview(args[1], remote, base, html); }
      if (sub === 'merge') { const into = flag(args, '--into'); return branchMerge(args[1], remote, into, args.includes('--no-push')); }
      fail('usage: git selo branch push <name> [--for group] | pull <name> [--force] | list | review <name> [--html F] | merge <name> [--into B]   [--remote R]');
    }
    case 'trace': {
      const server = flag(args, '--server') || process.env.SELO_TRACE_SERVER || TRACE_DEFAULT_SERVER;
      const email = flag(args, '--email'), varName = flag(args, '--var') || 'BACKUP_ADMIN_URL';
      const [sub, arg] = args;
      if (varName && !/^[A-Z_][A-Z0-9_]{0,63}$/.test(varName)) fail('--var must look like an env var name (A-Z, 0-9, _)');
      if (sub === 'on') return traceOn(email, server, varName);
      if (sub === 'status') return traceStatus();
      if (sub === 'identify') { if (!arg) fail('usage: git selo trace identify <file|->'); return traceIdentify(arg); }
      if (sub === 'scan') return traceScan();
      if (sub === 'off') return traceOff();
      fail('usage: git selo trace on --email E [--server URL] [--var NAME] | status | identify <file> | scan | off');
    }
    case 'room': {
      const remote = flag(args, '--remote') || 'origin', base = flag(args, '--base'), owner = flag(args, '--owner');
      const [sub, name] = args;
      if (sub === 'open') return roomOpen(name, remote, base, owner);
      if (sub === 'close') return roomClose(name, remote, args.includes('--keep'));
      fail('usage: git selo room open <branch> [--owner org] [--base B] | close <branch> [--keep]');
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
      if (cmd === 'unlock') { configureFilters(); refreshTrace(loadPolicy(dir), dir); }
      else for (const k of ['filter.selo.clean', 'filter.selo.smudge', 'filter.selo.required', 'diff.selo.textconv']) try { git(['config', '--unset', k]); } catch {}
      for (const f of files) fs.rmSync(path.join(dir, f), { force: true });
      if (files.length) git(['checkout', '--', ...files], { cwd: dir });
      if (cmd === 'lock') { for (const f of files) fs.rmSync(cacheFile(f), { force: true }); fs.rmSync(traceFile(), { force: true }); removeHook(); }
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
