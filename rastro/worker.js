// Servidor do rastro do git selo: guarda os tokens-isca de cada leitor e manda um e-mail ao dono do
// repositório quando alguém usa o link de uma cópia. Não recebe código nem segredo: só o rótulo de cada
// leitor (ex.: "@bob"), o e-mail do dono e o nome do repositório.
// Bindings: DB (D1 com schema.sql), RESEND_API_KEY (opcional: sem ele nada sai e o acesso só é gravado),
// REMETENTE (opcional).
const UA = "git-selo-rastro/1 (+https://github.com/thiagopatzdorf/git-selo)";
const REMETENTES = ["git selo <rastro@genesisinnovation.io>", "git selo <james@genesisinnovation.io>"];
const MAX_LEITORES = 50, EMAIL_INTERVALO = 10 * 60e3, GUARDA_ACESSOS = 90 * 864e5;
const agora = () => Date.now();
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const json = (o, st = 200) => new Response(JSON.stringify(o), { status: st, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const html = (t, st = 200) => new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>git selo</title><body style="font:16px system-ui;max-width:560px;margin:48px auto;padding:0 16px">${t}`, { status: st, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
export function aleatorio(n = 24) { const b = new Uint8Array(n); crypto.getRandomValues(b); return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
export async function sha256(t) { const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t)); return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, "0")).join(""); }
const EMAIL = /^[^\s@<>]{1,64}@[^\s@<>]{1,190}\.[a-z]{2,24}$/i;
const ROTULO = /^[\w@.\-:+]{1,80}$/;
const REPO = /^[\w.\-/ ]{1,120}$/;

// Teto por chave e janela, guardado no próprio D1 (um Worker não tem memória entre pedidos).
async function limite(env, chave, max, janela) {
  const t = agora(), r = await env.DB.prepare("SELECT n, ate FROM limites WHERE chave = ?").bind(chave).first();
  if (!r || r.ate < t) { await env.DB.prepare("INSERT OR REPLACE INTO limites (chave, n, ate) VALUES (?, 1, ?)").bind(chave, t + janela).run(); return true; }
  if (r.n >= max) return false;
  await env.DB.prepare("UPDATE limites SET n = n + 1 WHERE chave = ?").bind(chave).run();
  return true;
}

export async function enviarEmail(env, para, assunto, linhas, botoes = []) {
  if (!env.RESEND_API_KEY) return { aceito: false, motivo: "sem RESEND_API_KEY" };
  const texto = linhas.join("\n\n") + botoes.map((b) => `\n\n${b.texto}: ${b.url}`).join("") + "\n\n— git selo";
  const corpo = `<div style="font:15px/1.55 system-ui,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#1f2328">` +
    `<p style="font-weight:700">git selo</p>` + linhas.map((l) => `<p>${esc(l)}</p>`).join("") +
    botoes.map((b) => `<p><a href="${esc(b.url)}" style="background:#1f2328;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none">${esc(b.texto)}</a></p>`).join("") + `</div>`;
  let ult = { aceito: false };
  for (const from of env.REMETENTE ? [env.REMETENTE] : REMETENTES) {
    try {
      const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json", "User-Agent": UA },
        body: JSON.stringify({ from, to: [para], subject: assunto.slice(0, 180), text: texto, html: corpo }) });
      const d = await r.json().catch(() => ({}));
      ult = { aceito: r.status < 300 && !!d.id, status: r.status };
      if (ult.aceito || ![403, 422].includes(r.status)) return ult;
    } catch { ult = { aceito: false, status: 0 }; }
  }
  return ult;
}

async function autenticar(env, req, id) {
  const k = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!k) return null;
  const v = await env.DB.prepare("SELECT * FROM vigias WHERE id = ?").bind(id).first();
  return v && v.gerencia === (await sha256(k)) ? v : null;
}

async function criar(env, req, origem) {
  const ip = req.headers.get("cf-connecting-ip") || "?";
  if (!(await limite(env, "ip:" + ip, 10, 36e5))) return json({ error: "too many watches from this address, try again in an hour" }, 429);
  let b; try { b = await req.json(); } catch { return json({ error: "body must be JSON" }, 400); }
  const email = String(b.email || "").trim(), repo = String(b.repo || "").trim(), leitores = [...new Set((b.readers || []).map(String))];
  if (!EMAIL.test(email)) return json({ error: "invalid email" }, 400);
  if (!REPO.test(repo)) return json({ error: "invalid repo name" }, 400);
  if (!leitores.length || leitores.length > MAX_LEITORES || !leitores.every((l) => ROTULO.test(l))) return json({ error: `readers: 1 to ${MAX_LEITORES} labels like @user` }, 400);
  // Um mesmo e-mail não recebe mais que alguns pedidos de confirmação por dia: o servidor não vira canhão de e-mail.
  if (!(await limite(env, "email:" + email.toLowerCase(), 3, 864e5))) return json({ error: "too many confirmation emails to this address today" }, 429);
  const id = aleatorio(9), gerencia = aleatorio(24), codigo = aleatorio(18), tokens = {};
  await env.DB.prepare("INSERT INTO vigias (id, email, repo, gerencia, confirmacao, ativo, criado) VALUES (?,?,?,?,?,0,?)").bind(id, email, repo, await sha256(gerencia), await sha256(codigo), agora()).run();
  for (const l of leitores) { tokens[l] = aleatorio(18); await env.DB.prepare("INSERT INTO iscas (token, vigia, rotulo) VALUES (?,?,?)").bind(tokens[l], id, l).run(); }
  const e = await enviarEmail(env, email, `Confirm leak alerts for ${repo}`, [
    `Someone asked to send leak alerts for the repository "${repo}" to this address (${leitores.length} reader copies marked).`,
    "Nothing is sent until you confirm. If this wasn't you, ignore this email."], [{ texto: "Confirm alerts", url: `${origem}/v1/confirm/${codigo}` }]);
  return json({ id, manage: gerencia, tokens, hit_url: `${origem}/c/`, confirmation_email: e.aceito ? "sent" : "not sent" }, 201);
}

async function acesso(env, req, token, caminho) {
  const isca = await env.DB.prepare("SELECT iscas.*, vigias.email, vigias.repo, vigias.ativo FROM iscas JOIN vigias ON vigias.id = iscas.vigia WHERE token = ?").bind(token).first();
  if (isca) {
    const t = agora(), ip = req.headers.get("cf-connecting-ip") || "", pais = req.headers.get("cf-ipcountry") || "", ag = (req.headers.get("user-agent") || "").slice(0, 300);
    await env.DB.prepare("INSERT INTO acessos (vigia, token, quando, ip, pais, agente, caminho) VALUES (?,?,?,?,?,?,?)").bind(isca.vigia, token, t, ip, pais, ag, caminho.slice(0, 200)).run();
    await env.DB.prepare("DELETE FROM acessos WHERE vigia = ? AND quando < ?").bind(isca.vigia, t - GUARDA_ACESSOS).run();
    // Um e-mail a cada 10 minutos por cópia: robô batendo no link não enche a caixa do dono; todos ficam gravados.
    if (isca.ativo && t - isca.ultimo_email > EMAIL_INTERVALO) {
      await env.DB.prepare("UPDATE iscas SET ultimo_email = ? WHERE token = ?").bind(t, token).run();
      await enviarEmail(env, isca.email, `Leak alert: ${isca.rotulo}'s copy of ${isca.repo} was used`, [
        `The trace link from ${isca.rotulo}'s copy of "${isca.repo}" was just opened.`,
        `When: ${new Date(t).toISOString()}. From: ${ip || "unknown IP"}${pais ? ` (${pais})` : ""}. Client: ${ag || "unknown"}.`,
        `That link exists only inside the decrypted files of ${isca.rotulo}'s copy. Either that copy left their machine, or they opened it themselves. Rotate the secrets in it.`,
        "Run `git selo trace status` to see every hit."]);
    }
  }
  // Mesma resposta exista o token ou não: o link não diz a quem testa que é uma isca.
  return json({ status: "ok" });
}

export default {
  async fetch(req, env) {
    const u = new URL(req.url), p = u.pathname, origem = u.origin;
    let m;
    if ((m = p.match(/^\/c\/([\w-]{8,64})(\/.*)?$/))) return acesso(env, req, m[1], m[2] || "/");
    if (p === "/v1/watch" && req.method === "POST") return criar(env, req, origem);
    if ((m = p.match(/^\/v1\/(confirm|stop)\/([\w-]{8,64})$/))) {
      const v = await env.DB.prepare("SELECT id, repo FROM vigias WHERE confirmacao = ?").bind(await sha256(m[2])).first();
      if (!v) return html("<p>This link is not valid (or the watch was deleted).</p>", 404);
      const ligar = m[1] === "confirm";
      await env.DB.prepare("UPDATE vigias SET ativo = ? WHERE id = ?").bind(ligar ? 1 : 0, v.id).run();
      return ligar ? html(`<h1>Alerts on</h1><p>You'll get an email when a marked copy of <b>${esc(v.repo)}</b> is used. To stop: <a href="${origem}/v1/stop/${esc(m[2])}">turn alerts off</a>.</p>`)
        : html(`<h1>Alerts off</h1><p>No more emails for <b>${esc(v.repo)}</b>. Turn them back on: <a href="${origem}/v1/confirm/${esc(m[2])}">confirm again</a>.</p>`);
    }
    if ((m = p.match(/^\/v1\/watch\/([\w-]{6,32})(\/identify)?$/))) {
      const v = await autenticar(env, req, m[1]);
      if (!v) return json({ error: "unknown watch or wrong manage key" }, 401);
      if (m[2] && req.method === "POST") {
        let b; try { b = await req.json(); } catch { return json({ error: "body must be JSON" }, 400); }
        const i = await env.DB.prepare("SELECT rotulo FROM iscas WHERE vigia = ? AND token = ?").bind(v.id, String(b.token || "")).first();
        return i ? json({ reader: i.rotulo }) : json({ error: "token is not from this watch" }, 404);
      }
      if (req.method === "DELETE") {
        for (const t of ["acessos", "iscas"]) await env.DB.prepare(`DELETE FROM ${t} WHERE vigia = ?`).bind(v.id).run();
        await env.DB.prepare("DELETE FROM vigias WHERE id = ?").bind(v.id).run();
        return json({ deleted: true });
      }
      if (req.method === "GET") {
        const leitores = (await env.DB.prepare("SELECT token, rotulo FROM iscas WHERE vigia = ?").bind(v.id).all()).results;
        const nome = Object.fromEntries(leitores.map((l) => [l.token, l.rotulo]));
        const hits = (await env.DB.prepare("SELECT token, quando, ip, pais, agente, caminho FROM acessos WHERE vigia = ? ORDER BY quando DESC LIMIT 100").bind(v.id).all()).results
          .map((h) => ({ reader: nome[h.token], at: new Date(h.quando).toISOString(), ip: h.ip, country: h.pais, client: h.agente, path: h.caminho }));
        return json({ repo: v.repo, active: !!v.ativo, readers: leitores.map((l) => l.rotulo), hits });
      }
    }
    if (p === "/") return html(`<h1>git selo trace server</h1><p>Leak alerts for <a href="https://github.com/thiagopatzdorf/git-selo">git selo</a>. It stores only reader labels, the owner's email and the repo name; never code or secrets.</p>`);
    return json({ error: "not found" }, 404);
  },
};
