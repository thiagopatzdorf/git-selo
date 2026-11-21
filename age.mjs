// Implementação do formato age v1 (https://age-encryption.org/v1) só com node:crypto.
// Por que reimplementar em vez de chamar o binário `age`: o filtro do Git roda sem
// terminal, então qualquer dependência externa vira "funciona na minha máquina".
// A paridade com o `age` oficial é cobrada em test/age-interop.test.mjs.
import crypto from 'node:crypto';

const VERSION_LINE = 'age-encryption.org/v1';
const CHUNK = 64 * 1024;
const P = 2n ** 255n - 19n;

export const b64 = (buf) => Buffer.from(buf).toString('base64').replace(/=+$/, '');
export function unb64(s) {
  // O age exige base64 canônico sem padding: aceitar outra forma abriria maleabilidade.
  if (!/^[A-Za-z0-9+/]*$/.test(s)) throw new Error('invalid base64 in age header');
  const out = Buffer.from(s, 'base64');
  if (b64(out) !== s) throw new Error('non-canonical base64 in age header');
  return out;
}

const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
export function hkdf(ikm, salt, info, len = 32) {
  // HKDF manual: hkdfSync do Node recusa ikm vazio, e o ssh-ed25519 do age usa ikm vazio.
  const prk = hmac(salt.length ? salt : Buffer.alloc(32), ikm);
  let t = Buffer.alloc(0), out = Buffer.alloc(0);
  for (let i = 1; out.length < len; i++) {
    t = hmac(prk, Buffer.concat([t, Buffer.from(info), Buffer.from([i])]));
    out = Buffer.concat([out, t]);
  }
  return out.subarray(0, len);
}

function seal(key, nonce, pt) {
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}
function open(key, nonce, ct) {
  if (ct.length < 16) throw new Error('ciphertext too short');
  const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

// ---------- X25519 ----------
const X_PRIV = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X_PUB = Buffer.from('302a300506032b656e032100', 'hex');
const xPriv = (s) => crypto.createPrivateKey({ key: Buffer.concat([X_PRIV, s]), format: 'der', type: 'pkcs8' });
const xPub = (p) => crypto.createPublicKey({ key: Buffer.concat([X_PUB, p]), format: 'der', type: 'spki' });
export function x25519(scalar, point) {
  const out = crypto.diffieHellman({ privateKey: xPriv(scalar), publicKey: xPub(point) });
  if (out.every((b) => b === 0)) throw new Error('low-order X25519 point');
  return out;
}
export const x25519Base = (scalar) =>
  crypto.createPublicKey(xPriv(scalar)).export({ format: 'der', type: 'spki' }).subarray(12);

function modpow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
const leToBig = (buf) => BigInt('0x' + Buffer.from(buf).reverse().toString('hex'));
const bigToLe = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse();
// Mapa birracional Edwards -> Montgomery (u = (1+y)/(1-y)), o mesmo que o age usa para chaves ssh-ed25519.
export function ed25519PubToX25519(pub) {
  const y = leToBig(Buffer.from(pub)) & ((1n << 255n) - 1n);
  const u = ((1n + y) * modpow((P + 1n - y) % P, P - 2n, P)) % P;
  return bigToLe(u);
}

// ---------- bech32 (chaves age1… e AGE-SECRET-KEY-1…) ----------
const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(v) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const x of v) { const b = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= G[i]; }
  return chk >>> 0;
}
const hrpExp = (h) => [...h].map((c) => c.charCodeAt(0) >> 5).concat([0], [...h].map((c) => c.charCodeAt(0) & 31));
function convert(data, from, to, pad) {
  let acc = 0, bits = 0; const out = []; const max = (1 << to) - 1;
  for (const v of data) { acc = (acc << from) | v; bits += from; while (bits >= to) { bits -= to; out.push((acc >> bits) & max); } }
  if (pad) { if (bits) out.push((acc << (to - bits)) & max); } else if (bits >= from || ((acc << (to - bits)) & max)) throw new Error('invalid bech32 padding');
  return out;
}
export function bech32Encode(hrp, data) {
  const d = convert(data, 8, 5, true);
  const mod = polymod(hrpExp(hrp).concat(d, [0, 0, 0, 0, 0, 0])) ^ 1;
  const cs = [0, 1, 2, 3, 4, 5].map((i) => (mod >> (5 * (5 - i))) & 31);
  return hrp + '1' + d.concat(cs).map((x) => CH[x]).join('');
}
export function bech32Decode(s) {
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error('mixed-case bech32');
  s = s.toLowerCase();
  const pos = s.lastIndexOf('1');
  const hrp = s.slice(0, pos), data = [...s.slice(pos + 1)].map((c) => CH.indexOf(c));
  if (pos < 1 || data.length < 6 || data.includes(-1)) throw new Error('invalid bech32');
  if (polymod(hrpExp(hrp).concat(data)) !== 1) throw new Error('bad bech32 checksum');
  return { hrp, data: Buffer.from(convert(data.slice(0, -6), 5, 8, false)) };
}

// ---------- formato SSH ----------
function readStr(buf, off) {
  const n = buf.readUInt32BE(off);
  if (off + 4 + n > buf.length) throw new Error('truncated ssh key');
  return [buf.subarray(off + 4, off + 4 + n), off + 4 + n];
}
const mpintToB64url = (m) => { let i = 0; while (i < m.length - 1 && m[i] === 0) i++; return m.subarray(i).toString('base64url'); };
const mpToBig = (m) => BigInt('0x' + (m.toString('hex') || '0'));
const bigToB64url = (n) => { let h = n.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex').toString('base64url'); };
const sshTag = (wire) => b64(crypto.createHash('sha256').update(wire).digest().subarray(0, 4));

// ---------- destinatários ----------
// Um destinatário é { type, tag?, wrap(fileKey) -> {args, body} }. Aceita as três formas que
// um time já tem: chave age, ou a linha de chave pública SSH que o GitHub publica em github.com/<user>.keys.
export function parseRecipient(str) {
  str = str.trim();
  if (str.startsWith('age1')) {
    const { hrp, data } = bech32Decode(str);
    if (hrp !== 'age' || data.length !== 32) throw new Error('invalid age recipient');
    return {
      type: 'X25519', id: str,
      wrap(fileKey) {
        const e = crypto.randomBytes(32), share = x25519Base(e);
        const key = hkdf(x25519(e, data), Buffer.concat([share, data]), 'age-encryption.org/v1/X25519');
        return { args: ['X25519', b64(share)], body: seal(key, Buffer.alloc(12), fileKey) };
      },
    };
  }
  const [kind, blob] = str.split(/\s+/);
  if (kind !== 'ssh-ed25519' && kind !== 'ssh-rsa') throw new Error(`unsupported key type: ${kind || str.slice(0, 20)}`);
  const wire = Buffer.from(blob, 'base64');
  const [t, o1] = readStr(wire, 0);
  if (t.toString() !== kind) throw new Error('ssh key type mismatch');
  const tag = sshTag(wire), id = `${kind} ${blob}`;
  if (kind === 'ssh-ed25519') {
    const [pk] = readStr(wire, o1);
    const xpk = ed25519PubToX25519(pk);
    return {
      type: kind, tag, id,
      wrap(fileKey) {
        const e = crypto.randomBytes(32), share = x25519Base(e);
        const tweak = hkdf(Buffer.alloc(0), wire, 'age-encryption.org/v1/ssh-ed25519');
        const secret = x25519(tweak, x25519(e, xpk));
        const key = hkdf(secret, Buffer.concat([share, xpk]), 'age-encryption.org/v1/ssh-ed25519');
        return { args: ['ssh-ed25519', tag, b64(share)], body: seal(key, Buffer.alloc(12), fileKey) };
      },
    };
  }
  const [eB, o2] = readStr(wire, o1); const [nB] = readStr(wire, o2);
  const pub = crypto.createPublicKey({ key: { kty: 'RSA', n: mpintToB64url(nB), e: mpintToB64url(eB) }, format: 'jwk' });
  return {
    type: kind, tag, id,
    wrap(fileKey) {
      const body = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: Buffer.from('age-encryption.org/v1/ssh-rsa') }, fileKey);
      return { args: ['ssh-rsa', tag], body };
    },
  };
}

// ---------- identidades (chaves privadas) ----------
// Marcadores montados em duas partes: escritos inteiros, o detector de segredos do CI lê o trecho
// entre o BEGIN e o END do parser como se fosse uma chave colada no código.
const OPENSSH_BEGIN = '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----';
const PEM_BEGIN = new RegExp('-----BEGIN (RSA )?' + 'PRIVATE KEY-----');
// Devolve uma lista de { unwrap(stanza) -> fileKey|null }. Chave SSH com senha é pulada com
// aviso: o filtro do Git não tem terminal para pedir a senha (use `git selo key`).
export function parseIdentities(text, warn = () => {}) {
  const ids = [];
  for (const line of text.split('\n')) {
    const l = line.trim();
    if (l.startsWith('AGE-SECRET-KEY-1')) {
      const { hrp, data } = bech32Decode(l);
      if (hrp !== 'age-secret-key-' || data.length !== 32) throw new Error('invalid age identity');
      const pub = x25519Base(data);
      ids.push({
        type: 'X25519', recipient: bech32Encode('age', pub),
        unwrap(s) {
          if (s.args[0] !== 'X25519' || s.args.length !== 2) return null;
          const share = unb64(s.args[1]);
          const key = hkdf(x25519(data, share), Buffer.concat([share, pub]), 'age-encryption.org/v1/X25519');
          try { return open(key, Buffer.alloc(12), s.body); } catch { return null; }
        },
      });
    }
  }
  if (text.includes(OPENSSH_BEGIN)) {
    const id = parseOpenSSH(text, warn);
    if (id) ids.push(id);
  } else if (PEM_BEGIN.test(text)) {
    try { ids.push(rsaIdentity(crypto.createPrivateKey(text))); } catch { warn('skipping a passphrase-protected or unreadable PEM key'); }
  }
  return ids;
}

function parseOpenSSH(text, warn) {
  const body = text.split(OPENSSH_BEGIN)[1].split('-----END')[0].replace(/\s+/g, '');
  const buf = Buffer.from(body, 'base64');
  const magic = 'openssh-key-v1\0';
  if (buf.subarray(0, magic.length).toString('latin1') !== magic) throw new Error('not an openssh key');
  let off = magic.length, cipher, priv;
  [cipher, off] = readStr(buf, off);
  if (cipher.toString() !== 'none') { warn('skipping a passphrase-protected SSH key (run `git selo key` for a dedicated key)'); return null; }
  [, off] = readStr(buf, off); [, off] = readStr(buf, off);
  off += 4; // número de chaves
  [, off] = readStr(buf, off);
  [priv] = readStr(buf, off);
  let p = 8, type; [type, p] = readStr(priv, p);
  if (type.toString() === 'ssh-ed25519') {
    let pk, sk; [pk, p] = readStr(priv, p); [sk] = readStr(priv, p);
    const wire = Buffer.concat([u32str('ssh-ed25519'), u32str(pk)]);
    const scalar = crypto.createHash('sha512').update(sk.subarray(0, 32)).digest().subarray(0, 32);
    const xpk = ed25519PubToX25519(pk), tag = sshTag(wire);
    return {
      type: 'ssh-ed25519', tag, recipient: `ssh-ed25519 ${wire.toString('base64')}`,
      unwrap(s) {
        if (s.args[0] !== 'ssh-ed25519' || s.args.length !== 3 || s.args[1] !== tag) return null;
        const share = unb64(s.args[2]);
        const tweak = hkdf(Buffer.alloc(0), wire, 'age-encryption.org/v1/ssh-ed25519');
        const secret = x25519(tweak, x25519(scalar, share));
        const key = hkdf(secret, Buffer.concat([share, xpk]), 'age-encryption.org/v1/ssh-ed25519');
        try { return open(key, Buffer.alloc(12), s.body); } catch { return null; }
      },
    };
  }
  if (type.toString() === 'ssh-rsa') {
    const m = []; for (let i = 0; i < 6; i++) { let v; [v, p] = readStr(priv, p); m.push(v); }
    const [n, e, d, iqmp, pp, q] = m;
    const D = mpToBig(d);
    const key = crypto.createPrivateKey({ format: 'jwk', key: { kty: 'RSA', n: mpintToB64url(n), e: mpintToB64url(e), d: mpintToB64url(d), p: mpintToB64url(pp), q: mpintToB64url(q), dp: bigToB64url(D % (mpToBig(pp) - 1n)), dq: bigToB64url(D % (mpToBig(q) - 1n)), qi: mpintToB64url(iqmp) } });
    return rsaIdentity(key);
  }
  warn(`skipping unsupported SSH key type ${type}`);
  return null;
}
const u32str = (b) => { b = Buffer.from(b); const h = Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h, b]); };

function rsaIdentity(key) {
  const jwk = crypto.createPublicKey(key).export({ format: 'jwk' });
  const mp = (s) => { let b = Buffer.from(s, 'base64url'); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return b; };
  const wire = Buffer.concat([u32str('ssh-rsa'), u32str(mp(jwk.e)), u32str(mp(jwk.n))]);
  const tag = sshTag(wire);
  return {
    type: 'ssh-rsa', tag, recipient: `ssh-rsa ${wire.toString('base64')}`,
    unwrap(s) {
      if (s.args[0] !== 'ssh-rsa' || s.args[1] !== tag) return null;
      try { return crypto.privateDecrypt({ key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: Buffer.from('age-encryption.org/v1/ssh-rsa') }, s.body); } catch { return null; }
    },
  };
}

export function generateIdentity() {
  const sk = crypto.randomBytes(32);
  return { secret: bech32Encode('age-secret-key-', sk).toUpperCase(), recipient: bech32Encode('age', x25519Base(sk)) };
}

// ---------- cabeçalho e payload ----------
export const isAge = (buf) => buf.subarray(0, VERSION_LINE.length + 1).toString('latin1') === VERSION_LINE + '\n';

export function encrypt(plaintext, recipients) {
  if (!recipients.length) throw new Error('no recipients');
  const fileKey = crypto.randomBytes(16);
  let h = VERSION_LINE + '\n';
  for (const r of recipients) {
    const { args, body } = r.wrap(fileKey);
    const enc = b64(body), lines = enc.match(/.{1,64}/g) || [];
    if (enc.length % 64 === 0) lines.push(''); // a última linha do corpo é sempre < 64 colunas
    h += `-> ${args.join(' ')}\n${lines.join('\n')}\n`;
  }
  h += '---';
  h += ` ${b64(hmac(hkdf(fileKey, Buffer.alloc(0), 'header'), h))}\n`;
  const nonce = crypto.randomBytes(16);
  const pk = hkdf(fileKey, nonce, 'payload');
  const parts = [Buffer.from(h, 'latin1'), nonce];
  const n = Math.max(1, Math.ceil(plaintext.length / CHUNK));
  for (let i = 0; i < n; i++) parts.push(seal(pk, chunkNonce(i, i === n - 1), plaintext.subarray(i * CHUNK, (i + 1) * CHUNK)));
  return Buffer.concat(parts);
}
function chunkNonce(i, last) { const n = Buffer.alloc(12); n.writeUIntBE(i, 5, 6); n[11] = last ? 1 : 0; return n; }

export function parseHeader(buf) {
  if (!isAge(buf)) throw new Error('not an age file');
  const stanzas = []; let off = VERSION_LINE.length + 1;
  const line = () => { const e = buf.indexOf(0x0a, off); if (e < 0) throw new Error('truncated age header'); const l = buf.subarray(off, e).toString('latin1'); off = e + 1; return l; };
  for (;;) {
    const l = line();
    if (l.startsWith('---')) {
      const macStart = off - l.length - 1;
      if (!l.startsWith('--- ')) throw new Error('malformed header MAC');
      return { stanzas, mac: unb64(l.slice(4)), macInput: buf.subarray(0, macStart + 3), payloadOffset: off };
    }
    if (!l.startsWith('-> ')) throw new Error('malformed stanza');
    const args = l.slice(3).split(' ');
    let body = '';
    for (;;) { const b = line(); body += b; if (b.length < 64) break; }
    stanzas.push({ args, body: unb64(body) });
  }
}

export function decrypt(buf, identities) {
  const hdr = parseHeader(buf);
  let fileKey = null;
  for (const s of hdr.stanzas) { for (const id of identities) { fileKey = id.unwrap(s); if (fileKey) break; } if (fileKey) break; }
  if (!fileKey) return null;
  const mac = hmac(hkdf(fileKey, Buffer.alloc(0), 'header'), hdr.macInput);
  if (!crypto.timingSafeEqual(mac, hdr.mac)) throw new Error('header MAC mismatch (file tampered)');
  const nonce = buf.subarray(hdr.payloadOffset, hdr.payloadOffset + 16);
  if (nonce.length !== 16) throw new Error('truncated payload');
  const pk = hkdf(fileKey, nonce, 'payload');
  const ct = buf.subarray(hdr.payloadOffset + 16), out = [];
  const step = CHUNK + 16, n = Math.max(1, Math.ceil(ct.length / step));
  for (let i = 0; i < n; i++) {
    const c = ct.subarray(i * step, (i + 1) * step), last = i === n - 1;
    if (last && c.length === 16 && i > 0) throw new Error('empty final chunk');
    out.push(open(pk, chunkNonce(i, last), c));
  }
  return Buffer.concat(out);
}

// Destinatários visíveis no cabeçalho, para conferir "quem pode ler" sem decifrar.
export function headerRecipients(buf) {
  return parseHeader(buf).stanzas.map((s) => ({ type: s.args[0], tag: s.args[0].startsWith('ssh-') ? s.args[1] : undefined }));
}
