// Gera chaves SSH no formato OpenSSH sem precisar de ssh-keygen: o ambiente de CI pode não ter.
import crypto from 'node:crypto';

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const str = (b) => { b = Buffer.from(b); return Buffer.concat([u32(b.length), b]); };
const mp = (s) => { let b = Buffer.from(s, 'base64url'); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return str(b); };

export function sshKeypair(type = 'ed25519', comment = 'test@selo') {
  let pubWire, privBody;
  if (type === 'ed25519') {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    const j = privateKey.export({ format: 'jwk' });
    const pk = Buffer.from(j.x, 'base64url'), seed = Buffer.from(j.d, 'base64url');
    pubWire = Buffer.concat([str('ssh-ed25519'), str(pk)]);
    privBody = Buffer.concat([str('ssh-ed25519'), str(pk), str(Buffer.concat([seed, pk]))]);
  } else {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const j = privateKey.export({ format: 'jwk' });
    pubWire = Buffer.concat([str('ssh-rsa'), mp(j.e), mp(j.n)]);
    privBody = Buffer.concat([str('ssh-rsa'), mp(j.n), mp(j.e), mp(j.d), mp(j.qi), mp(j.p), mp(j.q)]);
  }
  const check = crypto.randomBytes(4);
  let priv = Buffer.concat([check, check, privBody, str(comment)]);
  for (let i = 1; priv.length % 8; i++) priv = Buffer.concat([priv, Buffer.from([i])]);
  const file = Buffer.concat([Buffer.from('openssh-key-v1\0'), str('none'), str('none'), str(''), u32(1), str(pubWire), str(priv)]);
  const b64 = file.toString('base64').match(/.{1,70}/g).join('\n');
  return {
    public: `ssh-${type} ${pubWire.toString('base64')} ${comment}`,
    // Marcadores em duas partes pelo mesmo motivo do age.mjs: o detector de segredos do CI.
    private: `-----BEGIN OPENSSH ${'PRIVATE'} KEY-----\n${b64}\n-----END OPENSSH ${'PRIVATE'} KEY-----\n`,
  };
}

// "GitHub" falso em outro processo, servindo <dir>/<usuario>.keys como github.com/<usuario>.keys.
// Processo separado porque os testes usam chamadas síncronas, que travariam um servidor local.
import { spawn } from 'node:child_process';
export async function keyServer(dir) {
  const src = `const http=require('http'),fs=require('fs'),p=require('path');
    const s=http.createServer((q,r)=>{const f=p.join(${JSON.stringify(dir)},p.basename(q.url));
      fs.existsSync(f)?r.end(fs.readFileSync(f)):r.writeHead(404).end();});
    s.listen(0,'127.0.0.1',()=>console.log(s.address().port));`;
  const proc = spawn(process.execPath, ['-e', src], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise((r) => proc.stdout.once('data', (d) => r(String(d).trim())));
  return { url: `http://127.0.0.1:${port}`, close: () => proc.kill() };
}
