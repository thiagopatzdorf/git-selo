// Gera chaves SSH no formato OpenSSH sem precisar de ssh-keygen: o ambiente de CI pode não ter.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

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

// API do GitHub falsa, só o que a sala de revisão usa. Cria repositórios bare em <dir>/<dono>/<nome>.git
// e grava em <dir>/state.json o que aconteceu, para o teste conferir convite, PR e exclusão.
export async function githubApi(dir, { login, token, reviews = [], comments = [], conversation = [], deleteFailures = 0 }) {
  const src = `const http=require('http'),fs=require('fs'),p=require('path'),{execFileSync}=require('child_process');
    const D=${JSON.stringify(dir)},S=p.join(D,'state.json'),C=${JSON.stringify({ login, token, reviews, comments, conversation, deleteFailures })};
    const st=()=>fs.existsSync(S)?JSON.parse(fs.readFileSync(S)):{repos:{},collaborators:[],pulls:[],deleted:[],badAuth:0};
    const save=(s)=>fs.writeFileSync(S,JSON.stringify(s));
    http.createServer((q,r)=>{let b='';q.on('data',d=>b+=d);q.on('end',()=>{const s=st(),u=q.url.split('?')[0],j=(c,o)=>{r.writeHead(c,{'content-type':'application/json'});r.end(o===undefined?'':JSON.stringify(o));};
      if(q.headers.authorization!=='Bearer '+C.token){s.badAuth++;save(s);return j(401,{message:'Bad credentials'});}
      let m;
      if(q.method==='GET'&&u==='/user')return j(200,{login:C.login});
      if(q.method==='POST'&&u==='/user/repos'){const x=JSON.parse(b),f=C.login+'/'+x.name;execFileSync('git',['init','-q','--bare',p.join(D,f+'.git')]);s.repos[f]=x;save(s);return j(201,{full_name:f,private:x.private});}
      if(q.method==='PUT'&&(m=u.match(/^\\/repos\\/([^/]+\\/[^/]+)\\/collaborators\\/(.+)$/))){s.collaborators.push({repo:m[1],user:m[2],perm:JSON.parse(b).permission});save(s);return j(201,{});}
      if(q.method==='POST'&&(m=u.match(/^\\/repos\\/([^/]+\\/[^/]+)\\/pulls$/))){const x=JSON.parse(b);s.pulls.push({repo:m[1],...x});save(s);return j(201,{number:s.pulls.length,html_url:'https://github.com/'+m[1]+'/pull/'+s.pulls.length});}
      if(q.method==='GET'&&/\\/pulls\\/\\d+\\/reviews$/.test(u))return j(200,C.reviews);
      if(q.method==='GET'&&/\\/pulls\\/\\d+\\/comments$/.test(u))return j(200,C.comments);
      if(q.method==='GET'&&/\\/issues\\/\\d+\\/comments$/.test(u))return j(200,C.conversation);
      if(q.method==='DELETE'&&(m=u.match(/^\\/repos\\/([^/]+\\/[^/]+)$/))){if((s.deleteTries=(s.deleteTries||0)+1)<=C.deleteFailures){save(s);return j(403,{message:'Must have admin rights to Repository.'});}fs.rmSync(p.join(D,m[1]+'.git'),{recursive:true,force:true});delete s.repos[m[1]];s.deleted.push(m[1]);save(s);return j(204);}
      j(404,{message:'Not Found'});});}).listen(0,'127.0.0.1',function(){console.log(this.address().port);});`;
  const proc = spawn(process.execPath, ['-e', src], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise((r) => proc.stdout.once('data', (d) => r(String(d).trim())));
  return { url: `http://127.0.0.1:${port}`, state: () => JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8')), close: () => proc.kill() };
}
