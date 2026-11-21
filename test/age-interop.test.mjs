// Paridade com o age oficial (https://github.com/FiloSottile/age), nos dois sentidos.
// Sem isso, "formato age" seria só uma promessa: o arquivo tem de abrir com a ferramenta de referência.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import * as age from '../age.mjs';
import { sshKeypair } from './helpers.mjs';

const hasAge = spawnSync('age', ['--version']).status === 0;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'selo-age-'));
// Tamanhos que pegam as bordas do STREAM: vazio, 1 byte, um bloco exato, bloco + 1.
const SIZES = [0, 1, 65536, 65537, 200000];

for (const kind of ['x25519', 'ed25519', 'rsa']) {
  test(`${kind}: o que o git selo cifra, o age oficial decifra (e vice-versa)`, { skip: !hasAge && 'age not installed' }, () => {
    let pub, idFile = path.join(dir, kind);
    if (kind === 'x25519') { const id = age.generateIdentity(); pub = id.recipient; fs.writeFileSync(idFile, id.secret + '\n'); }
    else { const k = sshKeypair(kind); pub = k.public; fs.writeFileSync(idFile, k.private, { mode: 0o600 }); }
    const ids = age.parseIdentities(fs.readFileSync(idFile, 'utf8'));
    for (const n of SIZES) {
      const pt = Buffer.alloc(n, n % 251);
      const f = path.join(dir, `${kind}-${n}.age`);
      fs.writeFileSync(f, age.encrypt(pt, [age.parseRecipient(pub)]));
      assert.ok(execFileSync('age', ['-d', '-i', idFile, f]).equals(pt), `ours->age ${n}`);
      fs.writeFileSync(path.join(dir, 'pub'), pub + '\n');
      const theirs = execFileSync('age', ['-R', path.join(dir, 'pub')], { input: pt });
      assert.ok(age.decrypt(theirs, ids).equals(pt), `age->ours ${n}`);
    }
  });
}

test('arquivo adulterado é recusado em vez de devolver lixo', () => {
  const id = age.generateIdentity();
  const ct = age.encrypt(Buffer.from('segredo'), [age.parseRecipient(id.recipient)]);
  const ids = age.parseIdentities(id.secret);
  const bad = Buffer.from(ct); bad[bad.length - 1] ^= 1;
  assert.throws(() => age.decrypt(bad, ids));
  // Cabeçalho alterado sem mexer na parte que a chave abre (uma linha a mais antes do ---):
  // só o MAC do cabeçalho pega isso.
  const at = ct.indexOf('\n---') + 1;
  const hdr = Buffer.concat([ct.subarray(0, at), Buffer.from('-> extra\n\n'), ct.subarray(at)]);
  assert.throws(() => age.decrypt(hdr, ids), /MAC mismatch/);
});

test('quem não é destinatário recebe null, não exceção', () => {
  const a = age.generateIdentity(), b = age.generateIdentity();
  const ct = age.encrypt(Buffer.from('x'), [age.parseRecipient(a.recipient)]);
  assert.equal(age.decrypt(ct, age.parseIdentities(b.secret)), null);
});
