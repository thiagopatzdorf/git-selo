#!/usr/bin/env python3
"""Publica o servidor do rastro do git selo (rastro.genesisinnovation.io). Roda na factory-01 (cofre).

    python3 apps/git-selo/rastro/publicar.py               # seco: diz o que faria
    python3 apps/git-selo/rastro/publicar.py --confirmar   # D1 + esquema, Worker, rota + DNS e PROVA
    python3 apps/git-selo/rastro/publicar.py --so-prova

Worker `git-selo-rastro` com DB (D1 `git-selo-rastro`) e RESEND_API_KEY (cofre factory-cauteloso).
A zona genesisinnovation.io está no teto de domínios de Worker, então o host entra por rota + DNS
(`cloudflare.ligar_por_rota`). Inversa: apagar a rota `rastro.genesisinnovation.io/*`, o registro DNS
de mesmo nome e o Worker; o D1 fica (os dados das vigias), e se apaga à parte se for o caso.
Quem quiser o próprio servidor não precisa disto: `wrangler deploy` com worker.js e schema.sql.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

AQUI = Path(__file__).resolve().parent
RAIZ = AQUI.parent.parent.parent
sys.path.insert(0, str(RAIZ / "apps/factory/src"))
WORKER, HOST, D1 = "git-selo-rastro", "rastro.genesisinnovation.io", "git-selo-rastro"
UA = "git-selo-rastro-publicar/1 (+https://github.com/thiagopatzdorf/git-selo)"


def passo(m):
    print(f"[rastro] {m}", flush=True)


def comandos_do_esquema():
    sem = "\n".join(ln.split("--", 1)[0] for ln in (AQUI / "schema.sql").read_text("utf-8").splitlines())
    return [c.strip() for c in sem.split(";") if c.strip()]


def resend_key():
    from factory_cauteloso import vault
    try:
        return vault.get_secret("factory-cauteloso", "RESEND_API_KEY", actor="rastro-publicar") or ""
    except Exception:  # noqa: BLE001
        return ""


def d1_id(cf):
    r = cf.pedir("GET", f"/accounts/{cf.CONTA}/d1/database?name={D1}")
    for db in (r.get("dados") or []) if r["ok"] else []:
        if db.get("name") == D1:
            return db["uuid"]
    r = cf.pedir("POST", f"/accounts/{cf.CONTA}/d1/database", {"name": D1})
    if not r["ok"]:
        raise SystemExit(f"D1: criar falhou: {r.get('erro')}")
    return r["dados"]["uuid"]


def publicar(cf, db):
    chave = resend_key()
    if not chave:
        raise SystemExit("sem RESEND_API_KEY no cofre: o servidor subiria sem mandar alerta nenhum")
    b = [{"type": "d1", "name": "DB", "id": db}, {"type": "secret_text", "name": "RESEND_API_KEY", "text": chave}]
    meta = {"main_module": "worker.js", "compatibility_date": cf.COMPATIBILIDADE, "observability": {"enabled": False}, "bindings": b}
    corpo, ct = cf._multipart([("metadata", "", json.dumps(meta).encode(), "application/json"),
                               ("worker.js", "worker.js", (AQUI / "worker.js").read_bytes(), "application/javascript+module")])
    w = cf.pedir("PUT", f"/accounts/{cf.CONTA}/workers/scripts/{WORKER}", bruto=corpo, tipo=ct)
    if not w["ok"]:
        raise SystemExit(f"worker: subir falhou: {w.get('erro')}")
    r = cf.ligar_por_rota(WORKER, HOST, cf.ZONAS["genesisinnovation.io"])
    if not r["ok"]:
        raise SystemExit(f"rota: ligar falhou: {r.get('erro')} ({r.get('etapa', '')})")


def _pedir(url, metodo="GET", corpo=None):
    req = urllib.request.Request(url, method=metodo, data=json.dumps(corpo).encode() if corpo else None,
                                 headers={"User-Agent": UA, **({"Content-Type": "application/json"} if corpo else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e).encode()[:200]


def prova(tentativas=18, espera=10.0):
    """Só leitura e respostas que não gravam nada: a prova de produção não cria vigia."""
    out = {}
    for _ in range(tentativas):
        st, c = _pedir(f"https://{HOST}/?v={int(time.time())}")
        out["pagina"] = st == 200 and b"git selo trace server" in c
        if out["pagina"]:
            break
        time.sleep(espera)
    st, c = _pedir(f"https://{HOST}/c/tokenquenaoexiste123")
    out["isca_muda"] = st == 200 and json.loads(c or b"{}") == {"status": "ok"}
    out["gerencia_401"] = _pedir(f"https://{HOST}/v1/watch/naoexiste1")[0] == 401
    out["entrada_ruim_400"] = _pedir(f"https://{HOST}/v1/watch", "POST", {"email": "x"})[0] == 400
    out["ok"] = all(out.values())
    return out


def main(argv=None):
    a = argparse.ArgumentParser()
    a.add_argument("--confirmar", action="store_true")
    a.add_argument("--so-prova", action="store_true")
    args = a.parse_args(argv)
    if args.so_prova:
        p = prova()
        print(json.dumps(p))
        return 0 if p["ok"] else 1
    if not args.confirmar:
        print(json.dumps({"seco": True, "worker": WORKER, "host": HOST, "d1": D1, "esquema": len(comandos_do_esquema())}))
        return 0
    from factory_cauteloso import cloudflare as cf
    db = d1_id(cf)
    for sql in comandos_do_esquema():
        r = cf.pedir("POST", f"/accounts/{cf.CONTA}/d1/database/{db}/query", {"sql": sql, "params": []})
        if not r["ok"]:
            raise SystemExit(f"D1 esquema: {r.get('erro')}")
    passo(f"D1 {db} ok")
    publicar(cf, db)
    passo("worker e rota ok")
    p = prova()
    print(json.dumps({"ok": p["ok"], "prova": p, "url": f"https://{HOST}/"}))
    return 0 if p["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
