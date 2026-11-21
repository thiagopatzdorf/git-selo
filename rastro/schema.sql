-- Servidor do rastro do git selo (Cloudflare D1, ou SQLite em teste).
-- vigias: um por repositório vigiado; só manda alerta depois que o dono confirma o e-mail.
CREATE TABLE IF NOT EXISTS vigias (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  repo TEXT NOT NULL,
  gerencia TEXT NOT NULL,      -- sha256 da chave de gerência (a chave só o dono tem)
  confirmacao TEXT NOT NULL,   -- sha256 do código do link de confirmar/parar
  ativo INTEGER NOT NULL DEFAULT 0,
  criado INTEGER NOT NULL
);
-- iscas: um token por leitor; quem usar o link do token denuncia a cópia daquele leitor.
CREATE TABLE IF NOT EXISTS iscas (
  token TEXT PRIMARY KEY,
  vigia TEXT NOT NULL,
  rotulo TEXT NOT NULL,
  ultimo_email INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS iscas_vigia ON iscas (vigia);
CREATE TABLE IF NOT EXISTS acessos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vigia TEXT NOT NULL,
  token TEXT NOT NULL,
  quando INTEGER NOT NULL,
  ip TEXT, pais TEXT, agente TEXT, caminho TEXT
);
CREATE INDEX IF NOT EXISTS acessos_vigia ON acessos (vigia, quando);
CREATE TABLE IF NOT EXISTS limites (chave TEXT PRIMARY KEY, n INTEGER NOT NULL, ate INTEGER NOT NULL);
