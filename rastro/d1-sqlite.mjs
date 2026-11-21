// D1 de mentira sobre node:sqlite, com a mesma forma de chamada (prepare/bind/first/all/run).
// Serve o teste do Worker e o servidor local do teste de ponta a ponta.
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
export function d1() {
  const s = new DatabaseSync(':memory:');
  s.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));
  return { prepare(sql) { const mk = (a) => ({ bind: (...x) => mk(x), first: async () => s.prepare(sql).get(...a) ?? null, all: async () => ({ results: s.prepare(sql).all(...a) }), run: async () => (s.prepare(sql).run(...a), { success: true }) }); return mk([]); } };
}
