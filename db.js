// Database access: Neon Postgres in production (DATABASE_URL), PGlite for local testing.
let _q = null, _ready = null;

async function connect() {
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.DATABASE_URL_UNPOOLED;
  if (url) {
    const { neon } = await import('@neondatabase/serverless');
    const sql = neon(url);
    return (text, params = []) => sql.query(text, params);
  }
  if (process.env.SBW_PGLITE) { // local development only
    const { PGlite } = await import(process.env.SBW_PGLITE);
    const db = new PGlite(process.env.SBW_PGLITE_DIR || undefined);
    return async (text, params = []) => (await db.query(text, params)).rows;
  }
  throw Object.assign(new Error('The database is not connected yet. In Vercel, open this project → Storage → Create Database → Neon, then redeploy.'), { status: 503, code: 'no_db' });
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
     id text PRIMARY KEY, email text UNIQUE NOT NULL, name text NOT NULL DEFAULT '', role text NOT NULL DEFAULT 'member',
     active boolean NOT NULL DEFAULT true, pages jsonb, projects jsonb, hide_fields jsonb NOT NULL DEFAULT '[]'::jsonb,
     salt text NOT NULL, hash text NOT NULL, must_change boolean NOT NULL DEFAULT false, failed int NOT NULL DEFAULT 0,
     locked_until timestamptz, last_login timestamptz, created_at timestamptz NOT NULL DEFAULT now())`,
  `CREATE TABLE IF NOT EXISTS sessions (token_hash text PRIMARY KEY, user_id text NOT NULL, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now())`,
  `CREATE SEQUENCE IF NOT EXISTS doc_seq`,
  `CREATE TABLE IF NOT EXISTS docs (key text PRIMARY KEY, data jsonb, version int NOT NULL DEFAULT 1, deleted boolean NOT NULL DEFAULT false,
     seq bigint NOT NULL DEFAULT nextval('doc_seq'), updated_at timestamptz NOT NULL DEFAULT now(), updated_by text)`,
  `CREATE INDEX IF NOT EXISTS docs_seq_idx ON docs (seq)`,
  `CREATE TABLE IF NOT EXISTS doc_history (key text NOT NULL, version int NOT NULL, data jsonb, updated_at timestamptz NOT NULL DEFAULT now(), updated_by text, PRIMARY KEY (key, version))`,
  `CREATE TABLE IF NOT EXISTS settings (k text PRIMARY KEY, v jsonb)`,
  `CREATE TABLE IF NOT EXISTS files (id text PRIMARY KEY, name text, type text, size int, parts int NOT NULL DEFAULT 0, complete boolean NOT NULL DEFAULT false, created_by text, created_at timestamptz NOT NULL DEFAULT now())`,
  `CREATE TABLE IF NOT EXISTS file_parts (id text NOT NULL, n int NOT NULL, data text NOT NULL, PRIMARY KEY (id, n))`,
  `CREATE TABLE IF NOT EXISTS portal_links (pid text PRIMARY KEY, token text UNIQUE NOT NULL, active boolean NOT NULL DEFAULT true, pin text NOT NULL DEFAULT '',
     approve boolean NOT NULL DEFAULT true, html text NOT NULL DEFAULT '', snap_at timestamptz, views jsonb NOT NULL DEFAULT '[]'::jsonb,
     fails int NOT NULL DEFAULT 0, locked_until timestamptz, updated_by text, updated_at timestamptz NOT NULL DEFAULT now())`
];

export async function q(text, params) {
  if (!_q) _q = await connect();
  if (!_ready) _ready = (async () => { for (const s of SCHEMA) await _q(s); })().catch(e => { _ready = null; throw e; });
  await _ready;
  return _q(text, params);
}
export async function one(text, params) { const r = await q(text, params); return r[0] || null; }
