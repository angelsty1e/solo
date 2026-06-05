import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

// Hybrid schema: a wide `sessions` table for indexable scalars (the things
// you actually want to GROUP BY or filter on), plus per-area JSON blobs for
// the full payload. Lets you do `SELECT count(*) GROUP BY ja3_hash` cheaply
// while keeping the raw snapshot accessible.

const SCHEMA = `
CREATE TABLE IF NOT EXISTS sessions (
  id              TEXT PRIMARY KEY,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  server_captured_at TEXT,
  client_collected_at TEXT,
  duration_ms     INTEGER,

  ip              TEXT,
  asn             INTEGER,
  asn_org         TEXT,
  country         TEXT,
  is_datacenter   INTEGER,
  is_proxy_hint   INTEGER,
  reverse_dns     TEXT,
  is_tor_exit     INTEGER,
  tcp_rtt_ms      REAL,

  ja3             TEXT,
  ja3_hash        TEXT,
  ja4             TEXT,
  tls_version     INTEGER,
  sni             TEXT,
  alpn            TEXT,

  user_agent      TEXT,
  http_version    TEXT,
  accept_language TEXT,
  sec_fetch_site  TEXT,
  sec_fetch_mode  TEXT,
  sec_fetch_dest  TEXT,
  sec_fetch_user  TEXT,

  platform        TEXT,
  vendor          TEXT,
  language        TEXT,
  timezone        TEXT,
  screen_w        INTEGER,
  screen_h        INTEGER,
  dpr             REAL,
  webdriver       INTEGER,
  canvas_hash     TEXT,
  webgl_hash      TEXT,
  webgl_renderer  TEXT,
  audio_hash      TEXT,
  fonts_count     INTEGER,

  verdict           TEXT,
  bot_score         REAL,
  trust_score       REAL,
  decision_forced   INTEGER,
  decision_version  TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_ja3       ON sessions(ja3_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_ja4       ON sessions(ja4);
CREATE INDEX IF NOT EXISTS idx_sessions_ip        ON sessions(ip);
CREATE INDEX IF NOT EXISTS idx_sessions_canvas    ON sessions(canvas_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_webgl     ON sessions(webgl_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_audio     ON sessions(audio_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_ua        ON sessions(user_agent);
CREATE INDEX IF NOT EXISTS idx_sessions_expires   ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS server_tls (
  session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
  data       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_http (
  session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
  data       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_ip (
  session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
  data       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS client_full (
  session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
  data       TEXT NOT NULL
);

-- Full decision-engine output (per-level verdicts, signals, evidence) as JSON.
-- The indexable synthesis (verdict, bot_score) lives in the sessions table.
CREATE TABLE IF NOT EXISTS decisions (
  session_id  TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
  data        TEXT NOT NULL,
  computed_at TEXT NOT NULL
);
`;

// Indexes on the decision columns. Kept OUT of SCHEMA on purpose: on a DB
// created before the decision engine, `verdict`/`bot_score` are added by
// migrate(), so indexing them inside SCHEMA (which runs before the ALTERs)
// fails with "no such column: verdict". Run these after migrate() instead.
const DECISION_INDEXES = `
CREATE INDEX IF NOT EXISTS idx_sessions_verdict ON sessions(verdict);
CREATE INDEX IF NOT EXISTS idx_sessions_score   ON sessions(bot_score);
`;

// Columns added after v1.0 — `CREATE TABLE IF NOT EXISTS` won't add them to an
// existing DB, so we ALTER them in idempotently on every boot.
const SESSIONS_ADDED_COLUMNS: Array<{ name: string; ddl: string }> = [
  { name: 'verdict', ddl: 'ALTER TABLE sessions ADD COLUMN verdict TEXT' },
  { name: 'bot_score', ddl: 'ALTER TABLE sessions ADD COLUMN bot_score REAL' },
  { name: 'trust_score', ddl: 'ALTER TABLE sessions ADD COLUMN trust_score REAL' },
  { name: 'decision_forced', ddl: 'ALTER TABLE sessions ADD COLUMN decision_forced INTEGER' },
  { name: 'decision_version', ddl: 'ALTER TABLE sessions ADD COLUMN decision_version TEXT' },
];

function migrate(database: Database.Database): void {
  let existing: Set<string>;
  try {
    existing = new Set(
      (database.prepare('PRAGMA table_info(sessions)').all() as Array<{ name: string }>).map((c) => c.name),
    );
  } catch (err) {
    throw new Error(`DB migration: cannot read sessions schema — ${(err as Error).message}`);
  }
  for (const col of SESSIONS_ADDED_COLUMNS) {
    if (existing.has(col.name)) continue;
    try {
      database.exec(col.ddl);
    } catch (err) {
      // Fail fast with the exact column/DDL: a half-migrated schema would cause
      // confusing downstream errors during a rolling deploy.
      throw new Error(`DB migration failed adding column "${col.name}" — ${(err as Error).message}`);
    }
  }
}

let db: Database.Database | null = null;

export function initDb(dbPath: string): Database.Database {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  // Wait (instead of throwing SQLITE_BUSY) if another writer holds the lock.
  db.pragma('busy_timeout = 5000');
  // Schema + migrations are fail-fast: a DB that can't be brought to the current
  // shape must abort startup (and the rolling deploy) with a clear message,
  // rather than limp along and throw vague errors on the first query.
  try {
    db.exec(SCHEMA);
    migrate(db);
    // After migrate(): the columns are guaranteed to exist now (fresh DB via
    // SCHEMA, older DB via the ALTERs above), so the indexes can reference them.
    db.exec(DECISION_INDEXES);
  } catch (err) {
    db.close();
    db = null;
    throw new Error(`initDb: schema/migration failed for "${dbPath}" — ${(err as Error).message}`);
  }
  return db;
}

export function getDb(): Database.Database {
  if (!db) throw new Error('DB not initialized — call initDb() first');
  return db;
}

export function closeDb(): void {
  if (db) {
    try {
      // Fold the WAL back into the main db file so no -wal/-shm leftovers
      // linger on the volume after shutdown.
      db.pragma('wal_checkpoint(TRUNCATE)');
    } catch {
      // best-effort
    }
    db.close();
    db = null;
  }
}
