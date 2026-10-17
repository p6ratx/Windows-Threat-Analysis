import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '../..');

export function defaultDbPath() {
  return process.env.AEGIS_DB_PATH || path.join(root, 'data', 'aegis.db');
}

export function openDb(dbPath = defaultDbPath()) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

export function migrate(db) {
  const schemaDir = path.join(root, 'schema');
  const files = fs
    .readdirSync(schemaDir)
    .filter((f) => /^0\d+_.*\.sql$/i.test(f))
    .sort();
  for (const file of files) {
    const sql = fs.readFileSync(path.join(schemaDir, file), 'utf8');
    db.exec(sql);
  }
}

export function ensureActiveMap(db) {
  const row = db.prepare(`SELECT value FROM settings WHERE key = 'active_map_id'`).get();
  if (row?.value) {
    const exists = db.prepare(`SELECT id FROM threat_maps WHERE id = ?`).get(row.value);
    if (exists) return row.value;
  }
  const id = cryptoRandom();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO threat_maps (id, title, description, status, created_at, updated_at)
     VALUES (?, ?, ?, 'active', ?, ?)`
  ).run(id, 'Default Threat Map', 'Auto-created active map for evidence ingest', now, now);
  db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('active_map_id', ?)`).run(id);
  return id;
}

function cryptoRandom() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
