import { v4 as uuid } from 'uuid';
import os from 'os';
import { ensureActiveMap } from '../db.js';
import { upsertEvidenceIntoMap } from './mapEngine.js';
import { recordActivityFromEvent } from './activity.js';
import { recordPeersFromEvent } from './peers.js';
import { upsertAgent } from './fleet.js';
import {
  HttpError,
  normalizeEvidenceEvent,
  clampLimit,
  asString,
  asOptionalId,
  safeJsonParse
} from '../util/safe.js';

const MAX_BATCH = 100;

export function ingestEvent(db, payload, { scanRunId } = {}) {
  const normalized = normalizeEvidenceEvent(payload, {
    host_id: getHostId(db),
    scan_run_id: scanRunId || null
  });

  // Refuse synthetic / demo fixtures unless explicitly enabled
  if (process.env.AEGIS_ALLOW_SYNTHETIC !== '1' && isSyntheticPayload(normalized)) {
    return null;
  }

  const id = normalized.id || uuid();
  const event = { ...normalized, id };

  try {
    db.prepare(
      `INSERT INTO events (id, scan_run_id, ts, agent, host_id, type, severity, entities_json, edges_json, raw_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      event.id,
      event.scan_run_id,
      event.ts,
      event.agent,
      event.host_id,
      event.type,
      event.severity,
      JSON.stringify(event.entities),
      JSON.stringify(event.edges),
      JSON.stringify(event.raw)
    );
  } catch (e) {
    if (String(e.message || e).includes('UNIQUE')) {
      throw new HttpError(409, 'Event id already exists', 'conflict');
    }
    throw e;
  }

  try {
    upsertAgent(db, { kind: event.agent || 'gateway', host_id: event.host_id });
  } catch (e) {
    console.error('[aegis] agent upsert failed', e.message || e);
  }

  try {
    const mapId = ensureActiveMap(db);
    upsertEvidenceIntoMap(db, mapId, event);
    recordActivityFromEvent(db, mapId, event);
    recordPeersFromEvent(db, mapId, event);
  } catch (e) {
    console.error('[aegis] map upsert failed', e.message || e);
  }

  if (['high', 'critical'].includes(event.severity)) {
    try {
      createFindingFromEvent(db, event);
    } catch (e) {
      console.error('[aegis] finding create failed', e.message || e);
    }
  }

  return event;
}

export function ingestBatch(db, events, scanRunId) {
  if (!Array.isArray(events)) throw new HttpError(400, 'Batch must be an array');
  if (events.length === 0) return [];
  if (events.length > MAX_BATCH) {
    throw new HttpError(400, `Batch too large (max ${MAX_BATCH})`);
  }

  const out = [];
  const tx = db.transaction((items) => {
    for (const item of items) {
      const saved = ingestEvent(db, item, { scanRunId });
      if (saved) out.push(saved);
    }
  });
  try {
    tx(events);
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(400, `Batch ingest failed: ${String(e.message || e).slice(0, 120)}`);
  }
  return out;
}

function createFindingFromEvent(db, event) {
  const id = uuid();
  db.prepare(
    `INSERT INTO findings (id, scan_run_id, title, severity, confidence, summary, event_ids_json)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    event.scan_run_id,
    asString(`${event.type} on ${event.host_id}`, { max: 240 }),
    event.severity,
    0.7,
    asString(`Auto-finding from ${event.agent}: ${event.type}`, { max: 500 }),
    JSON.stringify([event.id])
  );
}

function getHostId(db) {
  try {
    const row = db.prepare(`SELECT value FROM settings WHERE key = 'host_id'`).get();
    const v = row?.value;
    if (v && !['local-host', 'test-host', 'smoke-host', 'docker-host'].includes(v)) return v;
  } catch {
    /* fall through */
  }
  try {
    return os.hostname() || 'local-host';
  } catch {
    return 'local-host';
  }
}

function isSyntheticPayload(event) {
  const raw = event?.raw || {};
  const note = String(raw.note || '').toLowerCase();
  const source = String(raw.source || '').toLowerCase();
  const heuristic = String(raw.heuristic || '').toLowerCase();
  if (note.includes('synthetic') || note.includes('demo_or_fallback') || note.includes('test egress')) {
    return true;
  }
  if (source === 'fallback') return true;
  if (heuristic === 'rdp_exposed') return true;
  const ents = Array.isArray(event?.entities) ? event.entities : [];
  for (const e of ents) {
    const id = String(e?.id || '').toLowerCase();
    const label = String(e?.label || '').toLowerCase();
    if (id === 'runkey:suspicious' || label.includes('hkcu run anomaly')) return true;
  }
  return false;
}

export function listEvents(db, { limit = 100, offset = 0, type, host_id } = {}) {
  const lim = clampLimit(limit, 100, 500);
  const off = Math.max(0, Math.min(100_000, Number(offset) || 0));
  let sql = `SELECT * FROM events WHERE 1=1`;
  const params = [];
  if (type) {
    sql += ` AND type = ?`;
    params.push(asString(type, { max: 120 }));
  }
  if (host_id) {
    sql += ` AND host_id = ?`;
    params.push(asString(host_id, { max: 128 }));
  }
  sql += ` ORDER BY ts DESC LIMIT ? OFFSET ?`;
  params.push(lim, off);
  return db.prepare(sql).all(...params).map(parseEventRow);
}

function parseEventRow(row) {
  return {
    ...row,
    entities: safeJsonParse(row.entities_json, []),
    edges: safeJsonParse(row.edges_json, []),
    raw: safeJsonParse(row.raw_json, {})
  };
}

export { asOptionalId };
