import { v4 as uuid } from 'uuid';
import { ensureActiveMap } from '../db.js';
import { asString, clampLimit, HttpError, safeJsonParse } from '../util/safe.js';
import {
  isNonRoutableThreatIp,
  TRUSTED_SOFTWARE_CLASSES,
  classifyProcessName,
  isPrivateIp,
  isDocOrSyntheticIp
} from './enrichment.js';

/**
 * Default watch/alert policy (quiet):
 * Alerts fire only for meaningful tiers:
 *  - high C2 (≥0.75) on public IPs
 *  - new public egress from unknown/unsigned processes
 *  - rare baseline + candidate C2 (≥0.45) from unknown process
 * Does NOT alert on: loopback, peer deltas alone, trusted HTTPS, every new baseline pair.
 */
export const ALERT_POLICY = {
  min_high_c2: 0.75,
  min_candidate_c2: 0.45,
  alert_on_peer_delta: false,
  alert_on_loopback: false,
  alert_trusted_https: false
};

export function listWatches(db, mapId, { limit = 100 } = {}) {
  const mid = mapId || ensureActiveMap(db);
  return db
    .prepare(`SELECT * FROM analyst_watches WHERE map_id = ? ORDER BY updated_at DESC LIMIT ?`)
    .all(mid, clampLimit(limit, 100, 300));
}

export function upsertWatch(db, mapId, { kind, value, note, confirmed } = {}) {
  const mid = mapId || ensureActiveMap(db);
  const k = asString(kind || 'ip', { max: 20 });
  const v = asString(value || '', { max: 200 });
  if (!v) throw new HttpError(400, 'watch value required');
  if (!['ip', 'process', 'peer'].includes(k)) throw new HttpError(400, 'invalid watch kind');

  const existing = db
    .prepare(`SELECT id FROM analyst_watches WHERE map_id = ? AND kind = ? AND value = ?`)
    .get(mid, k, v);
  const now = new Date().toISOString();
  if (existing) {
    db.prepare(
      `UPDATE analyst_watches SET note = ?, confirmed = ?, updated_at = ? WHERE id = ?`
    ).run(asString(note || '', { max: 500 }), confirmed ? 1 : 0, now, existing.id);
    return db.prepare(`SELECT * FROM analyst_watches WHERE id = ?`).get(existing.id);
  }
  const id = uuid();
  db.prepare(
    `INSERT INTO analyst_watches (id, map_id, kind, value, note, confirmed, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(id, mid, k, v, asString(note || '', { max: 500 }), confirmed ? 1 : 0, now, now);
  return db.prepare(`SELECT * FROM analyst_watches WHERE id = ?`).get(id);
}

export function deleteWatch(db, mapId, id) {
  const mid = mapId || ensureActiveMap(db);
  const row = db.prepare(`SELECT * FROM analyst_watches WHERE id = ? AND map_id = ?`).get(id, mid);
  if (!row) throw new HttpError(404, 'watch not found', 'not_found');
  db.prepare(`DELETE FROM analyst_watches WHERE id = ?`).run(id);
  return { ok: true, id };
}

export function isConfirmedWatch(db, mapId, { ip, process } = {}) {
  const mid = mapId || ensureActiveMap(db);
  if (ip) {
    const w = db
      .prepare(
        `SELECT 1 FROM analyst_watches WHERE map_id = ? AND confirmed = 1 AND kind IN ('ip','peer') AND value = ?`
      )
      .get(mid, ip);
    if (w) return true;
  }
  if (process) {
    const w = db
      .prepare(
        `SELECT 1 FROM analyst_watches WHERE map_id = ? AND confirmed = 1 AND kind = 'process' AND value = ?`
      )
      .get(mid, process);
    if (w) return true;
  }
  return false;
}

function ensureAlertsTable(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS threat_alerts (
      id TEXT PRIMARY KEY,
      map_id TEXT NOT NULL,
      host_id TEXT,
      ts TEXT NOT NULL,
      severity TEXT NOT NULL,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      detail TEXT,
      subject TEXT,
      dedupe_key TEXT,
      attrs_json TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_alert_dedupe ON threat_alerts(map_id, dedupe_key);
    CREATE INDEX IF NOT EXISTS idx_threat_alert_ts ON threat_alerts(map_id, ts DESC);
  `);
}

/**
 * Evaluate quiet, tiered alerts after a scan. Returns new alerts only.
 */
export function evaluateThreatAlerts(db, mapId, { hostId, limit = 40 } = {}) {
  const mid = mapId || ensureActiveMap(db);
  ensureAlertsTable(db);
  const now = new Date().toISOString();
  const host = hostId ? asString(hostId, { max: 128 }) : null;
  const alerts = [];

  let peerSql = `SELECT * FROM remote_peers WHERE map_id = ? AND c2_score >= ?`;
  const peerParams = [mid, ALERT_POLICY.min_candidate_c2];
  if (host) {
    peerSql += ` AND host_id = ?`;
    peerParams.push(host);
  }
  peerSql += ` ORDER BY c2_score DESC LIMIT 80`;
  const peers = db.prepare(peerSql).all(...peerParams);

  const insert = db.prepare(
    `INSERT OR IGNORE INTO threat_alerts
     (id, map_id, host_id, ts, severity, kind, title, detail, subject, dedupe_key, attrs_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  for (const p of peers) {
    if (isNonRoutableThreatIp(p.remote_ip) || isDocOrSyntheticIp(p.remote_ip)) continue;
    if (isPrivateIp(p.remote_ip) && (Number(p.c2_score) || 0) < ALERT_POLICY.min_high_c2) continue;

    let sw = p.software_class;
    const classified = classifyProcessName(p.process_name);
    if (classified) sw = classified;
    const port = Number(p.remote_port) || 0;
    if (TRUSTED_SOFTWARE_CLASSES.has(sw) && [80, 443, 53, 853].includes(port)) continue;

    const score = Number(p.c2_score) || 0;
    const baseline = db
      .prepare(
        `SELECT status FROM peer_baselines WHERE map_id = ? AND host_id = ? AND process_name = ?
           AND remote_ip = ? AND IFNULL(remote_port,-1) = IFNULL(?, -1)`
      )
      .get(mid, p.host_id, p.process_name, p.remote_ip, p.remote_port)?.status;

    let kind = null;
    let severity = 'medium';
    let title = null;

    if (score >= ALERT_POLICY.min_high_c2) {
      kind = 'high_c2';
      severity = 'high';
      title = `High C2 score ${score.toFixed(2)}: ${p.process_name} → ${p.remote_ip}:${port || '?'}`;
    } else if (
      score >= ALERT_POLICY.min_candidate_c2 &&
      (sw === 'unknown_process' || sw === 'unclassified') &&
      baseline === 'new' &&
      !isPrivateIp(p.remote_ip)
    ) {
      kind = 'new_unknown_egress';
      severity = 'medium';
      title = `New public egress from unknown process: ${p.process_name} → ${p.remote_ip}:${port || '?'}`;
    } else if (
      score >= ALERT_POLICY.min_candidate_c2 &&
      (sw === 'unknown_process' || sw === 'unclassified') &&
      baseline === 'rare' &&
      !isPrivateIp(p.remote_ip)
    ) {
      kind = 'rare_baseline_c2';
      severity = 'medium';
      title = `Rare baseline + C2 candidate: ${p.process_name} → ${p.remote_ip}:${port || '?'}`;
    } else {
      continue;
    }

    const dedupe = `${kind}|${p.host_id}|${p.process_name}|${p.remote_ip}|${port}`.slice(0, 200);
    const id = uuid();
    const detail = asString(
      `${title}. Tiered watch — not every peer delta alerts.`,
      { max: 500 }
    );
    const r = insert.run(
      id,
      mid,
      p.host_id,
      now,
      severity,
      kind,
      asString(title, { max: 240 }),
      detail,
      p.remote_ip,
      dedupe,
      JSON.stringify({
        c2_score: score,
        process: p.process_name,
        software_class: sw,
        baseline_status: baseline,
        remote_port: port
      })
    );
    if (r.changes) {
      alerts.push({
        id,
        map_id: mid,
        host_id: p.host_id,
        ts: now,
        severity,
        kind,
        title,
        subject: p.remote_ip,
        attrs: safeJsonParse(
          JSON.stringify({
            c2_score: score,
            process: p.process_name,
            software_class: sw,
            baseline_status: baseline
          }),
          {}
        )
      });
    }
    if (alerts.length >= limit) break;
  }

  return {
    map_id: mid,
    policy: ALERT_POLICY,
    created: alerts.length,
    alerts,
    note:
      'Alerts fire on high C2, new/rare unknown public egress — not loopback, trusted HTTPS, or every peer delta.'
  };
}

export function listThreatAlerts(db, mapId, { limit = 50, host_id } = {}) {
  const mid = mapId || ensureActiveMap(db);
  ensureAlertsTable(db);
  let sql = `SELECT * FROM threat_alerts WHERE map_id = ?`;
  const params = [mid];
  if (host_id) {
    sql += ` AND host_id = ?`;
    params.push(asString(host_id, { max: 128 }));
  }
  sql += ` ORDER BY ts DESC LIMIT ?`;
  params.push(clampLimit(limit, 50, 200));
  return db.prepare(sql).all(...params).map((r) => ({
    ...r,
    attrs: safeJsonParse(r.attrs_json, {})
  }));
}
