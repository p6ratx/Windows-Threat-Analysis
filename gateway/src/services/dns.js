import { v4 as uuid } from 'uuid';
import { ensureActiveMap } from '../db.js';
import { asString, clampLimit, safeJsonParse } from '../util/safe.js';

export function recordDnsFromEvent(db, mapId, event) {
  if (!event || event.type !== 'etw.dns.query') return;
  const mid = mapId || ensureActiveMap(db);
  const raw = event.raw || {};
  const hostname = asString(raw.query || raw.QueryName || raw.name || '', { max: 240 }).toLowerCase();
  if (!hostname || hostname === '.' || hostname.length < 2) return;

  let processName = raw.process || raw.process_name || null;
  let pid = Number(raw.pid || raw.PID || 0) || null;
  for (const ent of event.entities || []) {
    if (ent.kind === 'process') {
      processName = processName || ent.label;
      pid = pid || Number(ent.attrs?.pid) || null;
    }
  }

  db.prepare(
    `INSERT INTO dns_queries (
      id, map_id, scan_run_id, event_id, host_id, ts, hostname, pid, process_name, attrs_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    uuid(),
    mid,
    event.scan_run_id || null,
    event.id || null,
    asString(event.host_id || 'local-host', { max: 128 }),
    event.ts || new Date().toISOString(),
    hostname,
    pid,
    processName ? asString(processName, { max: 120 }) : null,
    JSON.stringify({ source: 'etw.dns.query' })
  );
}

export function joinDnsToPeers(db, mapId, { windowSecs = 90, scanRunId } = {}) {
  const mid = mapId || ensureActiveMap(db);
  const windowMs = Math.max(5, Number(windowSecs) || 90) * 1000;

  let dnsSql = `SELECT * FROM dns_queries WHERE map_id = ?`;
  const dnsParams = [mid];
  if (scanRunId) {
    dnsSql += ` AND (scan_run_id = ? OR scan_run_id IS NULL)`;
    dnsParams.push(scanRunId);
  }
  dnsSql += ` ORDER BY ts DESC LIMIT 600`;
  const dnsRows = db.prepare(dnsSql).all(...dnsParams);

  let joined = 0;
  for (const d of dnsRows) {
    const t = Date.parse(d.ts);
    if (!Number.isFinite(t)) continue;
    const start = new Date(t - windowMs).toISOString();
    const end = new Date(t + windowMs).toISOString();

    // Prefer PID match; fall back to same process name; then any peer on host in window
    let obs = [];
    if (d.pid) {
      obs = db
        .prepare(
          `SELECT * FROM peer_observations
           WHERE map_id = ? AND host_id = ? AND ts >= ? AND ts <= ? AND pid = ?
           ORDER BY ts DESC LIMIT 40`
        )
        .all(mid, d.host_id, start, end, d.pid);
    }
    if (!obs.length && d.process_name) {
      obs = db
        .prepare(
          `SELECT * FROM peer_observations
           WHERE map_id = ? AND host_id = ? AND ts >= ? AND ts <= ?
             AND lower(IFNULL(process_name,'')) = lower(?)
           ORDER BY ts DESC LIMIT 40`
        )
        .all(mid, d.host_id, start, end, d.process_name);
    }
    if (!obs.length) {
      obs = db
        .prepare(
          `SELECT * FROM peer_observations
           WHERE map_id = ? AND host_id = ? AND ts >= ? AND ts <= ?
             AND remote_ip NOT IN ('127.0.0.1','::1') AND remote_ip NOT LIKE '127.%'
           ORDER BY ts DESC LIMIT 20`
        )
        .all(mid, d.host_id, start, end);
    }

    for (const o of obs) {
      const conf =
        d.pid && o.pid && d.pid === o.pid
          ? 0.85
          : d.process_name &&
              o.process_name &&
              String(d.process_name).toLowerCase() === String(o.process_name).toLowerCase()
            ? 0.7
            : 0.45;
      upsertResolution(db, mid, {
        host_id: d.host_id,
        hostname: d.hostname,
        remote_ip: o.remote_ip,
        process_name: d.process_name || o.process_name,
        pid: d.pid || o.pid,
        confidence: conf,
        ts: d.ts
      });
      stampPeerHostname(db, mid, o, d.hostname);
      joined += 1;
    }
  }

  // Also stamp PTR hostnames from enrichment_cache onto peers missing hostname
  try {
    const peers = db
      .prepare(
        `SELECT id, host_id, remote_ip, attrs_json FROM remote_peers
         WHERE map_id = ? AND c2_score >= 0.45 LIMIT 40`
      )
      .all(mid);
    for (const p of peers) {
      const attrs = safeJsonParse(p.attrs_json, {});
      if (attrs.hostname) continue;
      const ptr = db
        .prepare(
          `SELECT data_json FROM enrichment_cache
           WHERE subject_kind = 'ip' AND subject = ? AND provider = 'ptr'`
        )
        .get(p.remote_ip);
      if (!ptr) continue;
      const data = safeJsonParse(ptr.data_json, {});
      if (!data.hostname) continue;
      attrs.hostname = data.hostname;
      db.prepare(`UPDATE remote_peers SET attrs_json = ? WHERE id = ?`).run(JSON.stringify(attrs), p.id);
      upsertResolution(db, mid, {
        host_id: p.host_id,
        hostname: data.hostname,
        remote_ip: p.remote_ip,
        confidence: 0.6,
        ts: new Date().toISOString()
      });
    }
  } catch {
    /* ignore */
  }

  return { map_id: mid, joined, dns_rows: dnsRows.length, window_secs: Math.round(windowMs / 1000) };
}

function upsertResolution(db, mapId, r) {
  const id = hashId(
    `${mapId}|${r.host_id}|${r.hostname}|${r.remote_ip}|${r.pid || -1}`
  );
  const now = r.ts || new Date().toISOString();
  const existing = db.prepare(`SELECT id, hit_count FROM ip_resolutions WHERE id = ?`).get(id);
  if (existing) {
    db.prepare(
      `UPDATE ip_resolutions SET last_seen = ?, hit_count = ?, confidence = MAX(confidence, ?),
        process_name = COALESCE(?, process_name) WHERE id = ?`
    ).run(now, (existing.hit_count || 1) + 1, r.confidence || 0.5, r.process_name || null, id);
  } else {
    db.prepare(
      `INSERT INTO ip_resolutions (
        id, map_id, host_id, hostname, remote_ip, process_name, pid, confidence, first_seen, last_seen, hit_count, attrs_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
    ).run(
      id,
      mapId,
      r.host_id,
      r.hostname,
      r.remote_ip,
      r.process_name || null,
      r.pid || null,
      r.confidence || 0.5,
      now,
      now,
      JSON.stringify({ source: 'time_window_join' })
    );
  }
}

function stampPeerHostname(db, mapId, obs, hostname) {
  const rows = db
    .prepare(
      `SELECT id, attrs_json FROM remote_peers
       WHERE map_id = ? AND host_id = ? AND remote_ip = ? AND IFNULL(remote_port, -1) = IFNULL(?, -1)
       LIMIT 5`
    )
    .all(mapId, obs.host_id, obs.remote_ip, obs.remote_port);
  for (const row of rows) {
    const attrs = safeJsonParse(row.attrs_json, {});
    if (attrs.hostname === hostname) continue;
    attrs.hostname = hostname;
    db.prepare(`UPDATE remote_peers SET attrs_json = ? WHERE id = ?`).run(JSON.stringify(attrs), row.id);
  }
}

export function listDns(db, mapId, { ip, hostname, limit = 80 } = {}) {
  const mid = mapId || ensureActiveMap(db);
  const lim = clampLimit(limit, 80, 300);
  if (ip) {
    const res = db
      .prepare(
        `SELECT * FROM ip_resolutions WHERE map_id = ? AND remote_ip = ? ORDER BY last_seen DESC LIMIT ?`
      )
      .all(mid, asString(ip, { max: 80 }), lim);
    return { map_id: mid, remote_ip: ip, resolutions: res };
  }
  let sql = `SELECT * FROM dns_queries WHERE map_id = ?`;
  const params = [mid];
  if (hostname) {
    sql += ` AND hostname LIKE ?`;
    params.push(`%${asString(hostname, { max: 120 }).toLowerCase()}%`);
  }
  sql += ` ORDER BY ts DESC LIMIT ?`;
  params.push(lim);
  return { map_id: mid, queries: db.prepare(sql).all(...params) };
}

export function hostnamesForIp(db, mapId, ip) {
  const mid = mapId || ensureActiveMap(db);
  return db
    .prepare(
      `SELECT hostname, confidence, hit_count, process_name, last_seen
       FROM ip_resolutions WHERE map_id = ? AND remote_ip = ?
       ORDER BY confidence DESC, hit_count DESC LIMIT 10`
    )
    .all(mid, ip);
}

function hashId(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `d${(h >>> 0).toString(16)}`;
}
