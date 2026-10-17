import { ensureActiveMap } from '../db.js';
import { asString, clampLimit } from '../util/safe.js';

/** Default rolling baseline window (days). Day-1 "new" ages into baseline across ~7d of sightings. */
export const BASELINE_WINDOW_DAYS = Number(process.env.AEGIS_BASELINE_WINDOW_DAYS || 7);
const SIGHTINGS_FOR_BASELINE = Number(process.env.AEGIS_BASELINE_SIGHTINGS || 3);
const SCANS_FOR_BASELINE = Number(process.env.AEGIS_BASELINE_SCANS || 2);
/** Prefer at least this many distinct calendar days before promoting to baseline (within window). */
const DAYS_FOR_BASELINE = Number(process.env.AEGIS_BASELINE_DISTINCT_DAYS || 2);

function windowCutoffIso(days = BASELINE_WINDOW_DAYS) {
  const d = Math.max(1, Number(days) || 7);
  return new Date(Date.now() - d * 86400 * 1000).toISOString();
}

export function recomputeBaseline(db, mapId, hostId) {
  const mid = mapId || ensureActiveMap(db);
  const hostFilter = hostId ? asString(hostId, { max: 128 }) : null;
  const cutoff = windowCutoffIso(BASELINE_WINDOW_DAYS);

  // Rolling window: only count sightings inside the retention window
  let sql = `
    SELECT host_id, process_name, remote_ip, remote_port,
           COUNT(*) AS sightings,
           COUNT(DISTINCT scan_run_id) AS distinct_scans,
           COUNT(DISTINCT substr(ts, 1, 10)) AS distinct_days,
           MIN(ts) AS first_seen,
           MAX(ts) AS last_seen
    FROM peer_observations
    WHERE map_id = ? AND ts >= ?`;
  const params = [mid, cutoff];
  if (hostFilter) {
    sql += ` AND host_id = ?`;
    params.push(hostFilter);
  }
  sql += `
    GROUP BY host_id, process_name, remote_ip, IFNULL(remote_port, -1)`;

  const groups = db.prepare(sql).all(...params);
  const now = new Date().toISOString();
  let upserted = 0;

  const upsert = db.prepare(
    `INSERT INTO peer_baselines (
      id, map_id, host_id, process_name, remote_ip, remote_port,
      first_seen, last_seen, sightings, distinct_scans, status, attrs_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      last_seen = excluded.last_seen,
      first_seen = CASE
        WHEN peer_baselines.first_seen IS NULL OR excluded.first_seen < peer_baselines.first_seen
        THEN excluded.first_seen ELSE peer_baselines.first_seen END,
      sightings = excluded.sightings,
      distinct_scans = excluded.distinct_scans,
      status = excluded.status,
      attrs_json = excluded.attrs_json`
  );

  const seenIds = new Set();
  const tx = db.transaction((rows) => {
    for (const g of rows) {
      const id = baselineId(mid, g.host_id, g.process_name, g.remote_ip, g.remote_port);
      seenIds.add(id);
      let status = 'new';
      const days = Number(g.distinct_days) || 1;
      if (
        g.sightings >= SIGHTINGS_FOR_BASELINE &&
        g.distinct_scans >= SCANS_FOR_BASELINE &&
        days >= DAYS_FOR_BASELINE
      ) {
        status = 'baseline';
      } else if (g.sightings === 1 && days <= 1) {
        status = 'new';
      } else {
        status = 'rare';
      }
      upsert.run(
        id,
        mid,
        g.host_id,
        g.process_name || 'unknown',
        g.remote_ip,
        g.remote_port,
        g.first_seen || now,
        g.last_seen || now,
        g.sightings,
        g.distinct_scans,
        status,
        JSON.stringify({
          updated_at: now,
          window_days: BASELINE_WINDOW_DAYS,
          distinct_days: days,
          cutoff
        })
      );
      upserted += 1;
    }

    // Mark pairs that aged out of the window as disappeared (keep row, status rare→keep history)
    let staleSql = `SELECT id FROM peer_baselines WHERE map_id = ? AND last_seen < ? AND status = 'baseline'`;
    const staleParams = [mid, cutoff];
    if (hostFilter) {
      staleSql += ` AND host_id = ?`;
      staleParams.push(hostFilter);
    }
    const stale = db.prepare(staleSql).all(...staleParams);
    for (const s of stale) {
      if (seenIds.has(s.id)) continue;
      db.prepare(`UPDATE peer_baselines SET status = 'rare' WHERE id = ?`).run(s.id);
    }
  });
  tx(groups);

  // Soft retention: prune very old observations beyond 2x window (keep map lean)
  const pruneCutoff = windowCutoffIso(BASELINE_WINDOW_DAYS * 2);
  const pruned = db
    .prepare(`DELETE FROM peer_observations WHERE map_id = ? AND ts < ?`)
    .run(mid, pruneCutoff);

  return {
    map_id: mid,
    host_id: hostFilter,
    upserted,
    window_days: BASELINE_WINDOW_DAYS,
    cutoff,
    pruned_observations: pruned.changes || 0
  };
}

export function peersDelta(db, mapId, { host_id, limit = 80 } = {}) {
  const mid = mapId || ensureActiveMap(db);
  const lim = clampLimit(limit, 80, 300);
  const host = host_id ? asString(host_id, { max: 128 }) : null;

  let where = `map_id = ?`;
  const params = [mid];
  if (host) {
    where += ` AND host_id = ?`;
    params.push(host);
  }

  const neu = db
    .prepare(`SELECT * FROM peer_baselines WHERE ${where} AND status = 'new' ORDER BY last_seen DESC LIMIT ?`)
    .all(...params, lim);
  const rare = db
    .prepare(`SELECT * FROM peer_baselines WHERE ${where} AND status = 'rare' ORDER BY last_seen DESC LIMIT ?`)
    .all(...params, lim);
  const baseline = db
    .prepare(`SELECT COUNT(*) AS n FROM peer_baselines WHERE ${where} AND status = 'baseline'`)
    .get(...params);

  // Disappeared: baseline pairs not seen in last observation window (~2h or last scan)
  const cutoff = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
  const disappeared = db
    .prepare(
      `SELECT b.* FROM peer_baselines b
       WHERE b.map_id = ? ${host ? 'AND b.host_id = ?' : ''} AND b.status = 'baseline'
         AND b.last_seen < ?
       ORDER BY b.last_seen ASC LIMIT ?`
    )
    .all(...(host ? [mid, host, cutoff, lim] : [mid, cutoff, lim]));

  return {
    map_id: mid,
    host_id: host,
    window_days: BASELINE_WINDOW_DAYS,
    baseline_size: baseline?.n || 0,
    new: neu,
    rare,
    disappeared,
    counts: {
      new: neu.length,
      rare: rare.length,
      disappeared: disappeared.length
    },
    note: `Baselines use a rolling ${BASELINE_WINDOW_DAYS}-day window. "New" on day 1 can age into baseline after repeated sightings across ≥${DAYS_FOR_BASELINE} distinct days.`
  };
}

export function compareScans(db, mapId, scanA, scanB) {
  const mid = mapId || ensureActiveMap(db);
  const a = asString(scanA, { max: 80 });
  const b = asString(scanB, { max: 80 });

  const loadKeys = (scanId) => {
    const rows = db
      .prepare(
        `SELECT host_id, process_name, remote_ip, remote_port, MAX(c2_score) AS c2_score
         FROM peer_observations WHERE map_id = ? AND scan_run_id = ?
         GROUP BY host_id, process_name, remote_ip, IFNULL(remote_port, -1)`
      )
      .all(mid, scanId);
    const map = new Map();
    for (const r of rows) {
      map.set(keyOf(r), r);
    }
    return map;
  };

  const ma = loadKeys(a);
  const mb = loadKeys(b);
  const onlyA = [];
  const onlyB = [];
  const both = [];

  for (const [k, r] of ma) {
    if (mb.has(k)) both.push({ key: k, a: r, b: mb.get(k) });
    else onlyA.push(r);
  }
  for (const [k, r] of mb) {
    if (!ma.has(k)) onlyB.push(r);
  }

  const sumA = db.prepare(`SELECT * FROM scan_peer_summaries WHERE map_id = ? AND scan_run_id = ?`).get(mid, a);
  const sumB = db.prepare(`SELECT * FROM scan_peer_summaries WHERE map_id = ? AND scan_run_id = ?`).get(mid, b);

  return {
    map_id: mid,
    scan_a: a,
    scan_b: b,
    summaries: { a: sumA || null, b: sumB || null },
    only_in_a: onlyA.slice(0, 200),
    only_in_b: onlyB.slice(0, 200),
    in_both: both.slice(0, 200),
    counts: {
      only_a: onlyA.length,
      only_b: onlyB.length,
      both: both.length
    }
  };
}

export function writeScanPeerSummary(db, mapId, scanRunId, hostId) {
  const mid = mapId || ensureActiveMap(db);
  if (!scanRunId) return null;
  const rows = db
    .prepare(
      `SELECT remote_ip, MAX(c2_score) AS max_c2, COUNT(*) AS n
       FROM peer_observations WHERE map_id = ? AND scan_run_id = ?
       ${hostId ? 'AND host_id = ?' : ''}
       GROUP BY remote_ip ORDER BY max_c2 DESC, n DESC`
    )
    .all(...(hostId ? [mid, scanRunId, hostId] : [mid, scanRunId]));

  const peerCount = db
    .prepare(
      `SELECT COUNT(*) AS n FROM peer_observations WHERE map_id = ? AND scan_run_id = ? ${
        hostId ? 'AND host_id = ?' : ''
      }`
    )
    .get(...(hostId ? [mid, scanRunId, hostId] : [mid, scanRunId]))?.n || 0;

  const candidateCount = rows.filter((r) => (r.max_c2 || 0) >= 0.45).length;
  const maxC2 = rows.reduce((m, r) => Math.max(m, r.max_c2 || 0), 0);
  const id = `${mid}:${scanRunId}:${hostId || ''}`.slice(0, 200);
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO scan_peer_summaries (
      id, map_id, scan_run_id, host_id, ts, peer_count, unique_ips, candidate_count, max_c2, top_ips_json, attrs_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      ts = excluded.ts, peer_count = excluded.peer_count, unique_ips = excluded.unique_ips,
      candidate_count = excluded.candidate_count, max_c2 = excluded.max_c2, top_ips_json = excluded.top_ips_json`
  ).run(
    id,
    mid,
    scanRunId,
    hostId || null,
    now,
    peerCount,
    rows.length,
    candidateCount,
    maxC2,
    JSON.stringify(rows.slice(0, 20)),
    JSON.stringify({ window_days: BASELINE_WINDOW_DAYS })
  );
  return { id, peer_count: peerCount, unique_ips: rows.length, candidate_count: candidateCount, max_c2: maxC2 };
}

function baselineId(mapId, hostId, process, ip, port) {
  return hashId(`${mapId}|${hostId}|${process || ''}|${ip}|${port ?? -1}`);
}

function keyOf(r) {
  return `${r.host_id}|${r.process_name || ''}|${r.remote_ip}|${r.remote_port ?? -1}`;
}

function hashId(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `b${(h >>> 0).toString(16)}`;
}

export function baselineStatusFor(db, mapId, hostId, process, ip, port) {
  const id = baselineId(mapId, hostId, process, ip, port);
  return db.prepare(`SELECT status FROM peer_baselines WHERE id = ?`).get(id)?.status || null;
}
