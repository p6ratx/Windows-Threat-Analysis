import { ensureActiveMap } from '../db.js';
import { asString, clampLimit, safeJsonParse } from '../util/safe.js';
import {
  isNonRoutableThreatIp,
  huntLoopbackEnabled,
  TRUSTED_SOFTWARE_CLASSES,
  classifyProcessName,
  isPrivateIp
} from './enrichment.js';

function median(nums) {
  if (!nums.length) return null;
  const a = [...nums].sort((x, y) => x - y);
  const mid = Math.floor(a.length / 2);
  return a.length % 2 ? a[mid] : (a[mid - 1] + a[mid]) / 2;
}

function mean(nums) {
  if (!nums.length) return null;
  return nums.reduce((s, n) => s + n, 0) / nums.length;
}

function softClass(name, stored) {
  const classified = classifyProcessName(name);
  if (classified && classified !== 'unclassified') return classified;
  return stored || 'unclassified';
}

/** Purge loopback / link-local beacon rows (default threat views). */
export function purgeLoopbackBeacons(db, mapId) {
  const mid = mapId || ensureActiveMap(db);
  if (huntLoopbackEnabled()) return { map_id: mid, deleted: 0, hunted: true };
  const r = db
    .prepare(
      `DELETE FROM beacon_candidates WHERE map_id = ?
         AND (
           remote_ip IN ('127.0.0.1','::1','0:0:0:0:0:0:0:1')
           OR remote_ip LIKE '127.%'
           OR lower(remote_ip) LIKE 'fe80:%'
           OR remote_ip LIKE '::ffff:127.%'
           OR remote_ip LIKE '169.254.%'
         )`
    )
    .run(mid);
  return { map_id: mid, deleted: r.changes || 0 };
}

export function recomputeBeacons(db, mapId, hostId) {
  const mid = mapId || ensureActiveMap(db);
  purgeLoopbackBeacons(db, mid);

  let sql = `
    SELECT host_id, process_name, remote_ip, remote_port, software_class,
           GROUP_CONCAT(ts) AS ts_list, COUNT(*) AS sightings, MAX(c2_score) AS max_c2
    FROM peer_observations
    WHERE map_id = ?`;
  const params = [mid];
  if (hostId) {
    sql += ` AND host_id = ?`;
    params.push(asString(hostId, { max: 128 }));
  }
  sql += `
    GROUP BY host_id, process_name, remote_ip, IFNULL(remote_port, -1)
    HAVING COUNT(*) >= 4`;

  const groups = db.prepare(sql).all(...params);
  const now = new Date().toISOString();
  let upserted = 0;

  const upsert = db.prepare(
    `INSERT INTO beacon_candidates (
      id, map_id, host_id, process_name, remote_ip, remote_port, sightings,
      interval_mean_secs, interval_jitter_secs, score, reasons_json, tier,
      first_seen, last_seen, updated_at, attrs_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      sightings = excluded.sightings,
      interval_mean_secs = excluded.interval_mean_secs,
      interval_jitter_secs = excluded.interval_jitter_secs,
      score = excluded.score,
      reasons_json = excluded.reasons_json,
      tier = excluded.tier,
      last_seen = excluded.last_seen,
      updated_at = excluded.updated_at,
      attrs_json = excluded.attrs_json`
  );

  for (const g of groups) {
    const remoteIp = g.remote_ip;
    // Loopback / link-local never become C2 beacons unless explicitly hunting local services
    if (isNonRoutableThreatIp(remoteIp) && !huntLoopbackEnabled()) continue;

    const sw = softClass(g.process_name, g.software_class);
    const times = String(g.ts_list || '')
      .split(',')
      .map((t) => Date.parse(t))
      .filter((n) => Number.isFinite(n))
      .sort((a, b) => a - b);
    if (times.length < 4) continue;

    const intervals = [];
    for (let i = 1; i < times.length; i++) {
      intervals.push((times[i] - times[i - 1]) / 1000);
    }
    const med = median(intervals);
    const avg = mean(intervals);
    const jitter = mean(intervals.map((x) => Math.abs(x - (med || avg || 0))));
    const reasons = [];
    let score = 0;
    const port = Number(g.remote_port) || 0;
    const httpsLike = [80, 443, 53, 853].includes(port);

    // Trusted browser/dev/system HTTPS cadence is expected — suppress beacon threat
    if (TRUSTED_SOFTWARE_CLASSES.has(sw) && (httpsLike || isPrivateIp(remoteIp))) {
      continue;
    }

    if (med != null && med >= 25 && med <= 900) {
      score += 0.45;
      reasons.push('periodic_interval');
    }
    if (med != null && jitter != null && med > 0 && jitter / med < 0.35) {
      score += 0.25;
      reasons.push('low_jitter');
    }
    if (sw === 'unknown_process' || sw === 'unclassified') {
      score += 0.2;
      reasons.push('unknown_process');
    }
    if (g.remote_port && ![80, 443, 53].includes(Number(g.remote_port))) {
      score += 0.1;
      reasons.push('non_standard_port');
    }
    if ((g.max_c2 || 0) >= 0.45) {
      score += 0.15;
      reasons.push('elevated_c2_heuristic');
    }

    // Soft-cap trusted software even on odd ports
    if (TRUSTED_SOFTWARE_CLASSES.has(sw)) {
      score = Math.min(score, 0.35);
      reasons.push('trusted_software_cap');
    }

    score = Math.min(1, score);
    if (score < 0.4) continue;

    // Never "confirmed" without elevated C2 or unknown process on public IP
    let tier = 'watch';
    if (score >= 0.75 && (g.max_c2 || 0) >= 0.45 && (sw === 'unknown_process' || sw === 'unclassified')) {
      tier = 'confirmed';
    } else if (score >= 0.6 && (g.max_c2 || 0) >= 0.45) {
      tier = 'candidate';
    } else if (score >= 0.6) {
      tier = 'candidate';
    }

    const id = hashId(`${mid}|${g.host_id}|${g.process_name || ''}|${g.remote_ip}|${g.remote_port ?? -1}`);
    upsert.run(
      id,
      mid,
      g.host_id,
      g.process_name || null,
      g.remote_ip,
      g.remote_port,
      g.sightings,
      avg,
      jitter,
      score,
      JSON.stringify(reasons),
      tier,
      new Date(times[0]).toISOString(),
      new Date(times[times.length - 1]).toISOString(),
      now,
      JSON.stringify({ software_class: sw, max_c2: g.max_c2 })
    );
    upserted += 1;
  }

  return { map_id: mid, upserted };
}

export function listBeacons(db, mapId, { limit = 50, minScore = 0.4, host_id, includeLoopback = false } = {}) {
  const mid = mapId || ensureActiveMap(db);
  const lim = clampLimit(limit, 50, 200);
  let sql = `SELECT * FROM beacon_candidates WHERE map_id = ? AND score >= ?`;
  const params = [mid, Number(minScore) || 0];
  if (host_id) {
    sql += ` AND host_id = ?`;
    params.push(asString(host_id, { max: 128 }));
  }
  sql += ` ORDER BY score DESC, last_seen DESC LIMIT ?`;
  params.push(lim * 2); // over-fetch then filter
  const rows = db.prepare(sql).all(...params);
  const hunt = huntLoopbackEnabled() || includeLoopback;
  return rows
    .filter((r) => hunt || !isNonRoutableThreatIp(r.remote_ip))
    .filter((r) => {
      const sw = softClass(r.process_name, safeJsonParse(r.attrs_json, {}).software_class);
      // Hide trusted HTTPS noise from threat beacon list
      if (TRUSTED_SOFTWARE_CLASSES.has(sw) && [80, 443, 53, 853].includes(Number(r.remote_port) || 0)) {
        return false;
      }
      return true;
    })
    .slice(0, lim)
    .map((r) => ({
      ...r,
      reasons: safeJsonParse(r.reasons_json, []),
      attrs: safeJsonParse(r.attrs_json, {})
    }));
}

function hashId(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `bc${(h >>> 0).toString(16)}`;
}
