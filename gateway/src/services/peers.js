import { v4 as uuid } from 'uuid';
import { ensureActiveMap } from '../db.js';
import { clampLimit, asString, safeJsonParse } from '../util/safe.js';
import {
  isDocOrSyntheticIp,
  enrichPeerSync,
  computeTier,
  enrichOptionalHttp,
  enrichPtr,
  classifyProcessName,
  isNonRoutableThreatIp,
  huntLoopbackEnabled,
  TRUSTED_SOFTWARE_CLASSES,
  explainC2Score
} from './enrichment.js';
import { recordDnsFromEvent, hostnamesForIp } from './dns.js';
import { baselineStatusFor } from './baseline.js';
import { listBeacons } from './beacons.js';
import { isConfirmedWatch } from './watches.js';

const SOFTWARE_RATIONALE = {
  browser: 'Matches known browser binary; public HTTPS/HTTP egress is expected.',
  microsoft_system: 'Matches Windows system / service-host processes.',
  microsoft_update: 'Matches Windows Update / servicing components.',
  dev_tool: 'Matches developer tooling (IDE, runtimes, containers).',
  office_collab: 'Matches Office / Teams / OneDrive collaboration clients.',
  security_agent: 'Matches endpoint security / Defender components.',
  remote_access: 'Matches interactive remote-access clients.',
  unknown_process: 'Process name not in allowlist — treat public egress as higher priority.',
  unclassified: 'Could not classify process; limited attribution confidence.',
  etw_observed: 'Observed via ETW network/DNS telemetry.'
};

function allowSynthetic() {
  return process.env.AEGIS_ALLOW_SYNTHETIC === '1';
}

function rejectSynthetic(process, remoteIp, extras = {}) {
  if (allowSynthetic()) return false;
  const p = String(process || '').toLowerCase();
  if (p === 'test.exe' || p === 'synthetic.exe') return true;
  if (isDocOrSyntheticIp(remoteIp)) return true;
  const doing = String(extras.doing || '').toLowerCase();
  if (doing.includes('test egress') || doing.includes('synthetic smb')) return true;
  const note = String(extras.note || extras.source || '').toLowerCase();
  if (note === 'demo_or_fallback' || note === 'fallback') return true;
  return false;
}

function peerKey(hostId, process, pid, remoteIp, remotePort) {
  return `${hostId}|${process || ''}|${pid || 0}|${remoteIp}|${remotePort || 0}`;
}

export function recordPeersFromEvent(db, mapId, event) {
  if (!event) return;
  const mid = mapId || ensureActiveMap(db);
  const type = event.type || '';

  if (type === 'etw.dns.query') {
    recordDnsFromEvent(db, mid, event);
    return;
  }

  if (type === 'net.peers.summary') {
    const dests = event.raw?.destinations;
    if (Array.isArray(dests)) {
      for (const d of dests.slice(0, 120)) {
        upsertPeer(db, mid, event, d, { observe: true });
      }
    }
    return;
  }

  if (type === 'net.c2.candidate') {
    const d = {
      remote_ip: event.raw?.remote_ip,
      remote_port: event.raw?.remote_port,
      process: event.raw?.connection?.Process || event.raw?.connection?.process,
      pid: event.raw?.connection?.PID || event.raw?.connection?.pid,
      local: event.raw?.connection
        ? `${event.raw.connection.LocalIP || event.raw.connection.local_ip || ''}:${event.raw.connection.LocalPort || event.raw.connection.local_port || ''}`
        : undefined,
      public: true,
      software_class: event.raw?.software_class,
      attribution_confidence: 0.4,
      c2_score: event.raw?.c2_score,
      c2_reasons: event.raw?.reasons,
      doing: event.raw?.doing,
      port_role: remotePortRole(Number(event.raw?.remote_port))
    };
    upsertPeer(db, mid, event, d, { observe: true });
    insertC2Observation(db, mid, event, d);
    return;
  }

  if (type === 'etw.network.flow') {
    const raw = event.raw || {};
    const ip = raw.remote_ip || raw.dest || raw.RemoteAddress || raw.destination_ip;
    const port = Number(raw.remote_port || raw.dport || raw.RemotePort || raw.destination_port || 0);
    let process = raw.process || raw.ImageName || raw.process_name;
    let pid = raw.pid || raw.PID;
    for (const ent of event.entities || []) {
      if (ent.kind === 'process') {
        process = process || ent.label;
        pid = pid || ent.attrs?.pid;
      }
    }
    if (ip && typeof ip === 'string' && ip.length < 80) {
      upsertPeer(db, mid, event, {
        remote_ip: ip,
        remote_port: port || null,
        process,
        pid,
        software_class: 'etw_observed',
        attribution_confidence: 0.45,
        c2_score: 0,
        doing: `ETW network flow toward ${ip}:${port || '?'}`,
        port_role: remotePortRole(port),
        public: true,
        source: type
      }, { observe: true });
    }
  }
}

function upsertPeer(db, mapId, event, d, { observe = false } = {}) {
  const remoteIp = asString(d.remote_ip || d.RemoteIP || '', { max: 80 });
  if (!remoteIp || remoteIp === '*' || remoteIp === '0.0.0.0') return;

  const processName = asString(d.process || d.Process || 'unknown', { max: 120 });
  if (
    rejectSynthetic(processName, remoteIp, {
      doing: d.doing,
      note: d.note || event?.raw?.note,
      source: event?.raw?.source
    })
  ) {
    return;
  }

  const pid = Number(d.pid || d.PID || 0) || null;
  const remotePort = Number(d.remote_port || d.RemotePort || 0) || null;
  const hostId = asString(event.host_id || 'local-host', { max: 128 });
  const key = peerKey(hostId, processName, pid, remoteIp, remotePort);
  const id = hashId(key);
  const now = event.ts || new Date().toISOString();
  let sw = asString(d.software_class || 'unclassified', { max: 40 });
  const classified = classifyProcessName(processName);
  if (classified && classified !== 'unclassified') {
    // Prefer gateway allowlist when collector is stale/unknown
    if (sw === 'unknown_process' || sw === 'unclassified' || sw === 'etw_observed') {
      sw = classified;
    } else if (classified === 'windows_ui' || classified === 'browser' || classified === 'microsoft_system') {
      sw = classified;
    }
  }
  const conf = Number(d.attribution_confidence) || 0.4;
  let c2 = Number(d.c2_score) || 0;
  const reasons = Array.isArray(d.c2_reasons) ? [...d.c2_reasons] : [];
  const functionTag = asString(d.port_role || remotePortRole(remotePort), { max: 40 });
  const direction = d.public ? 'egress_public' : d.private ? 'egress_private' : 'egress';

  const enrichment = enrichPeerSync(db, {
    remote_ip: remoteIp,
    remote_port: remotePort,
    process_path: d.image || d.path
  });

  // Loopback / link-local: never inflate C2 (local-service hunt is opt-in)
  if (isNonRoutableThreatIp(remoteIp) && !huntLoopbackEnabled()) {
    c2 = 0;
    if (!reasons.includes('loopback_suppressed')) reasons.push('loopback_suppressed');
  }

  if (TRUSTED_SOFTWARE_CLASSES.has(sw) && ['https', 'http', 'dns', 'dot', 'unknown'].includes(functionTag)) {
    c2 = 0;
  }
  // Signed Microsoft / known publisher HTTPS should not inflate C2
  if (enrichment?.authenticode?.signed && ['https', 'http', 'dns', 'dot'].includes(functionTag)) {
    const pub = String(enrichment.authenticode.publisher || '').toLowerCase();
    if (
      pub.includes('microsoft') ||
      pub.includes('google') ||
      pub.includes('mozilla') ||
      TRUSTED_SOFTWARE_CLASSES.has(sw)
    ) {
      c2 = 0;
      if (!reasons.includes('signed_trusted_publisher')) reasons.push('signed_trusted_publisher');
    }
  }
  if (enrichment.ioc_hit && !isNonRoutableThreatIp(remoteIp)) {
    c2 = Math.max(c2, 0.7);
    reasons.push('ioc_seed_hit');
  }

  // Fire-and-forget optional enrich (do not await)
  if (remoteIp && !isNonRoutableThreatIp(remoteIp)) {
    if (process.env.AEGIS_ENRICH_URL) {
      enrichOptionalHttp(db, remoteIp).catch(() => {});
    }
    enrichPtr(db, remoteIp).catch(() => {});
  }

  const baselineStatus = baselineStatusFor(db, mapId, hostId, processName, remoteIp, remotePort);
  const watchConfirmed = isConfirmedWatch(db, mapId, { ip: remoteIp, process: processName });
  const tier = computeTier({
    c2Score: c2,
    baselineStatus,
    softwareClass: sw,
    enrichment,
    watchConfirmed,
    remoteIp
  });
  const why = explainC2Score({
    c2Score: c2,
    reasons,
    softwareClass: sw,
    enrichment,
    baselineStatus,
    tier
  });

  const attrs = {
    local: d.local,
    doing: d.doing,
    public: Boolean(d.public),
    private: Boolean(d.private),
    event_type: event.type,
    hostname: d.hostname || enrichment.ptr || null,
    enrichment,
    tier,
    baseline_status: baselineStatus,
    established_age_secs: d.established_age_secs ?? null,
    why
  };

  const existing = db.prepare(`SELECT id, hit_count, first_seen, attrs_json, c2_score FROM remote_peers WHERE id = ?`).get(id);
  if (existing) {
    const prev = safeJsonParse(existing.attrs_json, {});
    if (prev.hostname && !attrs.hostname) attrs.hostname = prev.hostname;
    // Absolute set for suppressed scores; otherwise take max of new vs stored
    const nextC2 =
      c2 === 0 && (isNonRoutableThreatIp(remoteIp) || TRUSTED_SOFTWARE_CLASSES.has(sw))
        ? 0
        : Math.max(Number(existing.c2_score) || 0, c2);
    db.prepare(
      `UPDATE remote_peers SET last_seen = ?, hit_count = ?, c2_score = ?,
        c2_reasons_json = ?, software_class = ?, attribution = ?, attribution_confidence = ?,
        function_tag = ?, attrs_json = ? WHERE id = ?`
    ).run(
      now,
      (existing.hit_count || 1) + 1,
      nextC2,
      JSON.stringify(reasons),
      sw,
      sw,
      conf,
      functionTag,
      JSON.stringify(attrs),
      id
    );
  } else {
    db.prepare(
      `INSERT INTO remote_peers (
        id, map_id, host_id, process_name, pid, local_addr, remote_ip, remote_port, proto,
        direction, function_tag, software_class, attribution, attribution_confidence,
        c2_score, c2_reasons_json, first_seen, last_seen, hit_count, attrs_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
    ).run(
      id,
      mapId,
      hostId,
      processName,
      pid,
      asString(d.local || '', { max: 80 }) || null,
      remoteIp,
      remotePort,
      'tcp',
      direction,
      functionTag,
      sw,
      sw,
      conf,
      c2,
      JSON.stringify(reasons),
      now,
      now,
      JSON.stringify(attrs)
    );
  }

  // Still record observations for baselines, but loopback observations are ignored by beacon scorer
  if (observe) {
    insertPeerObservation(db, mapId, event, {
      process: processName,
      pid,
      remote_ip: remoteIp,
      remote_port: remotePort,
      c2_score: c2,
      software_class: sw,
      direction,
      function_tag: functionTag,
      attrs
    });
  }

  upsertAttribution(db, mapId, {
    kind: 'process',
    id: `proc:${processName.toLowerCase()}`,
    label: processName,
    class: sw,
    confidence: conf,
    rationale: SOFTWARE_RATIONALE[sw] || `Classified as ${sw}`,
    indicators: { remote_ip: remoteIp, remote_port: remotePort, pid }
  });

  upsertAttribution(db, mapId, {
    kind: 'peer',
    id: `ip:${remoteIp}`,
    label: remoteIp,
    class: c2 >= 0.6 ? 'c2_destination_candidate' : 'remote_peer',
    confidence: Math.min(0.95, c2 > 0 ? c2 : Math.max(0.35, conf * 0.8)),
    rationale:
      c2 >= 0.6
        ? 'Outbound destination scored as C2 candidate from process/port heuristics.'
        : 'Observed remote peer IP from established TCP.',
    indicators: { process: processName, remote_port: remotePort, pid, software_class: sw, c2_score: c2, tier }
  });
}

function insertPeerObservation(db, mapId, event, d) {
  db.prepare(
    `INSERT INTO peer_observations (
      id, map_id, scan_run_id, host_id, ts, process_name, pid, remote_ip, remote_port,
      c2_score, software_class, direction, function_tag, attrs_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    uuid(),
    mapId,
    event.scan_run_id || null,
    asString(event.host_id || 'local-host', { max: 128 }),
    event.ts || new Date().toISOString(),
    d.process_name || d.process || null,
    d.pid || null,
    d.remote_ip,
    d.remote_port || null,
    d.c2_score || 0,
    d.software_class || null,
    d.direction || null,
    d.function_tag || null,
    JSON.stringify(d.attrs || {})
  );
}

function insertC2Observation(db, mapId, event, d) {
  const remoteIp = asString(d.remote_ip || '', { max: 80 });
  if (
    !remoteIp ||
    rejectSynthetic(d.process, remoteIp, {
      doing: d.doing,
      note: event?.raw?.note,
      source: event?.raw?.source
    })
  ) {
    return;
  }
  if (isNonRoutableThreatIp(remoteIp) && !huntLoopbackEnabled()) return;
  const sw = asString(d.software_class || classifyProcessName(d.process), { max: 40 });
  const role = remotePortRole(Number(d.remote_port) || 0);
  let score = Number(d.c2_score) || 0;
  if (TRUSTED_SOFTWARE_CLASSES.has(sw) && ['https', 'http', 'dns', 'dot', 'unknown'].includes(role)) {
    score = 0;
  }
  if (score < 0.45) return;

  let severity = 'medium';
  if (score >= 0.75) severity = 'high';
  if (score >= 0.9) severity = 'critical';

  db.prepare(
    `INSERT INTO c2_observations (
      id, map_id, host_id, event_id, ts, remote_ip, remote_port, process_name, pid,
      score, reasons_json, doing, severity, attrs_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    uuid(),
    mapId,
    asString(event.host_id || 'local-host', { max: 128 }),
    event.id || null,
    event.ts || new Date().toISOString(),
    remoteIp,
    Number(d.remote_port) || null,
    asString(d.process || 'unknown', { max: 120 }),
    Number(d.pid) || null,
    score,
    JSON.stringify(Array.isArray(d.c2_reasons) ? d.c2_reasons : []),
    asString(d.doing || `Outbound to ${remoteIp}`, { max: 400 }),
    severity,
    JSON.stringify({ software_class: d.software_class, port_role: d.port_role })
  );
}

function upsertAttribution(db, mapId, rec) {
  const id = hashId(`${mapId}|${rec.kind}|${rec.id}`);
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO attribution_records (
      id, map_id, subject_kind, subject_id, subject_label, class, confidence, rationale, indicators_json, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      class = excluded.class,
      confidence = excluded.confidence,
      rationale = excluded.rationale,
      indicators_json = excluded.indicators_json,
      subject_label = excluded.subject_label,
      updated_at = excluded.updated_at`
  ).run(
    id,
    mapId,
    asString(rec.kind, { max: 40 }),
    asString(rec.id, { max: 160 }),
    asString(rec.label || '', { max: 200 }),
    asString(rec.class, { max: 60 }),
    Number(rec.confidence) || 0.5,
    asString(rec.rationale || '', { max: 500 }),
    JSON.stringify(rec.indicators || {}),
    now
  );
}

function remotePortRole(port) {
  const p = Number(port);
  if (!Number.isFinite(p) || p <= 0) return 'unknown';
  const map = {
    80: 'http',
    443: 'https',
    53: 'dns',
    22: 'ssh',
    3389: 'rdp',
    445: 'smb',
    135: 'rpc',
    8080: 'alt_http',
    8443: 'alt_http',
    4444: 'suspicious_c2_port',
    1337: 'suspicious_c2_port',
    31337: 'suspicious_c2_port'
  };
  return map[p] || 'other';
}

function hashId(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `p${(h >>> 0).toString(16)}`;
}

export function listRemotePeers(db, mapId, { limit = 100, minC2 = 0, process, host_id, tier } = {}) {
  const mid = mapId || ensureActiveMap(db);
  const lim = clampLimit(limit, 100, 500);
  let sql = `SELECT * FROM remote_peers WHERE map_id = ? AND c2_score >= ?`;
  const params = [mid, Number(minC2) || 0];
  if (process) {
    sql += ` AND lower(process_name) LIKE ?`;
    params.push(`%${String(process).toLowerCase().slice(0, 60)}%`);
  }
  if (host_id) {
    sql += ` AND host_id = ?`;
    params.push(asString(host_id, { max: 128 }));
  }
  sql += ` ORDER BY c2_score DESC, last_seen DESC LIMIT ?`;
  params.push(lim);
  let peers = db.prepare(sql).all(...params).map((r) => shapePeer(db, mid, r));
  if (tier && tier !== 'all') {
    peers = peers.filter((p) => p.tier === tier);
  }
  return { map_id: mid, count: peers.length, peers };
}

export function listC2Activity(db, mapId, { limit = 80, host_id, tier } = {}) {
  const mid = mapId || ensureActiveMap(db);
  const lim = clampLimit(limit, 80, 300);
  let obsSql = `SELECT * FROM c2_observations WHERE map_id = ?`;
  const obsParams = [mid];
  if (host_id) {
    obsSql += ` AND host_id = ?`;
    obsParams.push(asString(host_id, { max: 128 }));
  }
  obsSql += ` ORDER BY score DESC, ts DESC LIMIT ?`;
  obsParams.push(lim);
  const rows = db.prepare(obsSql).all(...obsParams);

  const byIp = {};
  for (const r of rows) {
    if (isNonRoutableThreatIp(r.remote_ip) && !huntLoopbackEnabled()) continue;
    if (!byIp[r.remote_ip]) {
      byIp[r.remote_ip] = {
        remote_ip: r.remote_ip,
        max_score: r.score,
        hits: 0,
        processes: new Set(),
        ports: new Set(),
        latest: r.ts,
        doing: r.doing,
        tier: 'candidate'
      };
    }
    const b = byIp[r.remote_ip];
    b.hits += 1;
    b.max_score = Math.max(b.max_score, r.score);
    if (r.process_name) b.processes.add(r.process_name);
    if (r.remote_port) b.ports.add(r.remote_port);
    if (r.ts > b.latest) {
      b.latest = r.ts;
      b.doing = r.doing;
    }
  }

  const destinations = Object.values(byIp)
    .map((b) => {
      const peerRow = db
        .prepare(
          `SELECT * FROM remote_peers WHERE map_id = ? AND remote_ip = ? ORDER BY c2_score DESC, last_seen DESC LIMIT 1`
        )
        .get(mid, b.remote_ip);
      const shaped = peerRow ? shapePeer(db, mid, peerRow) : null;
      return {
        remote_ip: b.remote_ip,
        max_score: b.max_score,
        hits: b.hits,
        processes: [...b.processes],
        ports: [...b.ports],
        latest: b.latest,
        doing: b.doing,
        tier: shaped?.tier || 'candidate',
        hostnames: [
          ...new Set([
            ...(shaped?.hostnames || []),
            ...hostnamesForIp(db, mid, b.remote_ip).map((h) => h.hostname)
          ])
        ],
        enrichment: shaped?.enrichment || null,
        why: shaped?.why || null,
        first_seen: shaped?.first_seen || null,
        process_path: shaped?.attrs?.local || null,
        publisher: shaped?.why?.publisher || shaped?.enrichment?.authenticode?.publisher || null,
        org: shaped?.why?.org || shaped?.enrichment?.org || null,
        asn: shaped?.why?.asn || shaped?.enrichment?.asn || null
      };
    })
    .sort((a, b) => b.max_score - a.max_score);

  let peerSql = `SELECT * FROM remote_peers WHERE map_id = ?
         AND remote_ip IS NOT NULL
         AND remote_ip NOT IN ('127.0.0.1', '::1', '0.0.0.0', '*', '0:0:0:0:0:0:0:1')
         AND remote_ip NOT LIKE '127.%'
         AND lower(remote_ip) NOT LIKE 'fe80:%'
         AND remote_ip NOT LIKE '169.254.%'`;
  const peerParams = [mid];
  if (host_id) {
    peerSql += ` AND host_id = ?`;
    peerParams.push(asString(host_id, { max: 128 }));
  }
  peerSql += ` ORDER BY c2_score DESC, hit_count DESC, last_seen DESC LIMIT ?`;
  peerParams.push(Math.min(200, lim * 2));
  const peerRows = db.prepare(peerSql).all(...peerParams);

  const egressByIp = {};
  for (const r of peerRows) {
    if (isDocOrSyntheticIp(r.remote_ip) && !allowSynthetic()) continue;
    if (isNonRoutableThreatIp(r.remote_ip) && !huntLoopbackEnabled()) continue;
    const shaped = shapePeer(db, mid, r);
    if (!egressByIp[r.remote_ip]) {
      egressByIp[r.remote_ip] = {
        remote_ip: r.remote_ip,
        max_score: Number(shaped.c2_score) || 0,
        hits: 0,
        processes: new Set(),
        ports: new Set(),
        classes: new Set(),
        latest: r.last_seen,
        first_seen: r.first_seen,
        doing: shaped.attrs?.doing || null,
        tier: shaped.tier || 'watch',
        hostnames: new Set(shaped.hostnames || []),
        enrichment: shaped.enrichment,
        why: shaped.why
      };
    }
    const b = egressByIp[r.remote_ip];
    b.hits += Number(r.hit_count) || 1;
    b.max_score = Math.max(b.max_score, Number(shaped.c2_score) || 0);
    if (r.process_name) b.processes.add(r.process_name);
    if (r.remote_port) b.ports.add(r.remote_port);
    if (shaped.software_class) b.classes.add(shaped.software_class);
    if (r.last_seen > b.latest) b.latest = r.last_seen;
    if (r.first_seen && (!b.first_seen || r.first_seen < b.first_seen)) b.first_seen = r.first_seen;
    if (shaped.attrs?.hostname) b.hostnames.add(shaped.attrs.hostname);
    for (const h of shaped.hostnames || []) b.hostnames.add(h);
    if (shaped.tier === 'confirmed') b.tier = 'confirmed';
    else if (shaped.tier === 'candidate' && b.tier !== 'confirmed') b.tier = 'candidate';
    else if (b.max_score >= 0.45 && b.tier === 'watch') b.tier = 'candidate';
    if (shaped.why && (!b.why || (shaped.why.score || 0) >= (b.why.score || 0))) b.why = shaped.why;
    if (shaped.enrichment) b.enrichment = shaped.enrichment;
  }

  let egress_watch = Object.values(egressByIp)
    .map((b) => ({
      remote_ip: b.remote_ip,
      max_score: b.max_score,
      hits: b.hits,
      processes: [...b.processes],
      ports: [...b.ports],
      software_classes: [...b.classes],
      latest: b.latest,
      first_seen: b.first_seen,
      doing: b.doing,
      tier: b.tier,
      hostnames: [...b.hostnames],
      enrichment: b.enrichment,
      why: b.why,
      org: b.why?.org || b.enrichment?.org || b.enrichment?.http?.org || null,
      asn: b.why?.asn || b.enrichment?.asn || b.enrichment?.http?.asn || null,
      publisher: b.why?.publisher || b.enrichment?.authenticode?.publisher || null
    }))
    .sort((a, b) => b.max_score - a.max_score || b.hits - a.hits);

  if (tier && tier !== 'all') {
    egress_watch = egress_watch.filter((e) => e.tier === tier);
  }

  const peerStats = db
    .prepare(
      `SELECT COUNT(*) AS peer_count,
              COALESCE(MAX(c2_score), 0) AS max_c2,
              SUM(CASE WHEN c2_score >= 0.45 THEN 1 ELSE 0 END) AS candidate_peers
       FROM remote_peers WHERE map_id = ? ${host_id ? 'AND host_id = ?' : ''}`
    )
    .get(...(host_id ? [mid, asString(host_id, { max: 128 })] : [mid]));

  const beacons = listBeacons(db, mid, {
    limit: 40,
    host_id: host_id ? asString(host_id, { max: 128 }) : undefined
  });

  return {
    map_id: mid,
    disclaimer:
      'C2 scores are defensive heuristics (process allowlist + port role + public egress). They are not definitive attribution of an APT or operator. Loopback/link-local is suppressed unless AEGIS_HUNT_LOOPBACK=1.',
    threshold: 0.45,
    stats: {
      peer_count: peerStats?.peer_count || 0,
      max_c2: peerStats?.max_c2 || 0,
      candidate_peers: peerStats?.candidate_peers || 0,
      candidate_ips: destinations.length,
      egress_ips: egress_watch.length,
      beacon_count: beacons.length
    },
    observations: rows
      .filter((r) => huntLoopbackEnabled() || !isNonRoutableThreatIp(r.remote_ip))
      .map((r) => ({
        ...r,
        reasons: safeJsonParse(r.reasons_json, []),
        attrs: safeJsonParse(r.attrs_json, {}),
        hostnames: hostnamesForIp(db, mid, r.remote_ip).map((h) => h.hostname)
      })),
    destinations,
    egress_watch,
    beacons
  };
}

export function attributionReport(db, mapId, { limit = 100, host_id } = {}) {
  const mid = mapId || ensureActiveMap(db);
  const lim = clampLimit(limit, 100, 300);
  const rows = db
    .prepare(
      `SELECT * FROM attribution_records WHERE map_id = ? ORDER BY confidence DESC, updated_at DESC LIMIT ?`
    )
    .all(mid, lim);

  let peerSql = `SELECT software_class, COUNT(*) AS n, AVG(c2_score) AS avg_c2 FROM remote_peers WHERE map_id = ?`;
  const peerParams = [mid];
  if (host_id) {
    peerSql += ` AND host_id = ?`;
    peerParams.push(asString(host_id, { max: 128 }));
  }
  peerSql += ` GROUP BY software_class ORDER BY n DESC`;
  const peers = db.prepare(peerSql).all(...peerParams);

  let topSql = `SELECT remote_ip, COUNT(*) AS n, MAX(c2_score) AS max_c2, GROUP_CONCAT(DISTINCT process_name) AS processes
       FROM remote_peers WHERE map_id = ?`;
  const topParams = [mid];
  if (host_id) {
    topSql += ` AND host_id = ?`;
    topParams.push(asString(host_id, { max: 128 }));
  }
  topSql += ` GROUP BY remote_ip ORDER BY max_c2 DESC, n DESC LIMIT 25`;
  const topIps = db.prepare(topSql).all(...topParams);

  return {
    map_id: mid,
    disclaimer:
      'Attribution here means software/behavioral classification of local processes and remote destinations — not claiming a named threat actor.',
    by_class: peers,
    top_destination_ips: topIps.map((r) => ({
      remote_ip: r.remote_ip,
      connections: r.n,
      max_c2: r.max_c2,
      processes: String(r.processes || '')
        .split(',')
        .filter(Boolean)
        .slice(0, 8),
      hostnames: hostnamesForIp(db, mid, r.remote_ip).map((h) => h.hostname)
    })),
    records: rows.map((r) => ({
      ...r,
      indicators: safeJsonParse(r.indicators_json, {})
    }))
  };
}

export function rebuildPeersFromEvents(db, mapId) {
  const mid = mapId || ensureActiveMap(db);
  const rows = db
    .prepare(
      `SELECT * FROM events WHERE type IN ('net.peers.summary','net.c2.candidate','etw.dns.query','etw.network.flow')
       ORDER BY ts DESC LIMIT 500`
    )
    .all();
  let n = 0;
  for (const row of rows) {
    const event = {
      id: row.id,
      ts: row.ts,
      agent: row.agent,
      host_id: row.host_id,
      type: row.type,
      severity: row.severity,
      scan_run_id: row.scan_run_id,
      raw: safeJsonParse(row.raw_json, {}),
      entities: safeJsonParse(row.entities_json, []),
      edges: safeJsonParse(row.edges_json, [])
    };
    recordPeersFromEvent(db, mid, event);
    n += 1;
  }
  return { map_id: mid, processed_events: n };
}

function shapePeer(db, mapId, r) {
  const attrs = safeJsonParse(r.attrs_json, {});
  const enrichment = attrs.enrichment || enrichPeerSync(db, { remote_ip: r.remote_ip, remote_port: r.remote_port });
  let softwareClass = r.software_class;
  const classified = classifyProcessName(r.process_name);
  if (
    classified &&
    (softwareClass === 'unknown_process' ||
      softwareClass === 'unclassified' ||
      softwareClass === 'etw_observed' ||
      classified === 'windows_ui' ||
      classified === 'browser' ||
      classified === 'microsoft_system' ||
      classified === 'dev_tool')
  ) {
    softwareClass = classified;
  }
  let c2Score = Number(r.c2_score) || 0;
  const role = remotePortRole(Number(r.remote_port) || 0);
  if (TRUSTED_SOFTWARE_CLASSES.has(softwareClass) && ['https', 'http', 'dns', 'dot', 'unknown'].includes(role)) {
    c2Score = 0;
  }
  if (isNonRoutableThreatIp(r.remote_ip) && !huntLoopbackEnabled()) {
    c2Score = 0;
  }
  if (enrichment?.authenticode?.signed && ['https', 'http', 'dns', 'dot'].includes(role)) {
    c2Score = 0;
  }
  const baselineStatus =
    attrs.baseline_status ||
    baselineStatusFor(db, mapId, r.host_id, r.process_name, r.remote_ip, r.remote_port);
  const watchConfirmed = isConfirmedWatch(db, mapId, { ip: r.remote_ip, process: r.process_name });
  const tier = computeTier({
    c2Score,
    baselineStatus,
    softwareClass,
    enrichment,
    watchConfirmed,
    remoteIp: r.remote_ip
  });
  const hostnames = hostnamesForIp(db, mapId, r.remote_ip).map((h) => h.hostname);
  if (attrs.hostname && !hostnames.includes(attrs.hostname)) hostnames.unshift(attrs.hostname);
  if (enrichment?.ptr && !hostnames.includes(enrichment.ptr)) hostnames.push(enrichment.ptr);
  const reasons = safeJsonParse(r.c2_reasons_json, []);
  const why =
    attrs.why ||
    explainC2Score({
      c2Score,
      reasons,
      softwareClass,
      enrichment,
      baselineStatus,
      tier
    });

  return {
    ...r,
    software_class: softwareClass,
    c2_score: c2Score,
    c2_reasons: reasons,
    attrs,
    enrichment,
    baseline_status: baselineStatus,
    tier,
    hostnames,
    why,
    org: why.org,
    asn: why.asn,
    publisher: why.publisher
  };
}
