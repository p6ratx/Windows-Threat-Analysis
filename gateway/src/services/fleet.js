import { asString, safeJsonParse } from '../util/safe.js';
import os from 'os';

const FAKE_HOSTS = new Set(['local-host', 'test-host', 'smoke-host', 'smoke-host-1', 'docker-host']);

export function upsertAgent(db, { kind, host_id, meta } = {}) {
  let hostId = asString(host_id || 'local-host', { max: 128 });
  // Never register known fake / placeholder hosts as fleet members
  if (FAKE_HOSTS.has(hostId)) {
    try {
      const real =
        db.prepare(`SELECT value FROM settings WHERE key = 'host_id'`).get()?.value ||
        os.hostname() ||
        hostId;
      if (real && !FAKE_HOSTS.has(real)) hostId = asString(real, { max: 128 });
    } catch {
      /* ignore */
    }
  }
  const agentKind = asString(kind || 'gateway', { max: 40 });
  const id = `${agentKind}:${hostId}`.slice(0, 160);
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO agents (id, kind, host_id, last_seen_at, meta_json)
     VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET last_seen_at = excluded.last_seen_at, meta_json = excluded.meta_json`
  ).run(id, agentKind, hostId, now, JSON.stringify(meta || {}));
  return id;
}

export function listFleet(db) {
  const primary =
    db.prepare(`SELECT value FROM settings WHERE key = 'host_id'`).get()?.value ||
    os.hostname() ||
    null;

  const agents = db.prepare(`SELECT * FROM agents ORDER BY last_seen_at DESC LIMIT 200`).all();
  const hosts = {};

  for (const a of agents) {
    if (FAKE_HOSTS.has(a.host_id)) continue;
    if (!hosts[a.host_id]) {
      hosts[a.host_id] = {
        host_id: a.host_id,
        agents: [],
        last_seen_at: a.last_seen_at,
        peer_count: 0,
        event_count: 0,
        etw_elevated: null,
        is_primary: primary ? a.host_id === primary : false
      };
    }
    hosts[a.host_id].agents.push({
      id: a.id,
      kind: a.kind,
      last_seen_at: a.last_seen_at,
      meta: safeJsonParse(a.meta_json, {})
    });
    if (a.last_seen_at > hosts[a.host_id].last_seen_at) {
      hosts[a.host_id].last_seen_at = a.last_seen_at;
    }
  }

  // Also include hosts seen in events/peers even if agents row missing
  const eventHosts = db
    .prepare(
      `SELECT host_id, COUNT(*) AS n, MAX(ts) AS last_ts FROM events GROUP BY host_id ORDER BY last_ts DESC LIMIT 100`
    )
    .all();
  for (const e of eventHosts) {
    if (FAKE_HOSTS.has(e.host_id)) continue;
    if (!hosts[e.host_id]) {
      hosts[e.host_id] = {
        host_id: e.host_id,
        agents: [],
        last_seen_at: e.last_ts,
        peer_count: 0,
        event_count: e.n,
        etw_elevated: null,
        is_primary: primary ? e.host_id === primary : false
      };
    } else {
      hosts[e.host_id].event_count = e.n;
    }
  }

  const peerCounts = db
    .prepare(`SELECT host_id, COUNT(*) AS n FROM remote_peers GROUP BY host_id`)
    .all();
  for (const p of peerCounts) {
    if (FAKE_HOSTS.has(p.host_id)) continue;
    if (!hosts[p.host_id]) {
      hosts[p.host_id] = {
        host_id: p.host_id,
        agents: [],
        last_seen_at: null,
        peer_count: p.n,
        event_count: 0,
        etw_elevated: null,
        is_primary: primary ? p.host_id === primary : false
      };
    } else {
      hosts[p.host_id].peer_count = p.n;
    }
  }

  for (const hostId of Object.keys(hosts)) {
    const etw = db
      .prepare(
        `SELECT raw_json, ts FROM events WHERE host_id = ? AND type = 'etw.session' ORDER BY ts DESC LIMIT 1`
      )
      .get(hostId);
    if (etw) {
      const raw = safeJsonParse(etw.raw_json, {});
      hosts[hostId].etw_elevated = Boolean(raw.elevated);
      hosts[hostId].etw_ts = etw.ts;
    }
  }

  const list = Object.values(hosts).sort((a, b) =>
    String(b.last_seen_at || '').localeCompare(String(a.last_seen_at || ''))
  );

  return {
    primary_host_id: primary,
    hosts: list,
    host_count: list.length,
    agent_count: agents.filter((a) => !FAKE_HOSTS.has(a.host_id)).length,
    note:
      list.length <= 1
        ? 'Single-host fleet — add a second machine with a distinct AEGIS_HOST_ID to see multi-host rows.'
        : 'Multi-host fleet — filter Peers/C2/baselines/watches by host_id.'
  };
}
