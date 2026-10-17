/**
 * Remigrate local-host telemetry onto the real OS hostname.
 * Also purges remaining demo/synthetic fixtures.
 * Usage: node scripts/remigrate_local_host.cjs
 */
const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');

const db = new Database(path.join(__dirname, '../../data/aegis.db'));
const realHost = os.hostname() || 'local-host';
const counts = {};

function del(label, sql, params = []) {
  try {
    const r = db.prepare(sql).run(...params);
    counts[label] = (counts[label] || 0) + (r.changes || 0);
  } catch (e) {
    counts[`${label}:error`] = String(e.message || e).slice(0, 160);
  }
}

function upd(label, sql, params = []) {
  try {
    const r = db.prepare(sql).run(...params);
    counts[label] = (counts[label] || 0) + (r.changes || 0);
  } catch (e) {
    counts[`${label}:error`] = String(e.message || e).slice(0, 160);
  }
}

const HOST_TABLES = [
  'events',
  'remote_peers',
  'peer_observations',
  'peer_baselines',
  'c2_observations',
  'beacon_candidates',
  'dns_queries',
  'ip_resolutions',
  'activity_log',
  'scan_peer_summaries',
  'attack_surface_snapshots'
];

db.transaction(() => {
  // Drop leftover demo / synthetic fixtures first
  del(
    'demo_events',
    `DELETE FROM events WHERE lower(IFNULL(raw_json,'')) LIKE '%demo_or_fallback%'
      OR lower(IFNULL(raw_json,'')) LIKE '%"source":"fallback"%'
      OR lower(IFNULL(raw_json,'')) LIKE '%synthetic smb%'
      OR lower(IFNULL(raw_json,'')) LIKE '%test egress%'
      OR lower(IFNULL(raw_json,'')) LIKE '%"heuristic":"rdp_exposed"%'
      OR lower(IFNULL(raw_json,'')) LIKE '%runkey:suspicious%'`
  );
  del(
    'demo_findings',
    `DELETE FROM findings WHERE lower(IFNULL(summary,'')) LIKE '%synthetic%'
      OR lower(IFNULL(title,'')) LIKE '%runkey:suspicious%'
      OR lower(IFNULL(title,'')) LIKE '%hkcu run anomaly%'`
  );

  for (const table of HOST_TABLES) {
    // Prefer update; on UNIQUE conflicts delete remaining local-host rows
    upd(`remap:${table}`, `UPDATE ${table} SET host_id = ? WHERE host_id = 'local-host'`, [realHost]);
    del(`drop_conflict:${table}`, `DELETE FROM ${table} WHERE host_id = 'local-host'`);
  }

  // agents.id embeds host_id — recreate under real host
  const agents = db.prepare(`SELECT * FROM agents WHERE host_id = 'local-host'`).all();
  for (const a of agents) {
    const newId = `${a.kind}:${realHost}`.slice(0, 160);
    try {
      db.prepare(
        `INSERT INTO agents (id, kind, host_id, last_seen_at, meta_json)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET last_seen_at = excluded.last_seen_at, meta_json = excluded.meta_json`
      ).run(newId, a.kind, realHost, a.last_seen_at, a.meta_json);
      counts['agents:upsert'] = (counts['agents:upsert'] || 0) + 1;
    } catch (e) {
      counts['agents:error'] = String(e.message || e).slice(0, 120);
    }
  }
  del('agents:local', `DELETE FROM agents WHERE host_id = 'local-host'`);

  // Map host node: merge local-host node into real hostname node
  const maps = db.prepare(`SELECT id FROM threat_maps`).all();
  for (const { id: mapId } of maps) {
    const localNode = db
      .prepare(
        `SELECT * FROM map_nodes WHERE map_id = ? AND (
          label = 'local-host' OR id LIKE '%:host:local-host'
          OR attrs_json LIKE '%"host_id":"local-host"%'
          OR attrs_json LIKE '%"external_id":"local-host"%'
        ) LIMIT 1`
      )
      .get(mapId);
    const realNode = db
      .prepare(
        `SELECT * FROM map_nodes WHERE map_id = ? AND (
          label = ? OR id LIKE ?
          OR attrs_json LIKE ?
        ) LIMIT 1`
      )
      .get(mapId, realHost, `%:host:${realHost}`, `%"host_id":"${realHost}"%`);

    if (localNode && realNode && localNode.id !== realNode.id) {
      upd(
        'map_edges_src',
        `UPDATE map_edges SET src_id = ? WHERE map_id = ? AND src_id = ?`,
        [realNode.id, mapId, localNode.id]
      );
      upd(
        'map_edges_dst',
        `UPDATE map_edges SET dst_id = ? WHERE map_id = ? AND dst_id = ?`,
        [realNode.id, mapId, localNode.id]
      );
      upd(
        'map_evlinks',
        `UPDATE map_evidence_links SET node_id = ? WHERE node_id = ?`,
        [realNode.id, localNode.id]
      );
      del('map_local_node', `DELETE FROM map_nodes WHERE id = ?`, [localNode.id]);
    } else if (localNode && !realNode) {
      upd(
        'map_rename_label',
        `UPDATE map_nodes SET label = ?, attrs_json = replace(attrs_json, 'local-host', ?) WHERE id = ?`,
        [realHost, realHost, localNode.id]
      );
    }

    const nodes = db
      .prepare(`SELECT id, attrs_json FROM map_nodes WHERE map_id = ? AND attrs_json LIKE '%local-host%'`)
      .all(mapId);
    for (const n of nodes) {
      const next = String(n.attrs_json || '').split('local-host').join(realHost);
      if (next !== n.attrs_json) {
        upd('map_attrs', `UPDATE map_nodes SET attrs_json = ? WHERE id = ?`, [next, n.id]);
      }
    }
  }

  // Rename any remaining node ids that still embed local-host (e.g. port:local-host:445)
  const idNodes = db.prepare(`SELECT * FROM map_nodes WHERE id LIKE '%local-host%'`).all();
  for (const n of idNodes) {
    const newId = n.id.split('local-host').join(realHost);
    if (newId === n.id) continue;
    const existing = db.prepare(`SELECT id FROM map_nodes WHERE id = ?`).get(newId);
    if (existing) {
      upd('id_merge_edges_src', `UPDATE map_edges SET src_id = ? WHERE src_id = ?`, [newId, n.id]);
      upd('id_merge_edges_dst', `UPDATE map_edges SET dst_id = ? WHERE dst_id = ?`, [newId, n.id]);
      upd('id_merge_links', `UPDATE map_evidence_links SET node_id = ? WHERE node_id = ?`, [newId, n.id]);
      del('id_merge_drop', `DELETE FROM map_nodes WHERE id = ?`, [n.id]);
    } else {
      db.prepare(
        `INSERT INTO map_nodes (id, map_id, kind, label, attrs_json, severity, pinned, x, y, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        newId,
        n.map_id,
        n.kind,
        n.label === 'local-host' ? realHost : n.label,
        String(n.attrs_json || '').split('local-host').join(realHost),
        n.severity,
        n.pinned,
        n.x,
        n.y,
        n.created_at,
        n.updated_at
      );
      upd('id_rename_edges_src', `UPDATE map_edges SET src_id = ? WHERE src_id = ?`, [newId, n.id]);
      upd('id_rename_edges_dst', `UPDATE map_edges SET dst_id = ? WHERE dst_id = ?`, [newId, n.id]);
      upd('id_rename_links', `UPDATE map_evidence_links SET node_id = ? WHERE node_id = ?`, [newId, n.id]);
      del('id_rename_drop', `DELETE FROM map_nodes WHERE id = ?`, [n.id]);
      counts['id_renamed'] = (counts['id_renamed'] || 0) + 1;
    }
  }

  // Denoise loopback / UI C2 leftovers after remap
  del(
    'c2_loopback',
    `DELETE FROM c2_observations WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'`
  );
  upd(
    'peers_loopback_c2',
    `UPDATE remote_peers SET c2_score = 0
     WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'`
  );
  upd(
    'peers_trusted_https',
    `UPDATE remote_peers SET c2_score = 0
     WHERE c2_score > 0 AND IFNULL(remote_port,0) IN (80,443,53,853)
       AND lower(IFNULL(software_class,'')) IN (
         'browser','windows_ui','microsoft_system','microsoft_update',
         'dev_tool','office_collab','security_agent','hypervisor'
       )`
  );

  db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('host_id', ?)`).run(realHost);
})();

console.log(JSON.stringify({ realHost, counts }, null, 2));
db.close();
