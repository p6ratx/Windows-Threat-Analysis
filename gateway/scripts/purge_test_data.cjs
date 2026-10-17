/**
 * Purge synthetic / test host data. Keeps real machine evidence.
 * Usage: node scripts/purge_test_data.cjs
 */
const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');

const db = new Database(path.join(__dirname, '../../data/aegis.db'));
const realHost = os.hostname() || 'local-host';
const TEST_HOSTS = ['test-host', 'smoke-host', 'smoke-host-1'];
const counts = {};

function del(label, sql, params = []) {
  try {
    const r = db.prepare(sql).run(...params);
    counts[label] = (counts[label] || 0) + (r.changes || 0);
  } catch (e) {
    counts[`${label}:error`] = String(e.message || e).slice(0, 120);
  }
}

const wipe = db.transaction(() => {
  for (const h of TEST_HOSTS) {
    del(`events:${h}`, `DELETE FROM events WHERE host_id = ?`, [h]);
    del(`remote_peers:${h}`, `DELETE FROM remote_peers WHERE host_id = ?`, [h]);
    del(`peer_obs:${h}`, `DELETE FROM peer_observations WHERE host_id = ?`, [h]);
    del(`baselines:${h}`, `DELETE FROM peer_baselines WHERE host_id = ?`, [h]);
    del(`c2:${h}`, `DELETE FROM c2_observations WHERE host_id = ?`, [h]);
    del(`beacons:${h}`, `DELETE FROM beacon_candidates WHERE host_id = ?`, [h]);
    del(`dns:${h}`, `DELETE FROM dns_queries WHERE host_id = ?`, [h]);
    del(`ipres:${h}`, `DELETE FROM ip_resolutions WHERE host_id = ?`, [h]);
    del(`activity:${h}`, `DELETE FROM activity_log WHERE host_id = ?`, [h]);
    del(`agents:${h}`, `DELETE FROM agents WHERE host_id = ?`, [h]);
    del(`scan_sum:${h}`, `DELETE FROM scan_peer_summaries WHERE host_id = ?`, [h]);
  }

  del(
    'events_synthetic',
    `DELETE FROM events WHERE lower(raw_json) LIKE '%test egress%'
      OR lower(raw_json) LIKE '%synthetic smb%'
      OR lower(raw_json) LIKE '%"process":"curl.exe"%'
      OR lower(raw_json) LIKE '%"process":"test.exe"%'
      OR lower(raw_json) LIKE '%heuristic":"rdp_exposed"%'`
  );

  del(
    'peers_synth',
    `DELETE FROM remote_peers WHERE lower(process_name) IN ('curl.exe','test.exe','synthetic.exe')
      OR remote_ip LIKE '203.0.113.%'
      OR remote_ip LIKE '198.51.100.%'
      OR remote_ip LIKE '192.0.2.%'
      OR (remote_ip = '1.1.1.1' AND lower(IFNULL(process_name,'')) = 'curl.exe')
      OR lower(IFNULL(attrs_json,'')) LIKE '%test egress%'`
  );

  del(
    'obs_synth',
    `DELETE FROM peer_observations WHERE lower(IFNULL(process_name,'')) IN ('curl.exe','test.exe')
      OR remote_ip LIKE '203.0.113.%'
      OR lower(IFNULL(attrs_json,'')) LIKE '%test egress%'`
  );

  del(
    'c2_synth',
    `DELETE FROM c2_observations WHERE lower(IFNULL(process_name,'')) IN ('curl.exe','test.exe')
      OR lower(IFNULL(doing,'')) LIKE '%test egress%'
      OR remote_ip LIKE '203.0.113.%'`
  );

  const mapIds = db.prepare(`SELECT id FROM threat_maps`).all().map((r) => r.id);
  for (const mapId of mapIds) {
    const nodes = db
      .prepare(
        `SELECT id FROM map_nodes WHERE map_id = ? AND (
          label IN ('test-host','smoke-host')
          OR attrs_json LIKE '%"host_id":"test-host"%'
          OR attrs_json LIKE '%"host_id":"smoke-host"%'
          OR attrs_json LIKE '%"external_id":"test-host"%'
          OR id LIKE '%test-host%'
          OR id LIKE '%smoke-host%'
        )`
      )
      .all(mapId);
    for (const n of nodes) {
      del('map_edges', `DELETE FROM map_edges WHERE map_id = ? AND (src_id = ? OR dst_id = ?)`, [
        mapId,
        n.id,
        n.id
      ]);
      del('map_evlinks', `DELETE FROM map_evidence_links WHERE node_id = ?`, [n.id]);
      del('map_nodes', `DELETE FROM map_nodes WHERE id = ?`, [n.id]);
    }
  }

  del('orphan_links', `DELETE FROM map_evidence_links WHERE event_id NOT IN (SELECT id FROM events)`);
  del(
    'orphan_findings',
    `DELETE FROM findings WHERE summary LIKE '%synthetic%' OR title LIKE '%test-host%'`
  );

  const NOISE = [
    'searchapp.exe',
    'searchhost.exe',
    'searchindexer.exe',
    'startmenuexperiencehost.exe',
    'shellexperiencehost.exe',
    'runtimebroker.exe',
    'applicationframehost.exe',
    'systemsettings.exe',
    'textinputhost.exe',
    'lockapp.exe',
    'widgets.exe',
    'widgetservice.exe',
    'phoneexperiencehost.exe',
    'gamebar.exe',
    'gamebarftserver.exe'
  ];
  for (const name of NOISE) {
    del(
      `denoise_peers:${name}`,
      `UPDATE remote_peers SET c2_score = 0, c2_reasons_json = ?
       WHERE lower(process_name) = ?`,
      [JSON.stringify(['allowlisted_windows_ui']), name]
    );
    del(`denoise_c2:${name}`, `DELETE FROM c2_observations WHERE lower(process_name) = ?`, [name]);
  }

  // Also demote loopback peers from candidate views
  del(
    'denoise_loopback',
    `UPDATE remote_peers SET c2_score = 0
     WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'`
  );
  del(
    'c2_loopback',
    `DELETE FROM c2_observations WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'`
  );

  db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('host_id', ?)`).run(realHost);

  del('smoke_scans', `DELETE FROM scan_runs WHERE id LIKE 'smoke-%'`);
});

wipe();
console.log(JSON.stringify({ realHost, counts }, null, 2));
db.close();
