/**
 * Verify test/synthetic data is gone and host_id is real.
 * Usage: node scripts/verify_clean.cjs
 */
const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');

const db = new Database(path.join(__dirname, '../../data/aegis.db'), { readonly: true });
const realHost = os.hostname() || 'local-host';

function count(sql, params = []) {
  try {
    return db.prepare(sql).get(...params)?.n ?? 0;
  } catch (e) {
    return { error: String(e.message || e).slice(0, 160) };
  }
}

const hostId = db.prepare(`SELECT value FROM settings WHERE key = 'host_id'`).get()?.value;

const report = {
  realHost,
  host_id: hostId,
  host_id_ok: hostId === realHost && !['local-host', 'test-host', 'smoke-host'].includes(hostId),
  events_test_host: count(`SELECT COUNT(*) AS n FROM events WHERE host_id = ?`, ['test-host']),
  events_smoke_host: count(`SELECT COUNT(*) AS n FROM events WHERE host_id IN ('smoke-host','smoke-host-1')`),
  peers_test_host: count(`SELECT COUNT(*) AS n FROM remote_peers WHERE host_id = ?`, ['test-host']),
  peers_smoke_host: count(`SELECT COUNT(*) AS n FROM remote_peers WHERE host_id IN ('smoke-host','smoke-host-1')`),
  peers_curl: count(`SELECT COUNT(*) AS n FROM remote_peers WHERE lower(process_name) = 'curl.exe'`),
  peers_test_exe: count(`SELECT COUNT(*) AS n FROM remote_peers WHERE lower(process_name) = 'test.exe'`),
  peers_test_egress: count(
    `SELECT COUNT(*) AS n FROM remote_peers WHERE lower(IFNULL(attrs_json,'')) LIKE '%test egress%'`
  ),
  events_test_egress: count(
    `SELECT COUNT(*) AS n FROM events WHERE lower(raw_json) LIKE '%test egress%'`
  ),
  rfc5737_peers: count(
    `SELECT COUNT(*) AS n FROM remote_peers WHERE remote_ip LIKE '203.0.113.%'
       OR remote_ip LIKE '198.51.100.%' OR remote_ip LIKE '192.0.2.%'`
  ),
  rfc5737_c2: count(
    `SELECT COUNT(*) AS n FROM c2_observations WHERE remote_ip LIKE '203.0.113.%'
       OR remote_ip LIKE '198.51.100.%' OR remote_ip LIKE '192.0.2.%'`
  ),
  map_test_nodes: count(
    `SELECT COUNT(*) AS n FROM map_nodes WHERE label IN ('test-host','smoke-host')
       OR id LIKE '%test-host%' OR id LIKE '%smoke-host%'
       OR attrs_json LIKE '%"host_id":"test-host"%'
       OR attrs_json LIKE '%"host_id":"smoke-host"%'`
  ),
  local_host_peers: count(`SELECT COUNT(*) AS n FROM remote_peers WHERE host_id = 'local-host'`),
  local_host_events: count(`SELECT COUNT(*) AS n FROM events WHERE host_id = 'local-host'`),
  local_host_map_nodes: count(
    `SELECT COUNT(*) AS n FROM map_nodes WHERE attrs_json LIKE '%"host_id":"local-host"%'
       OR label = 'local-host' OR id LIKE '%local-host%'`
  ),
  demo_events: count(
    `SELECT COUNT(*) AS n FROM events WHERE lower(IFNULL(raw_json,'')) LIKE '%demo_or_fallback%'
       OR lower(IFNULL(raw_json,'')) LIKE '%"source":"fallback"%'
       OR lower(IFNULL(raw_json,'')) LIKE '%test egress%'
       OR lower(IFNULL(raw_json,'')) LIKE '%"heuristic":"rdp_exposed"%'`
  ),
  peer_hosts: db
    .prepare(`SELECT host_id, COUNT(*) AS n FROM remote_peers GROUP BY host_id ORDER BY n DESC LIMIT 20`)
    .all(),
  event_hosts: db
    .prepare(`SELECT host_id, COUNT(*) AS n FROM events GROUP BY host_id ORDER BY n DESC LIMIT 20`)
    .all(),
  top_c2: db
    .prepare(
      `SELECT process_name, remote_ip, remote_port, c2_score, software_class, host_id
       FROM remote_peers WHERE c2_score > 0
       ORDER BY c2_score DESC LIMIT 25`
    )
    .all(),
  loopback_c2: count(
    `SELECT COUNT(*) AS n FROM remote_peers
     WHERE c2_score > 0 AND (remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'
        OR lower(remote_ip) LIKE 'fe80:%' OR remote_ip LIKE '169.254.%')`
  ),
  loopback_beacons: count(
    `SELECT COUNT(*) AS n FROM beacon_candidates
     WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'
        OR lower(remote_ip) LIKE 'fe80:%' OR remote_ip LIKE '169.254.%'`
  ),
  loopback_beacons_confirmed: count(
    `SELECT COUNT(*) AS n FROM beacon_candidates
     WHERE tier IN ('confirmed','candidate')
       AND (remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'
            OR lower(remote_ip) LIKE 'fe80:%')`
  ),
  ui_noise_c2: count(
    `SELECT COUNT(*) AS n FROM remote_peers WHERE c2_score > 0 AND lower(process_name) IN (
       'searchapp.exe','searchhost.exe','runtimebroker.exe','applicationframehost.exe',
       'startmenuexperiencehost.exe','shellexperiencehost.exe','textinputhost.exe',
       'widgets.exe','widgetservice.exe','lockapp.exe','systemsettings.exe'
     )`
  )
};

const dirty =
  !report.host_id_ok ||
  report.events_test_host > 0 ||
  report.events_smoke_host > 0 ||
  report.peers_test_host > 0 ||
  report.peers_smoke_host > 0 ||
  report.peers_curl > 0 ||
  report.peers_test_exe > 0 ||
  report.peers_test_egress > 0 ||
  report.events_test_egress > 0 ||
  report.rfc5737_peers > 0 ||
  report.rfc5737_c2 > 0 ||
  report.map_test_nodes > 0 ||
  report.local_host_peers > 0 ||
  report.local_host_events > 0 ||
  report.local_host_map_nodes > 0 ||
  report.demo_events > 0 ||
  report.loopback_c2 > 0 ||
  report.loopback_beacons > 0 ||
  report.loopback_beacons_confirmed > 0 ||
  report.ui_noise_c2 > 0;

report.clean = !dirty;
console.log(JSON.stringify(report, null, 2));
db.close();
process.exit(dirty ? 1 : 0);
