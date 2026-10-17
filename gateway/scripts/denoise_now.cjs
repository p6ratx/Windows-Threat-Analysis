/**
 * One-shot purge/re-score of loopback + trusted HTTPS false positives, then recompute beacons/baselines.
 * Usage: node scripts/denoise_now.cjs
 */
const Database = require('better-sqlite3');
const path = require('path');
const { pathToFileURL } = require('url');

async function main() {
  // Use gateway ESM services via dynamic import from compiled path — call SQL denoise inline for CJS
  const db = new Database(path.join(__dirname, '../../data/aegis.db'));
  const mapId =
    db.prepare(`SELECT value FROM settings WHERE key = 'active_map_id'`).get()?.value ||
    db.prepare(`SELECT id FROM threat_maps LIMIT 1`).get()?.id;

  const counts = {};
  const run = (label, sql, params = []) => {
    const r = db.prepare(sql).run(...params);
    counts[label] = r.changes || 0;
  };

  run(
    'peers_loopback',
    `UPDATE remote_peers SET c2_score = 0, c2_reasons_json = ?
     WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'
        OR lower(remote_ip) LIKE 'fe80:%' OR remote_ip LIKE '169.254.%'`
  , [JSON.stringify(['loopback_suppressed'])]);

  run(
    'c2_loopback',
    `DELETE FROM c2_observations WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'
        OR lower(remote_ip) LIKE 'fe80:%' OR remote_ip LIKE '169.254.%'`
  );

  run(
    'beacons_loopback',
    `DELETE FROM beacon_candidates WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'
        OR lower(remote_ip) LIKE 'fe80:%' OR remote_ip LIKE '169.254.%'`
  );

  run(
    'beacons_trusted_https',
    `DELETE FROM beacon_candidates WHERE IFNULL(remote_port,0) IN (80,443,53,853)
       AND lower(IFNULL(process_name,'')) IN (
         'msedge.exe','chrome.exe','firefox.exe','brave.exe','msedgewebview2.exe',
         'node.exe','cursor.exe','code.exe','python.exe','python3.12.exe','devenv.exe',
         'svchost.exe','onedrive.exe','teams.exe','msmpeng.exe','explorer.exe'
       )`
  );

  console.log(JSON.stringify({ mapId, counts }, null, 2));
  db.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
