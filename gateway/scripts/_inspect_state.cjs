const Database = require('better-sqlite3');
const path = require('path');
const db = new Database(path.join(__dirname, '../../data/aegis.db'), { readonly: true });

const report = {
  beacons: db
    .prepare(
      `SELECT process_name, remote_ip, remote_port, score, tier FROM beacon_candidates ORDER BY score DESC LIMIT 40`
    )
    .all(),
  loopback_beacons: db
    .prepare(
      `SELECT process_name, remote_ip, remote_port, score, tier FROM beacon_candidates
       WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%'
          OR lower(remote_ip) LIKE 'fe80:%' OR remote_ip LIKE '::ffff:127.%'`
    )
    .all(),
  trusted_loopback_peers: db
    .prepare(
      `SELECT process_name, remote_ip, remote_port, c2_score, software_class, hit_count
       FROM remote_peers
       WHERE remote_ip IN ('127.0.0.1','::1') OR remote_ip LIKE '127.%' OR lower(remote_ip) LIKE 'fe80:%'
       ORDER BY hit_count DESC LIMIT 30`
    )
    .all(),
  agents: db.prepare(`SELECT id, kind, host_id, last_seen_at FROM agents`).all(),
  movement: db
    .prepare(
      `SELECT actor_label, confidence, ml_score, substr(summary,1,200) AS summary FROM movement_campaigns ORDER BY created_at DESC LIMIT 3`
    )
    .all(),
  baselines: db.prepare(`SELECT status, COUNT(*) AS n FROM peer_baselines GROUP BY status`).all(),
  dns: db.prepare(`SELECT COUNT(*) AS n FROM dns_queries`).get(),
  resolutions: db.prepare(`SELECT COUNT(*) AS n FROM ip_resolutions`).get(),
  watches: db.prepare(`SELECT * FROM analyst_watches LIMIT 20`).all(),
  top_public_c2: db
    .prepare(
      `SELECT process_name, remote_ip, remote_port, c2_score, software_class, first_seen, last_seen
       FROM remote_peers WHERE c2_score >= 0.45 ORDER BY c2_score DESC LIMIT 10`
    )
    .all()
};

console.log(JSON.stringify(report, null, 2));
db.close();
