/**
 * Denoise / re-score bad loopback & trusted false positives in threat tables.
 * Safe to run on boot and after each postScan.
 */
import {
  isNonRoutableThreatIp,
  huntLoopbackEnabled,
  TRUSTED_SOFTWARE_CLASSES,
  classifyProcessName
} from './enrichment.js';
import { purgeLoopbackBeacons } from './beacons.js';
import { ensureActiveMap } from '../db.js';

const HTTPS_LIKE = new Set([80, 443, 53, 853]);

export function denoiseThreatTables(db, mapId) {
  const mid = mapId || ensureActiveMap(db);
  const counts = {};

  // Loopback / link-local C2 scores → 0
  if (!huntLoopbackEnabled()) {
    const lb = db
      .prepare(
        `UPDATE remote_peers SET c2_score = 0, c2_reasons_json = ?
         WHERE map_id = ? AND (
           remote_ip IN ('127.0.0.1','::1','0:0:0:0:0:0:0:1')
           OR remote_ip LIKE '127.%'
           OR lower(remote_ip) LIKE 'fe80:%'
           OR remote_ip LIKE '::ffff:127.%'
           OR remote_ip LIKE '169.254.%'
         ) AND c2_score > 0`
      )
      .run(JSON.stringify(['loopback_suppressed']), mid);
    counts.peers_loopback_zeroed = lb.changes || 0;

    const c2 = db
      .prepare(
        `DELETE FROM c2_observations WHERE map_id = ? AND (
           remote_ip IN ('127.0.0.1','::1','0:0:0:0:0:0:0:1')
           OR remote_ip LIKE '127.%'
           OR lower(remote_ip) LIKE 'fe80:%'
           OR remote_ip LIKE '::ffff:127.%'
           OR remote_ip LIKE '169.254.%'
         )`
      )
      .run(mid);
    counts.c2_loopback_deleted = c2.changes || 0;
  }

  counts.beacons_loopback = purgeLoopbackBeacons(db, mid).deleted;

  // Re-tier trusted HTTPS peers to c2=0 (fixes sticky MAX(c2_score) leftovers)
  const peers = db
    .prepare(
      `SELECT id, process_name, software_class, remote_port, remote_ip, c2_score, c2_reasons_json
       FROM remote_peers WHERE map_id = ? AND c2_score > 0`
    )
    .all(mid);

  let trustedZeroed = 0;
  const upd = db.prepare(
    `UPDATE remote_peers SET c2_score = 0, c2_reasons_json = ? WHERE id = ?`
  );
  for (const p of peers) {
    if (isNonRoutableThreatIp(p.remote_ip) && !huntLoopbackEnabled()) {
      upd.run(JSON.stringify(['loopback_suppressed']), p.id);
      trustedZeroed += 1;
      continue;
    }
    let sw = p.software_class;
    const classified = classifyProcessName(p.process_name);
    if (classified && classified !== 'unclassified') sw = classified;
    const port = Number(p.remote_port) || 0;
    if (TRUSTED_SOFTWARE_CLASSES.has(sw) && HTTPS_LIKE.has(port)) {
      upd.run(JSON.stringify(['trusted_https_suppressed']), p.id);
      trustedZeroed += 1;
    }
  }
  counts.trusted_https_zeroed = trustedZeroed;

  // Drop C2 observations for trusted HTTPS
  const c2Trusted = db
    .prepare(
      `DELETE FROM c2_observations
       WHERE map_id = ? AND IFNULL(remote_port,0) IN (80,443,53,853)
         AND lower(IFNULL(process_name,'')) IN (
           'msedge.exe','chrome.exe','firefox.exe','brave.exe','msedgewebview2.exe',
           'node.exe','cursor.exe','code.exe','python.exe','devenv.exe',
           'svchost.exe','onedrive.exe','teams.exe','ms-teams.exe','outlook.exe',
           'msmpeng.exe','sense.exe','explorer.exe'
         )`
    )
    .run(mid);
  counts.c2_trusted_deleted = c2Trusted.changes || 0;

  // Drop beacon candidates for trusted HTTPS / private that slipped through
  const bc = db
    .prepare(
      `DELETE FROM beacon_candidates WHERE map_id = ?
         AND IFNULL(remote_port,0) IN (80,443,53,853)
         AND lower(IFNULL(process_name,'')) IN (
           'msedge.exe','chrome.exe','firefox.exe','brave.exe','msedgewebview2.exe',
           'node.exe','cursor.exe','code.exe','python.exe','python3.12.exe','devenv.exe',
           'svchost.exe','onedrive.exe','teams.exe','msmpeng.exe','explorer.exe'
         )`
    )
    .run(mid);
  counts.beacons_trusted_deleted = bc.changes || 0;

  return { map_id: mid, ...counts };
}
