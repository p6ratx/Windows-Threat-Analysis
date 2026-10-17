import { ensureActiveMap } from '../db.js';
import { recomputeBaseline, writeScanPeerSummary } from './baseline.js';
import { recomputeBeacons } from './beacons.js';
import { joinDnsToPeers } from './dns.js';
import { denoiseThreatTables } from './denoise.js';
import { evaluateThreatAlerts } from './watches.js';
import { enrichPtr, enrichOptionalHttp } from './enrichment.js';

/** Run after a scan or peer poll completes. */
export function postScanAnalyze(db, { mapId, scanRunId, hostId } = {}) {
  const mid = mapId || ensureActiveMap(db);
  const denoise = denoiseThreatTables(db, mid);
  const baseline = recomputeBaseline(db, mid, hostId);
  const beacons = recomputeBeacons(db, mid, hostId);
  // Wider DNS join window (90s) helps correlate query → connect without PID
  const dns = joinDnsToPeers(db, mid, { scanRunId, windowSecs: 90 });
  const summary = writeScanPeerSummary(db, mid, scanRunId, hostId);
  const alerts = evaluateThreatAlerts(db, mid, { hostId });

  // Enrich top public C2 candidates (fire-and-forget; offline-friendly when DNS/API fail)
  try {
    const tops = db
      .prepare(
        `SELECT DISTINCT remote_ip FROM remote_peers
         WHERE map_id = ? AND c2_score >= 0.45
           AND remote_ip NOT IN ('127.0.0.1','::1')
           AND remote_ip NOT LIKE '127.%'
         ORDER BY c2_score DESC LIMIT 15`
      )
      .all(mid);
    for (const t of tops) {
      enrichPtr(db, t.remote_ip).catch(() => {});
      if (process.env.AEGIS_ENRICH_URL) {
        enrichOptionalHttp(db, t.remote_ip).catch(() => {});
      }
    }
  } catch {
    /* ignore */
  }

  return {
    map_id: mid,
    scan_run_id: scanRunId || null,
    denoise,
    baseline,
    beacons,
    dns,
    summary,
    alerts
  };
}
