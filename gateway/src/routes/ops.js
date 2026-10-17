import { Router } from 'express';
import { runMlScore } from '../services/ml.js';
import {
  buildAttackSurface,
  getFindingDetail,
  backfillActivity,
  upsertFindingDossier,
  listRecentActivity,
  listActiveTargets,
  etwStatus
} from '../services/activity.js';
import {
  listMovementCampaigns,
  getMovementCampaign,
  getLatestMovement
} from '../services/movement.js';
import {
  listRemotePeers,
  listC2Activity,
  attributionReport,
  rebuildPeersFromEvents
} from '../services/peers.js';
import { peersDelta, compareScans, recomputeBaseline } from '../services/baseline.js';
import { listBeacons, recomputeBeacons } from '../services/beacons.js';
import { listDns, joinDnsToPeers } from '../services/dns.js';
import { listWatches, upsertWatch, deleteWatch, listThreatAlerts, ALERT_POLICY } from '../services/watches.js';
import { listFleet } from '../services/fleet.js';
import { postScanAnalyze } from '../services/postScan.js';
import { denoiseThreatTables } from '../services/denoise.js';
import { BASELINE_WINDOW_DAYS } from '../services/baseline.js';
import { ensureActiveMap } from '../db.js';
import {
  asyncHandler,
  asOptionalId,
  asId,
  asString,
  clampLimit,
  safeJsonParse,
  HttpError
} from '../util/safe.js';

export function opsRouter(db, supervisor) {
  const r = Router();

  r.get(
    '/findings',
    asyncHandler(async (_req, res) => {
      const rows = db.prepare(`SELECT * FROM findings ORDER BY created_at DESC LIMIT 100`).all();
      res.json(
        rows.map((f) => ({
          ...f,
          event_ids: safeJsonParse(f.event_ids_json, [])
        }))
      );
    })
  );

  r.get(
    '/findings/:id',
    asyncHandler(async (req, res) => {
      res.json(getFindingDetail(db, asId(req.params.id, 'finding_id')));
    })
  );

  r.post(
    '/findings/:id/analyze',
    asyncHandler(async (req, res) => {
      const finding = db.prepare(`SELECT * FROM findings WHERE id = ?`).get(asId(req.params.id));
      if (!finding) throw new HttpError(404, 'finding not found', 'not_found');
      const mapId = ensureActiveMap(db);
      res.json(upsertFindingDossier(db, finding, mapId));
    })
  );

  r.get(
    '/attack-surface',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json(buildAttackSurface(db, mapId));
    })
  );

  r.post(
    '/activity/backfill',
    asyncHandler(async (req, res) => {
      const mapId = req.body?.map_id ? asId(req.body.map_id, 'map_id') : ensureActiveMap(db);
      res.json(backfillActivity(db, mapId));
    })
  );

  r.get(
    '/activity',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json(
        listRecentActivity(db, {
          mapId,
          nodeId: req.query.node_id ? asId(req.query.node_id, 'node_id') : undefined,
          limit: clampLimit(req.query.limit, 120, 500),
          functionTag: req.query.function_tag
            ? asString(req.query.function_tag, { max: 40 })
            : undefined
        })
      );
    })
  );

  r.get(
    '/activity/targets',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      const minSeverity = asString(req.query.min_severity || 'info', { max: 20 });
      res.json({
        map_id: mapId,
        etw: etwStatus(db),
        targets: listActiveTargets(db, mapId, {
          limit: clampLimit(req.query.limit, 80, 200),
          minSeverity
        })
      });
    })
  );

  r.get(
    '/etw/status',
    asyncHandler(async (_req, res) => {
      res.json(etwStatus(db));
    })
  );

  r.post(
    '/scan/start',
    asyncHandler(async (req, res) => {
      try {
        const result = await supervisor.startScan({
          agents: req.body?.agents || ['go-net', 'rust-host', 'rust-etw']
        });
        res.status(202).json(result);
      } catch (e) {
        if (e instanceof HttpError) throw e;
        throw new HttpError(409, String(e.message || e).slice(0, 200), 'scan_error');
      }
    })
  );

  r.post(
    '/scan/stop',
    asyncHandler(async (_req, res) => {
      supervisor.stopScan();
      res.json({ ok: true });
    })
  );

  r.get(
    '/scan/runs',
    asyncHandler(async (_req, res) => {
      res.json(db.prepare(`SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT 50`).all());
    })
  );

  r.post(
    '/ml/score',
    asyncHandler(async (req, res) => {
      const result = await runMlScore(db, {
        scanRunId: asOptionalId(req.body?.scan_run_id, 'scan_run_id'),
        mapId: asOptionalId(req.body?.map_id, 'map_id')
      });
      res.json(result);
    })
  );

  r.post(
    '/ml/movement',
    asyncHandler(async (req, res) => {
      // Full pipeline score includes movement; expose dedicated alias
      const result = await runMlScore(db, {
        scanRunId: asOptionalId(req.body?.scan_run_id, 'scan_run_id'),
        mapId: asOptionalId(req.body?.map_id, 'map_id')
      });
      res.json(result);
    })
  );

  r.get(
    '/movement',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      if (req.query.latest === '1' || req.query.latest === 'true') {
        return res.json(getLatestMovement(db, mapId) || { empty: true, map_id: mapId });
      }
      res.json(listMovementCampaigns(db, mapId, { limit: clampLimit(req.query.limit, 20, 50) }));
    })
  );

  r.get(
    '/movement/:id',
    asyncHandler(async (req, res) => {
      res.json(getMovementCampaign(db, asId(req.params.id, 'campaign_id')));
    })
  );

  r.get(
    '/agents',
    asyncHandler(async (_req, res) => {
      res.json(db.prepare(`SELECT * FROM agents ORDER BY last_seen_at DESC LIMIT 100`).all());
    })
  );

  r.get(
    '/peers',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json(
        listRemotePeers(db, mapId, {
          limit: clampLimit(req.query.limit, 120, 500),
          minC2: Number(req.query.min_c2 || 0) || 0,
          process: req.query.process ? asString(req.query.process, { max: 80 }) : undefined,
          host_id: req.query.host_id ? asString(req.query.host_id, { max: 128 }) : undefined,
          tier: req.query.tier ? asString(req.query.tier, { max: 20 }) : undefined
        })
      );
    })
  );

  r.get(
    '/c2',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json(
        listC2Activity(db, mapId, {
          limit: clampLimit(req.query.limit, 80, 300),
          host_id: req.query.host_id ? asString(req.query.host_id, { max: 128 }) : undefined,
          tier: req.query.tier ? asString(req.query.tier, { max: 20 }) : undefined
        })
      );
    })
  );

  r.get(
    '/attribution',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json(
        attributionReport(db, mapId, {
          limit: clampLimit(req.query.limit, 100, 300),
          host_id: req.query.host_id ? asString(req.query.host_id, { max: 128 }) : undefined
        })
      );
    })
  );

  r.post(
    '/peers/rebuild',
    asyncHandler(async (req, res) => {
      const mapId = req.body?.map_id ? asId(req.body.map_id, 'map_id') : ensureActiveMap(db);
      const rebuilt = rebuildPeersFromEvents(db, mapId);
      const analyzed = postScanAnalyze(db, { mapId });
      res.json({ ...rebuilt, analyzed });
    })
  );

  r.get(
    '/peers/delta',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json(
        peersDelta(db, mapId, {
          host_id: req.query.host_id ? asString(req.query.host_id, { max: 128 }) : undefined,
          limit: clampLimit(req.query.limit, 80, 300)
        })
      );
    })
  );

  r.get(
    '/peers/compare',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      const a = asString(req.query.a || '', { max: 80, allowEmpty: false });
      const b = asString(req.query.b || '', { max: 80, allowEmpty: false });
      res.json(compareScans(db, mapId, a, b));
    })
  );

  r.post(
    '/baselines/rebuild',
    asyncHandler(async (req, res) => {
      const mapId = req.body?.map_id ? asId(req.body.map_id, 'map_id') : ensureActiveMap(db);
      const hostId = req.body?.host_id ? asString(req.body.host_id, { max: 128 }) : undefined;
      res.json({
        baseline: recomputeBaseline(db, mapId, hostId),
        beacons: recomputeBeacons(db, mapId, hostId),
        dns: joinDnsToPeers(db, mapId, { windowSecs: 30 })
      });
    })
  );

  r.get(
    '/c2/beacons',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json({
        map_id: mapId,
        beacons: listBeacons(db, mapId, {
          limit: clampLimit(req.query.limit, 50, 200),
          minScore: Number(req.query.min_score || 0.4) || 0.4
        })
      });
    })
  );

  r.get(
    '/dns',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json(
        listDns(db, mapId, {
          ip: req.query.ip ? asString(req.query.ip, { max: 80 }) : undefined,
          hostname: req.query.hostname ? asString(req.query.hostname, { max: 120 }) : undefined,
          limit: clampLimit(req.query.limit, 80, 300)
        })
      );
    })
  );

  r.get(
    '/watches',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json({ map_id: mapId, watches: listWatches(db, mapId) });
    })
  );

  r.post(
    '/watches',
    asyncHandler(async (req, res) => {
      const mapId = req.body?.map_id ? asId(req.body.map_id, 'map_id') : ensureActiveMap(db);
      res.status(201).json(
        upsertWatch(db, mapId, {
          kind: req.body?.kind,
          value: req.body?.value,
          note: req.body?.note,
          confirmed: Boolean(req.body?.confirmed)
        })
      );
    })
  );

  r.delete(
    '/watches/:id',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json(deleteWatch(db, mapId, asId(req.params.id, 'watch_id')));
    })
  );

  r.get(
    '/fleet',
    asyncHandler(async (_req, res) => {
      res.json(listFleet(db));
    })
  );

  r.get(
    '/alerts',
    asyncHandler(async (req, res) => {
      const mapId = req.query.map_id ? asId(req.query.map_id, 'map_id') : ensureActiveMap(db);
      res.json({
        map_id: mapId,
        policy: ALERT_POLICY,
        alerts: listThreatAlerts(db, mapId, {
          limit: clampLimit(req.query.limit, 50, 200),
          host_id: req.query.host_id ? asString(req.query.host_id, { max: 128 }) : undefined
        })
      });
    })
  );

  r.post(
    '/denoise',
    asyncHandler(async (req, res) => {
      const mapId = req.body?.map_id ? asId(req.body.map_id, 'map_id') : ensureActiveMap(db);
      res.json(denoiseThreatTables(db, mapId));
    })
  );

  r.get(
    '/baselines/meta',
    asyncHandler(async (_req, res) => {
      res.json({
        window_days: BASELINE_WINDOW_DAYS,
        note: `Peer baselines use a rolling ${BASELINE_WINDOW_DAYS}-day observation window.`
      });
    })
  );

  return r;
}
