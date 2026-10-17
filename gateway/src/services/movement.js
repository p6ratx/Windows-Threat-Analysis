import { safeJsonParse, asId, HttpError } from '../util/safe.js';
import { ensureActiveMap } from '../db.js';

export function listMovementCampaigns(db, mapId, { limit = 20 } = {}) {
  mapId = mapId || ensureActiveMap(db);
  const rows = db
    .prepare(
      `SELECT * FROM movement_campaigns WHERE map_id = ? ORDER BY created_at DESC LIMIT ?`
    )
    .all(mapId, Math.min(50, Math.max(1, limit)));
  return rows.map((r) => ({
    ...r,
    stages: safeJsonParse(r.stages_json, []),
    path_node_ids: safeJsonParse(r.path_node_ids_json, []),
    path_edge_ids: safeJsonParse(r.path_edge_ids_json, []),
    techniques: safeJsonParse(r.techniques_json, [])
  }));
}

export function getMovementCampaign(db, campaignId) {
  campaignId = asId(campaignId, 'campaign_id');
  const c = db.prepare(`SELECT * FROM movement_campaigns WHERE id = ?`).get(campaignId);
  if (!c) throw new HttpError(404, 'campaign not found', 'not_found');
  const hops = db
    .prepare(`SELECT * FROM movement_hops WHERE campaign_id = ? ORDER BY seq ASC`)
    .all(campaignId);
  return {
    ...c,
    stages: safeJsonParse(c.stages_json, []),
    path_node_ids: safeJsonParse(c.path_node_ids_json, []),
    path_edge_ids: safeJsonParse(c.path_edge_ids_json, []),
    techniques: safeJsonParse(c.techniques_json, []),
    hops
  };
}

export function getLatestMovement(db, mapId) {
  mapId = mapId || ensureActiveMap(db);
  const row = db
    .prepare(
      `SELECT id FROM movement_campaigns WHERE map_id = ? ORDER BY created_at DESC LIMIT 1`
    )
    .get(mapId);
  if (!row) return null;
  return getMovementCampaign(db, row.id);
}
