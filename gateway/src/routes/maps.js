import { Router } from 'express';
import { v4 as uuid } from 'uuid';
import { ensureActiveMap } from '../db.js';
import { getMapGraph, stableNodeId } from '../services/mapEngine.js';
import {
  asyncHandler,
  asString,
  asEnum,
  asNumber,
  asBool,
  asId,
  asOptionalId,
  sanitizeAttrs,
  HttpError,
  SEVERITIES,
  NODE_KINDS,
  EDGE_RELS,
  safeJsonParse
} from '../util/safe.js';
import { getNodeDossier } from '../services/activity.js';

export function mapsRouter(db) {
  const r = Router();

  r.get(
    '/',
    asyncHandler(async (_req, res) => {
      res.json(db.prepare(`SELECT * FROM threat_maps ORDER BY updated_at DESC LIMIT 200`).all());
    })
  );

  r.post(
    '/',
    asyncHandler(async (req, res) => {
      const id = uuid();
      const now = new Date().toISOString();
      db.prepare(
        `INSERT INTO threat_maps (id, title, description, status, created_at, updated_at)
         VALUES (?, ?, ?, 'active', ?, ?)`
      ).run(
        id,
        asString(req.body?.title || 'Threat Map', { max: 200 }),
        asString(req.body?.description || '', { max: 4000 }),
        now,
        now
      );
      if (asBool(req.body?.set_active)) {
        db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('active_map_id', ?)`).run(id);
      }
      res.status(201).json(db.prepare(`SELECT * FROM threat_maps WHERE id = ?`).get(id));
    })
  );

  r.get(
    '/active',
    asyncHandler(async (_req, res) => {
      const id = ensureActiveMap(db);
      res.json(getMapGraph(db, id));
    })
  );

  r.post(
    '/active',
    asyncHandler(async (req, res) => {
      const id = asId(req.body?.map_id, 'map_id');
      const exists = db.prepare(`SELECT id FROM threat_maps WHERE id = ?`).get(id);
      if (!exists) throw new HttpError(404, 'map not found', 'not_found');
      db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('active_map_id', ?)`).run(id);
      res.json(getMapGraph(db, id));
    })
  );

  r.get(
    '/:id/graph',
    asyncHandler(async (req, res) => {
      const graph = getMapGraph(db, asId(req.params.id, 'map_id'));
      if (!graph) throw new HttpError(404, 'not found', 'not_found');
      res.json(graph);
    })
  );

  r.post(
    '/:id/nodes',
    asyncHandler(async (req, res) => {
      const mapId = asId(req.params.id, 'map_id');
      if (!db.prepare(`SELECT id FROM threat_maps WHERE id = ?`).get(mapId)) {
        throw new HttpError(404, 'map not found', 'not_found');
      }
      const kind = asEnum(req.body?.kind || 'asset', NODE_KINDS, 'asset');
      const label = asString(req.body?.label || 'Node', { max: 200 });
      const id = req.body?.id
        ? asId(req.body.id, 'node.id')
        : stableNodeId(mapId, kind, label || uuid());
      const now = new Date().toISOString();
      try {
        db.prepare(
          `INSERT INTO map_nodes (id, map_id, kind, label, attrs_json, severity, pinned, x, y, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          id,
          mapId,
          kind,
          label,
          JSON.stringify(sanitizeAttrs(req.body?.attrs)),
          asEnum(req.body?.severity || 'info', SEVERITIES, 'info'),
          asBool(req.body?.pinned) ? 1 : 0,
          req.body?.x != null ? asNumber(req.body.x, { min: -1e6, max: 1e6 }) : null,
          req.body?.y != null ? asNumber(req.body.y, { min: -1e6, max: 1e6 }) : null,
          now,
          now
        );
      } catch (e) {
        if (String(e.message || e).includes('UNIQUE')) {
          throw new HttpError(409, 'Node already exists', 'conflict');
        }
        throw e;
      }
      db.prepare(`UPDATE threat_maps SET updated_at = ? WHERE id = ?`).run(now, mapId);
      res.status(201).json(db.prepare(`SELECT * FROM map_nodes WHERE id = ?`).get(id));
    })
  );

  r.patch(
    '/:id/nodes/:nodeId',
    asyncHandler(async (req, res) => {
      const mapId = asId(req.params.id, 'map_id');
      const nodeId = asId(req.params.nodeId, 'node_id');
      const node = db
        .prepare(`SELECT * FROM map_nodes WHERE id = ? AND map_id = ?`)
        .get(nodeId, mapId);
      if (!node) throw new HttpError(404, 'not found', 'not_found');
      db.prepare(
        `UPDATE map_nodes SET
          label = COALESCE(?, label),
          severity = COALESCE(?, severity),
          pinned = COALESCE(?, pinned),
          x = COALESCE(?, x),
          y = COALESCE(?, y),
          attrs_json = COALESCE(?, attrs_json),
          updated_at = ?
         WHERE id = ?`
      ).run(
        req.body?.label != null ? asString(req.body.label, { max: 200 }) : null,
        req.body?.severity != null ? asEnum(req.body.severity, SEVERITIES, 'info') : null,
        req.body?.pinned === undefined ? null : asBool(req.body.pinned) ? 1 : 0,
        req.body?.x != null ? asNumber(req.body.x, { min: -1e6, max: 1e6 }) : null,
        req.body?.y != null ? asNumber(req.body.y, { min: -1e6, max: 1e6 }) : null,
        req.body?.attrs ? JSON.stringify(sanitizeAttrs(req.body.attrs)) : null,
        new Date().toISOString(),
        nodeId
      );
      res.json(db.prepare(`SELECT * FROM map_nodes WHERE id = ?`).get(nodeId));
    })
  );

  r.post(
    '/:id/edges',
    asyncHandler(async (req, res) => {
      const mapId = asId(req.params.id, 'map_id');
      if (!db.prepare(`SELECT id FROM threat_maps WHERE id = ?`).get(mapId)) {
        throw new HttpError(404, 'map not found', 'not_found');
      }
      const src = asId(req.body?.src_id, 'src_id');
      const dst = asId(req.body?.dst_id, 'dst_id');
      if (src === dst) throw new HttpError(400, 'src and dst must differ');
      const srcOk = db.prepare(`SELECT id FROM map_nodes WHERE id = ? AND map_id = ?`).get(src, mapId);
      const dstOk = db.prepare(`SELECT id FROM map_nodes WHERE id = ? AND map_id = ?`).get(dst, mapId);
      if (!srcOk || !dstOk) throw new HttpError(400, 'src/dst must exist on this map');
      const id = req.body?.id ? asId(req.body.id, 'edge.id') : uuid();
      db.prepare(
        `INSERT INTO map_edges (id, map_id, src_id, dst_id, rel, confidence, suggested, attrs_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        id,
        mapId,
        src,
        dst,
        asEnum(req.body?.rel || 'targets', EDGE_RELS, 'targets'),
        asNumber(req.body?.confidence, { min: 0, max: 1, fallback: 1 }),
        asBool(req.body?.suggested) ? 1 : 0,
        JSON.stringify(sanitizeAttrs(req.body?.attrs)),
        new Date().toISOString()
      );
      db.prepare(`UPDATE threat_maps SET updated_at = ? WHERE id = ?`).run(new Date().toISOString(), mapId);
      res.status(201).json(db.prepare(`SELECT * FROM map_edges WHERE id = ?`).get(id));
    })
  );

  r.get(
    '/:id/evidence/:nodeId',
    asyncHandler(async (req, res) => {
      const mapId = asId(req.params.id, 'map_id');
      const nodeId = asId(req.params.nodeId, 'node_id');
      const links = db
        .prepare(
          `SELECT e.* FROM map_evidence_links l
           JOIN events e ON e.id = l.event_id
           WHERE l.map_id = ? AND l.node_id = ?
           ORDER BY e.ts DESC LIMIT 50`
        )
        .all(mapId, nodeId);
      res.json(
        links.map((row) => ({
          ...row,
          entities: safeJsonParse(row.entities_json, []),
          edges: safeJsonParse(row.edges_json, []),
          raw: safeJsonParse(row.raw_json, {})
        }))
      );
    })
  );

  r.get(
    '/:id/nodes/:nodeId/dossier',
    asyncHandler(async (req, res) => {
      res.json(getNodeDossier(db, asId(req.params.id), asId(req.params.nodeId)));
    })
  );

  // Query-param dossier avoids path issues with complex node ids
  r.get(
    '/:id/dossier',
    asyncHandler(async (req, res) => {
      const nodeId = asId(req.query.node_id, 'node_id');
      res.json(getNodeDossier(db, asId(req.params.id), nodeId));
    })
  );

  return r;
}

void asOptionalId;
