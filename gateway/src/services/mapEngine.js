import { v4 as uuid } from 'uuid';
import { safeJsonParse, asString, asEnum, SEVERITIES } from '../util/safe.js';

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function upsertEvidenceIntoMap(db, mapId, event) {
  if (!mapId || !event?.id) return;
  const entityIdMap = new Map();

  for (const ent of event.entities || []) {
    const nodeId = stableNodeId(mapId, ent.kind, ent.id);
    entityIdMap.set(ent.id, nodeId);
    const existing = db.prepare(`SELECT id, severity, attrs_json FROM map_nodes WHERE id = ?`).get(nodeId);
    const label = asString(ent.label || `${ent.kind}:${ent.id}`, { max: 200 });
    const attrs = { ...(ent.attrs || {}), external_id: ent.id, host_id: event.host_id };
    if (existing) {
      const merged = { ...safeJsonParse(existing.attrs_json, {}), ...attrs };
      const sev = higherSeverity(existing.severity, event.severity);
      db.prepare(
        `UPDATE map_nodes SET label = ?, attrs_json = ?, severity = ?, updated_at = ? WHERE id = ?`
      ).run(label, JSON.stringify(merged), sev, new Date().toISOString(), nodeId);
    } else {
      db.prepare(
        `INSERT INTO map_nodes (id, map_id, kind, label, attrs_json, severity, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        nodeId,
        mapId,
        asString(ent.kind, { max: 40 }),
        label,
        JSON.stringify(attrs),
        asEnum(event.severity || 'info', SEVERITIES, 'info'),
        new Date().toISOString(),
        new Date().toISOString()
      );
    }

    db.prepare(
      `INSERT INTO map_evidence_links (id, map_id, node_id, edge_id, event_id, created_at)
       VALUES (?, ?, ?, NULL, ?, ?)`
    ).run(uuid(), mapId, nodeId, event.id, new Date().toISOString());
  }

  for (const edge of event.edges || []) {
    const src = entityIdMap.get(edge.src) || stableNodeId(mapId, 'unknown', edge.src);
    const dst = entityIdMap.get(edge.dst) || stableNodeId(mapId, 'unknown', edge.dst);
    ensureStubNode(db, mapId, src, edge.src);
    ensureStubNode(db, mapId, dst, edge.dst);

    const edgeId = stableEdgeId(mapId, src, dst, edge.rel);
    const existing = db.prepare(`SELECT id FROM map_edges WHERE id = ?`).get(edgeId);
    if (!existing) {
      try {
        db.prepare(
          `INSERT INTO map_edges (id, map_id, src_id, dst_id, rel, confidence, suggested, attrs_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`
        ).run(
          edgeId,
          mapId,
          src,
          dst,
          asString(edge.rel, { max: 40 }),
          Number.isFinite(edge.confidence) ? edge.confidence : 1.0,
          JSON.stringify({ from_event: event.id }),
          new Date().toISOString()
        );
      } catch (e) {
        // FK races / duplicate — skip edge, keep ingest alive
        console.warn('[aegis] edge insert skipped', String(e.message || e).slice(0, 120));
        continue;
      }
    }
    try {
      db.prepare(
        `INSERT INTO map_evidence_links (id, map_id, node_id, edge_id, event_id, created_at)
         VALUES (?, ?, NULL, ?, ?, ?)`
      ).run(uuid(), mapId, edgeId, event.id, new Date().toISOString());
    } catch {
      /* ignore link dupes */
    }
  }
}

function ensureStubNode(db, mapId, nodeId, externalId) {
  const exists = db.prepare(`SELECT id FROM map_nodes WHERE id = ?`).get(nodeId);
  if (exists) return;
  try {
    db.prepare(
      `INSERT INTO map_nodes (id, map_id, kind, label, attrs_json, severity, created_at, updated_at)
       VALUES (?, ?, 'asset', ?, '{}', 'info', ?, ?)`
    ).run(
      nodeId,
      mapId,
      asString(externalId, { max: 200, fallback: 'unknown' }),
      new Date().toISOString(),
      new Date().toISOString()
    );
  } catch {
    /* concurrent insert */
  }
}

export function stableNodeId(mapId, kind, externalId) {
  const raw = `node:${mapId}:${kind}:${externalId}`.replace(/\s+/g, '_');
  return raw.slice(0, 240);
}

function stableEdgeId(mapId, src, dst, rel) {
  return `edge:${mapId}:${src}:${rel}:${dst}`.slice(0, 240);
}

function higherSeverity(a, b) {
  return (SEVERITY_RANK[a] || 0) >= (SEVERITY_RANK[b] || 0) ? a : b;
}

export function getMapGraph(db, mapId) {
  const map = db.prepare(`SELECT * FROM threat_maps WHERE id = ?`).get(mapId);
  if (!map) return null;
  const nodes = db.prepare(`SELECT * FROM map_nodes WHERE map_id = ?`).all(mapId).map((n) => ({
    ...n,
    attrs: safeJsonParse(n.attrs_json, {}),
    pinned: !!n.pinned
  }));
  const edges = db.prepare(`SELECT * FROM map_edges WHERE map_id = ?`).all(mapId).map((e) => ({
    ...e,
    attrs: safeJsonParse(e.attrs_json, {}),
    suggested: !!e.suggested
  }));
  return { map, nodes, edges };
}
