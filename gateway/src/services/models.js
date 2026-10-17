import { v4 as uuid } from 'uuid';
import {
  asString,
  asEnum,
  asNumber,
  asOptionalId,
  asStringArray,
  sanitizeAttrs,
  safeJsonParse,
  HttpError,
  MODEL_STATUSES,
  STRIDE,
  SEVERITIES
} from '../util/safe.js';

export function createModel(db, body = {}) {
  const id = uuid();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO threat_models (id, title, classification, owner, scope, status, map_id, residual_risk, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    asString(body.title || 'Untitled Model', { max: 200, allowEmpty: false }),
    asString(body.classification || 'internal', { max: 64 }),
    asString(body.owner || '', { max: 120 }),
    asString(body.scope || '', { max: 4000 }),
    asEnum(body.status || 'draft', MODEL_STATUSES, 'draft'),
    asOptionalId(body.map_id, 'map_id'),
    asNumber(body.residual_risk, { min: 0, max: 1, fallback: 0 }),
    now,
    now
  );
  return getModel(db, id);
}

export function listModels(db) {
  return db.prepare(`SELECT * FROM threat_models ORDER BY updated_at DESC LIMIT 500`).all();
}

export function getModel(db, id) {
  const model = db.prepare(`SELECT * FROM threat_models WHERE id = ?`).get(id);
  if (!model) return null;
  return {
    ...model,
    assets: db.prepare(`SELECT * FROM model_assets WHERE model_id = ?`).all(id),
    actors: db.prepare(`SELECT * FROM model_actors WHERE model_id = ?`).all(id),
    boundaries: db.prepare(`SELECT * FROM model_boundaries WHERE model_id = ?`).all(id),
    scenarios: db
      .prepare(`SELECT * FROM model_scenarios WHERE model_id = ?`)
      .all(id)
      .map((s) => ({
        ...s,
        stride_tags: safeJsonParse(s.stride_tags_json, []),
        steps: safeJsonParse(s.steps_json, []),
        map_edge_ids: safeJsonParse(s.map_edge_ids_json, []),
        event_ids: safeJsonParse(s.event_ids_json, [])
      })),
    mitigations: db.prepare(`SELECT * FROM model_mitigations WHERE model_id = ?`).all(id)
  };
}

export function updateModel(db, id, body = {}) {
  const existing = db.prepare(`SELECT id FROM threat_models WHERE id = ?`).get(id);
  if (!existing) return null;
  db.prepare(
    `UPDATE threat_models SET
      title = COALESCE(?, title),
      classification = COALESCE(?, classification),
      owner = COALESCE(?, owner),
      scope = COALESCE(?, scope),
      status = COALESCE(?, status),
      map_id = COALESCE(?, map_id),
      residual_risk = COALESCE(?, residual_risk),
      updated_at = ?
     WHERE id = ?`
  ).run(
    body.title != null ? asString(body.title, { max: 200 }) : null,
    body.classification != null ? asString(body.classification, { max: 64 }) : null,
    body.owner != null ? asString(body.owner, { max: 120 }) : null,
    body.scope != null ? asString(body.scope, { max: 4000 }) : null,
    body.status != null ? asEnum(body.status, MODEL_STATUSES, 'draft') : null,
    body.map_id !== undefined ? asOptionalId(body.map_id, 'map_id') : null,
    body.residual_risk != null
      ? asNumber(body.residual_risk, { min: 0, max: 1, fallback: 0 })
      : null,
    new Date().toISOString(),
    id
  );
  return getModel(db, id);
}

export function addAsset(db, modelId, body = {}) {
  if (!asString(body.name, { max: 200 }).trim()) throw new HttpError(400, 'Asset name required');
  const id = uuid();
  db.prepare(
    `INSERT INTO model_assets (id, model_id, name, kind, description, map_node_id, attrs_json)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    modelId,
    asString(body.name, { max: 200 }),
    asString(body.kind || 'system', { max: 64 }),
    asString(body.description || '', { max: 2000 }),
    asOptionalId(body.map_node_id, 'map_node_id'),
    JSON.stringify(sanitizeAttrs(body.attrs))
  );
  return db.prepare(`SELECT * FROM model_assets WHERE id = ?`).get(id);
}

export function addActor(db, modelId, body = {}) {
  if (!asString(body.name, { max: 200 }).trim()) throw new HttpError(400, 'Actor name required');
  const id = uuid();
  db.prepare(
    `INSERT INTO model_actors (id, model_id, name, intent, capability, access, map_node_id, attrs_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    modelId,
    asString(body.name, { max: 200 }),
    asString(body.intent || '', { max: 2000 }),
    asString(body.capability || 'medium', { max: 64 }),
    asString(body.access || '', { max: 500 }),
    asOptionalId(body.map_node_id, 'map_node_id'),
    JSON.stringify(sanitizeAttrs(body.attrs))
  );
  return db.prepare(`SELECT * FROM model_actors WHERE id = ?`).get(id);
}

export function addBoundary(db, modelId, body = {}) {
  if (!asString(body.name, { max: 200 }).trim()) throw new HttpError(400, 'Boundary name required');
  const id = uuid();
  db.prepare(
    `INSERT INTO model_boundaries (id, model_id, name, description, attrs_json)
     VALUES (?, ?, ?, ?, ?)`
  ).run(
    id,
    modelId,
    asString(body.name, { max: 200 }),
    asString(body.description || '', { max: 2000 }),
    JSON.stringify(sanitizeAttrs(body.attrs))
  );
  return db.prepare(`SELECT * FROM model_boundaries WHERE id = ?`).get(id);
}

export function addScenario(db, modelId, body = {}) {
  if (!asString(body.title, { max: 200 }).trim()) throw new HttpError(400, 'Scenario title required');
  const tags = asStringArray(body.stride_tags, { maxItems: 8, maxLen: 40 }).filter((t) =>
    STRIDE.includes(t)
  );
  const id = uuid();
  db.prepare(
    `INSERT INTO model_scenarios (id, model_id, title, description, stride_tags_json, steps_json, map_edge_ids_json, event_ids_json, severity, likelihood)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    modelId,
    asString(body.title, { max: 200 }),
    asString(body.description || '', { max: 4000 }),
    JSON.stringify(tags),
    JSON.stringify(asStringArray(body.steps, { maxItems: 40, maxLen: 500 })),
    JSON.stringify(asStringArray(body.map_edge_ids, { maxItems: 100, maxLen: 200 })),
    JSON.stringify(asStringArray(body.event_ids, { maxItems: 100, maxLen: 200 })),
    asEnum(body.severity || 'medium', SEVERITIES, 'medium'),
    asNumber(body.likelihood, { min: 0, max: 1, fallback: 0.5 })
  );
  const row = db.prepare(`SELECT * FROM model_scenarios WHERE id = ?`).get(id);
  return {
    ...row,
    stride_tags: safeJsonParse(row.stride_tags_json, []),
    steps: safeJsonParse(row.steps_json, []),
    map_edge_ids: safeJsonParse(row.map_edge_ids_json, []),
    event_ids: safeJsonParse(row.event_ids_json, [])
  };
}

export function addMitigation(db, modelId, body = {}) {
  if (!asString(body.title, { max: 200 }).trim()) throw new HttpError(400, 'Mitigation title required');
  const id = uuid();
  db.prepare(
    `INSERT INTO model_mitigations (id, model_id, scenario_id, title, description, status, residual_risk, map_node_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    modelId,
    asOptionalId(body.scenario_id, 'scenario_id'),
    asString(body.title, { max: 200 }),
    asString(body.description || '', { max: 4000 }),
    asString(body.status || 'proposed', { max: 40 }),
    asNumber(body.residual_risk, { min: 0, max: 1, fallback: 0 }),
    asOptionalId(body.map_node_id, 'map_node_id')
  );
  return db.prepare(`SELECT * FROM model_mitigations WHERE id = ?`).get(id);
}

export function deleteModel(db, id) {
  const info = db.prepare(`DELETE FROM threat_models WHERE id = ?`).run(id);
  return info.changes > 0;
}
