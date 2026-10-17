/** Shared validation & safe parsing for Aegis TI gateway */

export const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);
export const MODEL_STATUSES = Object.freeze(['draft', 'review', 'published']);
export const PACKAGE_STATUSES = Object.freeze(['draft', 'approved', 'distributed']);
export const MAP_STATUSES = Object.freeze(['active', 'archived']);
export const NODE_KINDS = Object.freeze([
  'host', 'process', 'service', 'port', 'identity', 'asset', 'actor', 'finding', 'peer', 'unknown'
]);
export const EDGE_RELS = Object.freeze([
  'spawns', 'listens', 'connects', 'connects_to', 'egress_to', 'persists', 'exposes', 'targets',
  'mitigates', 'observed_as', 'suggested', 'loads'
]);
export const AGENTS = Object.freeze(['go-net', 'rust-host', 'rust-etw', 'gateway', 'ml']);
export const STRIDE = Object.freeze([
  'spoofing', 'tampering', 'repudiation', 'info_disclosure', 'dos', 'elevation'
]);

const ID_RE = /^[A-Za-z0-9_.:@\-\/]{1,240}$/;
const HOST_ID_RE = /^[A-Za-z0-9_.:\-]{1,128}$/;

export class HttpError extends Error {
  constructor(status, message, code = 'bad_request') {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function safeJsonParse(text, fallback) {
  if (text == null || text === '') return fallback;
  if (typeof text !== 'string') return fallback;
  try {
    const v = JSON.parse(text);
    return v === undefined ? fallback : v;
  } catch {
    return fallback;
  }
}

export function asString(v, { max = 2000, fallback = '', allowEmpty = true } = {}) {
  if (v == null) return fallback;
  const s = String(v).normalize('NFKC').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
  const trimmed = s.slice(0, max);
  if (!allowEmpty && !trimmed.trim()) throw new HttpError(400, 'Value required');
  return trimmed;
}

export function asEnum(v, allowed, fallback) {
  if (v == null || v === '') return fallback;
  const s = String(v).toLowerCase();
  if (!allowed.includes(s) && !allowed.includes(v)) {
    throw new HttpError(400, `Invalid value: ${String(v).slice(0, 40)}`);
  }
  return allowed.includes(v) ? v : s;
}

export function asId(v, label = 'id') {
  const s = asString(v, { max: 240, allowEmpty: false, fallback: '' });
  if (!ID_RE.test(s)) throw new HttpError(400, `Invalid ${label}`);
  return s;
}

export function asOptionalId(v, label = 'id') {
  if (v == null || v === '') return null;
  return asId(v, label);
}

export function asHostId(v, fallback = 'local-host') {
  if (v == null || v === '') return fallback;
  const s = asString(v, { max: 128, allowEmpty: false });
  if (!HOST_ID_RE.test(s)) throw new HttpError(400, 'Invalid host_id');
  return s;
}

export function asNumber(v, { min = -1e9, max = 1e9, fallback = 0, integer = false } = {}) {
  if (v == null || v === '') return fallback;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new HttpError(400, 'Invalid number');
  const clamped = Math.min(max, Math.max(min, n));
  return integer ? Math.trunc(clamped) : clamped;
}

export function asBool(v, fallback = false) {
  if (v == null) return fallback;
  if (typeof v === 'boolean') return v;
  if (v === '1' || v === 'true') return true;
  if (v === '0' || v === 'false') return false;
  return fallback;
}

export function asStringArray(v, { maxItems = 50, maxLen = 500 } = {}) {
  if (v == null) return [];
  if (!Array.isArray(v)) throw new HttpError(400, 'Expected array');
  return v.slice(0, maxItems).map((x) => asString(x, { max: maxLen }));
}

export function asObject(v, fallback = {}) {
  if (v == null) return fallback;
  if (typeof v !== 'object' || Array.isArray(v)) throw new HttpError(400, 'Expected object');
  // Shallow clone; drop prototype pollution keys
  const out = {};
  for (const [k, val] of Object.entries(v)) {
    if (k === '__proto__' || k === 'prototype' || k === 'constructor') continue;
    if (typeof k !== 'string' || k.length > 120) continue;
    out[k] = val;
  }
  return out;
}

export function clampLimit(v, def = 100, max = 500) {
  return asNumber(v, { min: 1, max, fallback: def, integer: true });
}

export function sanitizeAttrs(attrs, { maxValueLen = 4000, maxTotal = 20000 } = {}) {
  const obj = asObject(attrs, {});
  const out = {};
  let size = 0;
  for (const [k, val] of Object.entries(obj)) {
    const key = asString(k, { max: 64 });
    // Peer inventory arrays are large; sanitize element-wise instead of dropping.
    if ((key === 'destinations' || key === 'c2_candidates') && Array.isArray(val)) {
      const items = val.slice(0, 120).map((item) => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
        return sanitizeAttrs(item, { maxValueLen: 2000, maxTotal: 8000 });
      }).filter(Boolean);
      let encoded;
      try {
        encoded = JSON.stringify(items);
      } catch {
        continue;
      }
      size += encoded.length;
      if (size > maxTotal) break;
      out[key] = items;
      continue;
    }
    let encoded;
    try {
      encoded = JSON.stringify(val);
    } catch {
      continue;
    }
    if (encoded.length > maxValueLen) continue;
    size += encoded.length;
    if (size > maxTotal) break;
    out[key] = typeof val === 'string' ? asString(val, { max: 2000 }) : val;
  }
  return out;
}

/** Bound evidence ingest payload */
export function normalizeEvidenceEvent(payload, defaults = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new HttpError(400, 'Event must be an object');
  }
  const entitiesIn = Array.isArray(payload.entities) ? payload.entities.slice(0, 100) : [];
  const edgesIn = Array.isArray(payload.edges) ? payload.edges.slice(0, 200) : [];

  const entities = entitiesIn.map((e, i) => {
    if (!e || typeof e !== 'object') throw new HttpError(400, `Invalid entity at ${i}`);
    return {
      kind: asEnum(e.kind, NODE_KINDS, 'asset'),
      id: asId(e.id, 'entity.id'),
      label: asString(e.label || e.id, { max: 200 }),
      attrs: sanitizeAttrs(e.attrs)
    };
  });

  const entityIds = new Set(entities.map((e) => e.id));
  const edges = edgesIn.map((e, i) => {
    if (!e || typeof e !== 'object') throw new HttpError(400, `Invalid edge at ${i}`);
    const src = asId(e.src, 'edge.src');
    const dst = asId(e.dst, 'edge.dst');
    return {
      src,
      dst,
      rel: asEnum(e.rel, EDGE_RELS, 'observed_as'),
      confidence: asNumber(e.confidence, { min: 0, max: 1, fallback: 1 })
    };
  }).filter((e) => entityIds.has(e.src) || entityIds.has(e.dst) || true);

  return {
    id: payload.id ? asId(payload.id, 'event.id') : undefined,
    ts: asString(payload.ts || new Date().toISOString(), { max: 64 }),
    agent: asEnum(payload.agent || defaults.agent || 'gateway', AGENTS, 'gateway'),
    host_id: asHostId(payload.host_id || defaults.host_id),
    type: asString(payload.type || 'unknown', { max: 120, allowEmpty: false }),
    severity: asEnum(payload.severity || 'info', SEVERITIES, 'info'),
    entities,
    edges,
    // Peer summaries carry destination inventories that exceed node-attr limits.
    raw: sanitizeAttrs(payload.raw, { maxValueLen: 120_000, maxTotal: 250_000 }),
    scan_run_id: asOptionalId(payload.scan_run_id || defaults.scan_run_id, 'scan_run_id')
  };
}

export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
