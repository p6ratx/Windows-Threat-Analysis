import { v4 as uuid } from 'uuid';
import { getModel } from './models.js';
import { getMapGraph } from './mapEngine.js';
import {
  asString,
  asEnum,
  asNumber,
  asOptionalId,
  asStringArray,
  safeJsonParse,
  HttpError,
  SEVERITIES,
  PACKAGE_STATUSES
} from '../util/safe.js';

export function createPackage(db, body = {}) {
  const id = uuid();
  const now = new Date().toISOString();
  const actions = asStringArray(body.recommended_actions, { maxItems: 40, maxLen: 500 });
  db.prepare(
    `INSERT INTO intel_packages (id, title, model_id, map_id, executive_summary, severity, confidence, recommended_actions_json, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    asString(body.title || 'Intel Package', { max: 240, allowEmpty: false }),
    asOptionalId(body.model_id, 'model_id'),
    asOptionalId(body.map_id, 'map_id'),
    asString(body.executive_summary || '', { max: 8000 }),
    asEnum(body.severity || 'medium', SEVERITIES, 'medium'),
    asNumber(body.confidence, { min: 0, max: 1, fallback: 0.5 }),
    JSON.stringify(actions),
    asEnum(body.status || 'draft', PACKAGE_STATUSES, 'draft'),
    now,
    now
  );

  const items = Array.isArray(body.items) ? body.items.slice(0, 100) : [];
  for (const item of items) {
    if (!item || typeof item !== 'object') continue;
    try {
      db.prepare(
        `INSERT INTO package_items (id, package_id, kind, ref_id, note) VALUES (?, ?, ?, ?, ?)`
      ).run(
        uuid(),
        id,
        asString(item.kind, { max: 40, allowEmpty: false }),
        asString(item.ref_id, { max: 200, allowEmpty: false }),
        asString(item.note || '', { max: 500 })
      );
    } catch {
      /* skip bad items */
    }
  }

  return getPackage(db, id);
}

export function listPackages(db) {
  return db
    .prepare(`SELECT * FROM intel_packages ORDER BY updated_at DESC LIMIT 500`)
    .all()
    .map((p) => ({
      ...p,
      recommended_actions: safeJsonParse(p.recommended_actions_json, [])
    }));
}

export function getPackage(db, id) {
  const pkg = db.prepare(`SELECT * FROM intel_packages WHERE id = ?`).get(id);
  if (!pkg) return null;
  const items = db.prepare(`SELECT * FROM package_items WHERE package_id = ?`).all(id);
  const dist = db
    .prepare(`SELECT * FROM distribution_log WHERE package_id = ? ORDER BY distributed_at DESC`)
    .all(id);
  return {
    ...pkg,
    recommended_actions: safeJsonParse(pkg.recommended_actions_json, []),
    items,
    distribution_log: dist
  };
}

export function updatePackageStatus(db, id, status, { channel, note } = {}) {
  const existing = getPackage(db, id);
  if (!existing) return null;
  const next = asEnum(status, PACKAGE_STATUSES, null);
  if (!next) throw new HttpError(400, 'Invalid package status');

  db.prepare(`UPDATE intel_packages SET status = ?, updated_at = ? WHERE id = ?`).run(
    next,
    new Date().toISOString(),
    id
  );
  if (next === 'distributed') {
    db.prepare(
      `INSERT INTO distribution_log (id, package_id, channel, note, distributed_at)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      uuid(),
      id,
      asString(channel || 'internal', { max: 64 }),
      asString(note || '', { max: 1000 }),
      new Date().toISOString()
    );
  }
  return getPackage(db, id);
}

export function exportPackage(db, id) {
  const pkg = getPackage(db, id);
  if (!pkg) return null;

  const model = pkg.model_id ? getModel(db, pkg.model_id) : null;
  const graph = pkg.map_id ? getMapGraph(db, pkg.map_id) : null;
  const findings = db.prepare(`SELECT * FROM findings ORDER BY created_at DESC LIMIT 25`).all();

  const mapId = pkg.map_id || null;
  let peerExcerpt = null;
  if (mapId) {
    const peers = db
      .prepare(
        `SELECT id, host_id, process_name, remote_ip, remote_port, c2_score, software_class, last_seen, attrs_json
         FROM remote_peers WHERE map_id = ? ORDER BY c2_score DESC, last_seen DESC LIMIT 80`
      )
      .all(mapId);
    const c2 = db
      .prepare(
        `SELECT id, host_id, remote_ip, remote_port, process_name, score, doing, ts, event_id
         FROM c2_observations WHERE map_id = ? ORDER BY score DESC, ts DESC LIMIT 40`
      )
      .all(mapId);
    const beacons = db
      .prepare(
        `SELECT id, host_id, process_name, remote_ip, remote_port, score, reasons_json, tier, last_seen
         FROM beacon_candidates WHERE map_id = ? ORDER BY score DESC LIMIT 30`
      )
      .all(mapId);
    const dns = db
      .prepare(
        `SELECT hostname, remote_ip, process_name, confidence, hit_count, last_seen
         FROM ip_resolutions WHERE map_id = ? ORDER BY last_seen DESC LIMIT 40`
      )
      .all(mapId);
    const eventIds = [
      ...new Set(c2.map((r) => r.event_id).filter(Boolean))
    ].slice(0, 40);
    peerExcerpt = { peers, c2_observations: c2, beacons, dns_resolutions: dns, event_ids: eventIds };
  }

  const payload = {
    package: pkg,
    model,
    map_excerpt: graph
      ? {
          map: graph.map,
          nodes: graph.nodes.slice(0, 200),
          edges: graph.edges.slice(0, 400)
        }
      : null,
    findings,
    peer_evidence: peerExcerpt,
    exported_at: new Date().toISOString()
  };

  return { json: payload, markdown: renderBriefing(payload) };
}

function escapeMd(s) {
  return String(s || '')
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\r/g, '');
}

function renderBriefing(payload) {
  const p = payload.package;
  const actions =
    (p.recommended_actions || [])
      .map((a, i) => `${i + 1}. ${escapeMd(a)}`)
      .join('\n') || '1. Review mapped attack paths and residual risk.';
  const scenarios = payload.model?.scenarios || [];
  const scenarioBlock = scenarios.length
    ? scenarios
        .map(
          (s) =>
            `- **${escapeMd(s.title)}** (${escapeMd(s.severity)}) — ${escapeMd(
              (s.stride_tags || []).join(', ') || 'n/a'
            )}`
        )
        .join('\n')
    : '- No scenarios attached.';

  return `# ${escapeMd(p.title)}

**Classification:** ${escapeMd(payload.model?.classification || 'internal')}  
**Severity:** ${escapeMd(p.severity)}  
**Confidence:** ${Math.round((p.confidence || 0) * 100)}%  
**Status:** ${escapeMd(p.status)}  
**Exported:** ${escapeMd(payload.exported_at)}

## Executive Summary

${escapeMd(p.executive_summary || 'No summary provided.')}

## Affected Scope

${escapeMd(payload.model?.scope || 'See attached threat map.')}

## Attack Paths / Scenarios

${scenarioBlock}

## Recommended Actions

${actions}

## Evidence Appendix

- Findings included: ${payload.findings.length}
- Map nodes: ${payload.map_excerpt?.nodes?.length ?? 0}
- Map edges: ${payload.map_excerpt?.edges?.length ?? 0}
- Peer rows: ${payload.peer_evidence?.peers?.length ?? 0}
- C2 observations: ${payload.peer_evidence?.c2_observations?.length ?? 0}
- Beacon candidates: ${payload.peer_evidence?.beacons?.length ?? 0}
- DNS resolutions: ${payload.peer_evidence?.dns_resolutions?.length ?? 0}
- Linked event ids: ${(payload.peer_evidence?.event_ids || []).length}

---
*Generated by Aegis TI — defensive threat mapping & modeling platform*
`;
}
