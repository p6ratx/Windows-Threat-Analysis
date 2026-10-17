import { v4 as uuid } from 'uuid';
import { ensureActiveMap } from '../db.js';
import { getMapGraph, stableNodeId } from './mapEngine.js';
import { safeJsonParse, asString, HttpError, asId } from '../util/safe.js';

/** Defensive function catalog — what a signal typically means on Windows estates */
const PORT_FUNCTIONS = {
  21: { tag: 'ftp', role: 'File transfer service', how: 'FTP control channel accepts remote file ops' },
  22: { tag: 'ssh', role: 'Remote shell', how: 'Encrypted interactive/admin access' },
  23: { tag: 'telnet', role: 'Cleartext remote shell', how: 'Unencrypted interactive access' },
  53: { tag: 'dns', role: 'Name resolution', how: 'DNS queries/responses on UDP/TCP 53' },
  80: { tag: 'http', role: 'Web service', how: 'HTTP application listener' },
  135: { tag: 'rpc', role: 'Windows RPC endpoint mapper', how: 'Maps RPC interfaces used by remote management' },
  139: { tag: 'netbios', role: 'NetBIOS session', how: 'Legacy Windows file/print session service' },
  443: { tag: 'https', role: 'TLS web service', how: 'HTTPS application listener' },
  445: { tag: 'smb', role: 'SMB file/print sharing', how: 'Server Message Block accepts remote share access' },
  3389: { tag: 'rdp', role: 'Remote Desktop', how: 'RDP graphical interactive sessions' },
  5985: { tag: 'winrm', role: 'WinRM HTTP', how: 'Windows Remote Management over HTTP' },
  5986: { tag: 'winrm', role: 'WinRM HTTPS', how: 'Windows Remote Management over HTTPS' },
  47001: { tag: 'winrm', role: 'WinRM alternate', how: 'Alternate WinRM listener' }
};

const PROCESS_FUNCTIONS = [
  { match: /lsass/i, tag: 'auth', role: 'Local Security Authority', how: 'Handles authentication & credential material in memory' },
  { match: /services\.exe/i, tag: 'scm', role: 'Service Control Manager', how: 'Starts/stops Windows services' },
  { match: /svchost/i, tag: 'host', role: 'Service host process', how: 'Hosts one or more DLL-based Windows services' },
  { match: /explorer/i, tag: 'shell', role: 'User shell', how: 'Desktop shell; common persistence/user-context target' },
  { match: /powershell|pwsh/i, tag: 'shell', role: 'PowerShell interpreter', how: 'Script execution / admin automation' },
  { match: /cmd\.exe/i, tag: 'shell', role: 'Command interpreter', how: 'Interactive or scripted command execution' },
  { match: /winlogon/i, tag: 'auth', role: 'Logon UI coordinator', how: 'Manages interactive logon path' },
  { match: /csrss/i, tag: 'kernel', role: 'Client/Server Runtime', how: 'Critical Windows subsystem process' },
  { match: /system$/i, tag: 'kernel', role: 'Kernel process', how: 'Handles kernel-mode work including some listeners' }
];

export function classifyFunction({ kind, label, attrs = {}, type, raw = {} }) {
  const port = Number(attrs.port ?? raw.port ?? raw?.listener?.Port ?? raw?.listener?.port);
  if (Number.isFinite(port) && PORT_FUNCTIONS[port]) {
    return PORT_FUNCTIONS[port];
  }
  const name = String(label || attrs.name || attrs.exe || '');
  for (const p of PROCESS_FUNCTIONS) {
    if (p.match.test(name)) return { tag: p.tag, role: p.role, how: p.how };
  }
  if (type?.includes('persistence') || kind === 'finding' && /run/i.test(name)) {
    return {
      tag: 'persistence',
      role: 'Persistence artifact',
      how: 'Survives reboot via autorun/registry/task mechanism'
    };
  }
  if (type?.startsWith('etw.process') || type === 'etw.image.load') {
    return {
      tag: 'etw_process',
      role: 'Kernel-observed process activity',
      how: 'ETW Microsoft-Windows-Kernel-Process real-time trace'
    };
  }
  if (type === 'etw.dns.query') {
    return {
      tag: 'dns',
      role: 'DNS resolution activity',
      how: 'ETW Microsoft-Windows-DNS-Client query observation'
    };
  }
  if (type === 'etw.network.flow') {
    return {
      tag: 'network',
      role: 'Kernel networking path',
      how: 'ETW Microsoft-Windows-TCPIP flow/connect telemetry'
    };
  }
  if (type === 'net.peers.summary') {
    return {
      tag: 'peers',
      role: 'Remote peer inventory',
      how: 'Enumerates ESTABLISHED TCP remotes and maps process → destination IP'
    };
  }
  if (type === 'net.c2.candidate') {
    return {
      tag: 'c2',
      role: 'C2 / egress candidate',
      how: 'Outbound connection scored by process allowlist, port role, and public IP heuristics'
    };
  }
  if (type?.startsWith('etw.')) {
    return {
      tag: 'etw',
      role: 'ETW telemetry',
      how: 'Windows Event Tracing (defensive kernel/user observation)'
    };
  }
  if (kind === 'service') {
    return { tag: 'service', role: 'Windows service', how: 'Long-running background component managed by SCM' };
  }
  if (kind === 'port') {
    return { tag: 'network', role: 'Network listener', how: 'Accepts inbound packets on a bound address/port' };
  }
  if (kind === 'process') {
    return { tag: 'process', role: 'Running process', how: 'Executable image currently scheduled on the host' };
  }
  return { tag: 'unknown', role: 'Observed artifact', how: 'Captured from host/network telemetry' };
}

export function recordActivityFromEvent(db, mapId, event) {
  if (!event?.entities?.length) return;
  const inserts = [];
  for (const ent of event.entities) {
    const nodeId = stableNodeId(mapId, ent.kind, ent.id);
    const fn = classifyFunction({
      kind: ent.kind,
      label: ent.label,
      attrs: ent.attrs || {},
      type: event.type,
      raw: event.raw || {}
    });
    const action = deriveAction(event, ent);
    const mechanism = deriveMechanism(event, ent, fn);
    const summary = deriveSummary(event, ent, fn, action);
    inserts.push({
      id: uuid(),
      map_id: mapId,
      node_id: nodeId,
      event_id: event.id,
      host_id: event.host_id,
      ts: event.ts,
      action,
      summary,
      mechanism,
      function_tag: fn.tag,
      severity: event.severity || 'info',
      attrs_json: JSON.stringify({
        ...(ent.attrs || {}),
        event_type: event.type,
        agent: event.agent,
        function_role: fn.role
      })
    });
  }

  const stmt = db.prepare(
    `INSERT INTO activity_log
     (id, map_id, node_id, event_id, host_id, ts, action, summary, mechanism, function_tag, severity, attrs_json)
     VALUES (@id, @map_id, @node_id, @event_id, @host_id, @ts, @action, @summary, @mechanism, @function_tag, @severity, @attrs_json)`
  );
  const tx = db.transaction((rows) => {
    for (const row of rows) stmt.run(row);
  });
  try {
    tx(inserts);
  } catch (e) {
    console.warn('[aegis] activity_log insert', e.message || e);
  }

  // Refresh dossiers for high-sev findings linked to this event
  if (['high', 'critical', 'medium'].includes(event.severity)) {
    try {
      refreshFindingDossiersForEvent(db, mapId, event);
    } catch (e) {
      console.warn('[aegis] dossier refresh', e.message || e);
    }
  }
}

function deriveAction(event, ent) {
  const t = event.type || '';
  if (t.includes('listen') || ent.kind === 'port') return 'listens';
  if (t.includes('conn') || t.includes('network') || t.includes('dns')) return 'connects';
  if (t.includes('persist')) return 'persists';
  if (t.includes('image.load')) return 'loads';
  if (t.includes('process.start')) return 'spawns';
  if (t.includes('process') || ent.kind === 'process') return 'runs';
  if (t.includes('service') || ent.kind === 'service') return 'exposes';
  if (t.includes('misconfig')) return 'exposes';
  if (t.includes('pipe')) return 'exposes';
  if (t.startsWith('etw.')) return 'observed';
  return 'observed';
}

function deriveMechanism(event, ent, fn) {
  const attrs = ent.attrs || {};
  const raw = event.raw || {};
  const parts = [];
  if (attrs.bind || raw?.listener?.Bind || raw?.listener?.bind) {
    parts.push(`bind=${attrs.bind || raw.listener.Bind || raw.listener.bind}`);
  }
  if (attrs.port || raw.port || raw?.listener?.Port) {
    parts.push(`port=${attrs.port || raw.port || raw.listener.Port}`);
  }
  if (attrs.proto || raw?.listener?.Proto) {
    parts.push(`proto=${attrs.proto || raw.listener.Proto}`);
  }
  if (attrs.pid || raw?.listener?.PID) {
    parts.push(`pid=${attrs.pid || raw.listener.PID}`);
  }
  if (attrs.ppid) parts.push(`ppid=${attrs.ppid}`);
  if (attrs.exe || raw.exe) parts.push(`exe=${attrs.exe || raw.exe}`);
  if (attrs.cmdline || raw.cmdline) {
    parts.push(`cmdline=${String(attrs.cmdline || raw.cmdline).slice(0, 160)}`);
  }
  if (raw.heuristic) parts.push(`heuristic=${raw.heuristic}`);
  if (raw.source) parts.push(`source=${raw.source}`);
  if (attrs.key || raw.key) parts.push(`key=${attrs.key || raw.key}`);
  if (!parts.length) parts.push(fn.how);
  return parts.join('; ').slice(0, 500);
}

function deriveSummary(event, ent, fn, action) {
  const label = ent.label || ent.id;
  return asString(`${action}: ${label} — ${fn.role}`, { max: 300 });
}

function refreshFindingDossiersForEvent(db, mapId, event) {
  const findings = db
    .prepare(
      `SELECT * FROM findings WHERE event_ids_json LIKE ? ORDER BY created_at DESC LIMIT 5`
    )
    .all(`%${event.id}%`);
  for (const f of findings) {
    upsertFindingDossier(db, f, mapId);
  }
}

export function upsertFindingDossier(db, finding, mapId) {
  const eventIds = safeJsonParse(finding.event_ids_json, []);
  const events = eventIds
    .map((id) => db.prepare(`SELECT * FROM events WHERE id = ?`).get(id))
    .filter(Boolean)
    .map((e) => ({
      ...e,
      entities: safeJsonParse(e.entities_json, []),
      edges: safeJsonParse(e.edges_json, []),
      raw: safeJsonParse(e.raw_json, {})
    }));

  const relatedNodeIds = new Set();
  const surface = [];
  const mechanisms = [];
  const functions = [];

  for (const e of events) {
    for (const ent of e.entities || []) {
      const nodeId = stableNodeId(mapId, ent.kind, ent.id);
      relatedNodeIds.add(nodeId);
      const fn = classifyFunction({
        kind: ent.kind,
        label: ent.label,
        attrs: ent.attrs || {},
        type: e.type,
        raw: e.raw || {}
      });
      functions.push(fn);
      mechanisms.push(deriveMechanism(e, ent, fn));
      if (ent.kind === 'port' || e.type?.includes('misconfig') || e.type?.includes('persist')) {
        surface.push({
          kind: ent.kind,
          label: ent.label || ent.id,
          function_tag: fn.tag,
          role: fn.role,
          severity: e.severity,
          node_id: nodeId
        });
      }
    }
  }

  const primary = functions[0] || { tag: 'unknown', role: 'Finding', how: 'Correlated evidence' };
  let activityCount = 0;
  if (relatedNodeIds.size) {
    const ids = [...relatedNodeIds];
    activityCount =
      db
        .prepare(
          `SELECT COUNT(*) AS c FROM activity_log WHERE node_id IN (${ids.map(() => '?').join(',')})`
        )
        .get(...ids)?.c || 0;
  }

  const dossier = {
    id: uuid(),
    finding_id: finding.id,
    map_node_id: [...relatedNodeIds][0] || null,
    function_summary: `${primary.role} (${primary.tag})`,
    mechanism_summary: [...new Set(mechanisms)].slice(0, 5).join(' | ').slice(0, 1000),
    attack_surface_json: JSON.stringify(surface.slice(0, 40)),
    related_node_ids_json: JSON.stringify([...relatedNodeIds].slice(0, 100)),
    activity_count: activityCount,
    risk_notes: buildRiskNotes(finding, primary, surface),
    updated_at: new Date().toISOString()
  };

  db.prepare(`DELETE FROM finding_dossiers WHERE finding_id = ?`).run(finding.id);
  db.prepare(
    `INSERT INTO finding_dossiers
     (id, finding_id, map_node_id, function_summary, mechanism_summary, attack_surface_json, related_node_ids_json, activity_count, risk_notes, updated_at)
     VALUES (@id, @finding_id, @map_node_id, @function_summary, @mechanism_summary, @attack_surface_json, @related_node_ids_json, @activity_count, @risk_notes, @updated_at)`
  ).run(dossier);

  return getFindingDetail(db, finding.id);
}

function buildRiskNotes(finding, primary, surface) {
  const notes = [];
  notes.push(`Observed as ${finding.severity} severity: ${finding.title}`);
  notes.push(`Primary function: ${primary.role} — ${primary.how}`);
  if (surface.some((s) => s.function_tag === 'smb' || s.function_tag === 'rdp')) {
    notes.push('Admin/file-sharing protocol exposure increases remote attack surface.');
  }
  if (surface.some((s) => s.function_tag === 'persistence')) {
    notes.push('Persistence artifact can re-establish foothold after reboot.');
  }
  if (surface.some((s) => s.function_tag === 'auth')) {
    notes.push('Touches authentication components — credential impact possible if abused.');
  }
  return notes.join(' ');
}

export function getNodeDossier(db, mapId, nodeId) {
  mapId = asId(mapId, 'map_id');
  nodeId = asId(nodeId, 'node_id');
  const node = db.prepare(`SELECT * FROM map_nodes WHERE id = ? AND map_id = ?`).get(nodeId, mapId);
  if (!node) throw new HttpError(404, 'node not found', 'not_found');

  const attrs = safeJsonParse(node.attrs_json, {});
  const fn = classifyFunction({ kind: node.kind, label: node.label, attrs });

  const activity = db
    .prepare(
      `SELECT * FROM activity_log WHERE map_id = ? AND node_id = ? ORDER BY ts DESC LIMIT 100`
    )
    .all(mapId, nodeId)
    .map((a) => ({ ...a, attrs: safeJsonParse(a.attrs_json, {}) }));

  const evidence = db
    .prepare(
      `SELECT e.* FROM map_evidence_links l
       JOIN events e ON e.id = l.event_id
       WHERE l.map_id = ? AND l.node_id = ?
       ORDER BY e.ts DESC LIMIT 50`
    )
    .all(mapId, nodeId)
    .map((row) => ({
      ...row,
      entities: safeJsonParse(row.entities_json, []),
      edges: safeJsonParse(row.edges_json, []),
      raw: safeJsonParse(row.raw_json, {})
    }));

  const graph = getMapGraph(db, mapId);
  const neighbors = [];
  if (graph) {
    for (const e of graph.edges) {
      if (e.src_id === nodeId) {
        const n = graph.nodes.find((x) => x.id === e.dst_id);
        if (n) neighbors.push({ direction: 'out', rel: e.rel, node: n, confidence: e.confidence });
      } else if (e.dst_id === nodeId) {
        const n = graph.nodes.find((x) => x.id === e.src_id);
        if (n) neighbors.push({ direction: 'in', rel: e.rel, node: n, confidence: e.confidence });
      }
    }
  }

  const surfaceContribution = activity
    .filter((a) => ['listens', 'exposes', 'persists'].includes(a.action))
    .map((a) => ({
      action: a.action,
      summary: a.summary,
      mechanism: a.mechanism,
      function_tag: a.function_tag,
      severity: a.severity,
      ts: a.ts
    }));

  return {
    node: { ...node, attrs, pinned: !!node.pinned },
    function: fn,
    what_it_does: fn.role,
    how_it_works: fn.how,
    activity,
    evidence,
    neighbors: neighbors.slice(0, 60),
    attack_surface_contribution: surfaceContribution,
    stats: {
      activity_count: activity.length,
      evidence_count: evidence.length,
      neighbor_count: neighbors.length
    }
  };
}

export function getFindingDetail(db, findingId) {
  findingId = asId(findingId, 'finding_id');
  const finding = db.prepare(`SELECT * FROM findings WHERE id = ?`).get(findingId);
  if (!finding) throw new HttpError(404, 'finding not found', 'not_found');

  let dossier = db.prepare(`SELECT * FROM finding_dossiers WHERE finding_id = ?`).get(findingId);
  const mapId = ensureActiveMap(db);
  if (!dossier) {
    upsertFindingDossier(db, finding, mapId);
    dossier = db.prepare(`SELECT * FROM finding_dossiers WHERE finding_id = ?`).get(findingId);
  }

  const eventIds = safeJsonParse(finding.event_ids_json, []);
  const events = eventIds
    .map((id) => db.prepare(`SELECT * FROM events WHERE id = ?`).get(id))
    .filter(Boolean)
    .map((e) => ({
      ...e,
      entities: safeJsonParse(e.entities_json, []),
      edges: safeJsonParse(e.edges_json, []),
      raw: safeJsonParse(e.raw_json, {})
    }));

  const relatedIds = safeJsonParse(dossier?.related_node_ids_json, []);
  const relatedNodes = relatedIds
    .map((id) => db.prepare(`SELECT * FROM map_nodes WHERE id = ?`).get(id))
    .filter(Boolean)
    .map((n) => ({ ...n, attrs: safeJsonParse(n.attrs_json, {}) }));

  const activity = relatedIds.length
    ? db
        .prepare(
          `SELECT * FROM activity_log WHERE node_id IN (${relatedIds.map(() => '?').join(',')})
           ORDER BY ts DESC LIMIT 100`
        )
        .all(...relatedIds)
        .map((a) => ({ ...a, attrs: safeJsonParse(a.attrs_json, {}) }))
    : [];

  return {
    finding: {
      ...finding,
      event_ids: eventIds
    },
    dossier: dossier
      ? {
          ...dossier,
          attack_surface: safeJsonParse(dossier.attack_surface_json, []),
          related_node_ids: relatedIds
        }
      : null,
    events,
    related_nodes: relatedNodes,
    activity,
    function: classifyFunction({
      kind: relatedNodes[0]?.kind,
      label: relatedNodes[0]?.label || finding.title,
      attrs: relatedNodes[0] ? safeJsonParse(relatedNodes[0].attrs_json, {}) : {},
      type: events[0]?.type,
      raw: events[0] ? safeJsonParse(events[0].raw_json, {}) : {}
    })
  };
}

export function buildAttackSurface(db, mapId) {
  mapId = mapId ? asId(mapId, 'map_id') : ensureActiveMap(db);
  const graph = getMapGraph(db, mapId);
  if (!graph) throw new HttpError(404, 'map not found', 'not_found');

  const items = [];
  for (const n of graph.nodes) {
    const attrs = n.attrs || safeJsonParse(n.attrs_json, {});
    const fn = classifyFunction({ kind: n.kind, label: n.label, attrs });
    const interesting =
      n.kind === 'port' ||
      n.kind === 'finding' ||
      (n.kind === 'service' && ['medium', 'high', 'critical'].includes(n.severity)) ||
      ['smb', 'rdp', 'rpc', 'winrm', 'persistence', 'auth', 'telnet', 'ftp'].includes(fn.tag);

    if (!interesting) continue;

    const recent = db
      .prepare(
        `SELECT action, summary, mechanism, ts, severity FROM activity_log
         WHERE node_id = ? ORDER BY ts DESC LIMIT 5`
      )
      .all(n.id);

    items.push({
      node_id: n.id,
      kind: n.kind,
      label: n.label,
      severity: n.severity,
      function_tag: fn.tag,
      role: fn.role,
      how: fn.how,
      bind: attrs.bind || null,
      port: attrs.port || null,
      proto: attrs.proto || null,
      recent_activity: recent
    });
  }

  items.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  const byTag = {};
  for (const it of items) {
    byTag[it.function_tag] = (byTag[it.function_tag] || 0) + 1;
  }

  const summary = {
    map_id: mapId,
    total_surface_items: items.length,
    by_function: byTag,
    high_or_critical: items.filter((i) => ['high', 'critical'].includes(i.severity)).length,
    exposed_admin_protocols: items.filter((i) =>
      ['smb', 'rdp', 'winrm', 'telnet', 'ftp'].includes(i.function_tag)
    ).length,
    persistence_artifacts: items.filter((i) => i.function_tag === 'persistence').length
  };

  const snapId = uuid();
  db.prepare(
    `INSERT INTO attack_surface_snapshots (id, map_id, host_id, captured_at, summary_json, items_json)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(
    snapId,
    mapId,
    null,
    new Date().toISOString(),
    JSON.stringify(summary),
    JSON.stringify(items.slice(0, 500))
  );

  return { summary, items, snapshot_id: snapId };
}

function severityRank(s) {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[s] || 0;
}

export function listRecentActivity(db, { mapId, nodeId, limit = 100, functionTag } = {}) {
  const lim = Math.min(500, Math.max(1, Number(limit) || 100));
  let sql = `SELECT a.*, n.label AS node_label, n.kind AS node_kind, n.severity AS node_severity
             FROM activity_log a
             LEFT JOIN map_nodes n ON n.id = a.node_id
             WHERE 1=1`;
  const params = [];
  if (mapId) {
    sql += ` AND a.map_id = ?`;
    params.push(mapId);
  }
  if (nodeId) {
    sql += ` AND a.node_id = ?`;
    params.push(nodeId);
  }
  if (functionTag) {
    sql += ` AND a.function_tag = ?`;
    params.push(functionTag);
  }
  sql += ` ORDER BY a.ts DESC LIMIT ?`;
  params.push(lim);
  return db.prepare(sql).all(...params).map((a) => ({
    ...a,
    attrs: safeJsonParse(a.attrs_json, {})
  }));
}

/** Active targets: nodes with recent activity, ranked by severity + recency */
export function listActiveTargets(db, mapId, { limit = 80, minSeverity = 'info' } = {}) {
  mapId = mapId || ensureActiveMap(db);
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const minRank = rank[minSeverity] ?? 0;

  const rows = db
    .prepare(
      `SELECT a.node_id,
              MAX(a.ts) AS last_seen,
              COUNT(*) AS activity_count,
              n.label, n.kind, n.severity, n.attrs_json,
              GROUP_CONCAT(DISTINCT a.function_tag) AS function_tags,
              GROUP_CONCAT(DISTINCT a.action) AS actions
       FROM activity_log a
       JOIN map_nodes n ON n.id = a.node_id
       WHERE a.map_id = ?
       GROUP BY a.node_id
       ORDER BY last_seen DESC
       LIMIT 300`
    )
    .all(mapId);

  return rows
    .filter((r) => (rank[r.severity] ?? 0) >= minRank)
    .slice(0, limit)
    .map((r) => {
      const attrs = safeJsonParse(r.attrs_json, {});
      const latest = db
        .prepare(
          `SELECT action, summary, mechanism, function_tag, severity, ts
           FROM activity_log WHERE node_id = ? ORDER BY ts DESC LIMIT 1`
        )
        .get(r.node_id);
      return {
        node_id: r.node_id,
        label: r.label,
        kind: r.kind,
        severity: r.severity,
        activity_count: r.activity_count,
        last_seen: r.last_seen,
        function_tags: String(r.function_tags || '')
          .split(',')
          .filter(Boolean),
        actions: String(r.actions || '')
          .split(',')
          .filter(Boolean),
        latest,
        attrs
      };
    });
}

export function etwStatus(db) {
  const row = db
    .prepare(
      `SELECT raw_json, severity, ts FROM events WHERE type = 'etw.session' ORDER BY ts DESC LIMIT 1`
    )
    .get();
  if (!row) return { seen: false, elevated: null };
  const raw = safeJsonParse(row.raw_json, {});
  return {
    seen: true,
    elevated: !!raw.elevated,
    severity: row.severity,
    ts: row.ts,
    note: raw.note || null
  };
}

/** Backfill activity for existing events (one-shot / on demand) */
export function backfillActivity(db, mapId) {
  mapId = mapId || ensureActiveMap(db);
  const events = db.prepare(`SELECT * FROM events ORDER BY ts DESC LIMIT 1000`).all();
  let count = 0;
  for (const row of events) {
    const event = {
      ...row,
      entities: safeJsonParse(row.entities_json, []),
      edges: safeJsonParse(row.edges_json, []),
      raw: safeJsonParse(row.raw_json, {})
    };
    recordActivityFromEvent(db, mapId, event);
    count += 1;
  }
  const findings = db.prepare(`SELECT * FROM findings ORDER BY created_at DESC LIMIT 100`).all();
  for (const f of findings) {
    try {
      upsertFindingDossier(db, f, mapId);
    } catch {
      /* ignore */
    }
  }
  return { events_processed: count, findings_processed: findings.length, map_id: mapId };
}
