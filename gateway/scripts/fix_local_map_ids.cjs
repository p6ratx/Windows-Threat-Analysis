/**
 * Rename map_nodes whose id still embeds local-host → real hostname.
 * Merges into an existing node for the same host when present.
 */
const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');

const db = new Database(path.join(__dirname, '../../data/aegis.db'));
const realHost = os.hostname() || 'local-host';
const counts = { renamed: 0, merged: 0, edges: 0, links: 0, skipped: 0 };

db.transaction(() => {
  const nodes = db
    .prepare(`SELECT * FROM map_nodes WHERE id LIKE '%local-host%'`)
    .all();

  for (const n of nodes) {
    const newId = n.id.split('local-host').join(realHost);
    if (newId === n.id) {
      counts.skipped += 1;
      continue;
    }

    const existing = db.prepare(`SELECT id FROM map_nodes WHERE id = ?`).get(newId);
    if (existing) {
      const e1 = db.prepare(`UPDATE map_edges SET src_id = ? WHERE src_id = ?`).run(newId, n.id);
      const e2 = db.prepare(`UPDATE map_edges SET dst_id = ? WHERE dst_id = ?`).run(newId, n.id);
      const l = db.prepare(`UPDATE map_evidence_links SET node_id = ? WHERE node_id = ?`).run(newId, n.id);
      counts.edges += (e1.changes || 0) + (e2.changes || 0);
      counts.links += l.changes || 0;
      db.prepare(`DELETE FROM map_nodes WHERE id = ?`).run(n.id);
      counts.merged += 1;
    } else {
      db.prepare(
        `INSERT INTO map_nodes (id, map_id, kind, label, attrs_json, severity, pinned, x, y, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        newId,
        n.map_id,
        n.kind,
        n.label === 'local-host' ? realHost : n.label,
        String(n.attrs_json || '').split('local-host').join(realHost),
        n.severity,
        n.pinned,
        n.x,
        n.y,
        n.created_at,
        n.updated_at
      );
      const e1 = db.prepare(`UPDATE map_edges SET src_id = ? WHERE src_id = ?`).run(newId, n.id);
      const e2 = db.prepare(`UPDATE map_edges SET dst_id = ? WHERE dst_id = ?`).run(newId, n.id);
      const l = db.prepare(`UPDATE map_evidence_links SET node_id = ? WHERE node_id = ?`).run(newId, n.id);
      counts.edges += (e1.changes || 0) + (e2.changes || 0);
      counts.links += l.changes || 0;
      db.prepare(`DELETE FROM map_nodes WHERE id = ?`).run(n.id);
      counts.renamed += 1;
    }
  }

  db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('host_id', ?)`).run(realHost);
})();

console.log(JSON.stringify({ realHost, counts }, null, 2));
db.close();
