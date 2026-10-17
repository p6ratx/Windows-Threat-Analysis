-- Activity tracking & finding dossiers

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  map_id TEXT,
  node_id TEXT,
  event_id TEXT,
  host_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  action TEXT NOT NULL,          -- listens|connects|spawns|persists|exposes|runs|binds|queries
  summary TEXT NOT NULL,
  mechanism TEXT DEFAULT '',     -- how: API, bind addr, registry path, etc.
  function_tag TEXT DEFAULT '',  -- smb|rdp|rpc|dns|auth|shell|persistence|unknown
  severity TEXT DEFAULT 'info',
  attrs_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE SET NULL,
  FOREIGN KEY (node_id) REFERENCES map_nodes(id) ON DELETE SET NULL,
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_node ON activity_log(node_id, ts);
CREATE INDEX IF NOT EXISTS idx_activity_host ON activity_log(host_id, ts);
CREATE INDEX IF NOT EXISTS idx_activity_map ON activity_log(map_id, ts);
CREATE INDEX IF NOT EXISTS idx_activity_fn ON activity_log(function_tag);

CREATE TABLE IF NOT EXISTS finding_dossiers (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL UNIQUE,
  map_node_id TEXT,
  function_summary TEXT DEFAULT '',
  mechanism_summary TEXT DEFAULT '',
  attack_surface_json TEXT DEFAULT '[]',
  related_node_ids_json TEXT DEFAULT '[]',
  activity_count INTEGER DEFAULT 0,
  risk_notes TEXT DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_surface_snapshots (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  host_id TEXT,
  captured_at TEXT NOT NULL,
  summary_json TEXT NOT NULL DEFAULT '{}',
  items_json TEXT NOT NULL DEFAULT '[]',
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_surface_map ON attack_surface_snapshots(map_id, captured_at);
