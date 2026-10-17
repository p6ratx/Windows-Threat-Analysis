-- Threat actor movement paths (ML pipeline output)

CREATE TABLE IF NOT EXISTS movement_campaigns (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  title TEXT NOT NULL,
  actor_label TEXT DEFAULT 'Unknown actor',
  confidence REAL DEFAULT 0.5,
  summary TEXT DEFAULT '',
  stages_json TEXT NOT NULL DEFAULT '[]',
  path_node_ids_json TEXT NOT NULL DEFAULT '[]',
  path_edge_ids_json TEXT NOT NULL DEFAULT '[]',
  techniques_json TEXT NOT NULL DEFAULT '[]',
  ml_score REAL DEFAULT 0.0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_movement_map ON movement_campaigns(map_id, created_at);

CREATE TABLE IF NOT EXISTS movement_hops (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  stage TEXT NOT NULL,
  technique TEXT DEFAULT '',
  from_node_id TEXT,
  to_node_id TEXT,
  event_id TEXT,
  summary TEXT DEFAULT '',
  mechanism TEXT DEFAULT '',
  confidence REAL DEFAULT 0.5,
  FOREIGN KEY (campaign_id) REFERENCES movement_campaigns(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_movement_hops ON movement_hops(campaign_id, seq);
