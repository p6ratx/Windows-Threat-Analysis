-- Aegis TI core schema: evidence, maps, models, packages

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL, -- go-net | rust-host | gateway
  host_id TEXT NOT NULL,
  last_seen_at TEXT,
  meta_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'running', -- running | completed | failed
  started_at TEXT NOT NULL,
  finished_at TEXT,
  trigger_source TEXT DEFAULT 'api',
  meta_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  scan_run_id TEXT,
  ts TEXT NOT NULL,
  agent TEXT NOT NULL,
  host_id TEXT NOT NULL,
  type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  entities_json TEXT NOT NULL DEFAULT '[]',
  edges_json TEXT NOT NULL DEFAULT '[]',
  raw_json TEXT NOT NULL DEFAULT '{}',
  anomaly_score REAL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host_id);
CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_run_id);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_run_id TEXT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL DEFAULT 0.5,
  summary TEXT,
  event_ids_json TEXT DEFAULT '[]',
  ml_score REAL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

-- Threat maps
CREATE TABLE IF NOT EXISTS threat_maps (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active', -- active | archived
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS map_nodes (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  kind TEXT NOT NULL, -- host|process|service|port|identity|asset|actor|finding
  label TEXT NOT NULL,
  attrs_json TEXT NOT NULL DEFAULT '{}',
  severity TEXT DEFAULT 'info',
  pinned INTEGER DEFAULT 0,
  x REAL,
  y REAL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_map_nodes_map ON map_nodes(map_id);
CREATE INDEX IF NOT EXISTS idx_map_nodes_kind ON map_nodes(kind);

CREATE TABLE IF NOT EXISTS map_edges (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  src_id TEXT NOT NULL,
  dst_id TEXT NOT NULL,
  rel TEXT NOT NULL, -- spawns|listens|connects|persists|exposes|targets|mitigates|observed_as|suggested
  confidence REAL DEFAULT 1.0,
  suggested INTEGER DEFAULT 0,
  attrs_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE,
  FOREIGN KEY (src_id) REFERENCES map_nodes(id) ON DELETE CASCADE,
  FOREIGN KEY (dst_id) REFERENCES map_nodes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_map_edges_map ON map_edges(map_id);

CREATE TABLE IF NOT EXISTS map_evidence_links (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  node_id TEXT,
  edge_id TEXT,
  event_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE,
  FOREIGN KEY (node_id) REFERENCES map_nodes(id) ON DELETE SET NULL,
  FOREIGN KEY (edge_id) REFERENCES map_edges(id) ON DELETE SET NULL,
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

-- Threat models
CREATE TABLE IF NOT EXISTS threat_models (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  classification TEXT DEFAULT 'internal',
  owner TEXT DEFAULT '',
  scope TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft', -- draft|review|published
  map_id TEXT,
  residual_risk REAL DEFAULT 0.0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS model_assets (
  id TEXT PRIMARY KEY,
  model_id TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'system', -- system|datastore|identity|zone
  description TEXT DEFAULT '',
  map_node_id TEXT,
  attrs_json TEXT DEFAULT '{}',
  FOREIGN KEY (model_id) REFERENCES threat_models(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS model_actors (
  id TEXT PRIMARY KEY,
  model_id TEXT NOT NULL,
  name TEXT NOT NULL,
  intent TEXT DEFAULT '',
  capability TEXT DEFAULT 'medium',
  access TEXT DEFAULT '',
  map_node_id TEXT,
  attrs_json TEXT DEFAULT '{}',
  FOREIGN KEY (model_id) REFERENCES threat_models(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS model_boundaries (
  id TEXT PRIMARY KEY,
  model_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  attrs_json TEXT DEFAULT '{}',
  FOREIGN KEY (model_id) REFERENCES threat_models(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS model_scenarios (
  id TEXT PRIMARY KEY,
  model_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  stride_tags_json TEXT DEFAULT '[]', -- spoofing,tampering,repudiation,info_disclosure,dos,elevation
  steps_json TEXT DEFAULT '[]',
  map_edge_ids_json TEXT DEFAULT '[]',
  event_ids_json TEXT DEFAULT '[]',
  severity TEXT DEFAULT 'medium',
  likelihood REAL DEFAULT 0.5,
  FOREIGN KEY (model_id) REFERENCES threat_models(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS model_mitigations (
  id TEXT PRIMARY KEY,
  model_id TEXT NOT NULL,
  scenario_id TEXT,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  status TEXT DEFAULT 'proposed', -- proposed|implemented|accepted_risk
  residual_risk REAL DEFAULT 0.0,
  map_node_id TEXT,
  FOREIGN KEY (model_id) REFERENCES threat_models(id) ON DELETE CASCADE,
  FOREIGN KEY (scenario_id) REFERENCES model_scenarios(id) ON DELETE SET NULL
);

-- Intel packages
CREATE TABLE IF NOT EXISTS intel_packages (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  model_id TEXT,
  map_id TEXT,
  executive_summary TEXT DEFAULT '',
  severity TEXT DEFAULT 'medium',
  confidence REAL DEFAULT 0.5,
  recommended_actions_json TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'draft', -- draft|approved|distributed
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (model_id) REFERENCES threat_models(id) ON DELETE SET NULL,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS package_items (
  id TEXT PRIMARY KEY,
  package_id TEXT NOT NULL,
  kind TEXT NOT NULL, -- finding|scenario|node|edge|event
  ref_id TEXT NOT NULL,
  note TEXT DEFAULT '',
  FOREIGN KEY (package_id) REFERENCES intel_packages(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS distribution_log (
  id TEXT PRIMARY KEY,
  package_id TEXT NOT NULL,
  channel TEXT NOT NULL, -- official|internal|other
  note TEXT DEFAULT '',
  distributed_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (package_id) REFERENCES intel_packages(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('active_map_id', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('gateway_mode', 'local');
INSERT OR IGNORE INTO settings (key, value) VALUES ('host_id', 'local-host');
-- Bootstrapping uses local-host as a placeholder only; gateway boot replaces it with os.hostname().
