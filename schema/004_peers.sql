-- Remote peers, C2 destination tracking, and attribution classifications

CREATE TABLE IF NOT EXISTS remote_peers (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  process_name TEXT,
  pid INTEGER,
  local_addr TEXT,
  remote_ip TEXT NOT NULL,
  remote_port INTEGER,
  proto TEXT,
  direction TEXT,
  function_tag TEXT,
  software_class TEXT,
  attribution TEXT,
  attribution_confidence REAL DEFAULT 0.5,
  c2_score REAL DEFAULT 0,
  c2_reasons_json TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  hit_count INTEGER DEFAULT 1,
  attrs_json TEXT,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_remote_peers_map ON remote_peers(map_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_remote_peers_ip ON remote_peers(remote_ip);
CREATE INDEX IF NOT EXISTS idx_remote_peers_c2 ON remote_peers(c2_score DESC);
CREATE INDEX IF NOT EXISTS idx_remote_peers_host ON remote_peers(host_id, process_name);

CREATE TABLE IF NOT EXISTS c2_observations (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  event_id TEXT,
  ts TEXT NOT NULL,
  remote_ip TEXT NOT NULL,
  remote_port INTEGER,
  process_name TEXT,
  pid INTEGER,
  score REAL NOT NULL,
  reasons_json TEXT,
  doing TEXT,
  severity TEXT,
  attrs_json TEXT,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_c2_obs_map ON c2_observations(map_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_c2_obs_ip ON c2_observations(remote_ip);
CREATE INDEX IF NOT EXISTS idx_c2_obs_score ON c2_observations(score DESC);

CREATE TABLE IF NOT EXISTS attribution_records (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  subject_label TEXT,
  class TEXT NOT NULL,
  confidence REAL DEFAULT 0.5,
  rationale TEXT,
  indicators_json TEXT,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_attr_subject ON attribution_records(map_id, subject_kind, subject_id);
CREATE INDEX IF NOT EXISTS idx_attr_class ON attribution_records(map_id, class);
