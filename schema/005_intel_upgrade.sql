-- Aegis TI intel upgrade: baselines, beacons, DNS join, enrichment, watches, fleet helpers

CREATE TABLE IF NOT EXISTS peer_observations (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  scan_run_id TEXT,
  host_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  process_name TEXT,
  pid INTEGER,
  remote_ip TEXT NOT NULL,
  remote_port INTEGER,
  c2_score REAL DEFAULT 0,
  software_class TEXT,
  direction TEXT,
  function_tag TEXT,
  attrs_json TEXT,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_peer_obs_map_ts ON peer_observations(map_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_peer_obs_scan ON peer_observations(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_peer_obs_key ON peer_observations(map_id, host_id, process_name, remote_ip, remote_port);
CREATE INDEX IF NOT EXISTS idx_peer_obs_host_ip ON peer_observations(host_id, remote_ip, ts);

CREATE TABLE IF NOT EXISTS peer_baselines (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  process_name TEXT NOT NULL,
  remote_ip TEXT NOT NULL,
  remote_port INTEGER,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  sightings INTEGER DEFAULT 1,
  distinct_scans INTEGER DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'new', -- baseline | new | rare
  attrs_json TEXT,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_base_key
  ON peer_baselines(map_id, host_id, process_name, remote_ip, IFNULL(remote_port, -1));
CREATE INDEX IF NOT EXISTS idx_peer_base_status ON peer_baselines(map_id, status);

CREATE TABLE IF NOT EXISTS beacon_candidates (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  process_name TEXT,
  remote_ip TEXT NOT NULL,
  remote_port INTEGER,
  sightings INTEGER DEFAULT 0,
  interval_mean_secs REAL,
  interval_jitter_secs REAL,
  score REAL DEFAULT 0,
  reasons_json TEXT,
  tier TEXT DEFAULT 'watch',
  first_seen TEXT,
  last_seen TEXT,
  updated_at TEXT NOT NULL,
  attrs_json TEXT,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_beacon_key
  ON beacon_candidates(map_id, host_id, IFNULL(process_name, ''), remote_ip, IFNULL(remote_port, -1));
CREATE INDEX IF NOT EXISTS idx_beacon_score ON beacon_candidates(map_id, score DESC);

CREATE TABLE IF NOT EXISTS dns_queries (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  scan_run_id TEXT,
  event_id TEXT,
  host_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  hostname TEXT NOT NULL,
  pid INTEGER,
  process_name TEXT,
  attrs_json TEXT,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_dns_map_ts ON dns_queries(map_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_host ON dns_queries(hostname);
CREATE INDEX IF NOT EXISTS idx_dns_pid ON dns_queries(host_id, pid, ts);

CREATE TABLE IF NOT EXISTS ip_resolutions (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  remote_ip TEXT NOT NULL,
  process_name TEXT,
  pid INTEGER,
  confidence REAL DEFAULT 0.5,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  hit_count INTEGER DEFAULT 1,
  attrs_json TEXT,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_res_key
  ON ip_resolutions(map_id, host_id, hostname, remote_ip, IFNULL(pid, -1));
CREATE INDEX IF NOT EXISTS idx_ip_res_ip ON ip_resolutions(remote_ip);

CREATE TABLE IF NOT EXISTS enrichment_cache (
  id TEXT PRIMARY KEY,
  subject_kind TEXT NOT NULL, -- ip | hostname | process
  subject TEXT NOT NULL,
  provider TEXT NOT NULL,
  data_json TEXT NOT NULL DEFAULT '{}',
  expires_at TEXT,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_enrich_subject
  ON enrichment_cache(subject_kind, subject, provider);

CREATE TABLE IF NOT EXISTS analyst_watches (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  kind TEXT NOT NULL, -- ip | process | peer
  value TEXT NOT NULL,
  note TEXT,
  confirmed INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_watch_key ON analyst_watches(map_id, kind, value);
CREATE INDEX IF NOT EXISTS idx_watch_map ON analyst_watches(map_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS scan_peer_summaries (
  id TEXT PRIMARY KEY,
  map_id TEXT NOT NULL,
  scan_run_id TEXT NOT NULL,
  host_id TEXT,
  ts TEXT NOT NULL,
  peer_count INTEGER DEFAULT 0,
  unique_ips INTEGER DEFAULT 0,
  candidate_count INTEGER DEFAULT 0,
  max_c2 REAL DEFAULT 0,
  top_ips_json TEXT,
  attrs_json TEXT,
  FOREIGN KEY (map_id) REFERENCES threat_maps(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_peer_sum
  ON scan_peer_summaries(map_id, scan_run_id, IFNULL(host_id, ''));
CREATE INDEX IF NOT EXISTS idx_scan_peer_sum_ts ON scan_peer_summaries(map_id, ts DESC);
