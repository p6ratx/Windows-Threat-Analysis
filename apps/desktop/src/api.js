const STORAGE_KEY = 'aegis.gatewayUrl';
const TOKEN_KEY = 'aegis.apiToken';

export function getGatewayUrl() {
  return localStorage.getItem(STORAGE_KEY) || 'http://127.0.0.1:8787';
}

/** Only allow http(s) to localhost / private / configured hosts — block javascript: etc. */
export function setGatewayUrl(url) {
  const cleaned = String(url || '').trim().replace(/\/$/, '');
  let parsed;
  try {
    parsed = new URL(cleaned);
  } catch {
    throw new Error('Gateway URL must be a valid http(s) URL');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Gateway URL must use http or https');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Gateway URL must not embed credentials');
  }
  localStorage.setItem(STORAGE_KEY, `${parsed.origin}${parsed.pathname === '/' ? '' : parsed.pathname}`);
}

export function getApiToken() {
  return localStorage.getItem(TOKEN_KEY) || '';
}

export function setApiToken(token) {
  const t = String(token || '').slice(0, 256);
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 30000);
  try {
    const headers = {
      Accept: 'application/json',
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {})
    };
    const token = getApiToken();
    if (token) headers['X-Aegis-Token'] = token;

    const res = await fetch(`${getGatewayUrl()}${path}`, {
      ...options,
      headers,
      signal: controller.signal
    });

    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        detail = body.error || body.code || detail;
      } catch {
        try {
          detail = (await res.text()).slice(0, 200);
        } catch {
          /* ignore */
        }
      }
      throw new Error(detail || `HTTP ${res.status}`);
    }
    if (res.status === 204) return null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
  } catch (e) {
    if (e?.name === 'AbortError') throw new Error('Request timed out');
    throw e;
  } finally {
    clearTimeout(timeout);
  }
}

export const api = {
  health: () => request('/api/health', { timeoutMs: 8000 }),
  activeMap: () => request('/api/maps/active'),
  maps: () => request('/api/maps'),
  createMap: (body) => request('/api/maps', { method: 'POST', body: JSON.stringify(body) }),
  addNode: (mapId, body) =>
    request(`/api/maps/${encodeURIComponent(mapId)}/nodes`, {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  addEdge: (mapId, body) =>
    request(`/api/maps/${encodeURIComponent(mapId)}/edges`, {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  nodeEvidence: (mapId, nodeId) =>
    request(`/api/maps/${encodeURIComponent(mapId)}/evidence/${encodeURIComponent(nodeId)}`),
  nodeDossier: (mapId, nodeId) =>
    request(
      `/api/maps/${encodeURIComponent(mapId)}/dossier?node_id=${encodeURIComponent(nodeId)}`
    ),
  attackSurface: (mapId) =>
    request(mapId ? `/api/attack-surface?map_id=${encodeURIComponent(mapId)}` : '/api/attack-surface'),
  findingDetail: (id) => request(`/api/findings/${encodeURIComponent(id)}`),
  analyzeFinding: (id) =>
    request(`/api/findings/${encodeURIComponent(id)}/analyze`, { method: 'POST', body: '{}' }),
  backfillActivity: () => request('/api/activity/backfill', { method: 'POST', body: '{}' }),
  recentActivity: (params = {}) => {
    const q = new URLSearchParams();
    if (params.map_id) q.set('map_id', params.map_id);
    if (params.node_id) q.set('node_id', params.node_id);
    if (params.limit) q.set('limit', String(params.limit));
    if (params.function_tag) q.set('function_tag', params.function_tag);
    const qs = q.toString();
    return request(`/api/activity${qs ? `?${qs}` : ''}`);
  },
  activityTargets: (params = {}) => {
    const q = new URLSearchParams();
    if (params.map_id) q.set('map_id', params.map_id);
    if (params.limit) q.set('limit', String(params.limit));
    if (params.min_severity) q.set('min_severity', params.min_severity);
    const qs = q.toString();
    return request(`/api/activity/targets${qs ? `?${qs}` : ''}`);
  },
  etwStatus: () => request('/api/etw/status'),
  models: () => request('/api/models'),
  getModel: (id) => request(`/api/models/${encodeURIComponent(id)}`),
  createModel: (body) => request('/api/models', { method: 'POST', body: JSON.stringify(body) }),
  updateModel: (id, body) =>
    request(`/api/models/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) }),
  addAsset: (id, body) =>
    request(`/api/models/${encodeURIComponent(id)}/assets`, {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  addActor: (id, body) =>
    request(`/api/models/${encodeURIComponent(id)}/actors`, {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  addBoundary: (id, body) =>
    request(`/api/models/${encodeURIComponent(id)}/boundaries`, {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  addScenario: (id, body) =>
    request(`/api/models/${encodeURIComponent(id)}/scenarios`, {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  addMitigation: (id, body) =>
    request(`/api/models/${encodeURIComponent(id)}/mitigations`, {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  packages: () => request('/api/packages'),
  createPackage: (body) => request('/api/packages', { method: 'POST', body: JSON.stringify(body) }),
  packageStatus: (id, body) =>
    request(`/api/packages/${encodeURIComponent(id)}/status`, {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  exportPackage: (id) => request(`/api/packages/${encodeURIComponent(id)}/export`),
  events: (limit = 80) => request(`/api/events?limit=${Number(limit) || 80}`),
  findings: () => request('/api/findings'),
  startScan: () => request('/api/scan/start', { method: 'POST', body: '{}' }),
  stopScan: () => request('/api/scan/stop', { method: 'POST', body: '{}' }),
  mlScore: (body = {}) => request('/api/ml/score', { method: 'POST', body: JSON.stringify(body) }),
  mlMovement: (body = {}) => request('/api/ml/movement', { method: 'POST', body: JSON.stringify(body) }),
  latestMovement: () => request('/api/movement?latest=1'),
  movementCampaign: (id) => request(`/api/movement/${encodeURIComponent(id)}`),
  peers: (params = {}) => {
    const q = new URLSearchParams();
    if (params.map_id) q.set('map_id', params.map_id);
    if (params.limit) q.set('limit', String(params.limit));
    if (params.min_c2 != null) q.set('min_c2', String(params.min_c2));
    if (params.process) q.set('process', params.process);
    if (params.host_id) q.set('host_id', params.host_id);
    if (params.tier) q.set('tier', params.tier);
    const qs = q.toString();
    return request(`/api/peers${qs ? `?${qs}` : ''}`);
  },
  c2: (params = {}) => {
    const q = new URLSearchParams();
    if (params.map_id) q.set('map_id', params.map_id);
    if (params.limit) q.set('limit', String(params.limit));
    if (params.host_id) q.set('host_id', params.host_id);
    if (params.tier) q.set('tier', params.tier);
    const qs = q.toString();
    return request(`/api/c2${qs ? `?${qs}` : ''}`);
  },
  attribution: (params = {}) => {
    const q = new URLSearchParams();
    if (params.map_id) q.set('map_id', params.map_id);
    if (params.limit) q.set('limit', String(params.limit));
    if (params.host_id) q.set('host_id', params.host_id);
    const qs = q.toString();
    return request(`/api/attribution${qs ? `?${qs}` : ''}`);
  },
  rebuildPeers: () => request('/api/peers/rebuild', { method: 'POST', body: '{}' }),
  peersDelta: (params = {}) => {
    const q = new URLSearchParams();
    if (params.host_id) q.set('host_id', params.host_id);
    if (params.limit) q.set('limit', String(params.limit));
    const qs = q.toString();
    return request(`/api/peers/delta${qs ? `?${qs}` : ''}`);
  },
  peersCompare: (a, b) =>
    request(`/api/peers/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`),
  rebuildBaselines: () => request('/api/baselines/rebuild', { method: 'POST', body: '{}' }),
  beacons: () => request('/api/c2/beacons'),
  dns: (params = {}) => {
    const q = new URLSearchParams();
    if (params.ip) q.set('ip', params.ip);
    if (params.hostname) q.set('hostname', params.hostname);
    const qs = q.toString();
    return request(`/api/dns${qs ? `?${qs}` : ''}`);
  },
  watches: () => request('/api/watches'),
  alerts: (params = {}) => {
    const q = new URLSearchParams();
    if (params.host_id) q.set('host_id', params.host_id);
    if (params.limit) q.set('limit', String(params.limit));
    const qs = q.toString();
    return request(`/api/alerts${qs ? `?${qs}` : ''}`);
  },
  createWatch: (body) => request('/api/watches', { method: 'POST', body: JSON.stringify(body) }),
  deleteWatch: (id) => request(`/api/watches/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  fleet: () => request('/api/fleet'),
  denoise: () => request('/api/denoise', { method: 'POST', body: '{}' }),
  baselinesMeta: () => request('/api/baselines/meta'),
  scanRuns: () => request('/api/scan/runs')
};
