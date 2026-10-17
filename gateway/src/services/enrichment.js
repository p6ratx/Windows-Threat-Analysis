import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { asString, safeJsonParse } from '../util/safe.js';

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

let iocSeeds = null;

function loadIocSeeds() {
  if (iocSeeds) return iocSeeds;
  const p = path.join(__dirname, '../../data/ioc_seeds.json');
  try {
    iocSeeds = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    iocSeeds = { abuse_ports: [], bad_ips: [], bad_cidrs: [] };
  }
  return iocSeeds;
}

export function isDocOrSyntheticIp(ip) {
  const s = String(ip || '');
  if (s.startsWith('203.0.113.') || s.startsWith('198.51.100.') || s.startsWith('192.0.2.')) return true;
  return false;
}

/** Hunt loopback / link-local as C2 only when explicitly enabled (default OFF). */
export function huntLoopbackEnabled() {
  return process.env.AEGIS_HUNT_LOOPBACK === '1';
}

export function isLoopbackIp(ip) {
  const s = String(ip || '')
    .replace(/^\[|\]$/g, '')
    .toLowerCase();
  if (!s) return false;
  if (s === '127.0.0.1' || s === '::1' || s === '0:0:0:0:0:0:0:1') return true;
  if (s.startsWith('127.')) return true;
  if (s.startsWith('::ffff:127.')) return true;
  return false;
}

/** Link-local / IPv6 ULA — never treat as public C2 egress. */
export function isLinkLocalIp(ip) {
  const s = String(ip || '')
    .replace(/^\[|\]$/g, '')
    .toLowerCase();
  if (!s) return false;
  if (s.startsWith('fe80:') || s.startsWith('169.254.')) return true;
  if (s.startsWith('fc') || s.startsWith('fd')) {
    // Unique-local IPv6 (fc00::/7) — private, not public C2
    if (/^f[cd][0-9a-f]{2}:/.test(s)) return true;
  }
  return false;
}

/** Non-routable for threat views: loopback + link-local (unless hunting). */
export function isNonRoutableThreatIp(ip) {
  return isLoopbackIp(ip) || isLinkLocalIp(ip);
}

export function isPrivateIp(ip) {
  const s = String(ip || '').replace(/^\[|\]$/g, '');
  if (isLoopbackIp(s) || isLinkLocalIp(s)) return true;
  if (s.startsWith('10.')) return true;
  if (s.startsWith('192.168.')) return true;
  const m = /^172\.(\d+)\./.exec(s);
  if (m) {
    const n = Number(m[1]);
    if (n >= 16 && n <= 31) return true;
  }
  return false;
}

export const TRUSTED_SOFTWARE_CLASSES = new Set([
  'browser',
  'windows_ui',
  'microsoft_system',
  'microsoft_update',
  'dev_tool',
  'office_collab',
  'security_agent',
  'hypervisor'
]);

export function classifyIpRfc(ip) {
  if (isDocOrSyntheticIp(ip)) return { class: 'documentation', tags: ['rfc5737', 'doc-ip'] };
  if (isLoopbackIp(ip)) return { class: 'loopback', tags: ['loopback'] };
  if (isPrivateIp(ip)) return { class: 'private', tags: ['rfc1918'] };
  return { class: 'public', tags: ['public'] };
}

function ipInCidr(ip, cidr) {
  // Minimal IPv4 CIDR match for offline IOC seeds
  const [base, bitsStr] = String(cidr).split('/');
  const bits = Number(bitsStr);
  if (!Number.isFinite(bits) || bits < 0 || bits > 32) return false;
  const toInt = (x) =>
    String(x)
      .split('.')
      .reduce((a, p) => (a << 8) + (Number(p) & 255), 0) >>> 0;
  try {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (toInt(ip) & mask) === (toInt(base) & mask);
  } catch {
    return false;
  }
}

export function matchLocalIoc({ ip, port } = {}) {
  const seeds = loadIocSeeds();
  const hits = [];
  if (port != null && (seeds.abuse_ports || []).includes(Number(port))) {
    hits.push({ kind: 'abuse_port', value: Number(port) });
  }
  if (ip && (seeds.bad_ips || []).includes(ip)) {
    hits.push({ kind: 'bad_ip', value: ip });
  }
  if (ip) {
    for (const cidr of seeds.bad_cidrs || []) {
      if (ipInCidr(ip, cidr)) hits.push({ kind: 'bad_cidr', value: cidr });
    }
  }
  return hits;
}

function cacheGet(db, subjectKind, subject, provider) {
  const row = db
    .prepare(
      `SELECT * FROM enrichment_cache WHERE subject_kind = ? AND subject = ? AND provider = ?`
    )
    .get(subjectKind, subject, provider);
  if (!row) return null;
  if (row.expires_at && row.expires_at < new Date().toISOString()) return null;
  return { ...safeJsonParse(row.data_json, {}), provider, cached: true };
}

function cacheSet(db, subjectKind, subject, provider, data, ttlSecs = 86400) {
  const id = `${subjectKind}:${subject}:${provider}`.slice(0, 200);
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + ttlSecs * 1000).toISOString();
  db.prepare(
    `INSERT INTO enrichment_cache (id, subject_kind, subject, provider, data_json, expires_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET data_json = excluded.data_json, expires_at = excluded.expires_at, updated_at = excluded.updated_at`
  ).run(id, subjectKind, asString(subject, { max: 240 }), provider, JSON.stringify(data || {}), expires, now);
}

export function enrichIpLocal(db, ip) {
  const cached = cacheGet(db, 'ip', ip, 'local_rfc');
  if (cached) return cached;
  const rfc = classifyIpRfc(ip);
  const ioc = matchLocalIoc({ ip });
  const data = {
    ...rfc,
    ioc_hits: ioc,
    ioc_hit: ioc.length > 0
  };
  cacheSet(db, 'ip', ip, 'local_rfc', data, 7 * 86400);
  return data;
}

export function enrichPortLocal(port) {
  const ioc = matchLocalIoc({ port });
  return { ioc_hits: ioc, ioc_hit: ioc.length > 0, abuse_port: ioc.some((h) => h.kind === 'abuse_port') };
}

/** Best-effort Authenticode lookup; never throws; caches results. */
export async function enrichAuthenticode(db, imagePath) {
  const subject = asString(imagePath || '', { max: 400 });
  if (!subject || process.platform !== 'win32') return null;
  const cached = cacheGet(db, 'process', subject.toLowerCase(), 'authenticode');
  if (cached) return cached;
  try {
    const script = `$p = ${JSON.stringify(subject)}; try { $s = Get-AuthenticodeSignature -FilePath $p -ErrorAction Stop; [pscustomobject]@{Status=[string]$s.Status; Publisher=($s.SignerCertificate.Subject); } | ConvertTo-Json -Compress } catch { '{"Status":"Unknown","Publisher":null}' }`;
    const { stdout } = await execFileAsync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: 4000, windowsHide: true, maxBuffer: 64 * 1024 }
    );
    const parsed = JSON.parse(String(stdout || '{}').trim() || '{}');
    const data = {
      signed: String(parsed.Status || '') === 'Valid',
      status: parsed.Status || 'Unknown',
      publisher: parsed.Publisher || null
    };
    cacheSet(db, 'process', subject.toLowerCase(), 'authenticode', data, 7 * 86400);
    return data;
  } catch {
    const data = { signed: false, status: 'Unavailable', publisher: null };
    cacheSet(db, 'process', subject.toLowerCase(), 'authenticode', data, 3600);
    return data;
  }
}

/** Optional external enrichment; never blocks ingest path when called fire-and-forget. */
export async function enrichOptionalHttp(db, ip) {
  const url = process.env.AEGIS_ENRICH_URL;
  if (!url || !ip) return null;
  const cached = cacheGet(db, 'ip', ip, 'optional_http');
  if (cached) return cached;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), Number(process.env.AEGIS_ENRICH_TIMEOUT_MS || 2500));
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ ip }),
      signal: ctrl.signal
    });
    clearTimeout(t);
    if (!res.ok) return null;
    const body = await res.json();
    const data = {
      asn: body.asn || body.AS || null,
      org: body.org || body.organization || null,
      tags: Array.isArray(body.tags) ? body.tags.slice(0, 20) : []
    };
    cacheSet(db, 'ip', ip, 'optional_http', data, 86400);
    return data;
  } catch {
    return null;
  }
}

export function enrichPeerSync(db, { remote_ip, remote_port, process_path } = {}) {
  const out = { providers: [] };
  if (remote_ip) {
    const rfc = enrichIpLocal(db, remote_ip);
    out.ip = rfc;
    out.providers.push('local_rfc');
    if (rfc.ioc_hit) out.ioc_hit = true;
  }
  if (remote_port != null) {
    out.port = enrichPortLocal(remote_port);
    if (out.port.ioc_hit) out.ioc_hit = true;
  }
  if (process_path) {
    const cached = cacheGet(db, 'process', String(process_path).toLowerCase(), 'authenticode');
    if (cached) {
      out.authenticode = cached;
      out.providers.push('authenticode');
    }
  }
  const httpCached = remote_ip ? cacheGet(db, 'ip', remote_ip, 'optional_http') : null;
  if (httpCached) {
    out.http = httpCached;
    out.providers.push('optional_http');
    if (httpCached.org || httpCached.asn) {
      out.org = httpCached.org || null;
      out.asn = httpCached.asn || null;
    }
  }
  const ptrCached = remote_ip ? cacheGet(db, 'ip', remote_ip, 'ptr') : null;
  if (ptrCached?.hostname) {
    out.ptr = ptrCached.hostname;
    out.providers.push('ptr');
  }
  return out;
}

/** Best-effort reverse DNS (PTR); caches; never throws. Offline-friendly when DNS fails. */
export async function enrichPtr(db, ip) {
  const subject = asString(ip || '', { max: 80 });
  if (!subject || isNonRoutableThreatIp(subject) || isPrivateIp(subject) || isDocOrSyntheticIp(subject)) {
    return null;
  }
  const cached = cacheGet(db, 'ip', subject, 'ptr');
  if (cached) return cached;
  try {
    const dns = await import('dns');
    const promises = dns.promises;
    const ctrlMs = Number(process.env.AEGIS_PTR_TIMEOUT_MS || 1500);
    const hostnames = await Promise.race([
      promises.reverse(subject),
      new Promise((_, reject) => setTimeout(() => reject(new Error('ptr_timeout')), ctrlMs))
    ]);
    const hostname = Array.isArray(hostnames) && hostnames[0] ? String(hostnames[0]).toLowerCase() : null;
    const data = { hostname, hostnames: (hostnames || []).slice(0, 5) };
    cacheSet(db, 'ip', subject, 'ptr', data, 3 * 86400);
    return data;
  } catch {
    cacheSet(db, 'ip', subject, 'ptr', { hostname: null }, 3600);
    return null;
  }
}

/** Compact "why this score" for UI / API. */
export function explainC2Score({ c2Score = 0, reasons = [], softwareClass, enrichment, baselineStatus, tier } = {}) {
  const parts = [];
  const score = Number(c2Score) || 0;
  if (Array.isArray(reasons) && reasons.length) {
    parts.push(...reasons.slice(0, 6));
  }
  if (baselineStatus === 'new') parts.push('new_to_baseline');
  if (baselineStatus === 'rare') parts.push('rare_baseline');
  if (enrichment?.ioc_hit) parts.push('ioc_seed_hit');
  if (enrichment?.authenticode?.signed) {
    parts.push(`signed:${String(enrichment.authenticode.publisher || 'unknown').slice(0, 80)}`);
  } else if (softwareClass === 'unknown_process') {
    parts.push('unsigned_or_unknown_process');
  }
  if (TRUSTED_SOFTWARE_CLASSES.has(softwareClass) && score <= 0) {
    parts.push('trusted_software_suppressed');
  }
  return {
    score,
    tier: tier || null,
    reasons: [...new Set(parts)].slice(0, 10),
    org: enrichment?.org || enrichment?.http?.org || null,
    asn: enrichment?.asn || enrichment?.http?.asn || null,
    publisher: enrichment?.authenticode?.publisher || null,
    ptr: enrichment?.ptr || null
  };
}

export function computeTier({
  c2Score = 0,
  baselineStatus,
  softwareClass,
  enrichment,
  watchConfirmed,
  beaconScore,
  remoteIp
} = {}) {
  // Loopback / link-local never escalate in threat views (unless hunting).
  if (isNonRoutableThreatIp(remoteIp) && !huntLoopbackEnabled()) {
    return 'watch';
  }
  if (watchConfirmed || enrichment?.ioc_hit) {
    return 'confirmed';
  }
  // Strong beacon only confirms on public / non-trusted egress
  if (
    (Number(beaconScore) || 0) >= 0.75 &&
    !TRUSTED_SOFTWARE_CLASSES.has(softwareClass) &&
    !isNonRoutableThreatIp(remoteIp)
  ) {
    return 'confirmed';
  }
  const score = Number(c2Score) || 0;
  if (TRUSTED_SOFTWARE_CLASSES.has(softwareClass) && score < 0.75) {
    return 'watch';
  }
  if (score >= 0.45 || (baselineStatus === 'new' && softwareClass === 'unknown_process' && !isPrivateIp(remoteIp))) {
    return 'candidate';
  }
  return 'watch';
}

/** Shared process classification for gateway-side denoise / re-tiering */
export function classifyProcessName(processName) {
  const p = String(processName || '').toLowerCase();
  const rules = [
    ['browser', ['msedge.exe', 'chrome.exe', 'firefox.exe', 'brave.exe', 'msedgewebview2.exe']],
    [
      'windows_ui',
      [
        'searchapp.exe',
        'searchhost.exe',
        'searchindexer.exe',
        'startmenuexperiencehost.exe',
        'shellexperiencehost.exe',
        'applicationframehost.exe',
        'systemsettings.exe',
        'textinputhost.exe',
        'lockapp.exe',
        'widgets.exe',
        'widgetservice.exe',
        'phoneexperiencehost.exe',
        'gamebar.exe',
        'gamebarftserver.exe',
        'explorer.exe'
      ]
    ],
    [
      'microsoft_system',
      [
        'svchost.exe',
        'lsass.exe',
        'services.exe',
        'runtimebroker.exe',
        'sihost.exe',
        'taskhostw.exe',
        'dwm.exe',
        'spoolsv.exe',
        'conhost.exe',
        'dllhost.exe',
        'powershell.exe',
        'pwsh.exe',
        'cmd.exe',
        'fontdrvhost.exe',
        'wmiprvse.exe',
        'taskmgr.exe'
      ]
    ],
    [
      'microsoft_update',
      ['usoclient.exe', 'wuauclt.exe', 'moagent.exe', 'tiworker.exe', 'trustedinstaller.exe']
    ],
    [
      'dev_tool',
      [
        'cursor.exe',
        'code.exe',
        'node.exe',
        'python.exe',
        'python3',
        'python3.',
        'devenv.exe',
        'lm studio.exe',
        'docker.exe'
      ]
    ],
    [
      'office_collab',
      ['outlook.exe', 'teams.exe', 'ms-teams.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe', 'onedrive.exe']
    ],
    ['security_agent', ['msmpeng.exe', 'sense.exe', 'mssense.exe', 'securityhealthservice.exe']],
    ['hypervisor', ['vmware-authd.exe', 'vmware-hostd.exe', 'vmware-vmx.exe']]
  ];
  for (const [cls, matches] of rules) {
    for (const m of matches) {
      if (p === m || p.includes(m)) return cls;
    }
  }
  if (p.endsWith('.exe')) return 'unknown_process';
  return 'unclassified';
}
