import { HttpError } from '../util/safe.js';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const buckets = new Map();
let resolvedToken = null;

export function setApiTokenResolver(fn) {
  resolvedToken = fn;
}

function expectedToken() {
  if (process.env.AEGIS_API_TOKEN) return process.env.AEGIS_API_TOKEN;
  if (typeof resolvedToken === 'function') return resolvedToken();
  return null;
}

function clientKey(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) {
    return xf.split(',')[0].trim().slice(0, 64);
  }
  return req.socket?.remoteAddress || 'unknown';
}

/** Simple fixed-window rate limiter (in-memory; per-process). */
export function rateLimit({ windowMs = 60_000, max = 120 } = {}) {
  return (req, res, next) => {
    const key = `${clientKey(req)}:${req.path.split('/').slice(0, 4).join('/')}`;
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || now - b.start > windowMs) {
      b = { start: now, count: 0 };
      buckets.set(key, b);
    }
    b.count += 1;
    const limit = req.path.includes('/events/ingest')
      ? Math.min(max, Number(process.env.AEGIS_INGEST_RATE_LIMIT || 90))
      : max;
    if (b.count > limit) {
      res.setHeader('Retry-After', String(Math.ceil((windowMs - (now - b.start)) / 1000)));
      return next(new HttpError(429, 'Too many requests', 'rate_limited'));
    }
    next();
  };
}

/** Require API token (env or auto-provisioned settings token). */
export function requireApiToken(req, res, next) {
  const expected = expectedToken();
  if (!expected) return next();

  const hdr = req.headers.authorization || '';
  const bearer = hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
  const alt = req.headers['x-aegis-token'];
  const provided = bearer || (typeof alt === 'string' ? alt : '');

  if (!provided || provided.length > 256 || provided !== expected) {
    return next(new HttpError(401, 'Unauthorized', 'unauthorized'));
  }
  next();
}

export function securityHeaders(_req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Aegis-Service', 'gateway');
  next();
}

export function errorHandler(err, _req, res, _next) {
  const status = err.status && Number.isInteger(err.status) ? err.status : 500;
  const code = err.code || (status >= 500 ? 'internal' : 'bad_request');
  const message =
    status >= 500
      ? 'Internal server error'
      : String(err.message || 'Request failed').slice(0, 300);

  if (status >= 500) {
    console.error('[aegis]', err);
  }

  res.status(status).json({ error: message, code });
}

/** Provision a local API token into settings (+ optional file) if none configured. */
export function ensureApiToken(db, { dataDir } = {}) {
  if (process.env.AEGIS_API_TOKEN) {
    return { token: process.env.AEGIS_API_TOKEN, source: 'env', created: false };
  }
  const existing = db.prepare(`SELECT value FROM settings WHERE key = 'api_token'`).get()?.value;
  if (existing) {
    return { token: existing, source: 'settings', created: false };
  }
  const token = crypto.randomBytes(24).toString('base64url');
  db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('api_token', ?)`).run(token);
  try {
    if (dataDir) {
      fs.mkdirSync(dataDir, { recursive: true });
      const tokenPath = path.join(dataDir, 'aegis.token');
      fs.writeFileSync(tokenPath, `${token}\n`, { encoding: 'utf8', mode: 0o600 });
    }
  } catch (e) {
    console.warn('[aegis] could not write aegis.token file', e.message || e);
  }
  console.warn('[aegis] Auto-provisioned API token (stored in settings.api_token / data/aegis.token)');
  console.warn(`[aegis] API token (paste into Settings once): ${token}`);
  return { token, source: 'generated', created: true };
}

setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) {
    if (now - b.start > 120_000) buckets.delete(k);
  }
}, 60_000).unref?.();
