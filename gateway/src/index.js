import http from 'http';
import express from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { openDb, migrate, ensureActiveMap, defaultDbPath } from './db.js';
import { mapsRouter } from './routes/maps.js';
import { modelsRouter } from './routes/models.js';
import { packagesRouter } from './routes/packages.js';
import { eventsRouter } from './routes/events.js';
import { opsRouter } from './routes/ops.js';
import { CollectorSupervisor } from './services/collectors.js';
import {
  rateLimit,
  requireApiToken,
  securityHeaders,
  errorHandler,
  ensureApiToken,
  setApiTokenResolver
} from './middleware/security.js';
import { HttpError, asString } from './util/safe.js';
import { denoiseThreatTables } from './services/denoise.js';
import path from 'path';
import os from 'os';

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '0.0.0.0';

if (!Number.isFinite(PORT) || PORT < 1 || PORT > 65535) {
  console.error('Invalid PORT');
  process.exit(1);
}

const db = openDb(defaultDbPath());
migrate(db);
const tokenInfo = ensureApiToken(db, { dataDir: path.dirname(defaultDbPath()) });
setApiTokenResolver(() => {
  if (process.env.AEGIS_API_TOKEN) return process.env.AEGIS_API_TOKEN;
  return db.prepare(`SELECT value FROM settings WHERE key = 'api_token'`).get()?.value || null;
});
{
  const desired =
    asString(process.env.HOST_ID || process.env.AEGIS_HOST_ID || os.hostname() || '', { max: 128 }) ||
    'local-host';
  try {
    const existing = db.prepare(`SELECT value FROM settings WHERE key = 'host_id'`).get()?.value;
    if (!existing || ['local-host', 'test-host', 'smoke-host', 'docker-host'].includes(existing)) {
      db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('host_id', ?)`).run(desired);
      console.log(`[aegis] host_id set to ${desired}`);
    } else if (process.env.HOST_ID || process.env.AEGIS_HOST_ID) {
      db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('host_id', ?)`).run(desired);
    }
  } catch (e) {
    console.warn('[aegis] host_id setting skipped', e.message || e);
  }
}
ensureActiveMap(db);

// Boot denoise: purge sticky loopback / trusted HTTPS false positives from prior versions
try {
  const cleaned = denoiseThreatTables(db, ensureActiveMap(db));
  if (Object.values(cleaned).some((v) => typeof v === 'number' && v > 0)) {
    console.log('[aegis] boot denoise', cleaned);
  }
} catch (e) {
  console.warn('[aegis] boot denoise skipped', e.message || e);
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);

const corsOrigins = (process.env.AEGIS_CORS_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      // Allow non-browser / same-origin tools (no Origin header)
      if (!origin) return cb(null, true);
      if (corsOrigins.length === 0) {
        // Dev default: localhost / tauri / 127.0.0.1 only
        try {
          const u = new URL(origin);
          const ok =
            ['localhost', '127.0.0.1'].includes(u.hostname) ||
            u.protocol === 'tauri:' ||
            origin.startsWith('http://localhost:') ||
            origin.startsWith('http://127.0.0.1:');
          return cb(null, ok);
        } catch {
          return cb(null, false);
        }
      }
      return cb(null, corsOrigins.includes(origin));
    },
    maxAge: 600
  })
);

app.use(securityHeaders);
app.use(express.json({ limit: '512kb', strict: true }));
app.use(rateLimit({ windowMs: 60_000, max: Number(process.env.AEGIS_RATE_LIMIT || 120) }));

// Health is public (for docker healthchecks); everything else requires token
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'aegis-ti-gateway',
    db: defaultDbPath(),
    mode: db.prepare(`SELECT value FROM settings WHERE key = 'gateway_mode'`).get()?.value || 'local',
    active_map_id:
      db.prepare(`SELECT value FROM settings WHERE key = 'active_map_id'`).get()?.value || null,
    auth_required: true,
    token_source: tokenInfo.source
  });
});

app.use('/api', requireApiToken);

const server = http.createServer(app);
const wss = new WebSocketServer({
  server,
  path: '/ws',
  maxPayload: 64 * 1024,
  clientTracking: true
});

function broadcast(msg) {
  let data;
  try {
    data = JSON.stringify(msg);
  } catch {
    return;
  }
  if (data.length > 256_000) return;
  for (const client of wss.clients) {
    if (client.readyState === 1) {
      try {
        client.send(data);
      } catch {
        /* ignore broken sockets */
      }
    }
  }
}

const supervisor = new CollectorSupervisor(db, { broadcast });

app.use('/api/maps', mapsRouter(db));
app.use('/api/models', modelsRouter(db));
app.use('/api/packages', packagesRouter(db));
app.use('/api/events', eventsRouter(db));
app.use('/api', opsRouter(db, supervisor));

app.use((_req, _res, next) => next(new HttpError(404, 'Not found', 'not_found')));
app.use(errorHandler);

wss.on('connection', (ws, req) => {
  const expected =
    process.env.AEGIS_API_TOKEN ||
    db.prepare(`SELECT value FROM settings WHERE key = 'api_token'`).get()?.value;
  if (expected) {
    try {
      const url = new URL(req.url || '', 'http://localhost');
      const token = url.searchParams.get('token') || '';
      if (token !== expected) {
        ws.close(1008, 'unauthorized');
        return;
      }
    } catch {
      ws.close(1008, 'unauthorized');
      return;
    }
  }

  ws.send(JSON.stringify({ type: 'hello', service: 'aegis-ti' }));
  ws.on('message', () => {
    /* intentionally no-op — prevent command injection over WS */
  });
  ws.on('error', () => {
    /* ignore */
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Aegis TI gateway listening on http://${HOST}:${PORT}`);
  console.log(`[aegis] API auth required (token source: ${tokenInfo.source})`);
});

function shutdown(signal) {
  console.log(`[aegis] ${signal} received, shutting down`);
  try {
    supervisor.stopScan();
  } catch {
    /* ignore */
  }
  wss.close();
  server.close(() => {
    try {
      db.close();
    } catch {
      /* ignore */
    }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref?.();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', (err) => {
  console.error('[aegis] uncaughtException', err);
});
process.on('unhandledRejection', (err) => {
  console.error('[aegis] unhandledRejection', err);
});
