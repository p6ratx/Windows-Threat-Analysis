import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { v4 as uuid } from 'uuid';
import { defaultDbPath } from '../db.js';
import { asOptionalId, asString, HttpError } from '../util/safe.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '../../..');
const ML_TIMEOUT_MS = 120_000;

function assertSafeDbPath(dbPath) {
  const resolved = path.resolve(dbPath);
  const allowed = [
    path.resolve(root, 'data'),
    path.resolve('/data'),
    path.resolve('/app/data')
  ];
  const ok = allowed.some(
    (base) => resolved === base || resolved.startsWith(base + path.sep)
  );
  if (!ok) throw new HttpError(400, 'Database path not allowed', 'unsafe_db');
  return resolved;
}

function resolvePython() {
  const py = process.env.AEGIS_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
  // Only allow bare interpreter names (no path injection via weird env)
  if (py.includes('/') || py.includes('\\') || py.includes('..')) {
    const resolved = path.resolve(py);
    // allow absolute path only if it exists and is a file
    if (!fs.existsSync(resolved)) {
      throw new HttpError(500, 'Python interpreter not found');
    }
    return resolved;
  }
  if (!/^[A-Za-z0-9._+-]+$/.test(py)) {
    throw new HttpError(500, 'Invalid Python interpreter name');
  }
  return py;
}

export function runMlScore(db, { scanRunId, mapId } = {}) {
  const safeRun = asOptionalId(scanRunId, 'scan_run_id');
  const safeMap = asOptionalId(mapId, 'map_id');
  const dbPath = assertSafeDbPath(defaultDbPath());

  return new Promise((resolve) => {
    let py;
    try {
      py = resolvePython();
    } catch {
      return resolve(fallbackScore(db, { scanRunId: safeRun, mapId: safeMap }));
    }

    const args = [
      '-m',
      'aegis_ml',
      'score',
      '--db',
      dbPath,
      ...(safeRun ? ['--run-id', safeRun] : []),
      ...(safeMap ? ['--map-id', safeMap] : [])
    ];

    let child;
    try {
      child = spawn(py, args, {
        cwd: path.join(root, 'ml'),
        env: {
          PATH: process.env.PATH,
          SystemRoot: process.env.SystemRoot,
          PYTHONPATH: [path.join(root, 'ml'), process.env.PYTHONPATH || '']
            .filter(Boolean)
            .join(path.delimiter),
          PYTHONNOUSERSITE: '1'
        },
        windowsHide: true
      });
    } catch {
      return resolve(fallbackScore(db, { scanRunId: safeRun, mapId: safeMap }));
    }

    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const timer = setTimeout(() => {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
      finish(fallbackScore(db, { scanRunId: safeRun, mapId: safeMap, stderr: 'ml_timeout' }));
    }, ML_TIMEOUT_MS);

    child.stdout?.on('data', (d) => {
      stdout += d.toString();
      if (stdout.length > 1_000_000) stdout = stdout.slice(0, 1_000_000);
    });
    child.stderr?.on('data', (d) => {
      stderr += d.toString();
      if (stderr.length > 200_000) stderr = stderr.slice(0, 200_000);
    });
    child.on('error', () => {
      finish(fallbackScore(db, { scanRunId: safeRun, mapId: safeMap }));
    });
    child.on('close', (code) => {
      if (code !== 0) {
        finish(fallbackScore(db, { scanRunId: safeRun, mapId: safeMap, stderr }));
        return;
      }
      try {
        const parsed = JSON.parse(stdout.trim().split('\n').filter(Boolean).pop() || '{}');
        if (!parsed || typeof parsed !== 'object') throw new Error('bad ml output');
        finish({
          ok: !!parsed.ok,
          mode: asString(parsed.mode || 'sklearn', { max: 64 }),
          events_scored: Number(parsed.events_scored) || 0,
          suggested_edges: Number(parsed.suggested_edges) || 0,
          job_id: asString(parsed.job_id || uuid(), { max: 80 }),
          mean_score: Number.isFinite(parsed.mean_score) ? parsed.mean_score : undefined,
          movement: parsed.movement || null
        });
      } catch {
        finish(fallbackScore(db, { scanRunId: safeRun, mapId: safeMap, stderr: stdout || stderr }));
      }
    });
  });
}

function fallbackScore(db, { scanRunId, mapId } = {}) {
  let events;
  try {
    events = scanRunId
      ? db.prepare(`SELECT * FROM events WHERE scan_run_id = ?`).all(scanRunId)
      : db.prepare(`SELECT * FROM events ORDER BY ts DESC LIMIT 200`).all();
  } catch {
    events = [];
  }

  let suggested = 0;
  let activeMap = mapId;
  try {
    activeMap =
      mapId ||
      db.prepare(`SELECT value FROM settings WHERE key = 'active_map_id'`).get()?.value;
  } catch {
    activeMap = mapId;
  }

  if (activeMap) {
    try {
      const hosts = db
        .prepare(`SELECT id FROM map_nodes WHERE map_id = ? AND kind = 'host'`)
        .all(activeMap);
      const findings = db
        .prepare(
          `SELECT id FROM map_nodes WHERE map_id = ? AND kind IN ('finding','port') AND severity IN ('high','critical')`
        )
        .all(activeMap);
      for (const h of hosts) {
        for (const f of findings.slice(0, 5)) {
          const edgeId = `edge:${activeMap}:${h.id}:targets:${f.id}`.slice(0, 240);
          const exists = db.prepare(`SELECT id FROM map_edges WHERE id = ?`).get(edgeId);
          if (!exists) {
            db.prepare(
              `INSERT INTO map_edges (id, map_id, src_id, dst_id, rel, confidence, suggested, attrs_json, created_at)
               VALUES (?, ?, ?, ?, 'targets', 0.55, 1, ?, ?)`
            ).run(
              edgeId,
              activeMap,
              h.id,
              f.id,
              JSON.stringify({ source: 'fallback_ml' }),
              new Date().toISOString()
            );
            suggested += 1;
          }
        }
      }
    } catch (e) {
      console.warn('[aegis] fallback suggest failed', e.message || e);
    }
  }

  const sevWeight = { info: 0.1, low: 0.25, medium: 0.45, high: 0.75, critical: 0.95 };
  for (const e of events) {
    try {
      const score = sevWeight[e.severity] ?? 0.3;
      db.prepare(`UPDATE events SET anomaly_score = ? WHERE id = ?`).run(score, e.id);
    } catch {
      /* ignore */
    }
  }

  try {
    const models = db.prepare(`SELECT id FROM threat_models`).all();
    for (const m of models) {
      const risk = Math.min(0.95, 0.2 + suggested * 0.05 + events.length * 0.002);
      db.prepare(`UPDATE threat_models SET residual_risk = ?, updated_at = ? WHERE id = ?`).run(
        risk,
        new Date().toISOString(),
        m.id
      );
    }
  } catch {
    /* ignore */
  }

  return {
    ok: true,
    mode: 'fallback',
    events_scored: events.length,
    suggested_edges: suggested,
    job_id: uuid()
  };
}
