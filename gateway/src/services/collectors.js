import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';
import readline from 'readline';
import { v4 as uuid } from 'uuid';
import { ingestEvent } from './evidence.js';
import { postScanAnalyze } from './postScan.js';
import { ensureActiveMap } from '../db.js';
import { HttpError, asString, AGENTS } from '../util/safe.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '../../..');
const LINE_MAX = 256_000;
const AGENT_TIMEOUT_MS = 120_000;

export class CollectorSupervisor {
  constructor(db, { broadcast } = {}) {
    this.db = db;
    this.broadcast = broadcast || (() => {});
    this.procs = new Map();
    this.scanRunId = null;
    this._pollTimer = null;
    this.startPeerPoller();
  }

  binPath(name) {
    const known = ['go-net', 'rust-host', 'rust-etw'];
    if (!known.includes(name)) {
      throw new HttpError(400, 'Unknown agent');
    }
    const envMap = {
      'go-net': 'AEGIS_GO_NET_BIN',
      'rust-host': 'AEGIS_RUST_HOST_BIN',
      'rust-etw': 'AEGIS_RUST_ETW_BIN'
    };
    const envKey = envMap[name];
    const candidate = process.env[envKey]
      ? path.resolve(process.env[envKey])
      : path.join(root, 'bin', process.platform === 'win32' ? `${name}.exe` : name);

    // Prevent path traversal / arbitrary binary execution outside allowed roots
    const allowedRoots = [
      path.join(root, 'bin'),
      path.join(root, 'collectors'),
      path.join('/app', 'bin')
    ].map((p) => path.resolve(p));

    const ok = allowedRoots.some(
      (base) => candidate === base || candidate.startsWith(base + path.sep)
    );
    if (!ok) {
      throw new HttpError(400, 'Collector binary path not allowed', 'unsafe_bin');
    }
    if (!fs.existsSync(candidate)) {
      const err = new Error(`Binary not found: ${name}`);
      err.code = 'ENOENT';
      throw err;
    }
    return candidate;
  }

  async startScan({ agents = ['go-net', 'rust-host', 'rust-etw'] } = {}) {
    if (this.scanRunId) {
      throw new HttpError(409, 'Scan already running', 'scan_busy');
    }
    const list = Array.isArray(agents) ? agents.slice(0, 6) : ['go-net', 'rust-host', 'rust-etw'];
    const filtered = list.filter((a) => ['go-net', 'rust-host', 'rust-etw'].includes(a));
    if (!filtered.length) throw new HttpError(400, 'No valid agents requested');

    // ETW sessions need more time than a quick netstat snapshot
    this._agentTimeoutMs = filtered.includes('rust-etw') ? 150_000 : AGENT_TIMEOUT_MS;

    const id = uuid();
    this.scanRunId = id;
    this.db
      .prepare(
        `INSERT INTO scan_runs (id, status, started_at, trigger_source) VALUES (?, 'running', ?, 'api')`
      )
      .run(id, new Date().toISOString());

    const started = [];
    for (const agent of filtered) {
      try {
        await this.spawnAgent(agent, id);
        started.push(agent);
      } catch (err) {
        this.broadcast({
          type: 'scan.error',
          agent,
          error: asString(err.message || err, { max: 200 })
        });
      }
    }

    if (started.length === 0) {
      if (process.env.AEGIS_ALLOW_SYNTHETIC === '1') {
        this.runSyntheticScan(id);
        return { scan_run_id: id, agents: started, synthetic: true };
      }
      this.scanRunId = null;
      try {
        this.db
          .prepare(`UPDATE scan_runs SET status = 'failed', finished_at = ?, meta_json = ? WHERE id = ?`)
          .run(
            new Date().toISOString(),
            JSON.stringify({ error: 'no_collectors', note: 'Install bin/go-net.exe (and friends); synthetic scan disabled' }),
            id
          );
      } catch {
        /* ignore */
      }
      throw new HttpError(
        503,
        'No collector binaries available (synthetic demo disabled). Build collectors into bin/.',
        'no_collectors'
      );
    }

    return { scan_run_id: id, agents: started, synthetic: false };
  }

  spawnAgent(agent, scanRunId) {
    return new Promise((resolve, reject) => {
      let bin;
      try {
        bin = this.binPath(agent);
      } catch (e) {
        return reject(e);
      }

      const child = spawn(bin, ['--once', '--jsonl'], {
        env: {
          PATH: process.env.PATH,
          SystemRoot: process.env.SystemRoot,
          AEGIS_HOST_ID: this.hostId(),
          AEGIS_SCAN_RUN_ID: scanRunId,
          ...(process.env.AEGIS_ALLOW_SYNTHETIC === '1'
            ? { AEGIS_ALLOW_SYNTHETIC: '1' }
            : {})
        },
        windowsHide: true
      });

      this.procs.set(agent, child);
      let settled = false;
      const timer = setTimeout(() => {
        try {
          child.kill();
        } catch {
          /* ignore */
        }
      }, this._agentTimeoutMs || AGENT_TIMEOUT_MS);

      child.on('error', (err) => {
        clearTimeout(timer);
        this.procs.delete(agent);
        if (!settled) {
          settled = true;
          reject(err);
        }
      });

      if (child.stdout) {
        child.stdout.setEncoding('utf8');
        const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
        rl.on('line', (line) => {
          if (!line || line.length > LINE_MAX) return;
          try {
            const evt = JSON.parse(line);
            if (!evt || typeof evt !== 'object') return;
            const saved = ingestEvent(this.db, evt, { scanRunId });
            if (!saved) return;
            this.broadcast({ type: 'event', event: { id: saved.id, type: saved.type, severity: saved.severity } });
          } catch (e) {
            this.broadcast({
              type: 'parse.error',
              agent,
              message: asString(e.message || 'parse error', { max: 120 })
            });
          }
        });
      }

      child.stderr?.on('data', (buf) => {
        this.broadcast({
          type: 'agent.log',
          agent,
          message: asString(buf.toString(), { max: 400 })
        });
      });

      child.on('exit', () => {
        clearTimeout(timer);
        this.procs.delete(agent);
        if (!settled) {
          settled = true;
          resolve();
        }
        this.maybeFinishScan();
      });

      setTimeout(() => {
        if (!settled && this.procs.has(agent)) {
          settled = true;
          resolve();
        }
      }, 250);
    });
  }

  maybeFinishScan() {
    if (!this.scanRunId) return;
    if (this.procs.size > 0) return;
    const id = this.scanRunId;
    this.scanRunId = null;
    try {
      this.db
        .prepare(`UPDATE scan_runs SET status = 'completed', finished_at = ? WHERE id = ?`)
        .run(new Date().toISOString(), id);
    } catch (e) {
      console.error('[aegis] finish scan', e.message || e);
    }
    try {
      const analysis = postScanAnalyze(this.db, {
        mapId: ensureActiveMap(this.db),
        scanRunId: id,
        hostId: this.hostId()
      });
      this.broadcast({ type: 'scan.analyzed', scan_run_id: id, analysis });
    } catch (e) {
      console.error('[aegis] postScanAnalyze', e.message || e);
    }
    this.broadcast({ type: 'scan.completed', scan_run_id: id });
  }

  startPeerPoller() {
    const ms = Number(process.env.AEGIS_PEER_POLL_MS ?? 90000);
    if (!Number.isFinite(ms) || ms <= 0) {
      console.log('[aegis] peer poller disabled (AEGIS_PEER_POLL_MS<=0)');
      return;
    }
    if (this._pollTimer) clearInterval(this._pollTimer);
    this._pollTimer = setInterval(() => {
      this.runPeerPoll().catch((e) => console.error('[aegis] peer poll', e.message || e));
    }, Math.max(15000, ms));
    this._pollTimer.unref?.();
    console.log(`[aegis] peer poller every ${Math.max(15000, ms)}ms`);
  }

  async runPeerPoll() {
    if (this.scanRunId || this.procs.size > 0) return;
    try {
      this.binPath('go-net');
    } catch {
      return;
    }
    const id = uuid();
    this.scanRunId = id;
    this.db
      .prepare(
        `INSERT INTO scan_runs (id, status, started_at, trigger_source, meta_json) VALUES (?, 'running', ?, 'poll', ?)`
      )
      .run(id, new Date().toISOString(), JSON.stringify({ kind: 'poll', agents: ['go-net'] }));
    try {
      await this.spawnAgent('go-net', id);
    } catch (e) {
      this.scanRunId = null;
      try {
        this.db
          .prepare(`UPDATE scan_runs SET status = 'failed', finished_at = ? WHERE id = ?`)
          .run(new Date().toISOString(), id);
      } catch {
        /* ignore */
      }
      throw e;
    }
  }

  stopScan() {
    for (const [, child] of this.procs) {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
    }
    this.procs.clear();
    if (this.scanRunId) {
      const id = this.scanRunId;
      this.scanRunId = null;
      try {
        this.db
          .prepare(`UPDATE scan_runs SET status = 'failed', finished_at = ? WHERE id = ?`)
          .run(new Date().toISOString(), id);
      } catch {
        /* ignore */
      }
      this.broadcast({ type: 'scan.stopped', scan_run_id: id });
    }
  }

  hostId() {
    try {
      const fromDb = this.db.prepare(`SELECT value FROM settings WHERE key = 'host_id'`).get()?.value;
      if (fromDb && !['local-host', 'test-host', 'smoke-host', 'docker-host'].includes(fromDb)) {
        return fromDb;
      }
    } catch {
      /* ignore */
    }
    return (
      process.env.AEGIS_HOST_ID ||
      process.env.HOST_ID ||
      os.hostname() ||
      'local-host'
    );
  }

  runSyntheticScan(scanRunId) {
    const host = this.hostId();
    const now = new Date().toISOString();
    const samples = [
      {
        ts: now,
        agent: 'go-net',
        host_id: host,
        type: 'net.port.listen',
        severity: 'medium',
        entities: [
          { kind: 'host', id: host, label: host },
          {
            kind: 'port',
            id: `${host}:445`,
            label: 'TCP 445',
            attrs: { port: 445, proto: 'tcp', bind: '0.0.0.0' }
          },
          { kind: 'process', id: 'pid:4', label: 'System', attrs: { pid: 4 } }
        ],
        edges: [
          { src: 'pid:4', dst: `${host}:445`, rel: 'listens' },
          { src: host, dst: `${host}:445`, rel: 'exposes' }
        ],
        raw: { note: 'synthetic SMB exposure signal' }
      },
      {
        ts: now,
        agent: 'go-net',
        host_id: host,
        type: 'net.misconfig',
        severity: 'high',
        entities: [
          { kind: 'host', id: host, label: host },
          {
            kind: 'port',
            id: `${host}:3389`,
            label: 'TCP 3389 RDP',
            attrs: { port: 3389, proto: 'tcp', bind: '0.0.0.0' }
          }
        ],
        edges: [{ src: host, dst: `${host}:3389`, rel: 'exposes' }],
        raw: { heuristic: 'rdp_exposed' }
      },
      {
        ts: now,
        agent: 'rust-host',
        host_id: host,
        type: 'host.persistence',
        severity: 'high',
        entities: [
          { kind: 'host', id: host, label: host },
          {
            kind: 'finding',
            id: 'runkey:suspicious',
            label: 'HKCU Run anomaly',
            attrs: { key: 'Run' }
          }
        ],
        edges: [{ src: host, dst: 'runkey:suspicious', rel: 'persists' }],
        raw: { source: 'registry_run' }
      }
    ];

    for (const s of samples) {
      try {
        const saved = ingestEvent(this.db, s, { scanRunId });
        if (!saved) continue;
        this.broadcast({ type: 'event', event: { id: saved.id, type: saved.type, severity: saved.severity } });
      } catch (e) {
        this.broadcast({ type: 'scan.error', error: asString(e.message || e, { max: 160 }) });
      }
    }
    try {
      this.db
        .prepare(`UPDATE scan_runs SET status = 'completed', finished_at = ? WHERE id = ?`)
        .run(new Date().toISOString(), scanRunId);
    } catch {
      /* ignore */
    }
    this.scanRunId = null;
    this.broadcast({ type: 'scan.completed', scan_run_id: scanRunId, synthetic: true });
  }
}

// silence unused import lint in some setups
void AGENTS;
