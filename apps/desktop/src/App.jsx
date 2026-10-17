import { useEffect, useMemo, useState, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { api, getGatewayUrl, setGatewayUrl, getApiToken, setApiToken } from './api.js';

const VIEWS = ['maps', 'activity', 'movement', 'peers', 'fleet', 'surface', 'models', 'packages', 'evidence', 'settings'];
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export default function App() {
  const [view, setView] = useState('maps');
  const [health, setHealth] = useState(null);
  const [error, setError] = useState('');

  async function refreshHealth() {
    try {
      setHealth(await api.health());
      setError('');
    } catch (e) {
      setHealth(null);
      setError(String(e.message || e));
    }
  }

  useEffect(() => {
    refreshHealth();
    const t = setInterval(refreshHealth, 8000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">Aegis <span>TI</span></div>
        <nav className="nav">
          {VIEWS.map((v) => (
            <button key={v} className={view === v ? 'active' : ''} onClick={() => setView(v)}>
              {v[0].toUpperCase() + v.slice(1)}
            </button>
          ))}
        </nav>
        <div className={`status-pill ${health?.ok ? 'ok' : ''}`}>
          {health?.ok ? `Gateway · ${health.mode || 'local'}` : 'Gateway offline'}
        </div>
      </header>
      <main className="main">
        {error && view !== 'settings' ? <div className="panel"><div className="error">{error}</div></div> : null}
        {view === 'maps' && <MapsView onError={setError} />}
        {view === 'activity' && <ActivityView onError={setError} />}
        {view === 'movement' && <MovementView onError={setError} />}
        {view === 'peers' && <PeersView onError={setError} />}
        {view === 'fleet' && <FleetView onError={setError} />}
        {view === 'surface' && <SurfaceView onError={setError} />}
        {view === 'models' && <ModelsView onError={setError} />}
        {view === 'packages' && <PackagesView onError={setError} />}
        {view === 'evidence' && <EvidenceView onError={setError} />}
        {view === 'settings' && <SettingsView onSaved={refreshHealth} />}
      </main>
    </div>
  );
}

function MapsView({ onError }) {
  const [graph, setGraph] = useState(null);
  const [selected, setSelected] = useState(null);
  const [dossier, setDossier] = useState(null);
  const [tab, setTab] = useState('activity');
  const [busy, setBusy] = useState(false);
  const [etw, setEtw] = useState(null);
  const [query, setQuery] = useState('');
  const [minSev, setMinSev] = useState('medium');
  const [kindFilter, setKindFilter] = useState('threats');
  const graphRef = useRef(null);

  async function load() {
    try {
      const [g, e] = await Promise.all([api.activeMap(), api.etwStatus().catch(() => null)]);
      setGraph(g);
      setEtw(e);
      onError('');
    } catch (err) {
      onError(String(err.message || err));
    }
  }

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    if (!graph) return { nodes: [], links: [], list: [] };
    const q = query.trim().toLowerCase();
    const min = SEV_RANK[minSev] ?? 0;
    const nodes = graph.nodes.filter((n) => {
      if ((SEV_RANK[n.severity] ?? 0) < min) return false;
      if (kindFilter === 'threats') {
        const threatKind = ['port', 'finding', 'service'].includes(n.kind)
          || ['high', 'critical'].includes(n.severity)
          || /etw|smb|rdp|rpc|persist/i.test(n.label || '');
        if (!threatKind && (SEV_RANK[n.severity] ?? 0) < 2) return false;
      } else if (kindFilter !== 'all' && n.kind !== kindFilter) {
        return false;
      }
      if (q && !(n.label || '').toLowerCase().includes(q) && !(n.kind || '').includes(q)) {
        return false;
      }
      return true;
    });
    const ids = new Set(nodes.map((n) => n.id));
    const links = graph.edges.filter((e) => ids.has(e.src_id) && ids.has(e.dst_id));
    const list = [...nodes].sort(
      (a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0)
    );
    return { nodes, links, list };
  }, [graph, query, minSev, kindFilter]);

  const fgData = useMemo(
    () => ({
      nodes: filtered.nodes.map((n) => ({
        id: n.id,
        name: n.label,
        kind: n.kind,
        severity: n.severity,
        val: 1.2 + (SEV_RANK[n.severity] ?? 0) * 0.9
      })),
      links: filtered.links.map((e) => ({
        source: e.src_id,
        target: e.dst_id,
        rel: e.rel,
        suggested: e.suggested
      }))
    }),
    [filtered]
  );

  async function selectNode(nodeLike) {
    const node = {
      id: nodeLike.id || nodeLike.node_id,
      name: nodeLike.name || nodeLike.label,
      kind: nodeLike.kind,
      severity: nodeLike.severity
    };
    setSelected(node);
    setTab('activity');
    setDossier(null);
    if (!graph?.map?.id) return;
    try {
      const d = await api.nodeDossier(graph.map.id, node.id);
      setDossier(d);
      onError('');
      // Zoom/center on node when possible
      const fg = graphRef.current;
      if (fg?.centerAt && nodeLike.x != null) {
        fg.centerAt(nodeLike.x, nodeLike.y, 600);
        fg.zoom(2.2, 600);
      }
    } catch (e) {
      onError(String(e.message || e));
      setDossier(null);
    }
  }

  async function runScan() {
    setBusy(true);
    try {
      await api.startScan();
      // ETW window ~6s — wait then refresh
      setTimeout(async () => {
        await api.backfillActivity().catch(() => {});
        await load();
        setBusy(false);
      }, 7500);
      onError('');
    } catch (e) {
      onError(String(e.message || e));
      setBusy(false);
    }
  }

  async function runMl() {
    setBusy(true);
    try {
      const result = await api.mlScore({ map_id: graph?.map?.id });
      await load();
      if (result?.movement?.summary) {
        onError('');
      }
    } catch (e) {
      onError(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    try {
      fg.d3Force?.('charge')?.strength(-85);
      fg.d3Force?.('link')?.distance(55);
      fg.d3ReheatSimulation?.();
    } catch {
      /* ignore */
    }
  }, [fgData]);

  return (
    <section className="panel map-panel">
      <h1 className="hero-line">Threat Map</h1>
      <p className="sub">Living graph of hosts, processes, ports, findings, and kernel ETW traces. Filter noise, then click a target or graph node.</p>
      <div className="toolbar">
        <button className="btn primary" disabled={busy} onClick={runScan}>Collect evidence + ETW</button>
        <button className="btn" disabled={busy} onClick={runMl}>Map actor movement (ML)</button>
        <button className="btn ghost" onClick={load}>Refresh</button>
        <span className="muted">
          {graph ? `${filtered.nodes.length}/${graph.nodes.length} nodes · ${filtered.links.length} edges` : '…'}
        </span>
      </div>
      <div className="toolbar filters">
        <label className="inline">
          Min severity
          <select value={minSev} onChange={(e) => setMinSev(e.target.value)}>
            <option value="info">info</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </label>
        <label className="inline">
          Show
          <select value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}>
            <option value="threats">threats (recommended)</option>
            <option value="all">all kinds</option>
            <option value="port">ports</option>
            <option value="process">processes</option>
            <option value="finding">findings</option>
            <option value="service">services</option>
          </select>
        </label>
        <label className="inline grow">
          Search
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="svchost, 445, lsass…" />
        </label>
      </div>
      <p className={`muted etw-banner ${etw?.elevated ? 'ok' : ''}`}>
        {etw?.elevated
          ? 'ETW kernel session elevated — process/image/DNS/TCPIP capture enabled.'
          : etw?.seen
            ? 'ETW seen but not elevated — run gateway as Administrator for full kernel capture.'
            : 'No ETW session yet — Collect evidence + ETW to start tracing.'}
      </p>
      <div className="layout-map">
        <div className="surface graph-wrap large">
          <ForceGraph2D
            ref={graphRef}
            graphData={fgData}
            nodeId="id"
            nodeLabel={(n) => `${n.kind}: ${n.name} [${n.severity}]`}
            linkColor={(l) => (l.suggested ? 'rgba(196,163,90,0.55)' : 'rgba(143,163,152,0.28)')}
            linkWidth={1.1}
            linkDirectionalArrowLength={3.5}
            linkDirectionalArrowRelPos={1}
            cooldownTicks={90}
            enableNodeDrag
            onNodeClick={(n) => selectNode(n)}
            nodePointerAreaPaint={(node, color, ctx) => {
              ctx.beginPath();
              ctx.fillStyle = color;
              ctx.arc(node.x, node.y, 14, 0, 2 * Math.PI, false);
              ctx.fill();
            }}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.name || node.id;
              const fontSize = Math.max(11 / globalScale, 2.2);
              const r = 4 + (SEV_RANK[node.severity] ?? 0) * 1.4;
              const active = selected?.id === node.id;
              ctx.beginPath();
              ctx.fillStyle = colorFor(node.severity, node.kind);
              ctx.arc(node.x, node.y, active ? r + 2.5 : r, 0, 2 * Math.PI, false);
              ctx.fill();
              if (active) {
                ctx.strokeStyle = 'rgba(196,163,90,0.95)';
                ctx.lineWidth = 2 / globalScale;
                ctx.stroke();
              }
              if (globalScale > 0.55 || active || (SEV_RANK[node.severity] ?? 0) >= 2) {
                ctx.font = `${fontSize}px DM Sans`;
                ctx.fillStyle = 'rgba(232,240,234,0.92)';
                ctx.fillText(label.slice(0, 26), node.x + r + 3, node.y + 3);
              }
            }}
            backgroundColor="rgba(0,0,0,0)"
          />
        </div>
        <div className="map-side">
          <div className="surface pad target-list">
            <h3 style={{ marginTop: 0 }}>Clickable targets</h3>
            <ul className="list compact">
              {filtered.list.slice(0, 60).map((n) => (
                <li
                  key={n.id}
                  className={selected?.id === n.id ? 'selected' : ''}
                  onClick={() => selectNode(n)}
                >
                  <span className={`sev ${n.severity}`}>{n.kind}</span>
                  {n.label}
                </li>
              ))}
              {!filtered.list.length ? <li className="muted">No nodes match filters.</li> : null}
            </ul>
          </div>
          <div className="surface pad inspector">
            {!selected ? (
              <p className="muted">Select a target from the list or graph to inspect activity and function.</p>
            ) : !dossier ? (
              <p className="muted">Loading dossier…</p>
            ) : (
              <NodeInspector dossier={dossier} tab={tab} setTab={setTab} />
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

function ActivityView({ onError }) {
  const [pack, setPack] = useState(null);
  const [feed, setFeed] = useState([]);
  const [selected, setSelected] = useState(null);
  const [dossier, setDossier] = useState(null);
  const [minSev, setMinSev] = useState('low');
  const [mapId, setMapId] = useState(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const [targets, activity, map] = await Promise.all([
        api.activityTargets({ min_severity: minSev, limit: 100 }),
        api.recentActivity({ limit: 150 }),
        api.activeMap()
      ]);
      setPack(targets);
      setFeed(activity);
      setMapId(map?.map?.id || targets.map_id);
      onError('');
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [minSev]);

  async function openTarget(t) {
    setSelected(t);
    setBusy(true);
    try {
      const d = await api.nodeDossier(mapId || pack?.map_id, t.node_id);
      setDossier(d);
      onError('');
    } catch (e) {
      onError(String(e.message || e));
      setDossier(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h1 className="hero-line">Active Activity</h1>
      <p className="sub">Target live nodes and map exactly what each one is doing — actions, mechanisms, and function.</p>
      <div className="toolbar">
        <button className="btn primary" onClick={load}>Refresh live</button>
        <label className="inline">
          Min severity
          <select value={minSev} onChange={(e) => setMinSev(e.target.value)}>
            <option value="info">info</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
          </select>
        </label>
        <span className="muted">
          {pack ? `${pack.targets.length} active targets` : '…'}
          {pack?.etw?.elevated ? ' · ETW elevated' : ''}
        </span>
      </div>
      <div className="layout-activity">
        <div className="surface pad">
          <h3 style={{ marginTop: 0 }}>Active targets</h3>
          <ul className="list">
            {(pack?.targets || []).map((t) => (
              <li
                key={t.node_id}
                className={selected?.node_id === t.node_id ? 'selected' : ''}
                style={{ cursor: 'pointer' }}
                onClick={() => openTarget(t)}
              >
                <span className={`sev ${t.severity}`}>{t.kind}</span>
                <strong>{t.label}</strong>
                <div className="meta">
                  {t.activity_count} actions · {t.function_tags?.join(', ') || 'n/a'} · last {t.last_seen}
                </div>
                {t.latest ? (
                  <div className="meta mech">
                    Now: {t.latest.action} — {t.latest.summary}
                  </div>
                ) : null}
              </li>
            ))}
            {!pack?.targets?.length ? <li className="muted">No active targets yet.</li> : null}
          </ul>
        </div>
        <div className="surface pad inspector">
          {!selected ? (
            <p className="muted">Select a target to map what it is doing right now.</p>
          ) : busy ? (
            <p className="muted">Mapping activity…</p>
          ) : dossier ? (
            <>
              <h3 style={{ marginTop: 0 }}>{dossier.node.label}</h3>
              <p className="dossier-lead"><strong>Doing:</strong> {dossier.what_it_does}</p>
              <p className="muted how-line"><strong>How:</strong> {dossier.how_it_works}</p>
              <h4>Live action trail</h4>
              <ul className="list">
                {(dossier.activity || []).map((a) => (
                  <li key={a.id}>
                    <span className={`sev ${a.severity}`}>{a.action}</span>
                    {a.summary}
                    <div className="meta mech">{a.mechanism}</div>
                    <div className="meta">{a.ts}</div>
                  </li>
                ))}
              </ul>
              <h4>Graph neighbors</h4>
              <ul className="list">
                {(dossier.neighbors || []).slice(0, 20).map((n, i) => (
                  <li key={`${n.node.id}-${i}`}>
                    <span className="sev info">{n.rel}</span>
                    {n.node.label}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="muted">Could not load dossier.</p>
          )}
        </div>
        <div className="surface pad">
          <h3 style={{ marginTop: 0 }}>Live feed</h3>
          <ul className="list compact">
            {feed.slice(0, 80).map((a) => (
              <li
                key={a.id}
                style={{ cursor: a.node_id ? 'pointer' : 'default' }}
                onClick={() => a.node_id && openTarget({
                  node_id: a.node_id,
                  label: a.node_label,
                  kind: a.node_kind,
                  severity: a.node_severity || a.severity
                })}
              >
                <span className={`sev ${a.severity}`}>{a.action}</span>
                {a.node_label || a.node_id}
                <div className="meta">{a.summary}</div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

function NodeInspector({ dossier, tab, setTab }) {
  const tabs = [
    ['activity', 'Activity'],
    ['function', 'Function'],
    ['surface', 'Surface'],
    ['links', 'Links'],
    ['raw', 'Evidence']
  ];
  return (
    <>
      <h3 style={{ marginTop: 0 }}>{dossier.node.label}</h3>
      <div className="meta muted">
        {dossier.node.kind} · {dossier.node.severity} · {dossier.function?.tag}
      </div>
      <p className="dossier-lead">{dossier.what_it_does}</p>
      <p className="muted how-line"><strong>How:</strong> {dossier.how_it_works}</p>
      <div className="nav inspector-tabs">
        {tabs.map(([id, label]) => (
          <button key={id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>
      {tab === 'activity' && (
        <ul className="list">
          {(dossier.activity || []).map((a) => (
            <li key={a.id}>
              <span className={`sev ${a.severity}`}>{a.action}</span>
              {a.summary}
              <div className="meta">{a.ts}</div>
              <div className="meta mech">{a.mechanism}</div>
            </li>
          ))}
          {!dossier.activity?.length ? <li className="muted">No activity recorded yet — run Collect or Backfill.</li> : null}
        </ul>
      )}
      {tab === 'function' && (
        <div className="dossier-block">
          <div><span className="muted">Role</span><div>{dossier.function?.role}</div></div>
          <div><span className="muted">Tag</span><div>{dossier.function?.tag}</div></div>
          <div><span className="muted">Mechanism</span><div>{dossier.how_it_works}</div></div>
          <div><span className="muted">Attrs</span><pre className="pre tiny">{JSON.stringify(dossier.node.attrs || {}, null, 2)}</pre></div>
        </div>
      )}
      {tab === 'surface' && (
        <ul className="list">
          {(dossier.attack_surface_contribution || []).map((s, i) => (
            <li key={`${s.ts}-${i}`}>
              <span className={`sev ${s.severity}`}>{s.function_tag}</span>
              {s.summary}
              <div className="meta mech">{s.mechanism}</div>
            </li>
          ))}
          {!dossier.attack_surface_contribution?.length ? (
            <li className="muted">This node is not currently contributing exposure/persistence surface.</li>
          ) : null}
        </ul>
      )}
      {tab === 'links' && (
        <ul className="list">
          {(dossier.neighbors || []).map((n, i) => (
            <li key={`${n.node.id}-${i}`}>
              <span className="sev info">{n.direction}/{n.rel}</span>
              {n.node.label}
              <div className="meta">{n.node.kind} · {n.node.severity}</div>
            </li>
          ))}
          {!dossier.neighbors?.length ? <li className="muted">No graph neighbors.</li> : null}
        </ul>
      )}
      {tab === 'raw' && (
        <ul className="list">
          {(dossier.evidence || []).map((e) => (
            <li key={e.id}>
              <span className={`sev ${e.severity}`}>{e.severity}</span>
              {e.type}
              <div className="meta">{e.ts} · {e.agent}</div>
              {e.raw && Object.keys(e.raw).length ? (
                <pre className="pre tiny">{JSON.stringify(e.raw, null, 2)}</pre>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function MovementView({ onError }) {
  const [campaign, setCampaign] = useState(null);
  const [busy, setBusy] = useState(false);
  const [lastRun, setLastRun] = useState(null);

  async function load() {
    try {
      const c = await api.latestMovement();
      setCampaign(c?.empty ? null : c);
      onError('');
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function runPipeline() {
    setBusy(true);
    try {
      const map = await api.activeMap();
      const result = await api.mlScore({ map_id: map?.map?.id });
      setLastRun(result);
      await load();
      onError('');
    } catch (e) {
      onError(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }

  const hops = campaign?.hops || [];
  const stages = campaign?.stages || [];
  const coverage = lastRun?.movement?.coverage || {};

  return (
    <section className="panel">
      <h1 className="hero-line">Actor Movement</h1>
      <p className="sub">
        ML pipeline maps how a threat actor could move across this Windows estate — initial access, execution,
        persistence, lateral movement, credential touch, and C2 — from host, network, and ETW evidence.
      </p>
      <div className="toolbar">
        <button className="btn primary" disabled={busy} onClick={runPipeline}>
          Run full ML movement map
        </button>
        <button className="btn ghost" onClick={load}>Refresh</button>
        {campaign ? (
          <span className="muted">
            score {(campaign.ml_score || campaign.confidence || 0).toFixed(2)} · {hops.length} hops · {campaign.actor_label}
            {campaign.confidence_capped || (campaign.ml_score || 0) <= 0.55
              ? ' · soft-capped (weak corroboration)'
              : ''}
          </span>
        ) : null}
      </div>

      {!campaign ? (
        <div className="surface pad">
          <p className="muted">No movement campaign yet. Run the ML pipeline after collecting evidence.</p>
        </div>
      ) : (
        <div className="layout-activity">
          <div className="surface pad">
            <h3 style={{ marginTop: 0 }}>Kill-chain coverage</h3>
            <p>{campaign.summary}</p>
            <ul className="list">
              {stages.map((s) => (
                <li key={s.stage}>
                  <span className={`sev ${s.max_severity}`}>{s.stage}</span>
                  {s.count} signals · {(s.techniques || []).slice(0, 2).join('; ')}
                </li>
              ))}
            </ul>
            <h4>Sensor coverage</h4>
            <ul className="list compact">
              {Object.entries(lastRun?.movement?.coverage || coverage || {}).map(([k, v]) => (
                <li key={k}>
                  <span className={`sev ${v ? 'ok' : 'info'}`}>{v ? 'yes' : 'no'}</span>
                  {k}
                </li>
              ))}
              {!Object.keys(lastRun?.movement?.coverage || {}).length ? (
                <li className="muted">Re-run ML to refresh coverage flags.</li>
              ) : null}
            </ul>
          </div>
          <div className="surface pad inspector">
            <h3 style={{ marginTop: 0 }}>Movement path</h3>
            <ol className="movement-path">
              {hops.map((h) => (
                <li key={`${h.seq}-${h.id || h.event_id}`}>
                  <div className="hop-head">
                    <span className="sev medium">{h.stage}</span>
                    <strong>{h.technique}</strong>
                    <span className="muted"> #{h.seq}</span>
                  </div>
                  <div>{h.summary}</div>
                  <div className="meta mech">{h.mechanism}</div>
                  <div className="meta">confidence {(h.confidence || 0).toFixed(2)} · {h.ts}</div>
                </li>
              ))}
            </ol>
          </div>
          <div className="surface pad">
            <h3 style={{ marginTop: 0 }}>What Windows activity is covered</h3>
            <ul className="list">
              <li><strong>Network</strong> — listeners, SMB/RDP/RPC/WinRM exposure, connection fan-out</li>
              <li><strong>Host</strong> — processes, services, persistence (Run keys), named pipes</li>
              <li><strong>ETW kernel</strong> — process start/stop, image loads, DNS, TCPIP flows</li>
              <li><strong>Credentials</strong> — LSASS-adjacent process observation</li>
              <li><strong>Lateral</strong> — admin protocol exposure used as movement hypotheses</li>
              <li><strong>C2</strong> — DNS queries and kernel network flows</li>
            </ul>
            <p className="muted">
              Edges suggested by ML are written back to the Threat Map as <code>targets</code> links tagged
              <code>aegis_ml_movement</code>.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

function PeersView({ onError }) {
  const [peers, setPeers] = useState(null);
  const [c2, setC2] = useState(null);
  const [attr, setAttr] = useState(null);
  const [delta, setDelta] = useState(null);
  const [watches, setWatches] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [runs, setRuns] = useState([]);
  const [compare, setCompare] = useState(null);
  const [scanA, setScanA] = useState('');
  const [scanB, setScanB] = useState('');
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState('c2');
  const [minC2, setMinC2] = useState(0);
  const [tier, setTier] = useState('all');
  const [hostId, setHostId] = useState('');

  async function load() {
    try {
      const params = {
        limit: 150,
        min_c2: minC2,
        tier: tier === 'all' ? undefined : tier,
        host_id: hostId || undefined
      };
      const [p, c, a, d, w, r, al] = await Promise.all([
        api.peers(params),
        api.c2({ limit: 100, host_id: hostId || undefined, tier: tier === 'all' ? undefined : tier }),
        api.attribution({ limit: 120, host_id: hostId || undefined }),
        api.peersDelta({ host_id: hostId || undefined }),
        api.watches(),
        api.scanRuns(),
        api.alerts({ host_id: hostId || undefined, limit: 20 }).catch(() => ({ alerts: [] }))
      ]);
      setPeers(p);
      setC2(c);
      setAttr(a);
      setDelta(d);
      setWatches(w.watches || []);
      setRuns(r || []);
      setAlerts(al.alerts || []);
      onError('');
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  useEffect(() => {
    load();
  }, [minC2, tier, hostId]);

  async function rebuild() {
    setBusy(true);
    try {
      await api.rebuildPeers();
      await load();
    } catch (e) {
      onError(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }

  async function scan() {
    setBusy(true);
    try {
      await api.startScan();
      setTimeout(async () => {
        try {
          await load();
        } catch (e) {
          onError(String(e.message || e));
        } finally {
          setBusy(false);
        }
      }, 10000);
    } catch (e) {
      onError(String(e.message || e));
      setBusy(false);
    }
  }

  async function pinIp(ip, confirmed = false) {
    try {
      await api.createWatch({ kind: 'ip', value: ip, confirmed, note: confirmed ? 'analyst confirmed' : 'pinned' });
      await load();
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  async function runCompare() {
    if (!scanA || !scanB) return;
    try {
      setCompare(await api.peersCompare(scanA, scanB));
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  const egressList = (c2?.destinations?.length ? c2.destinations : c2?.egress_watch) || [];

  return (
    <section className="panel">
      <h1 className="hero-line">Peers · C2 · Attribution</h1>
      <p className="sub">
        Baseline deltas ({delta?.window_days || 7}d rolling window), DNS join, beacon cadence, and tiered egress
        (watch / candidate / confirmed). Software/behavioral attribution only — not a named threat actor claim.
        Loopback is suppressed unless hunting local services.
      </p>
      {alerts.length ? (
        <div className="toolbar">
          <span className="muted">Alerts:</span>
          {alerts.slice(0, 6).map((a) => (
            <span key={a.id} className={`sev ${a.severity}`} title={a.detail || a.title}>
              {a.kind}: {a.subject || a.title}
            </span>
          ))}
        </div>
      ) : null}
      {watches.length ? (
        <div className="toolbar">
          <span className="muted">Pinned:</span>
          {watches.slice(0, 12).map((w) => (
            <button
              key={w.id}
              className="btn"
              onClick={() => api.deleteWatch(w.id).then(load).catch((e) => onError(String(e.message || e)))}
              title={w.note || w.kind}
            >
              {w.confirmed ? '✓ ' : ''}{w.value}
            </button>
          ))}
        </div>
      ) : null}
      <div className="toolbar">
        <button className="btn primary" disabled={busy} onClick={scan}>Scan now</button>
        <button className="btn" disabled={busy} onClick={load}>Refresh</button>
        <button className="btn" disabled={busy} onClick={rebuild}>Rebuild + analyze</button>
        <label className="muted">
          Tier{' '}
          <select value={tier} onChange={(e) => setTier(e.target.value)}>
            <option value="all">all</option>
            <option value="watch">watch</option>
            <option value="candidate">candidate</option>
            <option value="confirmed">confirmed</option>
          </select>
        </label>
        <label className="muted">
          Min C2{' '}
          <select value={minC2} onChange={(e) => setMinC2(Number(e.target.value))}>
            <option value={0}>0 · all peers</option>
            <option value={0.45}>0.45 · candidates</option>
            <option value={0.75}>0.75 · high</option>
          </select>
        </label>
        <label className="muted">
          Host{' '}
          <input
            value={hostId}
            onChange={(e) => setHostId(e.target.value)}
            placeholder="all hosts"
            style={{ width: '9rem' }}
          />
        </label>
        <span className="muted">
          {(peers?.count ?? 0)} peers · {(c2?.stats?.candidate_ips ?? 0)} C2 · {(c2?.beacons || []).length} beacons
          {delta ? ` · new ${delta.counts?.new || 0}` : ''}
          {c2?.stats ? ` · max ${(Number(c2.stats.max_c2) || 0).toFixed(2)}` : ''}
        </span>
      </div>
      <div className="toolbar">
        {['c2', 'peers', 'attribution', 'compare'].map((t) => (
          <button key={t} className={tab === t ? 'btn primary' : 'btn'} onClick={() => setTab(t)}>
            {t === 'c2' ? 'C2 / beacons' : t === 'peers' ? 'Remote peers' : t === 'attribution' ? 'Attribution' : 'Compare scans'}
          </button>
        ))}
      </div>
      {tab === 'c2' ? (
        <div className="layout-split">
          <div className="surface pad">
            <h3 style={{ marginTop: 0 }}>
              {(c2?.destinations || []).length ? 'C2 candidate IPs' : 'Outbound egress (watch)'}
            </h3>
            <p className="muted">{c2?.disclaimer}</p>
            {c2?.stats ? (
              <p className="muted">
                Inventory: {c2.stats.peer_count} peers · {c2.stats.egress_ips} IPs · {c2.stats.candidate_peers} candidates · {c2.stats.beacon_count || 0} beacons.
                Allowlisted HTTPS stays near zero on purpose.
              </p>
            ) : null}
            <ul className="list">
              {egressList.map((d) => (
                <li key={`${d.tier || 'ip'}-${d.remote_ip}`}>
                  <span className={`sev ${d.max_score >= 0.75 ? 'high' : d.max_score >= 0.45 ? 'medium' : 'info'}`}>
                    {Number(d.max_score).toFixed(2)}
                  </span>
                  <strong>{d.remote_ip}</strong>
                  <button className="btn" style={{ marginLeft: 8 }} onClick={() => pinIp(d.remote_ip, false)}>Pin</button>
                  <button className="btn" onClick={() => pinIp(d.remote_ip, true)}>Confirm</button>
                  <div className="meta">
                    {d.tier || 'watch'} · ports {(d.ports || []).join(', ') || '—'} · {(d.processes || []).join(', ') || 'unknown'}
                    {d.hostnames?.length ? ` · dns ${d.hostnames.slice(0, 3).join(', ')}` : ''}
                    {d.enrichment?.ioc_hit ? ' · IOC' : ''}
                    {d.enrichment?.ip?.class ? ` · ${d.enrichment.ip.class}` : ''}
                  </div>
                  {(d.org || d.asn || d.publisher || d.why || d.first_seen) ? (
                    <div className="meta mech">
                      {[
                        d.org ? `org ${d.org}` : null,
                        d.asn ? `ASN ${d.asn}` : null,
                        d.publisher ? `signed ${String(d.publisher).slice(0, 60)}` : null,
                        d.first_seen ? `first ${d.first_seen}` : null,
                        d.why?.reasons?.length ? `why: ${d.why.reasons.slice(0, 4).join(', ')}` : null
                      ]
                        .filter(Boolean)
                        .join(' · ') || 'enrichment pending'}
                    </div>
                  ) : null}
                  <div className="meta mech">{d.doing || 'Established remote destination'}</div>
                </li>
              ))}
              {!egressList.length ? (
                <li className="muted">No peer inventory yet — run Scan now.</li>
              ) : null}
            </ul>
            <h3>Cadence / beacon suspects</h3>
            <ul className="list">
              {(c2?.beacons || []).map((b) => (
                <li key={b.id}>
                  <span className={`sev ${b.score >= 0.75 ? 'high' : 'medium'}`}>{Number(b.score).toFixed(2)}</span>
                  <strong>{b.process_name || '?'}</strong> → {b.remote_ip}:{b.remote_port || '?'}
                  <div className="meta">
                    {b.tier} · interval ~{b.interval_mean_secs != null ? `${Math.round(b.interval_mean_secs)}s` : '—'} · jitter {b.interval_jitter_secs != null ? `${Math.round(b.interval_jitter_secs)}s` : '—'} · {b.sightings} sightings
                  </div>
                  <div className="meta mech">{(b.reasons || []).join(' · ')}</div>
                </li>
              ))}
              {!c2?.beacons?.length ? (
                <li className="muted">No beacon cadence yet — needs repeated scans/polls (≥4 sightings).</li>
              ) : null}
            </ul>
          </div>
          <div className="surface pad">
            <h3 style={{ marginTop: 0 }}>C2 observations</h3>
            <ul className="list">
              {(c2?.observations || []).map((o) => (
                <li key={o.id}>
                  <span className={`sev ${o.severity}`}>{o.severity}</span>
                  <strong>{o.process_name}</strong> → {o.remote_ip}:{o.remote_port || '?'}
                  <div className="meta">{o.doing}</div>
                  <div className="meta mech">{(o.reasons || []).join(' · ')}</div>
                </li>
              ))}
              {!c2?.observations?.length ? (
                <li className="muted">No elevated C2 observations on this host right now.</li>
              ) : null}
            </ul>
            <h3>Baseline delta</h3>
            <p className="muted">
              {delta?.window_days || 7}d window · baseline {delta?.baseline_size ?? 0} · new {delta?.counts?.new ?? 0} · rare {delta?.counts?.rare ?? 0} · quiet {delta?.counts?.disappeared ?? 0}
            </p>
            {delta?.note ? <p className="muted">{delta.note}</p> : null}
            <ul className="list">
              {(delta?.new || []).slice(0, 20).map((n) => (
                <li key={n.id}>
                  <span className="sev medium">new</span>
                  {n.process_name} → {n.remote_ip}:{n.remote_port || '?'}
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
      {tab === 'peers' ? (
        <div className="surface pad">
          <h3 style={{ marginTop: 0 }}>Established remote peers</h3>
          <ul className="list">
            {(peers?.peers || []).map((p) => (
              <li key={p.id}>
                <span className={`sev ${p.tier === 'confirmed' ? 'high' : p.tier === 'candidate' ? 'medium' : 'info'}`}>
                  {p.tier || p.function_tag || 'peer'}
                </span>
                <strong>{p.process_name}</strong> → {p.remote_ip}:{p.remote_port || '?'}
                <button className="btn" style={{ marginLeft: 8 }} onClick={() => pinIp(p.remote_ip, false)}>Pin</button>
                <div className="meta">
                  {p.host_id} · {p.software_class} · {p.baseline_status || '—'} · c2 {(Number(p.c2_score) || 0).toFixed(2)} · hits {p.hit_count}
                  {p.hostnames?.length ? ` · ${p.hostnames.slice(0, 2).join(', ')}` : ''}
                  {p.publisher ? ` · ${String(p.publisher).slice(0, 40)}` : ''}
                  {p.org ? ` · ${p.org}` : ''}
                </div>
                {p.why?.reasons?.length ? (
                  <div className="meta mech">why: {p.why.reasons.slice(0, 5).join(' · ')}</div>
                ) : null}
                <div className="meta mech">{p.attrs?.doing || p.direction}</div>
              </li>
            ))}
            {!peers?.peers?.length ? <li className="muted">No peers stored yet.</li> : null}
          </ul>
        </div>
      ) : null}
      {tab === 'attribution' ? (
        <div className="layout-split">
          <div className="surface pad">
            <h3 style={{ marginTop: 0 }}>By software class</h3>
            <p className="muted">{attr?.disclaimer}</p>
            <ul className="list">
              {(attr?.by_class || []).map((c) => (
                <li key={c.software_class}>
                  <strong>{c.software_class || 'unknown'}</strong>
                  <div className="meta">{c.n} peers · avg c2 {(Number(c.avg_c2) || 0).toFixed(2)}</div>
                </li>
              ))}
            </ul>
            <h3>Top destination IPs</h3>
            <ul className="list">
              {(attr?.top_destination_ips || []).map((ip) => (
                <li key={ip.remote_ip}>
                  <span className={`sev ${ip.max_c2 >= 0.75 ? 'high' : ip.max_c2 >= 0.45 ? 'medium' : 'info'}`}>
                    {(Number(ip.max_c2) || 0).toFixed(2)}
                  </span>
                  <strong>{ip.remote_ip}</strong>
                  <div className="meta">
                    {ip.connections} · {(ip.processes || []).join(', ')}
                    {ip.hostnames?.length ? ` · dns ${ip.hostnames.join(', ')}` : ''}
                  </div>
                </li>
              ))}
            </ul>
          </div>
          <div className="surface pad">
            <h3 style={{ marginTop: 0 }}>Attribution records</h3>
            <ul className="list">
              {(attr?.records || []).map((r) => (
                <li key={r.id}>
                  <span className="sev info">{r.class}</span>
                  <strong>{r.subject_label || r.subject_id}</strong>
                  <div className="meta">{r.subject_kind} · conf {(Number(r.confidence) || 0).toFixed(2)}</div>
                  <div className="meta mech">{r.rationale}</div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
      {tab === 'compare' ? (
        <div className="surface pad">
          <h3 style={{ marginTop: 0 }}>Compare scans</h3>
          <div className="toolbar">
            <label className="muted">
              A{' '}
              <select value={scanA} onChange={(e) => setScanA(e.target.value)}>
                <option value="">select</option>
                {runs.map((r) => (
                  <option key={r.id} value={r.id}>{r.started_at} · {r.trigger_source} · {r.status}</option>
                ))}
              </select>
            </label>
            <label className="muted">
              B{' '}
              <select value={scanB} onChange={(e) => setScanB(e.target.value)}>
                <option value="">select</option>
                {runs.map((r) => (
                  <option key={`b-${r.id}`} value={r.id}>{r.started_at} · {r.trigger_source} · {r.status}</option>
                ))}
              </select>
            </label>
            <button className="btn primary" onClick={runCompare}>Compare</button>
          </div>
          {compare ? (
            <div className="layout-split">
              <div>
                <h4>Only in A ({compare.counts?.only_a || 0})</h4>
                <ul className="list">
                  {(compare.only_in_a || []).slice(0, 40).map((r, i) => (
                    <li key={`a-${i}`}>{r.process_name} → {r.remote_ip}:{r.remote_port || '?'}</li>
                  ))}
                </ul>
              </div>
              <div>
                <h4>Only in B ({compare.counts?.only_b || 0})</h4>
                <ul className="list">
                  {(compare.only_in_b || []).slice(0, 40).map((r, i) => (
                    <li key={`b-${i}`}>{r.process_name} → {r.remote_ip}:{r.remote_port || '?'}</li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <p className="muted">Pick two scan runs to diff peer observations.</p>
          )}
        </div>
      ) : null}
    </section>
  );
}

function FleetView({ onError }) {
  const [data, setData] = useState(null);

  async function load() {
    try {
      setData(await api.fleet());
      onError('');
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <section className="panel">
      <h1 className="hero-line">Fleet</h1>
      <p className="sub">
        Hosts reporting into this gateway via distinct <code>host_id</code> values. Remote agents POST events with a token.
        Single-host estates show only this machine — no synthetic second host.
      </p>
      <div className="toolbar">
        <button className="btn primary" onClick={load}>Refresh</button>
        <span className="muted">
          {(data?.hosts || []).length} hosts · {data?.agent_count || 0} agents
          {data?.primary_host_id ? ` · primary ${data.primary_host_id}` : ''}
        </span>
      </div>
      {data?.note ? <p className="muted">{data.note}</p> : null}
      <ul className="list">
        {(data?.hosts || []).map((h) => (
          <li key={h.host_id}>
            <strong>{h.host_id}</strong>
            {h.is_primary ? <span className="muted"> · primary</span> : null}
            <div className="meta">
              last {h.last_seen_at || '—'} · {h.peer_count} peers · {h.event_count} events
              {h.etw_elevated == null ? '' : h.etw_elevated ? ' · ETW elevated' : ' · ETW not elevated'}
            </div>
            <div className="meta mech">
              agents: {(h.agents || []).map((a) => a.kind).join(', ') || 'none registered'}
            </div>
          </li>
        ))}
        {!data?.hosts?.length ? <li className="muted">No hosts yet — run a scan or ingest remote events.</li> : null}
      </ul>
    </section>
  );
}

function SurfaceView({ onError }) {
  const [data, setData] = useState(null);
  const [finding, setFinding] = useState(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      setData(await api.attackSurface());
      onError('');
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function backfill() {
    setBusy(true);
    try {
      await api.backfillActivity();
      await load();
    } catch (e) {
      onError(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }

  async function openFinding(id) {
    try {
      setFinding(await api.findingDetail(id));
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  const findings = useFindings(onError);

  return (
    <section className="panel">
      <h1 className="hero-line">Attack Surface</h1>
      <p className="sub">Mapped exposure: what is reachable or persistent, what function it serves, and how it operates on this estate.</p>
      <div className="toolbar">
        <button className="btn primary" disabled={busy} onClick={load}>Refresh surface</button>
        <button className="btn" disabled={busy} onClick={backfill}>Backfill activity from evidence</button>
        {data ? (
          <span className="muted">
            {data.summary.total_surface_items} items · {data.summary.high_or_critical} high/critical · {data.summary.exposed_admin_protocols} admin protocols
          </span>
        ) : null}
      </div>
      <div className="layout-split">
        <div className="surface pad">
          <h3 style={{ marginTop: 0 }}>Surface inventory</h3>
          <ul className="list">
            {(data?.items || []).map((it) => (
              <li key={it.node_id}>
                <span className={`sev ${it.severity}`}>{it.function_tag}</span>
                <strong>{it.label}</strong>
                <div className="meta">{it.role}</div>
                <div className="meta mech">{it.how}{it.bind ? ` · bind ${it.bind}` : ''}{it.port ? ` · :${it.port}/${it.proto || '?'}` : ''}</div>
                {it.recent_activity?.[0] ? (
                  <div className="meta">Latest: {it.recent_activity[0].summary}</div>
                ) : null}
              </li>
            ))}
            {!data?.items?.length ? <li className="muted">No surface items yet.</li> : null}
          </ul>
        </div>
        <div className="surface pad">
          <h3 style={{ marginTop: 0 }}>Finding deep-dive</h3>
          <ul className="list">
            {findings.map((f) => (
              <li key={f.id} style={{ cursor: 'pointer' }} onClick={() => openFinding(f.id)}>
                <span className={`sev ${f.severity}`}>{f.severity}</span>
                {f.title}
              </li>
            ))}
          </ul>
          {finding ? (
            <div className="dossier-block" style={{ marginTop: '1rem' }}>
              <h4>{finding.finding.title}</h4>
              <p>{finding.dossier?.function_summary}</p>
              <p className="muted"><strong>How:</strong> {finding.dossier?.mechanism_summary || finding.function?.how}</p>
              <p className="muted">{finding.dossier?.risk_notes}</p>
              <h4>Activity</h4>
              <ul className="list">
                {(finding.activity || []).slice(0, 20).map((a) => (
                  <li key={a.id}>
                    <span className={`sev ${a.severity}`}>{a.action}</span>
                    {a.summary}
                    <div className="meta mech">{a.mechanism}</div>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="muted">Select a finding to map its full activity and function.</p>
          )}
        </div>
      </div>
    </section>
  );
}

function useFindings(onError) {
  const [findings, setFindings] = useState([]);
  useEffect(() => {
    api.findings()
      .then(setFindings)
      .catch((e) => onError(String(e.message || e)));
  }, [onError]);
  return findings;
}

function colorFor(severity, kind) {
  if (severity === 'critical' || severity === 'high') return '#c45c4a';
  if (severity === 'medium') return '#c4a35a';
  if (kind === 'host') return '#3d8f6e';
  return '#8fa398';
}

function ModelsView({ onError }) {
  const [models, setModels] = useState([]);
  const [active, setActive] = useState(null);
  const [form, setForm] = useState({ title: '', scope: '', owner: '', classification: 'internal' });
  const [scenario, setScenario] = useState({ title: '', description: '', severity: 'high', stride_tags: 'elevation,info_disclosure' });
  const [asset, setAsset] = useState({ name: '', kind: 'system', description: '' });

  async function load() {
    try {
      const list = await api.models();
      setModels(list);
      onError('');
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function openModel(id) {
    try {
      setActive(await api.getModel(id));
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  async function create() {
    try {
      const m = await api.createModel(form);
      await load();
      setActive(m);
      setForm({ title: '', scope: '', owner: '', classification: 'internal' });
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  async function addScenario() {
    if (!active) return;
    try {
      await api.addScenario(active.id, {
        ...scenario,
        stride_tags: scenario.stride_tags.split(',').map((s) => s.trim()).filter(Boolean)
      });
      await openModel(active.id);
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  async function addAsset() {
    if (!active) return;
    try {
      await api.addAsset(active.id, asset);
      await openModel(active.id);
      setAsset({ name: '', kind: 'system', description: '' });
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  async function addDefaultActor() {
    if (!active) return;
    await api.addActor(active.id, {
      name: 'External adversary',
      intent: 'Establish persistence and exfiltrate sensitive data',
      capability: 'high',
      access: 'network-adjacent'
    });
    await api.addBoundary(active.id, {
      name: 'Corporate perimeter',
      description: 'Internet → DMZ → internal Windows estate'
    });
    await api.addMitigation(active.id, {
      title: 'Restrict RDP/SMB exposure',
      description: 'Remove 0.0.0.0 binds for admin protocols; require VPN + MFA.',
      residual_risk: 0.25
    });
    await openModel(active.id);
  }

  return (
    <section className="panel">
      <h1 className="hero-line">Threat Models</h1>
      <p className="sub">Structure assets, actors, trust boundaries, STRIDE scenarios, and mitigations — linked to the living map.</p>
      <div className="layout-split">
        <div>
          <div className="grid-cards">
            {models.map((m) => (
              <div className="card-item" key={m.id} onClick={() => openModel(m.id)}>
                <h3>{m.title}</h3>
                <div className="muted">{m.status} · risk {(m.residual_risk || 0).toFixed(2)}</div>
              </div>
            ))}
          </div>
          <form className="stack surface pad" style={{ marginTop: '1rem' }} onSubmit={(e) => { e.preventDefault(); create(); }}>
            <strong>New model</strong>
            <label>Title<input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required /></label>
            <label>Owner<input value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} /></label>
            <label>Scope<textarea value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })} /></label>
            <label>Classification
              <select value={form.classification} onChange={(e) => setForm({ ...form, classification: e.target.value })}>
                <option value="internal">internal</option>
                <option value="official">official</option>
                <option value="restricted">restricted</option>
              </select>
            </label>
            <button className="btn primary" type="submit">Create model</button>
          </form>
        </div>
        <div className="surface pad">
          {!active ? <p className="muted">Select or create a model.</p> : (
            <>
              <h2 style={{ marginTop: 0, fontFamily: 'var(--font-display)', fontWeight: 400 }}>{active.title}</h2>
              <p className="muted">{active.classification} · {active.status} · residual {(active.residual_risk || 0).toFixed(2)}</p>
              <p>{active.scope || 'No scope yet.'}</p>
              <div className="toolbar">
                <button className="btn" onClick={addDefaultActor}>Add actor + boundary + mitigation</button>
              </div>
              <h4>Assets</h4>
              <ul className="list">{active.assets?.map((a) => <li key={a.id}>{a.name} <span className="muted">({a.kind})</span></li>)}</ul>
              <form className="stack" onSubmit={(e) => { e.preventDefault(); addAsset(); }}>
                <label>Asset name<input value={asset.name} onChange={(e) => setAsset({ ...asset, name: e.target.value })} required /></label>
                <button className="btn" type="submit">Add asset</button>
              </form>
              <h4>Actors</h4>
              <ul className="list">{active.actors?.map((a) => <li key={a.id}>{a.name} — {a.capability}</li>)}</ul>
              <h4>Scenarios</h4>
              <ul className="list">
                {active.scenarios?.map((s) => (
                  <li key={s.id}>
                    <span className={`sev ${s.severity}`}>{s.severity}</span>
                    {s.title}
                    <div className="meta">{(s.stride_tags || []).join(', ')}</div>
                  </li>
                ))}
              </ul>
              <form className="stack" onSubmit={(e) => { e.preventDefault(); addScenario(); }}>
                <label>Scenario title<input value={scenario.title} onChange={(e) => setScenario({ ...scenario, title: e.target.value })} required /></label>
                <label>STRIDE tags<input value={scenario.stride_tags} onChange={(e) => setScenario({ ...scenario, stride_tags: e.target.value })} /></label>
                <label>Description<textarea value={scenario.description} onChange={(e) => setScenario({ ...scenario, description: e.target.value })} /></label>
                <button className="btn primary" type="submit">Add scenario</button>
              </form>
              <h4>Mitigations</h4>
              <ul className="list">{active.mitigations?.map((m) => <li key={m.id}>{m.title}</li>)}</ul>
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function PackagesView({ onError }) {
  const [packages, setPackages] = useState([]);
  const [models, setModels] = useState([]);
  const [maps, setMaps] = useState([]);
  const [form, setForm] = useState({
    title: '',
    executive_summary: '',
    severity: 'high',
    confidence: 0.7,
    model_id: '',
    map_id: '',
    recommended_actions: 'Restrict exposed admin ports\nValidate persistence entries\nBrief stakeholders with map excerpt'
  });
  const [exportOut, setExportOut] = useState(null);

  async function load() {
    try {
      const [p, m, mp] = await Promise.all([api.packages(), api.models(), api.maps()]);
      setPackages(p);
      setModels(m);
      setMaps(mp);
      onError('');
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function create() {
    try {
      await api.createPackage({
        ...form,
        confidence: Number(form.confidence),
        model_id: form.model_id || null,
        map_id: form.map_id || null,
        recommended_actions: form.recommended_actions.split('\n').map((s) => s.trim()).filter(Boolean)
      });
      await load();
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  async function doExport(id) {
    try {
      const out = await api.exportPackage(id);
      setExportOut(out);
    } catch (e) {
      onError(String(e.message || e));
    }
  }

  async function distribute(id) {
    await api.packageStatus(id, { status: 'distributed', channel: 'official', note: 'Handed to official channel' });
    await load();
  }

  return (
    <section className="panel">
      <h1 className="hero-line">Intel Packages</h1>
      <p className="sub">Curate broker-ready briefings for official and internal channels.</p>
      <div className="layout-split">
        <div>
          <div className="grid-cards">
            {packages.map((p) => (
              <div className="card-item" key={p.id}>
                <h3>{p.title}</h3>
                <div className="muted">{p.status} · {p.severity}</div>
                <div className="toolbar" style={{ marginTop: '0.6rem' }}>
                  <button className="btn" onClick={() => doExport(p.id)}>Export</button>
                  <button className="btn" onClick={() => distribute(p.id)}>Mark distributed</button>
                </div>
              </div>
            ))}
          </div>
          <form className="stack surface pad" style={{ marginTop: '1rem' }} onSubmit={(e) => { e.preventDefault(); create(); }}>
            <strong>Assemble package</strong>
            <label>Title<input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required /></label>
            <label>Model
              <select value={form.model_id} onChange={(e) => setForm({ ...form, model_id: e.target.value })}>
                <option value="">—</option>
                {models.map((m) => <option key={m.id} value={m.id}>{m.title}</option>)}
              </select>
            </label>
            <label>Map
              <select value={form.map_id} onChange={(e) => setForm({ ...form, map_id: e.target.value })}>
                <option value="">—</option>
                {maps.map((m) => <option key={m.id} value={m.id}>{m.title}</option>)}
              </select>
            </label>
            <label>Executive summary<textarea value={form.executive_summary} onChange={(e) => setForm({ ...form, executive_summary: e.target.value })} /></label>
            <label>Recommended actions<textarea value={form.recommended_actions} onChange={(e) => setForm({ ...form, recommended_actions: e.target.value })} /></label>
            <button className="btn primary" type="submit">Create package</button>
          </form>
        </div>
        <div className="surface pad">
          <h3 style={{ marginTop: 0 }}>Export preview</h3>
          {exportOut ? (
            <div className="pre">{exportOut.briefing_markdown || JSON.stringify(exportOut, null, 2)}</div>
          ) : (
            <p className="muted">Export a package to preview the stakeholder briefing.</p>
          )}
        </div>
      </div>
    </section>
  );
}

function EvidenceView({ onError }) {
  const [events, setEvents] = useState([]);
  const [findings, setFindings] = useState([]);

  async function load() {
    try {
      const [e, f] = await Promise.all([api.events(100), api.findings()]);
      setEvents(e);
      setFindings(f);
      onError('');
    } catch (err) {
      onError(String(err.message || err));
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  return (
    <section className="panel">
      <h1 className="hero-line">Evidence</h1>
      <p className="sub">Raw collector stream grounding maps and models.</p>
      <div className="layout-split">
        <div className="surface pad">
          <h3 style={{ marginTop: 0 }}>Events</h3>
          <ul className="list">
            {events.map((e) => (
              <li key={e.id}>
                <span className={`sev ${e.severity}`}>{e.severity}</span>
                {e.type}
                <div className="meta">{e.ts} · {e.agent} · {e.host_id}</div>
              </li>
            ))}
          </ul>
        </div>
        <div className="surface pad">
          <h3 style={{ marginTop: 0 }}>Findings</h3>
          <ul className="list">
            {findings.map((f) => (
              <li key={f.id}>
                <span className={`sev ${f.severity}`}>{f.severity}</span>
                {f.title}
                <div className="meta">{f.summary}</div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

function SettingsView({ onSaved }) {
  const [url, setUrl] = useState(getGatewayUrl());
  const [token, setToken] = useState(getApiToken());
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  async function save(e) {
    e.preventDefault();
    setErr('');
    try {
      setGatewayUrl(url);
      setApiToken(token);
      setMsg('Saved gateway settings');
      onSaved?.();
    } catch (ex) {
      setErr(String(ex.message || ex));
      setMsg('');
    }
  }

  return (
    <section className="panel">
      <h1 className="hero-line">Settings</h1>
      <p className="sub">
        Point the console at the gateway. API auth is required — paste the token from the gateway console or <code>data/aegis.token</code>.
      </p>
      <form className="stack surface pad" style={{ maxWidth: 520 }} onSubmit={save}>
        <label>Gateway base URL
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://127.0.0.1:8787" />
        </label>
        <label>API token (required)
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="From data/aegis.token or AEGIS_API_TOKEN"
            autoComplete="off"
          />
        </label>
        <button className="btn primary" type="submit">Save</button>
        {msg ? <div className="muted">{msg}</div> : null}
        {err ? <div className="error">{err}</div> : null}
      </form>
    </section>
  );
}
