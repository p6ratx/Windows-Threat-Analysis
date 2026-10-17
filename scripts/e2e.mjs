#!/usr/bin/env node
/**
 * End-to-end broker path: scan → map → model → package export
 */
const BASE = process.env.AEGIS_URL || 'http://127.0.0.1:8787';

async function req(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${path}: ${text}`);
  return text ? JSON.parse(text) : null;
}

async function main() {
  console.log('health', await req('/api/health'));

  const scan = await req('/api/scan/start', { method: 'POST', body: '{}' });
  console.log('scan', scan);

  await new Promise((r) => setTimeout(r, 500));

  const graph = await req('/api/maps/active');
  console.log(`map nodes=${graph.nodes.length} edges=${graph.edges.length}`);

  const ml = await req('/api/ml/score', {
    method: 'POST',
    body: JSON.stringify({ map_id: graph.map.id, scan_run_id: scan.scan_run_id })
  });
  console.log('ml', ml);

  const model = await req('/api/models', {
    method: 'POST',
    body: JSON.stringify({
      title: 'Windows Perimeter Exposure',
      classification: 'official',
      owner: 'Aegis Broker',
      scope: 'Windows estate admin protocols and persistence',
      map_id: graph.map.id
    })
  });
  await req(`/api/models/${model.id}/assets`, {
    method: 'POST',
    body: JSON.stringify({ name: 'Domain workstation fleet', kind: 'system' })
  });
  await req(`/api/models/${model.id}/actors`, {
    method: 'POST',
    body: JSON.stringify({
      name: 'External operator',
      intent: 'Lateral movement via exposed services',
      capability: 'high'
    })
  });
  await req(`/api/models/${model.id}/scenarios`, {
    method: 'POST',
    body: JSON.stringify({
      title: 'RDP/SMB exposure to persistence',
      severity: 'high',
      stride_tags: ['elevation', 'info_disclosure'],
      steps: ['Discover exposed listener', 'Authenticate or abuse misconfig', 'Plant Run-key persistence']
    })
  });
  await req(`/api/models/${model.id}/mitigations`, {
    method: 'POST',
    body: JSON.stringify({
      title: 'Close public admin listeners',
      description: 'Bind RDP/SMB to management VLAN only; enforce MFA.',
      residual_risk: 0.2
    })
  });

  const pkg = await req('/api/packages', {
    method: 'POST',
    body: JSON.stringify({
      title: 'Serious Threat Brief — Perimeter & Persistence',
      model_id: model.id,
      map_id: graph.map.id,
      severity: 'high',
      confidence: 0.78,
      executive_summary:
        'Observed sensitive listeners and persistence signals on the estate. Recommend immediate exposure reduction and stakeholder briefing.',
      recommended_actions: [
        'Quarantine hosts with 0.0.0.0 RDP/SMB binds',
        'Review HKCU Run persistence entries',
        'Distribute package to official channel'
      ]
    })
  });

  const exported = await req(`/api/packages/${pkg.id}/export`);
  await req(`/api/packages/${pkg.id}/status`, {
    method: 'POST',
    body: JSON.stringify({ status: 'distributed', channel: 'official', note: 'e2e handoff' })
  });

  console.log('--- briefing ---');
  console.log(exported.briefing_markdown);
  console.log('E2E OK', { model: model.id, package: pkg.id, map: graph.map.id });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
