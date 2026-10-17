# ML threat-actor movement pipeline

The Python ML worker (`ml/aegis_ml`) now runs a full pipeline against host + network + ETW evidence:

1. **Anomaly scoring** — Isolation Forest over multi-agent features (go-net, rust-host, rust-etw)
2. **Edge suggestion** — links hosts to high-severity ports/findings/processes
3. **Movement mapping** — kill-chain stages and ordered hops for how an actor could move

## Stages covered

initial_access → execution → persistence → privilege_escalation → defense_evasion → credential_access → discovery → lateral_movement → collection → command_and_control → exfiltration → impact

Windows signals mapped include SMB/RDP/RPC/WinRM exposure, process/image ETW, Run-key persistence, LSASS-adjacent activity, DNS, and TCPIP flows.

## Confidence

Scores are soft-capped when evidence is mostly stock Windows noise (PowerShell host DLLs, generic RPC, ordinary Run keys, bare DNS/ETW flows) **without** corroborating high-tier C2, suspicious credential dumping, or anomalous persistence. A healthy box should not casually read as “Persistent intrusion operator” at 0.99.

## API

- `POST /api/ml/score` — full pipeline (score + movement)
- `POST /api/ml/movement` — alias
- `GET /api/movement?latest=1` — latest campaign + hops
- `GET /api/movement/:id` — campaign detail

## UI

**Movement** tab — run pipeline, view stage coverage and hop-by-hop actor path. Map button on Threat Map: **Map actor movement (ML)**.
