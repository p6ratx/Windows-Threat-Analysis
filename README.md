# Aegis TI

Threat mapping and threat modeling platform for serious threats. Aegis TI turns host and network evidence into **threat maps**, **threat models**, and curated **intel packages** for official and internal channels.

## Stack

| Layer | Tech |
|-------|------|
| Desktop console | Tauri 2 + React |
| Gateway | Node.js (Express) + SQLite |
| Network collector | Go |
| Host collector | Rust |
| ETW / kernel tracing | Rust (`ferrisetw`) — see [docs/etw.md](docs/etw.md) |
| ML | Python (Isolation Forest) |
| Deploy | Docker Compose |

## Quick start (any machine)

Docker is the setup. It builds the gateway, network collector, host collector, and ML dependencies. The first boot creates a private database and API token for that machine. Nothing in the image is tied to a developer PC.

```bash
cd deploy
docker compose up --build
```

Gateway: `http://127.0.0.1:8787/api/health`

The API token is printed once in the gateway log (`API token (paste into Settings once)`). Paste it into the desktop Settings pane. The container hostname is this machine's `COMPUTERNAME` or `HOSTNAME`.

On a Linux Docker engine, attach the scan to the host itself:

```bash
docker compose -f docker-compose.yml -f docker-compose.host.yml up --build
```

Windows ETW still needs the native collectors (`scripts/build-collectors.ps1`) because kernel ETW cannot run inside the Linux image. `go-net` and `rust-host` in the image scan the network and processes visible to the container.

## Local development

```bash
# Gateway
cd gateway && npm install && npm run dev

# Collectors (optional local binaries)
cd collectors/go-net && go build -o ../../bin/go-net .
cd collectors/rust-host && cargo build --release

# ML
cd ml && pip install -r requirements.txt

# Desktop
cd apps/desktop && npm install && npm run tauri dev
```

## Product workflows

1. **Maps** — living graph of hosts, processes, ports, findings
2. **Peers / C2 / Attribution** — baselines, DNS join, beacons, tiers ([docs/peers-c2.md](docs/peers-c2.md))
3. **Fleet** — multi-host `host_id` inventory ([docs/fleet.md](docs/fleet.md))
4. **Models** — assets, actors, boundaries, STRIDE scenarios, mitigations
5. **Packages** — exportable briefings with peer/C2 evidence appendix


## Safety

Defensive intelligence only. Collectors are read-only / observational. No exploit tooling.

See [docs/security.md](docs/security.md) for API token, CORS, and container hardening notes.
