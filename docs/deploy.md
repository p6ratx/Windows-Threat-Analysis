# Docker deploy

From a clone, on any machine with Docker:

```bash
cd deploy
docker compose up --build
```

That build installs Node, Go, Rust, and Python dependencies inside the image. You do not install them on the host.

- Gateway: http://127.0.0.1:8787
- Health: http://127.0.0.1:8787/api/health
- Data volume: `aegis_data` (SQLite database and `aegis.token`)
- Host id: the machine name Compose sees (`COMPUTERNAME` on Windows, `HOSTNAME` on Linux), unless `AEGIS_HOST_ID` is set
- API token: generated on first boot, stored in the volume, printed once in the container log

Point the desktop console Settings → Gateway URL to `http://127.0.0.1:8787` and paste that token.

Read the token again later:

```bash
docker compose exec gateway cat /data/aegis.token
```

## What the container scans

`go-net` and `rust-host` are built into the image and the gateway starts them. They see the container's network and process namespaces.

On a Linux Docker engine, this sees the host machine:

```bash
docker compose -f docker-compose.yml -f docker-compose.host.yml up --build
```

Docker Desktop on Windows runs a Linux VM. That overlay cannot see the Windows desktop session or kernel ETW. For a Windows ETW scan, build the native collectors with `scripts/build-collectors.ps1` and run the gateway on Windows. Do not copy `data/aegis.token` or any start script from another PC; each machine provisions its own.

## Native Windows agents

Build collectors on Windows and either:

1. Place binaries in `bin/go-net.exe`, `bin/rust-host.exe`, and `bin/rust-etw.exe` for local gateway spawn, or
2. POST evidence to `POST /api/events/ingest` from remote hosts into the Dockerized broker.
