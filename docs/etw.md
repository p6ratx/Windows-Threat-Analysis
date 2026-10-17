# ETW / kernel tracing (Windows)

Aegis TI includes a defensive **ETW collector** (`collectors/rust-etw`, binary `bin/rust-etw.exe`).

## Providers

| Provider | GUID | Signals |
|----------|------|---------|
| Microsoft-Windows-Kernel-Process | `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716` | process start/stop, image load |
| Microsoft-Windows-DNS-Client | `1c95126e-7eea-49a9-a3fe-a378b03ddb4d` | DNS queries |
| Microsoft-Windows-TCPIP | `2f07e2ee-15db-40f1-90ef-9d7ba282188a` | kernel network flows |

## Privileges

- Full kernel-process tracing works best when the agent runs **elevated (Administrator)**.
- Without elevation the collector still starts a session when possible and emits `etw.session` with `elevated: false`, plus whatever providers the OS allows.
- Duration: `AEGIS_ETW_SECONDS` (default 6, max 30).

## Pipeline

Events use agent `rust-etw` and types such as:

- `etw.session`, `etw.error`
- `etw.process.start`, `etw.process.stop`, `etw.image.load`
- `etw.dns.query`, `etw.network.flow`

They ingest into the same threat map + activity dossier path as other collectors. Function tags include `etw_process`, `dns`, `network`, `etw`.

## Build

```powershell
.\scripts\build-collectors.ps1
```

Or:

```powershell
cargo build --release --manifest-path collectors/rust-etw/Cargo.toml
copy collectors\rust-etw\target\release\aegis-rust-etw.exe bin\rust-etw.exe
```

Scans include `rust-etw` by default alongside `go-net` and `rust-host`.
