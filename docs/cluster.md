# Cluster notes

Aegis TI is designed as a threat-intel **broker**:

1. Edge / host agents (Go + Rust) emit evidence with `host_id` + `agent`.
2. Central gateway (Docker) ingests events into the active threat map.
3. Analysts build threat models and assemble intel packages.
4. Packages are the distribution unit for official/internal channels (`distribution_log`).

Gateway modes (settings `gateway_mode`): `local` | `edge` | `central`.

Future: replace JSONL stdin with gRPC; swap SQLite for Postgres at the central tier.
