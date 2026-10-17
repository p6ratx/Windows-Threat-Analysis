# Fleet (multi-host)

Aegis TI supports **incremental fleet** on a shared gateway using distinct `host_id` values. It does **not** invent a second host — a single-machine estate shows only that machine's hostname.

## Local host

Collectors inherit `AEGIS_HOST_ID` (or the machine hostname). The gateway also stores `settings.host_id`. Placeholder ids (`local-host`, `test-host`, `smoke-host`) are filtered from fleet listings and remapped when possible.

## Remote agent pattern

1. Run a central gateway with API token (`data/aegis.token` or `AEGIS_API_TOKEN`).
2. On each estate host, run collectors (or POST JSONL events) with:
   - `AEGIS_HOST_ID=<unique-host-name>`
   - `X-Aegis-Token: <token>`
3. `POST /api/events/ingest` with evidence events that include `host_id`.

Agents are upserted into the `agents` table on ingest. Open the **Fleet** tab to see hosts, peer counts, and last ETW elevation status.

## Per-host intel

Peers, C2, baselines, beacons, DNS, and watches/alerts all key on `host_id`. Filter with `?host_id=` on those APIs when comparing machines.

## Notes

- One active threat map merges all hosts; filter Peers/Activity by host id.
- Do not share API tokens across untrusted networks without TLS.
