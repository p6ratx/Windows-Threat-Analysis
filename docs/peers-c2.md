# Peers, C2, baselines, DNS, beacons

Aegis TI maps **what is talking to whom**, learns a **baseline**, joins **DNS↔IP**, scores **C2 / beacon cadence**, and classifies **software behavior**.

## Tiers

| Tier | Meaning |
|------|---------|
| `watch` | Seen egress; allowlisted or low score |
| `candidate` | Heuristic score ≥ 0.45 or new unknown-process public egress |
| `confirmed` | Analyst pin, strong beacon + elevated C2 on unknown process, or offline IOC hit |

Loopback / link-local (`127.0.0.1`, `::1`, `fe80::/10`, …) is **suppressed** from C2/beacon threat views unless `AEGIS_HUNT_LOOPBACK=1` (default OFF).

## Continuity / baselines

- Each scan/poll writes `peer_observations`
- **Default rolling window: 7 days** (`AEGIS_BASELINE_WINDOW_DAYS`, exposed as `window_days` on `/api/peers/delta` and `/api/baselines/meta`)
- `peer_baselines` promotes repeated pairs to `baseline` / marks `new` / `rare` using sightings, distinct scans, and ≥2 distinct calendar days inside the window
- Day-1 “new” is expected; day-7 repeated sightings can become `baseline`
- Background poller: `AEGIS_PEER_POLL_MS` (default 90000; `0` disables)

## Watches / alerts

Quiet by default. `/api/alerts` fires only on:

- High C2 (≥ 0.75) on public IPs
- New public egress from unknown/unsigned processes
- Rare baseline + candidate C2 from unknown process

Not every peer delta, trusted HTTPS, or loopback.

## APIs

- `GET /api/peers`, `/api/c2`, `/api/attribution`
- `GET /api/peers/delta`, `/api/peers/compare?a=&b=`
- `GET /api/c2/beacons`, `/api/dns`, `/api/watches`, `/api/alerts`, `/api/fleet`
- `POST /api/peers/rebuild`, `/api/baselines/rebuild`, `/api/denoise`

## Enrichment

Offline RFC/IOC seeds + optional Authenticode cache + PTR reverse DNS (cached). Candidate rows expose `org` / `asn` / `publisher` / `why` when available. Set `AEGIS_ENRICH_URL` for optional HTTP enrichment (never required; timed out).

## Honest limits

High C2 / beacon scores mean **investigate**, not confirmed actor attribution.
