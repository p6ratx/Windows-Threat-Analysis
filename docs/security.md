# Security notes

## Trust boundary
- The Node gateway is the control plane. Treat it as sensitive.
- Bind Docker publish to `127.0.0.1:8787` by default (see `deploy/docker-compose.yml`).
- API auth is **always required**. If `AEGIS_API_TOKEN` is unset, the gateway auto-provisions a token into `settings.api_token` and `data/aegis.token` and prints it once. Desktop Settings must store that token. Do not commit `data/aegis.token`.

## Mitigations in this build
- Auto-provisioned / env API token on all `/api/*` except `/api/health`
- Stricter rate limit on `/events/ingest`
- Refusal of synthetic peers (`test.exe`, RFC5737 documentation IPs) unless `AEGIS_ALLOW_SYNTHETIC=1`
- Input validation / enum allowlists on API bodies
- Prototype-pollution key stripping on attrs objects
- Collector binary path allowlist (blocks arbitrary `AEGIS_*_BIN` execution)
- ML DB path allowlist + parameterized SQL
- Rate limiting (in-memory)
- Security headers, disabled `X-Powered-By`
- CORS allowlist (localhost/tauri by default)
- WebSocket ignores inbound commands; token via `?token=`
- Request body size capped (512kb)
- Package briefing markdown escaping + peer/C2/DNS evidence appendix
- Desktop gateway URL scheme allowlist (http/https only)
- Container: non-root, `cap_drop: ALL`, `no-new-privileges`, read-only root FS
- Collector Authenticode *signing* is an operator responsibility (`signtool` with your cert) — the gateway only *reads* signatures when present

## Residual risks
- No multi-tenant authz yet — one token is shared-secret, not per-user RBAC
- In-memory rate limits reset per process and are not cluster-wide
- Host collectors still need OS privileges for deep Windows signals; run least-privilege where possible
