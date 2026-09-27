# Changelog

## 0.3.0

- Issue managed OpenRouter keys to client services: per-client keys (`ask_…`,
  stored as SHA-256), tenant ceilings with their OpenRouter workspace, subject
  budgets inside them, and one budget-limited key per tenant, subject, bucket
  and UTC day created through the OpenRouter management API.
- Assign OpenRouter workspaces to exactly one client at creation; tenant
  budgets and every ledger write are limited to the client's own workspaces.
- Seal issued keys with XChaCha20-Poly1305 (`ASYSTANT_MANAGED_ENCRYPTION_KEY`),
  bound to their allocation; never store them in plaintext.
- Revoke keys when a budget is lowered, a client is revoked or a key expires,
  and settle budgets from confirmed OpenRouter usage, in a background worker
  (15-second revocation, 60-second usage sweeps).
- Authorize a recovery for an uncertain issuance without releasing its
  reservation.
- Remove the ticket/session/turn gateway, its inference proxy, CORS origins
  and the `/admin` panel. Startup refuses their variables and the migration
  drops their tables from existing databases.
- One per-peer admission window of 3,000 requests per minute for `/v1`.

## 0.2.0

- Extract the gateway from JhonaCodes/asystant-ai into its own deployment repository.
- Replace PostgreSQL with bundled SQLite and a persistent local volume.
- Serialize accounting writes with immediate transactions, WAL and bounded lock waits.
- Apply embedded migrations by default at startup and keep manual migration modes.
- Add isolated SQLite tests, standalone CI and a container persistence/backup smoke test.
- Preserve the existing /v1 wire contract and Flutter-local tool execution.

This release does not import live PostgreSQL data automatically.
