# Changelog

## 0.4.1

- Set up administrators in the browser through a one-time link (24 hours):
  choose the username and password, scan the authenticator QR code (SVG drawn
  in Rust, no JavaScript) and confirm with a code. While no administrator
  exists, every start logs the link; `admin create` prints one for another
  administrator. No password is printed anymore.
- `admin reset` disables the account and ends its sessions immediately, and
  prints a link that sets a new password and authenticator.
- Show the QR code when replacing the authenticator under Security.
- Migration `0004_admin_setup` adds the setup links table.

## 0.4.0

- Add the operator console at `/admin` (served on `ai.jhonacode.com`):
  server-rendered HTML without JavaScript to create companies, hand out their
  API keys, follow spend per company and tenant, authorize recoveries, suspend
  companies and export monthly spend as CSV.
- Protect it with argon2id passwords plus single-use TOTP codes, `__Host-`
  session cookies (30 minutes idle, 8 hours total), per-session CSRF tokens and
  an `Origin` check, a lockout after five failures in 15 minutes, a fresh code
  for every change, a strict CSP and an append-only audit log enforced by
  SQLite triggers.
- Replace the single key per client with several API keys per company:
  `ask_live_` + 256 random bits + a checksum, with issue/manage permissions, a
  mandatory expiry, optional source addresses, last use, revocation and
  rotation with a 7-day overlap.
- Add an optional company daily cap that bounds the sum of its daily tenant
  ceilings, and company suspension that rejects its keys and revokes its live
  OpenRouter keys.
- Add `ASYSTANT_PUBLIC_ORIGIN` (required for the console, turns on HSTS for
  HTTPS) and `ASYSTANT_CLIENT_IP_HEADER` (the caller address behind a proxy).
- Migration `0003_operator_console` removes the 0.3.0 key column: API keys of
  0.3.0 stop working and must be recreated in the console.

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
