# Security policy and deployment controls

## Scope

This repository contains the self-hosted Rust service that issues managed OpenRouter keys to client
services. The review covers code, protocol boundaries, database transactions, configuration and
local tests. It is not an OWASP certification or an external penetration test. Client backends,
their user authentication, OpenRouter's infrastructure and production ingress configuration are
outside this repository's verification boundary.

The `/v1` API is **server-to-server**: only client backends call it, with their API key. The
operator console at `/admin` is for the operator only. Both should be reachable over HTTPS only
behind a controlled ingress. Public API documentation does not mean anonymous access: every `/v1`
route requires an API key and every console page an administrator session.

## Reporting

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/JhonaCodes/asystant-api/security/advisories/new). Do not post credentials, customer data or an exploit containing secrets in a public issue. Include the affected version, reproduction steps and expected impact. Version 0.4.x is the currently maintained line.

## Trust boundaries and controls

| OWASP API Security Top 10 2023 concern | Implemented control | Required operator or client action |
| --- | --- | --- |
| API1 / API5: object and function authorization | Every query is scoped by the authenticated client; a client cannot read nor change another client's tenants, budgets or keys. OpenRouter workspaces are assigned to exactly one client when it is created, and every ledger write checks that the allocation's workspace belongs to the client. Amounts always come from stored policies. | Derive `tenant` and `subject` from the client's verified user session, never from values the user can choose. Assign each client only the workspaces it pays for. |
| API2: authentication | API keys with 256 random bits (`ask_live_` + 43 base62 + a CRC-32 checksum), only their SHA-256 stored, with a mandatory expiry, optional source ranges, and rejected once revoked, expired or the company is suspended. Malformed keys fail the checksum before any lookup. | Keep the API key in the client backend's secret manager; never ship it to a browser or app. Rotate it in the console if exposed. |
| API3: property authorization | Closed request DTOs (`deny_unknown_fields`), bounded identifiers and amounts, 64 KiB request limit. | Treat the returned OpenRouter key as a secret of that subject for that day. |
| API4 / API6: resource consumption and sensitive flows | Integer USD-micro budgets per tenant and subject, reserved in an immediate SQLite transaction before any key is created; an optional company daily cap that bounds the sum of its daily tenant ceilings; one key per subject, bucket and day; the POST to OpenRouter is never retried; process-local per-peer admission. | Set a daily cap on every company; apply shared rate limits and timeouts at ingress, restrict origin-server access and monitor storage growth. |
| API5: function authorization between keys | Each API key carries its own permissions: issuing credentials, managing budgets, or both; any other call answers 403. | Give the backend that serves users an issue-only key; keep the managing key where budgets are administered. |
| API7: SSRF | Fixed OpenRouter management endpoint with redirects disabled; requests cannot supply a URL. | Restrict server egress and filesystem access to the database volume. |
| API8: configuration | Generic errors, `no-store` responses, no-sniff and restrictive headers, HSTS when the public origin is HTTPS, non-root container, startup refuses partial managed settings and the removed gateway variables. | Terminate TLS, restrict access to the SQLite volume, keep secrets out of logs and images. |
| API9: inventory | Versioned `/v1` routes and an OpenAPI contract; documented health endpoints; every API key with its label, last use and expiry in the console. | Inventory deployed revisions and revoke unused keys. |
| API10: unsafe consumption of OpenRouter | Bounded response reads (64 KiB), deadlines, verification that OpenRouter applied exactly the requested name, limit, expiry and workspace before handing out a key, no provider bodies in errors or logs. | Keep the management key scoped to the organization that owns the workspaces; review OpenRouter terms and pricing. |

Reference: [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).

## Operator console

| Threat | Control |
| --- | --- |
| Stolen password | argon2id (64 MiB, 3 passes) plus a TOTP code (RFC 6238, ±30 s); each time step is consumed atomically, so a code works once |
| Guessing | Five failures in 15 minutes lock the username and the source address; unknown usernames spend the same argon2 time; one generic message |
| Session theft | 256-bit token in a `__Host-` cookie (Secure, HttpOnly, SameSite=Strict), stored as SHA-256, 30 minutes idle and 8 hours total, revocable per session |
| Cross-site requests | Per-session token compared in constant time, and the `Origin` (or `Referer`) must equal `ASYSTANT_PUBLIC_ORIGIN` |
| A hijacked session | Every change asks for a fresh authenticator code; refusals are audited |
| Script injection, framing | No JavaScript at all; `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`; every value escaped; `X-Frame-Options: DENY` |
| Covering tracks | Append-only audit log; SQLite triggers abort any update or delete |
| Spreadsheet injection | CSV cells that start with `=`, `+`, `-`, `@`, tab or carriage return are prefixed with `'` |

There is no sign-up: administrators are created and reset only from the shell (`asystant_api admin
create|reset <username>`). Authenticator secrets are sealed with `ASYSTANT_MANAGED_ENCRYPTION_KEY`.
An access gate at the edge in front of `/admin` (for example Cloudflare Access or an allowlist) is
recommended as a factor that lives outside this service.

Behind a proxy, set `ASYSTANT_CLIENT_IP_HEADER` to a header the proxy always overwrites; otherwise
every caller looks like the proxy for key source ranges, lockout and audit sources. Never set it
when the service is reachable without that proxy: a caller could choose its own address.

## Secrets at rest

Issued OpenRouter keys are sealed with XChaCha20-Poly1305 using `ASYSTANT_MANAGED_ENCRYPTION_KEY`
and a random nonce per operation. The ciphertext is bound to its allocation (client, tenant,
subject, bucket, limit, expiry, workspace) and to the key hash, so it cannot be moved to another
lease. The sealed value is erased when a lease leaves `issued`. API keys, administrator session
tokens and passwords are stored only as SHA-256 or argon2id hashes. No secret type prints in
`Debug` or `Serialize` output, and the audit log never holds a key.

## Admission details

The process-local guard permits 3,000 `/v1` requests per minute per TCP peer. Client backends act
for all their users, often from one address, so the window is wide. The table is bounded to 10,000
entries and fails closed at capacity. It ignores `Forwarded`, `X-Forwarded-For` and
`ASYSTANT_CLIENT_IP_HEADER`; callers cannot spoof an address to bypass it. Health, documentation
and console routes are outside these counters (the console has its own sign-in lockout). The
counters are per process and reset on restart; they are not a distributed quota or a DDoS defense.

## Operational limitations

- A company sets its own tenant ceilings. The daily cap bounds the sum of its `daily` ceilings;
  `migration` (lifetime) ceilings are outside it. A company without a cap is bounded only by the
  balance of the OpenRouter organization behind its workspaces: set a cap, and workspace limits at
  OpenRouter as a second line.
- Reserved money is only released by a confirmed usage observation. Monitor `uncertain` and
  `revocation_pending` leases in the budget overview; authorize a recovery only after checking the
  OpenRouter workspace.
- The worker needs outbound access to OpenRouter. While it cannot reach it, lowered budgets keep
  their live keys until the key expires at the end of the UTC day.
- No retention worker is included. Monitor database growth; keep revocation and usage evidence.
- Run one replica using a local persistent volume owned by UID 10001. Use SQLite online backups or
  stop the service before copying all database files; test restore procedures. Restoring an old
  snapshot can resurrect leases that were already revoked: reconcile against OpenRouter before
  serving traffic.
- Run dependency security checks in CI and rebuild images for security updates. No production
  penetration test, load test or multi-replica verification has been performed.

## Secrets

`.env`, `.env.*`, local state and build artifacts are ignored by Git. `.env.example` contains
placeholders only. The OpenRouter management key and the encryption key must be supplied by the
deployment secret manager, never as Docker build arguments. Avoid logging bearer headers, issued
keys or customer data.
