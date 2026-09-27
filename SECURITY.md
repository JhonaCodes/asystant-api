# Security policy and deployment controls

## Scope

This repository contains the self-hosted Rust service that issues managed OpenRouter keys to client
services. The review covers code, protocol boundaries, database transactions, configuration and
local tests. It is not an OWASP certification or an external penetration test. Client backends,
their user authentication, OpenRouter's infrastructure and production ingress configuration are
outside this repository's verification boundary.

The service is **server-to-server**: only client backends call it, with their client key. It should
be reachable over HTTPS only behind a controlled ingress. Public API documentation does not mean
anonymous access: every `/v1` route requires a client key.

## Reporting

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/JhonaCodes/asystant-api/security/advisories/new). Do not post credentials, customer data or an exploit containing secrets in a public issue. Include the affected version, reproduction steps and expected impact. Version 0.3.x is the currently maintained line.

## Trust boundaries and controls

| OWASP API Security Top 10 2023 concern | Implemented control | Required operator or client action |
| --- | --- | --- |
| API1 / API5: object and function authorization | Every query is scoped by the authenticated client; a client cannot read nor change another client's tenants, budgets or keys. OpenRouter workspaces are assigned to exactly one client when it is created, and every ledger write checks that the allocation's workspace belongs to the client. Amounts always come from stored policies. | Derive `tenant` and `subject` from the client's verified user session, never from values the user can choose. Assign each client only the workspaces it pays for. |
| API2: authentication | Client keys with 244 random bits from two v4 UUIDs (`ask_` + 64 hex), only their SHA-256 stored, rejected once the client is revoked. | Keep the client key in the client backend's secret manager; never ship it to a browser or app. Revoke and recreate it if exposed. |
| API3: property authorization | Closed request DTOs (`deny_unknown_fields`), bounded identifiers and amounts, 64 KiB request limit. | Treat the returned OpenRouter key as a secret of that subject for that day. |
| API4 / API6: resource consumption and sensitive flows | Integer USD-micro budgets per tenant and subject, reserved in an immediate SQLite transaction before any key is created; one key per subject, bucket and day; the POST to OpenRouter is never retried; process-local per-peer admission. | Apply shared rate limits and timeouts at ingress, restrict origin-server access and monitor storage growth. |
| API7: SSRF | Fixed OpenRouter management endpoint with redirects disabled; requests cannot supply a URL. | Restrict server egress and filesystem access to the database volume. |
| API8: configuration | Generic errors, `no-store` responses, no-sniff and restrictive headers, non-root container, startup refuses partial managed settings and the removed gateway variables. | Terminate TLS, configure HSTS at ingress, restrict access to the SQLite volume, keep secrets out of logs and images. |
| API9: inventory | Versioned `/v1` routes and an OpenAPI contract; documented health endpoints. | Inventory deployed revisions and revoke obsolete clients. |
| API10: unsafe consumption of OpenRouter | Bounded response reads (64 KiB), deadlines, verification that OpenRouter applied exactly the requested name, limit, expiry and workspace before handing out a key, no provider bodies in errors or logs. | Keep the management key scoped to the organization that owns the workspaces; review OpenRouter terms and pricing. |

Reference: [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).

## Secrets at rest

Issued OpenRouter keys are sealed with XChaCha20-Poly1305 using `ASYSTANT_MANAGED_ENCRYPTION_KEY`
and a random nonce per operation. The ciphertext is bound to its allocation (client, tenant,
subject, bucket, limit, expiry, workspace) and to the key hash, so it cannot be moved to another
lease. The sealed value is erased when a lease leaves `issued`. Client keys are stored only as
SHA-256. Neither secret type prints in `Debug` or `Serialize` output.

## Admission details

The process-local guard permits 3,000 `/v1` requests per minute per TCP peer. Client backends act
for all their users, often from one address, so the window is wide. The table is bounded to 10,000
entries and fails closed at capacity. It ignores `Forwarded` and `X-Forwarded-For`; callers cannot
spoof an address to bypass it. Health and documentation routes are outside these counters. The
counters are per process and reset on restart; they are not a distributed quota or a DDoS defense.

## Operational limitations

- A client sets its own tenant ceilings: there is no per-client maximum. The only upper bound on
  its spending is the balance of the OpenRouter organization behind its workspaces. Limit it there
  (workspace or organization limits) until a per-client cap exists.
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
