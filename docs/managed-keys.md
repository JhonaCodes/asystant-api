# Managed OpenRouter keys

asystant-api issues OpenRouter keys on behalf of **client services**. A client is a company or
product (for example `aulamas` or `turnosqr`). Inside a client, a **tenant** is the organization
that owns a budget (a school, a company) and a **subject** is the person who uses the key (a
teacher, an employee). Tenant and subject identifiers belong to the client: asystant-api treats them
as opaque text of up to 200 characters.

The client is the authority on who its users are. asystant-api is the authority on money: amounts
always come from the stored policies, never from the request.

## Client keys

A client has a unique `slug` (2–40 lowercase letters, digits or hyphens), a name, the OpenRouter
workspaces it may use (1–64) and the list of models it may advertise to its apps (default
`openai/gpt-oss-120b`). A workspace belongs to exactly one client: assigning it to a second client
is rejected, so no client can place keys inside another company's workspace. Its key is `ask_` plus
64 hex characters, shown once at creation. Only its SHA-256 is stored, so a lost key cannot be
recovered: create a new client.

Every `/v1/managed` route requires `Authorization: Bearer <client key>`. Every query is scoped by
the authenticated client, so a client never reads nor changes another client's tenants, budgets or
keys. Revoking a client rejects its key at once and queues all its live OpenRouter keys for
revocation.

There is no HTTP or command-line surface to create clients yet: `ClientService::create` exists and
is covered by tests, and the administration panel will expose it. Until then no client can call
the API.

## Budgets

| Route | Purpose |
| --- | --- |
| `PUT /v1/managed/tenants/{tenant}/budget` | Tenant ceiling and the OpenRouter `workspace_id` where its keys are created |
| `PUT /v1/managed/tenants/{tenant}/subjects/{subject}/budget` | Subject budget inside the ceiling |
| `GET /v1/managed/tenants/{tenant}/budget` | Policies, today's accounts and the state of each key |

Rules:

- The ceiling must exist before any subject budget, and the sum of the subject budgets can never
  exceed it (409).
- The tenant workspace must be one assigned to the client (403) and cannot change once budgets
  exist (409).
- The client sets its own ceilings; there is no per-client maximum yet.
- Each change stores who made it (`actor`) in an audit event. Repeating the same value is a no-op.
- **Lowering** a ceiling queues every live key of the tenant for revocation; lowering a subject
  budget queues that subject's key. Set a subject to 0 to stop issuing to them.
- A `daily` account opens every UTC day with the policy limit; a `migration` account lasts forever.

## Issuing a key

`POST /v1/managed/credentials` with `{"tenant", "subject", "bucket"}`, called by the client
backend after it authenticated the subject:

1. Resolve the allocation: the smallest remaining balance of the tenant and subject accounts for
   today, the tenant workspace and an expiry at the end of the UTC day.
2. Reserve that amount in both accounts and create the day's **lease**. There is at most one current
   lease per client, tenant, subject, bucket and day (unique index).
3. If the lease is already `issued`, decrypt and return the stored key: **no second key is created**.
4. Otherwise claim the lease (`reserved` → `provisioning`) and call OpenRouter once:
   `POST https://openrouter.ai/api/v1/keys` with `name = <client slug>:<bucket>:<lease id>`, the
   limit in USD, `expires_at`, `workspace_id` and `include_byok_in_limit: true`.
5. Check that OpenRouter applied exactly that policy, seal the key with
   `ASYSTANT_MANAGED_ENCRYPTION_KEY` (XChaCha20-Poly1305, bound to the allocation) and mark the lease
   `issued`. The key never reaches the database in plaintext.

The response carries `api_key`, `expires_at`, `refresh_after` (one minute) and `allowed_models`
with `Cache-Control: no-store`. The client hands the key to the subject's app, which calls OpenRouter
with it directly.

The POST is **never retried**: a timeout can hide a key that was actually created. A failure leaves
the lease `uncertain` (or back to `reserved` when OpenRouter proved it rejected the request with
400, 401, 403 or 429) and records the attempt. Transactions are never held open during HTTP.

## Lease states

| State | Meaning |
| --- | --- |
| `reserved` | Budget held, no request sent yet |
| `provisioning` | This process owns the single creation attempt |
| `uncertain` | The attempt may or may not have created a key |
| `issued` | Key created, confirmed and sealed |
| `revocation_pending` | Must be disabled at OpenRouter; the sealed key is already erased |
| `revoked` | Disabled at OpenRouter; usage keeps being observed |

## Worker

Started when both managed variables are set.

- **Every 15 seconds** it moves `uncertain` leases, `provisioning` leases older than two minutes and
  expired `issued` leases to `revocation_pending`. Then it disables each one at OpenRouter
  (`PATCH /keys/{hash}` with `disabled: true`), looking the key up by name when the hash is unknown.
  A lease is confirmed `revoked` only after OpenRouter answers `disabled: true`.
- **Every 60 seconds** it reads the confirmed usage of issued and revoked keys
  (`GET /keys/{hash}`) and settles it: spent grows, reserved shrinks, never twice for the same
  observation. Revoked keys are observed again daily, because an in-flight inference can be charged
  after the key was disabled. A key modified outside asystant-api is revoked, never recreated.

Reserved money is **never** released by a timeout, an expiry or a revocation alone; only a
confirmed usage observation settles it. A subject whose key was revoked receives a new one only
after its usage has been observed, and only from balance left after that reservation.

A lease still `reserved` (its key was never requested) is closed as `revoked` without a key when
its budget is lowered. It will never have a usage observation, so its reservation stays held: for
the `daily` bucket until the day ends, for the `migration` bucket permanently. This matches the
reference implementation.

## Recovery

When an issuance stays `uncertain` or `revocation_pending`, the subject cannot get another key that
day. `POST /v1/managed/tenants/{tenant}/leases/{lease}/recovery` with a limit, a reason of 10–500
characters, `acknowledge_pending_reserve: true` and the `actor` reserves a new allocation for today
and queues the previous lease for revocation. The previous reservation stays held until its usage
is confirmed. Repeating the same authorization returns the stored recovery.

## Configuration

| Variable | Purpose |
| --- | --- |
| `OPENROUTER_MANAGEMENT_API_KEY` | OpenRouter management (provisioning) key of the organization that owns the workspaces. It creates, reads and disables keys; it cannot run inference |
| `ASYSTANT_MANAGED_ENCRYPTION_KEY` | 32 random bytes in base64 (`openssl rand -base64 32`) that seal issued keys |

Both or neither. Rotating the encryption key makes the day's stored keys unreadable: those subjects
get a 503 until their keys expire at the end of the UTC day and the worker revokes them. Rotate at a
day boundary.

## Migrating an embedded implementation

This flow is the one AulaMás runs inside its own backend (`aula_ai` managed keys). Moving a service
like that onto asystant-api, without breaking its apps:

1. **Deploy** asystant-api with the same OpenRouter management organization and a new encryption
   key. Create the client (slug `aulamas` keeps the key names identical) with the workspaces its
   institutions already use, and store its key in the service as `ASYSTANT_API_URL` and
   `ASYSTANT_API_KEY`.
2. **Copy the policies**: for each institution, call the tenant `PUT` with its ceiling and
   workspace; for each teacher, the subject `PUT`. For the `migration` bucket, load as ceiling the
   remaining balance at cut-over (`limit - spent - reserved`), so no budget is replenished.
3. **Cut over at a UTC day boundary**: the service stops issuing from its own ledger and calls
   `POST /v1/managed/credentials`. Its keys of the previous day expire at midnight UTC. Keep its own
   revocation and usage worker running until every old lease is `revoked` and its usage settled.
4. **Adapt the service**: its credential and budget services become an HTTP client of this API. The
   contract of its own apps does not change; it maps `institution_id`/`staff_id` to
   `tenant`/`subject`.
5. **Retire** the embedded module and its tables in a new migration of that service.
