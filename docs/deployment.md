# Deploy on Dokploy with SQLite

Deploy one application from `JhonaCodes/asystant-api`, branch `main`.
Choose Dockerfile build, repository-root build context `.` and `Dockerfile`.
The internal HTTP port is **8787**. There is no separate database service.

## Persistent storage and startup

Before the first deployment, add a **named volume** mounted at `/data`, for
example `asystant_api_data`. Keep the same volume for every deployment.
The image prepares `/data` for UID/GID **10001:10001** and runs without root.
A bind mount must be pre-created with that ownership. The entire directory must
be writable: SQLite also creates WAL and shared-memory files next to the DB.
Do not mount just the database file, use temporary storage, or share the volume
with another replica. Use a local disk, not NFS/SMB.

`DATABASE_URL` is rejected at startup to prevent an accidental silent switch
from PostgreSQL to an empty SQLite database. Limit bind-mount directory
permissions to the service owner (`0700`).

Set these runtime environment variables in Dokploy (not Docker build arguments):

- `DATABASE_PATH=/data/asystant.db`
- `ASYSTANT_BIND=0.0.0.0:8787`
- `OPENROUTER_MANAGEMENT_API_KEY`: OpenRouter management (provisioning) key of the
  organization that owns the tenants' workspaces, stored as a secret.
- `ASYSTANT_MANAGED_ENCRYPTION_KEY`: 32 random bytes in base64 that seal issued
  keys and the administrators' authenticator secrets (`openssl rand -base64 32`),
  stored as a secret. Keep it for the life of the volume; rotate only at a UTC
  day boundary, and run `admin reset` for every administrator afterwards.
- `ASYSTANT_PUBLIC_ORIGIN=https://ai.jhonacode.com`: the public origin of the
  operator console. Without it `/admin` stays off. An `https://` origin also
  turns on HSTS.
- `ASYSTANT_CLIENT_IP_HEADER` (optional): the header your proxy always
  overwrites with the caller address, for example `CF-Connecting-IP` behind
  Cloudflare or `X-Real-IP` behind Traefik configured to set it. Without it,
  every caller looks like the proxy. Set it only when the container port is not
  reachable except through that proxy.

Set both managed variables or neither; without them the service starts but does
not issue keys and the console stays off. Use [.env.example](../.env.example) as
a template. Placeholder secrets must be replaced. Never commit actual secrets or
SQLite files.

Remove the variables of the removed ticket/session gateway before deploying
0.3.0: `ASYSTANT_PRODUCTS`, `ASYSTANT_MODELS`, `ASYSTANT_ORIGINS`,
`ASYSTANT_ADMIN_TOKEN` and `OPENROUTER_API_KEY`. Startup refuses them so a
deployment that still depends on that flow fails instead of serving 404s. The
first start of 0.3.0 drops that flow's tables from the existing volume.

The first start of 0.4.0 applies migration `0003_operator_console`: it moves
companies to keys created in the console, so API keys of 0.3.0 stop working.
Create new keys in the console and deploy them to each company.

Leave the start command unchanged. The default process applies embedded
migrations before starting HTTP. For manual operations, `--migrate-only` applies
migrations and exits; `--serve` starts without migration and readiness fails if
the schema is missing. Configure exactly **one replica** and stop the previous
container before starting its replacement (no rolling overlap).

## Domain and client integration

Add your HTTPS domain in Dokploy (`ai.jhonacode.com`), pointing to container
port 8787. The same domain serves the API under `/v1` and the console under
`/admin`; `/` redirects to the console. Configure request/header timeouts above
45 seconds (a key creation can take up to 40) and shared admission limits.
Restrict direct access to the container port. Do not expose the volume through
a web server. An access gate in front of `/admin` at the edge (for example
Cloudflare Access) is recommended.

## First administrator

After the first deployment, look for this line in the application logs:

```text
No administrator yet. Open this link once, before … UTC, to set up the /admin console: https://ai.jhonacode.com/admin/setup?token=…
```

Open the link, choose the username and password, scan the QR code with your
authenticator app and confirm with its code. The link works once and for 24
hours; every restart prints a new one until an administrator exists. If the
account is lost later, `docker exec -it CONTAINER asystant_api admin reset
<username>` locks it, signs it out everywhere and prints a new link. See
[operator console](operator-console.md).

Each company stores this HTTPS origin and the API key created for it in the
console in its own secret manager (for example `ASYSTANT_API_URL` and
`ASYSTANT_API_KEY`) and calls the API only from its backend. See
[managed keys](managed-keys.md).

Health endpoints:

- `/health/live`: the process is running.
- `/health/ready`: database and migrated schema are accessible.
- `/openapi.yaml`: public API specification without keys or client data.

Health does not validate the OpenRouter management key; the console's
**Security** page shows when the worker last reached OpenRouter. Once a company
exists, and before enabling users, set a small tenant and subject budget, issue
a credential, lower the budget and check that the worker disables the key in the
OpenRouter workspace.

## Backup, restore and failure handling

Use SQLite's online backup API, not a copy of the live `.db` file alone. The
container includes `sqlite3`; for example, make a consistent snapshot inside the
volume, then copy it to a separately protected backup destination:

```sh
docker exec CONTAINER sqlite3 /data/asystant.db '.backup /data/asystant-backup.db'
docker cp CONTAINER:/data/asystant-backup.db ./asystant-backup.db
```

Protect backups as sensitive data: they hold sealed provider keys, API key
hashes, administrator password hashes and sealed authenticator secrets. Remove temporary snapshots only after confirming off-volume backup
success. For restore, stop the application, preserve the current volume for
recovery, restore into a fresh volume owned by 10001:10001, and start one
instance. Never combine a restored DB with old `-wal`/`-shm` files. Restoring an
old snapshot can roll back revocations and budgets: compare the leases with the
OpenRouter workspaces before serving traffic.

WAL plus `synchronous=FULL` preserves committed writes. `BEGIN IMMEDIATE` makes
reservation, issuance, revocation and settlement atomic; each connection waits
up to five seconds for a writer. Lock exhaustion fails the request; it never
bypasses accounting. OpenRouter calls happen outside database transactions.

Do not release reserved budget just because the process stopped: the worker
settles it from confirmed OpenRouter usage. Monitor disk space and DB growth; no
retention worker is included. A volume on the same machine is persistence, not a
backup.

## Local container validation

```sh
cp .env.example .env
# Replace placeholders through your secret manager.
docker compose up -d --build
curl --fail http://127.0.0.1:8787/health/ready
```

For a credential-free smoke test after building the image:

```sh
docker build -t asystant-api:local .
python3 scripts/check_container.py
```

## Build locally and deploy a prebuilt image

Use this flow when Dokploy should only pull an image instead of compiling Rust.
From a clean `main` checkout synchronized with GitHub:

```sh
./scripts/deploy-local-image.sh
```

Docker Desktop/Engine must be running, Buildx must be available, and `gh` must
be authenticated with GHCR `write:packages` permission. The script securely pipes
the existing GitHub token to Docker login; it never embeds that token or runtime
secrets in the image. It checks the branch/worktree/remote revision, builds
`linux/amd64` locally, and pushes both `:prod` and a full-commit-SHA tag to
`ghcr.io/jhonacodes/asystant-api`. Use `TARGET_PLATFORM=linux/arm64` only if
the Dokploy host uses ARM64, or `TARGET_PLATFORM=linux/amd64,linux/arm64` for both.

In Dokploy change the application provider/source to **Docker image** and use:

```text
ghcr.io/jhonacodes/asystant-api:prod
```

Keep the existing environment, `/data` volume, HTTPS domain and port `8787`.
If GHCR requires authentication, configure registry `ghcr.io`, your GitHub
username and a registry credential with `read:packages` in Dokploy's registry
settings. Do not put registry credentials in application variables or source.
Public repository visibility does not automatically guarantee public package
visibility; the package owner can make the container public in GitHub settings.

Click Deploy after each successful publication. This script publishes the image
but does not trigger a Dokploy restart. Configure one replica and stop-first
replacement so two processes do not overlap on the same SQLite volume.
For rollback, use a previously published SHA tag after verifying schema
compatibility, retaining the same volume. Never delete the volume to roll back.
