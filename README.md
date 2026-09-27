# asystant-api

A Rust/Actix service with SQLite/Diesel persistence that gives **client services** (companies or
products such as a school platform or a booking app) short-lived, budget-limited
[OpenRouter](https://openrouter.ai) keys for their users.

Each client service authenticates with its own **client key** issued by asystant-api. With it, the
service sets budgets for its tenants and subjects and asks for the OpenRouter key of an
authenticated user. asystant-api creates that key through the OpenRouter management API, one per
tenant, subject, usage bucket and UTC day. It never proxies inference: the user's app talks to
OpenRouter directly with the key it received.

## How it works

1. **Client key.** The operator creates a client (`slug`, name, the OpenRouter workspaces it may use,
   allowed models) and receives its key once: `ask_` plus 64 hex characters. Only its SHA-256 is
   stored. The key lives in the client backend's secret manager and never reaches a browser or app.
   A workspace belongs to one client only. There is no HTTP or command-line surface for this yet;
   it comes with the administration panel.
2. **Budgets.** With that key the client backend sets, per tenant, a ceiling and one of its own
   workspaces where the keys are created, and then a budget per subject inside that ceiling. Amounts
   are integer USD micros (1,000,000 = USD 1). A `daily` bucket resets every UTC day; a `migration`
   bucket is a lifetime budget.
3. **Credential.** After authenticating its user, the client backend calls
   `POST /v1/managed/credentials` with `{tenant, subject, bucket}`. asystant-api reserves the
   smallest remaining tenant/subject balance and creates one OpenRouter key limited to that amount,
   expiring at the end of the UTC day. Repeated calls on the same day return the same key without
   creating another one.
4. **Revocation and usage.** A background worker disables at OpenRouter, every 15 seconds, the keys
   whose budget was lowered, whose client was revoked or that expired. Every 60 seconds it reads the
   confirmed usage of each key and settles the budgets.

See [managed keys](docs/managed-keys.md) for the full flow, states, failure handling and how to
migrate an embedded implementation. The [OpenAPI specification](openapi.yaml) is the HTTP contract,
also served at `/openapi.yaml`.

## Start

Supply the environment variables in [.env.example](.env.example). The binary reads process
environment variables; it does not load a dotenv file.

```sh
cargo run --bin asystant_api
```

Startup applies embedded migrations before listening. Run one replica with a persistent local
volume; no database service is needed. `--migrate-only` and `--serve` remain available for manual
operations. The default listener is `127.0.0.1:8787`; the container listens on `0.0.0.0:8787`. See
[deployment](docs/deployment.md).

Without `OPENROUTER_MANAGEMENT_API_KEY` and `ASYSTANT_MANAGED_ENCRYPTION_KEY` the service starts,
but `POST /v1/managed/credentials` answers 503 `managed_configuration_required`.

Version 0.3.0 removed the ticket/session/turn gateway and its `/admin` panel. Startup refuses the
variables of that flow (`ASYSTANT_PRODUCTS`, `ASYSTANT_MODELS`, `ASYSTANT_ORIGINS`,
`ASYSTANT_ADMIN_TOKEN`, `OPENROUTER_API_KEY`) so a deployment that still depends on it fails loudly,
and the migration drops its tables.

## Security and verification

See [SECURITY.md](SECURITY.md) for the controls and residual risks. Security posture is based on
code and local tests; it is not a certification or production penetration test.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Tests create isolated temporary SQLite files and use an in-memory OpenRouter management API; they
never call OpenRouter.
