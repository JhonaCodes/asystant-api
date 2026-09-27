-- The ticket/session/turn gateway was removed. Databases deployed with it still
-- hold its tables; fresh databases never created them.
DROP TABLE IF EXISTS requests;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS registrations;
DROP TABLE IF EXISTS revoked_sessions;
DROP TABLE IF EXISTS consumed_tickets;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS admin_policy;

-- A company or service that integrates with the API. Only the SHA-256 of its
-- key is stored; the key itself is shown once when the client is created.
CREATE TABLE managed_clients (
    id             TEXT PRIMARY KEY NOT NULL,
    slug           TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 2 AND 40 AND slug NOT GLOB '*[^a-z0-9-]*'),
    name           TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    key_hash       TEXT NOT NULL UNIQUE CHECK (length(key_hash) = 64 AND key_hash NOT GLOB '*[^0-9a-f]*'),
    allowed_models TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    revoked_at     TEXT
);

-- Assigned by the operator when the client is created. The primary key makes
-- a workspace belong to exactly one client, so no client can place tenant keys
-- in another company's workspace.
CREATE TABLE managed_client_workspaces (
    workspace_id TEXT PRIMARY KEY NOT NULL,
    client_id    TEXT NOT NULL REFERENCES managed_clients (id) ON DELETE RESTRICT,
    created_at   TEXT NOT NULL
);

CREATE INDEX managed_client_workspaces_client ON managed_client_workspaces (client_id);

CREATE TABLE managed_policies (
    id               TEXT PRIMARY KEY NOT NULL,
    client_id        TEXT NOT NULL REFERENCES managed_clients (id) ON DELETE RESTRICT,
    tenant           TEXT NOT NULL,
    owner_kind       TEXT NOT NULL CHECK (owner_kind IN ('tenant', 'subject')),
    owner_id         TEXT NOT NULL,
    workspace_id     TEXT NOT NULL,
    bucket           TEXT NOT NULL CHECK (bucket IN ('daily', 'migration')),
    limit_usd_micros BIGINT NOT NULL CHECK (limit_usd_micros BETWEEN 0 AND 9007199254740991),
    updated_by       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    CHECK (owner_kind <> 'tenant' OR owner_id = tenant),
    UNIQUE (client_id, tenant, owner_kind, owner_id, bucket)
);

CREATE TABLE managed_policy_events (
    id                        TEXT PRIMARY KEY NOT NULL,
    policy_id                 TEXT NOT NULL REFERENCES managed_policies (id) ON DELETE RESTRICT,
    actor                     TEXT NOT NULL,
    previous_limit_usd_micros BIGINT,
    limit_usd_micros          BIGINT NOT NULL,
    created_at                TEXT NOT NULL
);

CREATE INDEX managed_policy_events_policy ON managed_policy_events (policy_id, created_at);

-- reserved_usd_micros is never released by timeout, expiry or revocation:
-- only a confirmed provider usage observation settles it.
CREATE TABLE managed_budget_accounts (
    id                  TEXT PRIMARY KEY NOT NULL,
    client_id           TEXT NOT NULL REFERENCES managed_clients (id) ON DELETE RESTRICT,
    tenant              TEXT NOT NULL,
    owner_kind          TEXT NOT NULL CHECK (owner_kind IN ('tenant', 'subject')),
    owner_id            TEXT NOT NULL,
    workspace_id        TEXT NOT NULL,
    bucket              TEXT NOT NULL CHECK (bucket IN ('daily', 'migration')),
    period_key          TEXT NOT NULL,
    limit_usd_micros    BIGINT NOT NULL CHECK (limit_usd_micros >= 0),
    spent_usd_micros    BIGINT NOT NULL DEFAULT 0 CHECK (spent_usd_micros >= 0),
    reserved_usd_micros BIGINT NOT NULL DEFAULT 0 CHECK (reserved_usd_micros >= 0),
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    CHECK (owner_kind <> 'tenant' OR owner_id = tenant),
    CHECK (
        (bucket = 'migration' AND period_key = 'lifetime')
        OR (bucket = 'daily' AND period_key GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')
    ),
    UNIQUE (client_id, tenant, owner_kind, owner_id, bucket, period_key)
);

-- api_key_sealed is authenticated ciphertext bound to the allocation, never a
-- plaintext provider key.
CREATE TABLE managed_key_leases (
    id                         TEXT PRIMARY KEY NOT NULL,
    client_id                  TEXT NOT NULL REFERENCES managed_clients (id) ON DELETE RESTRICT,
    client_slug                TEXT NOT NULL,
    is_current                 BOOLEAN NOT NULL DEFAULT 1,
    tenant                     TEXT NOT NULL,
    subject                    TEXT NOT NULL,
    workspace_id               TEXT NOT NULL,
    bucket                     TEXT NOT NULL CHECK (bucket IN ('daily', 'migration')),
    period_key                 TEXT NOT NULL,
    lease_date                 TEXT NOT NULL,
    limit_usd_micros           BIGINT NOT NULL CHECK (limit_usd_micros > 0 AND limit_usd_micros <= 9007199254740991),
    expires_at                 TEXT NOT NULL,
    status                     TEXT NOT NULL
        CHECK (status IN ('reserved', 'provisioning', 'uncertain', 'issued', 'revocation_pending', 'revoked')),
    key_hash                   TEXT UNIQUE CHECK (key_hash IS NULL OR (length(key_hash) = 64 AND key_hash NOT GLOB '*[^0-9a-fA-F]*')),
    api_key_sealed             BLOB CHECK (api_key_sealed IS NULL OR length(api_key_sealed) BETWEEN 41 AND 65536),
    created_at                 TEXT NOT NULL,
    updated_at                 TEXT NOT NULL,
    accounted_usage_usd_micros BIGINT NOT NULL DEFAULT 0 CHECK (accounted_usage_usd_micros >= 0),
    usage_checked_at           TEXT,
    CHECK (status <> 'issued' OR (key_hash IS NOT NULL AND api_key_sealed IS NOT NULL)),
    CHECK (
        (bucket = 'migration' AND period_key = 'lifetime')
        OR (bucket = 'daily' AND period_key = lease_date)
    ),
    -- Timestamps are stored as '%F %T%.f+00:00', so text order is time order.
    CHECK (substr(created_at, 1, 10) = lease_date),
    CHECK (expires_at > created_at AND expires_at <= date(lease_date, '+1 day') || ' 00:00:00+00:00')
);

CREATE UNIQUE INDEX managed_key_leases_current
    ON managed_key_leases (client_id, tenant, subject, bucket, lease_date)
    WHERE is_current = 1;
CREATE INDEX managed_key_leases_revocation_queue ON managed_key_leases (status, id);
CREATE INDEX managed_key_leases_usage_poll ON managed_key_leases (usage_checked_at, id)
    WHERE key_hash IS NOT NULL AND status IN ('issued', 'revocation_pending', 'revoked');
CREATE INDEX managed_key_leases_tenant ON managed_key_leases (client_id, tenant, lease_date);

CREATE TABLE managed_attempts (
    id              TEXT PRIMARY KEY NOT NULL,
    lease_id        TEXT NOT NULL REFERENCES managed_key_leases (id) ON DELETE RESTRICT,
    stage           TEXT NOT NULL,
    category        TEXT NOT NULL,
    provider_status INTEGER CHECK (provider_status IS NULL OR provider_status BETWEEN 100 AND 599),
    created_at      TEXT NOT NULL,
    finished_at     TEXT
);

CREATE UNIQUE INDEX managed_attempts_open ON managed_attempts (lease_id) WHERE finished_at IS NULL;
CREATE INDEX managed_attempts_history ON managed_attempts (lease_id, created_at);

-- Audit of an authorized replacement; it is not evidence of a remote rejection.
CREATE TABLE managed_recoveries (
    id                   TEXT PRIMARY KEY NOT NULL,
    client_id            TEXT NOT NULL REFERENCES managed_clients (id) ON DELETE RESTRICT,
    tenant               TEXT NOT NULL,
    previous_lease_id    TEXT NOT NULL UNIQUE REFERENCES managed_key_leases (id) ON DELETE RESTRICT,
    replacement_lease_id TEXT NOT NULL UNIQUE REFERENCES managed_key_leases (id) ON DELETE RESTRICT,
    actor                TEXT NOT NULL,
    limit_usd_micros     BIGINT NOT NULL CHECK (limit_usd_micros > 0 AND limit_usd_micros <= 9007199254740991),
    reason               TEXT NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
    created_at           TEXT NOT NULL,
    CHECK (previous_lease_id <> replacement_lease_id)
);
