-- Companies own several API keys instead of one. Rebuild the table without
-- key_hash (SQLite cannot drop a UNIQUE column). The copy keeps every row; the
-- DROP fails, and with it the whole migration, if any row is still referenced,
-- so no data is lost silently. Keys of the 0.3.0 format stop working.
CREATE TABLE managed_clients_next (
    id                   TEXT PRIMARY KEY NOT NULL,
    slug                 TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 2 AND 40 AND slug NOT GLOB '*[^a-z0-9-]*'),
    name                 TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    allowed_models       TEXT NOT NULL,
    contact              TEXT CHECK (contact IS NULL OR length(contact) BETWEEN 3 AND 200),
    daily_cap_usd_micros BIGINT CHECK (daily_cap_usd_micros IS NULL OR daily_cap_usd_micros BETWEEN 0 AND 9007199254740991),
    created_at           TEXT NOT NULL,
    suspended_at         TEXT
);
INSERT INTO managed_clients_next (id, slug, name, allowed_models, contact, daily_cap_usd_micros, created_at, suspended_at)
    SELECT id, slug, name, allowed_models, NULL, NULL, created_at, revoked_at FROM managed_clients;
DROP TABLE managed_clients;
ALTER TABLE managed_clients_next RENAME TO managed_clients;

-- Only the SHA-256 of a key is stored; prefix and suffix identify it on screen.
CREATE TABLE managed_client_keys (
    id               TEXT PRIMARY KEY NOT NULL,
    client_id        TEXT NOT NULL REFERENCES managed_clients (id) ON DELETE RESTRICT,
    label            TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
    display_prefix   TEXT NOT NULL,
    display_suffix   TEXT NOT NULL,
    key_hash         TEXT NOT NULL UNIQUE CHECK (length(key_hash) = 64 AND key_hash NOT GLOB '*[^0-9a-f]*'),
    can_issue        BOOLEAN NOT NULL,
    can_manage       BOOLEAN NOT NULL,
    allowed_sources  TEXT NOT NULL,
    created_by       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    replaced_by      TEXT REFERENCES managed_client_keys (id) ON DELETE RESTRICT,
    revoked_at       TEXT,
    last_used_at     TEXT,
    last_used_source TEXT,
    CHECK (can_issue OR can_manage),
    CHECK (expires_at > created_at)
);

CREATE INDEX managed_client_keys_client ON managed_client_keys (client_id, created_at);

CREATE TABLE admin_users (
    id                  TEXT PRIMARY KEY NOT NULL,
    username            TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 3 AND 64 AND username NOT GLOB '*[^a-z0-9._-]*'),
    password_hash       TEXT NOT NULL,
    totp_sealed         BLOB NOT NULL,
    totp_last_step      BIGINT NOT NULL DEFAULT 0,
    pending_totp_sealed BLOB,
    created_at          TEXT NOT NULL,
    password_changed_at TEXT NOT NULL,
    last_sign_in_at     TEXT,
    last_sign_in_source TEXT,
    disabled_at         TEXT
);

CREATE TABLE admin_sessions (
    id           TEXT PRIMARY KEY NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    admin_id     TEXT NOT NULL REFERENCES admin_users (id) ON DELETE RESTRICT,
    csrf_token   TEXT NOT NULL,
    user_agent   TEXT NOT NULL,
    source       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    revoked_at   TEXT
);

CREATE INDEX admin_sessions_admin ON admin_sessions (admin_id, created_at);

CREATE TABLE admin_sign_in_attempts (
    id         TEXT PRIMARY KEY NOT NULL,
    username   TEXT NOT NULL,
    source     TEXT NOT NULL,
    succeeded  BOOLEAN NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX admin_sign_in_attempts_recent ON admin_sign_in_attempts (created_at);

CREATE TABLE admin_audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    actor      TEXT,
    action     TEXT NOT NULL,
    company_id TEXT,
    target     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    source     TEXT NOT NULL,
    result     TEXT NOT NULL CHECK (result IN ('done', 'refused'))
);

CREATE INDEX admin_audit_log_company ON admin_audit_log (company_id, id);

-- Append-only: the database itself refuses to edit or delete an entry.
CREATE TRIGGER admin_audit_log_no_update BEFORE UPDATE ON admin_audit_log
BEGIN
    SELECT RAISE(ABORT, 'admin_audit_log is append-only');
END;
CREATE TRIGGER admin_audit_log_no_delete BEFORE DELETE ON admin_audit_log
BEGIN
    SELECT RAISE(ABORT, 'admin_audit_log is append-only');
END;
