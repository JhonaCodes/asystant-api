-- Reverting drops the console tables. The 0.3.0 client keys cannot be restored:
-- each client gets an unusable placeholder hash and needs a new key.
DROP TRIGGER admin_audit_log_no_delete;
DROP TRIGGER admin_audit_log_no_update;
DROP TABLE admin_audit_log;
DROP TABLE admin_sign_in_attempts;
DROP TABLE admin_sessions;
DROP TABLE admin_users;
DROP TABLE managed_client_keys;
CREATE TABLE managed_clients_previous (
    id             TEXT PRIMARY KEY NOT NULL,
    slug           TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 2 AND 40 AND slug NOT GLOB '*[^a-z0-9-]*'),
    name           TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    key_hash       TEXT NOT NULL UNIQUE CHECK (length(key_hash) = 64 AND key_hash NOT GLOB '*[^0-9a-f]*'),
    allowed_models TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    revoked_at     TEXT
);
INSERT INTO managed_clients_previous (id, slug, name, key_hash, allowed_models, created_at, revoked_at)
    SELECT id, slug, name, lower(hex(randomblob(32))), allowed_models, created_at, suspended_at FROM managed_clients;
DROP TABLE managed_clients;
ALTER TABLE managed_clients_previous RENAME TO managed_clients;
