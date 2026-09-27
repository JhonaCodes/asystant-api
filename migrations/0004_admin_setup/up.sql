-- One-time links that set up an administrator in the browser: the first one
-- (no username yet), a new one, or a reset. Only the SHA-256 of the token is
-- stored; the authenticator secret is sealed like the administrators' own.
CREATE TABLE admin_setup_tokens (
    token_hash  TEXT PRIMARY KEY NOT NULL CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
    username    TEXT CHECK (username IS NULL OR (length(username) BETWEEN 3 AND 64 AND username NOT GLOB '*[^a-z0-9._-]*')),
    totp_sealed BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    CHECK (expires_at > created_at)
);
