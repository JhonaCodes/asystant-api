//! Operator console at `/admin`: server-rendered HTML without JavaScript,
//! argon2id + TOTP sign-in, audited actions over companies and their API keys.
pub mod credentials;
pub mod handler;
pub mod model;
pub mod repository;
pub mod service;
pub mod view;
