use std::collections::HashSet;
use std::fmt::{Debug, Formatter};

use chrono::{DateTime, Utc};
use diesel::{Insertable, Queryable, Selectable};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::model::ManagedSecret;
use crate::schema::{managed_client_workspaces, managed_clients};

/// A company or service integrating with the API (e.g. `aulamas`, `turnosqr`).
/// Only the SHA-256 of its key is stored.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Queryable, Selectable, Insertable,
)]
#[diesel(table_name = managed_clients)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ManagedClient {
    pub id: String,
    pub slug: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub allowed_models: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ManagedClient {
    pub fn uuid(&self) -> Result<Uuid, AppError> {
        Uuid::parse_str(&self.id).map_err(|_| AppError::Internal)
    }

    pub fn models(&self) -> Result<Vec<String>, AppError> {
        serde_json::from_str(&self.allowed_models).map_err(|_| AppError::Internal)
    }

    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// An OpenRouter workspace assigned to exactly one client when the client is
/// created. A client can only place tenant keys in its own workspaces, so it
/// can never create keys inside another company's workspace.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Queryable, Selectable, Insertable,
)]
#[diesel(table_name = managed_client_workspaces)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ManagedClientWorkspace {
    pub workspace_id: String,
    pub client_id: String,
    pub created_at: DateTime<Utc>,
}

/// Lowercase letters, digits and hyphens; it prefixes every provider key name.
pub struct ClientSlug;

impl ClientSlug {
    pub fn validate(slug: &str) -> Result<(), AppError> {
        let valid_chars = slug
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if !(2..=40).contains(&slug.len()) || !valid_chars || slug.starts_with('-') {
            return Err(AppError::Invalid);
        }
        Ok(())
    }
}

/// The client's bearer key: `ask_` plus 64 random hex characters.
pub struct ClientKey;

impl ClientKey {
    pub const PREFIX: &'static str = "ask_";

    pub fn generate() -> Result<ManagedSecret, AppError> {
        ManagedSecret::new(format!(
            "{}{}{}",
            Self::PREFIX,
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        ))
    }

    pub fn is_well_formed(key: &str) -> bool {
        key.strip_prefix(Self::PREFIX)
            .is_some_and(|rest| rest.len() == 64 && rest.bytes().all(|c| c.is_ascii_hexdigit()))
    }

    pub fn hash(key: &str) -> String {
        format!("{:x}", Sha256::digest(key.as_bytes()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewClientRequest {
    pub slug: String,
    pub name: String,
    /// OpenRouter workspaces this client may use; each belongs to one client only.
    pub workspaces: Vec<Uuid>,
    #[serde(default)]
    pub allowed_models: Vec<String>,
}

impl NewClientRequest {
    pub const DEFAULT_MODELS: [&'static str; 1] = ["openai/gpt-oss-120b"];
    pub const MAX_WORKSPACES: usize = 64;

    pub fn validate(&self) -> Result<(), AppError> {
        ClientSlug::validate(&self.slug)?;
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
            return Err(AppError::Invalid);
        }
        let unique = self.workspaces.iter().collect::<HashSet<_>>().len() == self.workspaces.len();
        if self.workspaces.is_empty()
            || self.workspaces.len() > Self::MAX_WORKSPACES
            || !unique
            || self.workspaces.iter().any(Uuid::is_nil)
        {
            return Err(AppError::Invalid);
        }
        if self.allowed_models.len() > 32
            || self.allowed_models.iter().any(|model| {
                model.is_empty()
                    || model.len() > 200
                    || model.chars().any(|c| c.is_whitespace() || c.is_control())
            })
        {
            return Err(AppError::Invalid);
        }
        Ok(())
    }

    pub fn models(&self) -> Vec<String> {
        if self.allowed_models.is_empty() {
            return Self::DEFAULT_MODELS
                .iter()
                .map(|m| (*m).to_string())
                .collect();
        }
        self.allowed_models.clone()
    }
}

/// Returned once, when the client is created. The key cannot be recovered later.
#[derive(Clone, Deserialize)]
pub struct CreatedClient {
    pub client: ManagedClient,
    pub workspaces: Vec<Uuid>,
    pub api_key: ManagedSecret,
}

impl Debug for CreatedClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedClient")
            .field("client", &self.client)
            .field("workspaces", &self.workspaces)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl Serialize for CreatedClient {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("CreatedClient", 3)?;
        state.serialize_field("client", &self.client)?;
        state.serialize_field("workspaces", &self.workspaces)?;
        state.serialize_field("api_key", self.api_key.expose())?;
        state.end()
    }
}
