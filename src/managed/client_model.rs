use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use diesel::{Insertable, Queryable, Selectable};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::model::{ExternalId, ManagedSecret};
use crate::crypto::{Fingerprint, Random};
use crate::schema::{managed_client_keys, managed_client_workspaces, managed_clients};

/// A company or service integrating with the API (e.g. `aulamas`, `turnosqr`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Queryable, Selectable, Insertable,
)]
#[diesel(table_name = managed_clients)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ManagedClient {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub allowed_models: String,
    pub contact: Option<String>,
    pub daily_cap_usd_micros: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub suspended_at: Option<DateTime<Utc>>,
}

impl ManagedClient {
    pub fn uuid(&self) -> Result<Uuid, AppError> {
        Uuid::parse_str(&self.id).map_err(|_| AppError::Internal)
    }

    pub fn models(&self) -> Result<Vec<String>, AppError> {
        serde_json::from_str(&self.allowed_models).map_err(|_| AppError::Internal)
    }

    pub fn is_active(&self) -> bool {
        self.suspended_at.is_none()
    }
}

/// An OpenRouter workspace assigned to exactly one client. A client can only
/// place tenant keys in its own workspaces, so it can never create keys inside
/// another company's workspace.
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

/// One API key of a client. Only its SHA-256 is stored; prefix and suffix
/// identify it on screen.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Queryable, Selectable, Insertable,
)]
#[diesel(table_name = managed_client_keys)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ManagedClientKey {
    pub id: String,
    pub client_id: String,
    pub label: String,
    pub display_prefix: String,
    pub display_suffix: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub can_issue: bool,
    pub can_manage: bool,
    pub allowed_sources: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub replaced_by: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_used_source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKeyState {
    Active,
    Rotating,
    Expired,
    Revoked,
}

impl ManagedClientKey {
    pub fn masked(&self) -> String {
        format!("{}…{}", self.display_prefix, self.display_suffix)
    }

    pub fn sources(&self) -> Result<Vec<SourceRange>, AppError> {
        let ranges: Vec<String> =
            serde_json::from_str(&self.allowed_sources).map_err(|_| AppError::Internal)?;
        ranges
            .iter()
            .map(|range| SourceRange::parse(range))
            .collect()
    }

    pub fn state(&self, now: DateTime<Utc>) -> ClientKeyState {
        if self.revoked_at.is_some() {
            ClientKeyState::Revoked
        } else if self.expires_at <= now {
            ClientKeyState::Expired
        } else if self.replaced_by.is_some() {
            ClientKeyState::Rotating
        } else {
            ClientKeyState::Active
        }
    }

    pub fn permits(&self, permission: KeyPermission) -> bool {
        match permission {
            KeyPermission::Issue => self.can_issue,
            KeyPermission::Manage => self.can_manage,
        }
    }
}

/// What a client key may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPermission {
    /// `POST /v1/managed/credentials`.
    Issue,
    /// Tenant ceilings, subject budgets, overview and recovery.
    Manage,
}

/// A client authenticated by one of its keys for one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedClient {
    pub client: ManagedClient,
    pub key_id: String,
}

/// Lowercase letters, digits and hyphens; it prefixes every provider key name.
pub struct ClientSlug;

impl ClientSlug {
    pub fn validate(slug: &str) -> Result<(), AppError> {
        let valid_chars = slug
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        // `new` is a console route (`/admin/companies/new`), never a company.
        if !(2..=40).contains(&slug.len()) || !valid_chars || slug.starts_with('-') || slug == "new"
        {
            return Err(AppError::Invalid);
        }
        Ok(())
    }
}

/// Client keys: `ask_live_` + 43 base62 characters (256 random bits) + a
/// 6-character base62 CRC-32 of those 43. The prefix lets secret scanners find
/// leaked keys; the checksum rejects typos without a database lookup.
pub struct ClientKey;

impl ClientKey {
    pub const PREFIX: &'static str = "ask_live_";
    const BODY_LEN: usize = 43;
    const CHECKSUM_LEN: usize = 6;

    pub fn generate() -> Result<ManagedSecret, AppError> {
        let body = Random::base62(Self::BODY_LEN)?;
        let checksum = Self::checksum(&body);
        ManagedSecret::new(format!("{}{body}{checksum}", Self::PREFIX))
    }

    pub fn is_well_formed(key: &str) -> bool {
        let Some(rest) = key.strip_prefix(Self::PREFIX) else {
            return false;
        };
        if rest.len() != Self::BODY_LEN + Self::CHECKSUM_LEN
            || !rest.bytes().all(|c| c.is_ascii_alphanumeric())
        {
            return false;
        }
        let (body, checksum) = rest.split_at(Self::BODY_LEN);
        Self::checksum(body) == checksum
    }

    pub fn hash(key: &str) -> String {
        Fingerprint::sha256_hex(key)
    }

    /// First characters shown on screen: the prefix and four of the body.
    pub fn display_prefix(key: &str) -> String {
        key.chars().take(Self::PREFIX.len() + 4).collect()
    }

    pub fn display_suffix(key: &str) -> String {
        let chars: Vec<char> = key.chars().collect();
        chars[chars.len().saturating_sub(4)..].iter().collect()
    }

    fn checksum(body: &str) -> String {
        let mut value = u64::from(Self::crc32(body.as_bytes()));
        let mut out = [b'0'; Self::CHECKSUM_LEN];
        for slot in out.iter_mut().rev() {
            *slot = Random::BASE62[(value % 62) as usize];
            value /= 62;
        }
        out.iter().map(|c| char::from(*c)).collect()
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFF_u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }
}

/// An IP address or CIDR block a key may be used from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRange {
    pub network: IpAddr,
    pub prefix: u8,
}

impl SourceRange {
    pub fn parse(value: &str) -> Result<Self, AppError> {
        let value = value.trim();
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value, None),
        };
        let network = IpAddr::from_str(address).map_err(|_| AppError::Invalid)?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix.parse::<u8>().map_err(|_| AppError::Invalid)?,
            None => max,
        };
        if prefix > max {
            return Err(AppError::Invalid);
        }
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => Self::same_prefix(
                u128::from(u32::from(network)),
                u128::from(u32::from(address)),
                self.prefix,
                32,
            ),
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                Self::same_prefix(u128::from(network), u128::from(address), self.prefix, 128)
            }
            _ => false,
        }
    }

    fn same_prefix(network: u128, address: u128, prefix: u8, width: u32) -> bool {
        if prefix == 0 {
            return true;
        }
        let shift = width - u32::from(prefix);
        (network >> shift) == (address >> shift)
    }

    pub fn render(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
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
    #[serde(default)]
    pub contact: Option<String>,
    #[serde(default)]
    pub daily_cap_usd_micros: Option<i64>,
}

impl NewClientRequest {
    pub const DEFAULT_MODELS: [&'static str; 1] = ["openai/gpt-oss-120b"];
    pub const MAX_WORKSPACES: usize = 64;

    pub fn validate(&self) -> Result<(), AppError> {
        ClientSlug::validate(&self.slug)?;
        ClientSettings::validate_name(&self.name)?;
        ClientSettings::validate_workspaces(&self.workspaces)?;
        ClientSettings::validate_models(&self.allowed_models)?;
        ClientSettings::validate_contact(self.contact.as_deref())?;
        ClientSettings::validate_cap(self.daily_cap_usd_micros)
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

/// Editable settings of an existing client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSettings {
    pub name: String,
    pub allowed_models: Vec<String>,
    pub contact: Option<String>,
    pub daily_cap_usd_micros: Option<i64>,
}

impl ClientSettings {
    pub fn validate(&self) -> Result<(), AppError> {
        Self::validate_name(&self.name)?;
        if self.allowed_models.is_empty() {
            return Err(AppError::Invalid);
        }
        Self::validate_models(&self.allowed_models)?;
        Self::validate_contact(self.contact.as_deref())?;
        Self::validate_cap(self.daily_cap_usd_micros)
    }

    fn validate_name(name: &str) -> Result<(), AppError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
            return Err(AppError::Invalid);
        }
        Ok(())
    }

    fn validate_workspaces(workspaces: &[Uuid]) -> Result<(), AppError> {
        let unique = workspaces.iter().collect::<HashSet<_>>().len() == workspaces.len();
        if workspaces.is_empty()
            || workspaces.len() > NewClientRequest::MAX_WORKSPACES
            || !unique
            || workspaces.iter().any(Uuid::is_nil)
        {
            return Err(AppError::Invalid);
        }
        Ok(())
    }

    fn validate_models(models: &[String]) -> Result<(), AppError> {
        if models.len() > 32
            || models.iter().any(|model| {
                model.is_empty()
                    || model.len() > 200
                    || model.chars().any(|c| c.is_whitespace() || c.is_control())
            })
        {
            return Err(AppError::Invalid);
        }
        Ok(())
    }

    fn validate_contact(contact: Option<&str>) -> Result<(), AppError> {
        if contact.is_some_and(|contact| {
            !(3..=200).contains(&contact.chars().count()) || contact.chars().any(char::is_control)
        }) {
            return Err(AppError::Invalid);
        }
        Ok(())
    }

    fn validate_cap(cap: Option<i64>) -> Result<(), AppError> {
        if cap.is_some_and(|cap| !(0..=9_007_199_254_740_991).contains(&cap)) {
            return Err(AppError::Invalid);
        }
        Ok(())
    }
}

/// A new API key for a client. Every key expires.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewKeyRequest {
    pub label: String,
    pub can_issue: bool,
    pub can_manage: bool,
    pub expires_in_days: i64,
    pub allowed_sources: Vec<SourceRange>,
    /// A key of the same client that keeps working during the overlap.
    pub replaces: Option<Uuid>,
    pub created_by: String,
}

impl NewKeyRequest {
    pub const EXPIRY_CHOICES: [i64; 4] = [30, 90, 180, 365];
    pub const ROTATION_OVERLAP_DAYS: i64 = 7;
    pub const MAX_SOURCES: usize = 32;

    pub fn validate(&self) -> Result<(), AppError> {
        let label = self.label.trim();
        if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
            return Err(AppError::Invalid);
        }
        if !(self.can_issue || self.can_manage)
            || !Self::EXPIRY_CHOICES.contains(&self.expires_in_days)
            || self.allowed_sources.len() > Self::MAX_SOURCES
        {
            return Err(AppError::Invalid);
        }
        ExternalId::validate(&self.created_by)
    }

    pub fn expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now + Duration::days(self.expires_in_days)
    }

    pub fn rotation_deadline(now: DateTime<Utc>) -> DateTime<Utc> {
        now + Duration::days(Self::ROTATION_OVERLAP_DAYS)
    }
}

/// Returned once, when the key is created. It cannot be recovered later.
#[derive(Clone, Deserialize)]
pub struct CreatedKey {
    pub key: ManagedClientKey,
    pub api_key: ManagedSecret,
}

impl Debug for CreatedKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedKey")
            .field("key", &self.key)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl Serialize for CreatedKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("CreatedKey", 2)?;
        state.serialize_field("key", &self.key)?;
        state.serialize_field("api_key", self.api_key.expose())?;
        state.end()
    }
}
