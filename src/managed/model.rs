use std::env;
use std::fmt::{Debug, Formatter};
use std::str::FromStr;

use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::client_model::ClientSlug;
use crate::managed::vault::ManagedKeyVault;

/// Provider or administration secret. Debug and Serialize never reveal it;
/// only `expose` does, at the single point that needs the plaintext.
#[derive(Clone)]
pub struct ManagedSecret(String);

impl ManagedSecret {
    pub fn new(value: String) -> Result<Self, AppError> {
        if value.is_empty() || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(AppError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Debug for ManagedSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ManagedSecret([REDACTED])")
    }
}

impl Serialize for ManagedSecret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for ManagedSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|_| serde::de::Error::custom("invalid managed secret"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedUsageBucket {
    Daily,
    Migration,
}

impl ManagedUsageBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Migration => "migration",
        }
    }

    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "daily" => Ok(Self::Daily),
            "migration" => Ok(Self::Migration),
            _ => Err(AppError::Invalid),
        }
    }
}

/// Tenant, subject and actor identifiers belong to the client service: they are
/// opaque here, bounded and free of control characters.
pub struct ExternalId;

impl ExternalId {
    pub const MAX_LEN: usize = 200;

    pub fn validate(value: &str) -> Result<(), AppError> {
        if value.is_empty()
            || value.chars().count() > Self::MAX_LEN
            || value.chars().any(char::is_control)
        {
            return Err(AppError::Invalid);
        }
        Ok(())
    }
}

/// Allocation already authorized by the service. Money is integer USD micros;
/// a tenant balance is never computed with floating point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedKeyAllocation {
    pub id: Uuid,
    pub client_id: Uuid,
    pub client_slug: String,
    pub tenant: String,
    pub subject: String,
    pub bucket: ManagedUsageBucket,
    pub limit_usd_micros: i64,
    pub expires_at: DateTime<Utc>,
    pub workspace_id: Uuid,
}

impl ManagedKeyAllocation {
    pub const MAX_LIMIT_USD_MICROS: i64 = 9_007_199_254_740_991;

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), AppError> {
        // Above 2^53 integers stop being exact in OpenRouter's double transport.
        // Reject instead of rounding an allocation.
        if self.limit_usd_micros <= 0 || self.limit_usd_micros > Self::MAX_LIMIT_USD_MICROS {
            return Err(AppError::Invalid);
        }
        if self.expires_at <= now || self.expires_at > Self::end_of_day(now)? {
            return Err(AppError::Invalid);
        }
        if self.id.is_nil() || self.client_id.is_nil() || self.workspace_id.is_nil() {
            return Err(AppError::Invalid);
        }
        ClientSlug::validate(&self.client_slug)?;
        ExternalId::validate(&self.tenant)?;
        ExternalId::validate(&self.subject)
    }

    pub fn end_of_day(now: DateTime<Utc>) -> Result<DateTime<Utc>, AppError> {
        now.date_naive()
            .succ_opt()
            .and_then(|date| date.and_hms_opt(0, 0, 0))
            .map(|date| date.and_utc())
            .ok_or(AppError::Invalid)
    }

    /// The limit in OpenRouter's USD double. Exact below 2^53 micros.
    pub fn limit_usd(&self) -> f64 {
        self.limit_usd_micros as f64 / 1_000_000.0
    }

    /// Identifies a recoverable reservation at the provider. It never carries
    /// names, documents or emails of the subject.
    pub fn provider_name(&self) -> String {
        format!("{}:{}:{}", self.client_slug, self.bucket.as_str(), self.id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenRouterManagedKeyData {
    pub hash: String,
    pub name: String,
    pub disabled: bool,
    pub limit: Option<f64>,
    pub limit_reset: Option<String>,
    pub include_byok_in_limit: bool,
    pub usage: f64,
    pub byok_usage: f64,
    pub expires_at: Option<DateTime<Utc>>,
    pub workspace_id: Option<Uuid>,
}

impl OpenRouterManagedKeyData {
    /// HTTP 200 does not prove the requested policy was applied. The secret is
    /// never handed out if the destination, ceiling or expiry differ.
    pub fn validate_issued_for(
        &self,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        allocation.validate(now)?;
        let matches = Self::validate_hash(&self.hash).is_ok()
            && self.name == allocation.provider_name()
            && self.workspace_id == Some(allocation.workspace_id)
            && !self.disabled
            && self.limit == Some(allocation.limit_usd())
            && self.limit_reset.is_none()
            && self.include_byok_in_limit
            && self.expires_at == Some(allocation.expires_at)
            && self.usage == 0.0
            && self.byok_usage == 0.0;
        if !matches {
            return Err(AppError::Provider);
        }
        Ok(())
    }

    pub fn validate_hash(hash: &str) -> Result<(), AppError> {
        if hash.len() != 64 || !hash.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(AppError::Invalid);
        }
        Ok(())
    }

    /// Conservative conversion at the boundary; accounting uses integers.
    /// BYOK counts because keys are issued with include_byok_in_limit.
    pub fn confirmed_usage_micros(&self) -> Result<i64, AppError> {
        if [self.usage, self.byok_usage]
            .iter()
            .any(|amount| !amount.is_finite() || *amount < 0.0)
        {
            return Err(AppError::Provider);
        }
        let usage =
            BigDecimal::from_str(&self.usage.to_string()).map_err(|_| AppError::Provider)?;
        let byok =
            BigDecimal::from_str(&self.byok_usage.to_string()).map_err(|_| AppError::Provider)?;
        let micros = (usage + byok) * BigDecimal::from(1_000_000);
        let truncated = micros.with_scale(0);
        let rounded = if truncated < micros {
            truncated + BigDecimal::from(1)
        } else {
            truncated
        };
        let amount = rounded
            .to_string()
            .parse::<i64>()
            .map_err(|_| AppError::Provider)?;
        if amount > ManagedKeyAllocation::MAX_LIMIT_USD_MICROS {
            return Err(AppError::Provider);
        }
        Ok(amount)
    }
}

/// The only provider response that carries the secret. It is sealed before
/// being persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRouterIssuedKey {
    pub data: OpenRouterManagedKeyData,
    pub key: ManagedSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRouterManagedKeyEnvelope {
    pub data: OpenRouterManagedKeyData,
}

/// Controlled categories only. Never carries provider text or bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedFailure {
    pub kind: ManagedFailureKind,
    pub provider_status: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedFailureKind {
    Configuration,
    Rejected,
    Transport,
    InvalidConfirmation,
    Persistence,
    Pending,
    NotFound,
    Pagination,
    Identity,
    MultipleKeys,
}

impl ManagedFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Rejected => "rejected",
            Self::Transport => "transport",
            Self::InvalidConfirmation => "invalid_confirmation",
            Self::Persistence => "persistence",
            Self::Pending => "pending",
            Self::NotFound => "not_found",
            Self::Pagination => "pagination",
            Self::Identity => "identity",
            Self::MultipleKeys => "multiple_keys",
        }
    }
}

impl From<ManagedFailureKind> for AppError {
    fn from(kind: ManagedFailureKind) -> Self {
        Self::Managed(ManagedFailure::new(kind))
    }
}

impl ManagedFailure {
    pub fn new(kind: ManagedFailureKind) -> Self {
        Self {
            kind,
            provider_status: None,
        }
    }

    pub fn from_http(status: u16) -> Self {
        // Closed list from OpenRouter's creation contract. A 5xx, redirect or
        // any other code does not prove there were no side effects.
        let kind = match status {
            401 | 403 => ManagedFailureKind::Configuration,
            400 | 429 => ManagedFailureKind::Rejected,
            _ => ManagedFailureKind::Pending,
        };
        Self {
            kind,
            provider_status: Some(status),
        }
    }

    pub fn safe(error: &AppError, fallback: ManagedFailureKind) -> Self {
        match error {
            AppError::Managed(failure) => *failure,
            _ => Self::new(fallback),
        }
    }

    pub fn retryable(self) -> bool {
        matches!(
            self.kind,
            ManagedFailureKind::Configuration | ManagedFailureKind::Rejected
        )
    }

    pub fn code(self) -> &'static str {
        match self.kind {
            ManagedFailureKind::Configuration => "managed_configuration_required",
            ManagedFailureKind::Rejected => "managed_creation_rejected",
            _ => "managed_reconciliation_pending",
        }
    }

    pub fn message(self) -> &'static str {
        match self.kind {
            ManagedFailureKind::Configuration => {
                "The managed-key service needs operator configuration; check access again afterwards."
            }
            ManagedFailureKind::Rejected => {
                "OpenRouter rejected the key creation; the operator must review the request before retrying."
            }
            _ => {
                "The managed key is pending reconciliation; the operator must verify the issuance and the budget stays protected."
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCredentialRequest {
    pub tenant: String,
    pub subject: String,
    pub bucket: ManagedUsageBucket,
}

/// The only DTO that serializes the provider secret, in a no-store response.
/// It is never persisted.
#[derive(Clone, Deserialize)]
pub struct ManagedCredentialResponse {
    pub tenant: String,
    pub subject: String,
    pub bucket: ManagedUsageBucket,
    pub expires_at: DateTime<Utc>,
    pub refresh_after: DateTime<Utc>,
    pub allowed_models: Vec<String>,
    pub api_key: ManagedSecret,
}

impl Debug for ManagedCredentialResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedCredentialResponse")
            .field("api_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Serialize for ManagedCredentialResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ManagedCredentialResponse", 7)?;
        state.serialize_field("tenant", &self.tenant)?;
        state.serialize_field("subject", &self.subject)?;
        state.serialize_field("bucket", &self.bucket)?;
        state.serialize_field("expires_at", &self.expires_at)?;
        state.serialize_field("refresh_after", &self.refresh_after)?;
        state.serialize_field("allowed_models", &self.allowed_models)?;
        state.serialize_field("api_key", self.api_key.expose())?;
        state.end()
    }
}

/// OpenRouter management credential and the key that seals issued keys.
/// Both are required together, or the managed flow is disabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedSettings {
    pub management_key: ManagedSecret,
    pub encryption_key: ManagedSecret,
}

impl ManagedSettings {
    pub const MANAGEMENT_KEY_ENV: &'static str = "OPENROUTER_MANAGEMENT_API_KEY";
    pub const ENCRYPTION_KEY_ENV: &'static str = "ASYSTANT_MANAGED_ENCRYPTION_KEY";

    pub fn from_env() -> Result<Option<Self>, AppError> {
        Self::from_values(
            env::var(Self::MANAGEMENT_KEY_ENV).ok(),
            env::var(Self::ENCRYPTION_KEY_ENV).ok(),
        )
    }

    pub fn from_values(
        management: Option<String>,
        encryption: Option<String>,
    ) -> Result<Option<Self>, AppError> {
        match (management, encryption) {
            (None, None) => Ok(None),
            (Some(management), Some(encryption)) => {
                let settings = Self {
                    management_key: ManagedSecret::new(management)?,
                    encryption_key: ManagedSecret::new(encryption)?,
                };
                ManagedKeyVault::from_base64_key(settings.encryption_key.expose())?;
                Ok(Some(settings))
            }
            _ => Err(AppError::Invalid),
        }
    }
}
