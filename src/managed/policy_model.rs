use chrono::{DateTime, Utc};
use diesel::{Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::ledger_model::{ManagedBudgetAccount, ManagedKeyLease, OWNER_SUBJECT, OWNER_TENANT};
use crate::managed::model::{ExternalId, ManagedKeyAllocation, ManagedUsageBucket};
use crate::schema::{managed_policies, managed_recoveries};

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Queryable, Selectable, Insertable,
)]
#[diesel(table_name = managed_policies)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ManagedPolicy {
    pub id: String,
    pub client_id: String,
    pub tenant: String,
    pub owner_kind: String,
    pub owner_id: String,
    pub workspace_id: String,
    pub bucket: String,
    pub limit_usd_micros: i64,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

/// Tenant ceiling and the OpenRouter workspace where its keys are created.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantBudgetRequest {
    pub workspace_id: Uuid,
    pub bucket: ManagedUsageBucket,
    pub limit_usd_micros: i64,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectBudgetRequest {
    pub bucket: ManagedUsageBucket,
    pub limit_usd_micros: i64,
    pub actor: String,
}

/// Internal command: identity and authority are never deserialized from a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedPolicyChange {
    pub client_id: Uuid,
    pub tenant: String,
    pub owner_kind: String,
    pub owner_id: String,
    pub workspace_id: Option<Uuid>,
    pub bucket: ManagedUsageBucket,
    pub limit_usd_micros: i64,
    pub actor: String,
}

impl ManagedPolicyChange {
    pub fn validate(&self) -> Result<(), AppError> {
        ManagedPolicyRules::validate_amount(self.limit_usd_micros)?;
        ExternalId::validate(&self.tenant)?;
        ExternalId::validate(&self.owner_id)?;
        ExternalId::validate(&self.actor)?;
        let valid_owner = match self.owner_kind.as_str() {
            OWNER_TENANT => {
                self.owner_id == self.tenant && self.workspace_id.is_some_and(|id| !id.is_nil())
            }
            OWNER_SUBJECT => self.workspace_id.is_none(),
            _ => false,
        };
        if !valid_owner || self.client_id.is_nil() {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedCredentialStatus {
    pub id: String,
    pub subject: String,
    pub is_current: bool,
    pub can_authorize_recovery: bool,
    pub bucket: String,
    pub status: String,
    pub limit_usd_micros: i64,
    pub expires_at: DateTime<Utc>,
    pub accounted_usage_usd_micros: i64,
    pub usage_checked_at: Option<DateTime<Utc>>,
}

impl From<ManagedKeyLease> for ManagedCredentialStatus {
    fn from(lease: ManagedKeyLease) -> Self {
        Self {
            can_authorize_recovery: lease.can_authorize_recovery(),
            id: lease.id,
            subject: lease.subject,
            is_current: lease.is_current,
            bucket: lease.bucket,
            status: lease.status,
            limit_usd_micros: lease.limit_usd_micros,
            expires_at: lease.expires_at,
            accounted_usage_usd_micros: lease.accounted_usage_usd_micros,
            usage_checked_at: lease.usage_checked_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedBudgetOverview {
    pub policies: Vec<ManagedPolicy>,
    pub accounts: Vec<ManagedBudgetAccount>,
    pub credentials: Vec<ManagedCredentialStatus>,
}

pub struct ManagedPolicyRules;

impl ManagedPolicyRules {
    pub fn validate_amount(amount: i64) -> Result<(), AppError> {
        if !(0..=ManagedKeyAllocation::MAX_LIMIT_USD_MICROS).contains(&amount) {
            return Err(AppError::Invalid);
        }
        Ok(())
    }

    pub fn validate_distribution(
        ceiling: i64,
        others: i64,
        requested: i64,
    ) -> Result<(), AppError> {
        for amount in [ceiling, others, requested] {
            Self::validate_amount(amount)?;
        }
        if i128::from(others) + i128::from(requested) > i128::from(ceiling) {
            return Err(AppError::Conflict);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRecoveryRequest {
    pub limit_usd_micros: i64,
    pub reason: String,
    pub acknowledge_pending_reserve: bool,
    pub actor: String,
}

impl ManagedRecoveryRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        ExternalId::validate(&self.actor)?;
        if !self.acknowledge_pending_reserve
            || !(1..=ManagedKeyAllocation::MAX_LIMIT_USD_MICROS).contains(&self.limit_usd_micros)
            || !(10..=500).contains(&self.reason.trim().chars().count())
            || self.reason.chars().any(char::is_control)
        {
            return Err(AppError::Invalid);
        }
        Ok(())
    }
}

/// Audit of an authorized replacement, not evidence of a remote rejection.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Queryable, Selectable, Insertable,
)]
#[diesel(table_name = managed_recoveries)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ManagedRecovery {
    pub id: String,
    pub client_id: String,
    pub tenant: String,
    pub previous_lease_id: String,
    pub replacement_lease_id: String,
    pub actor: String,
    pub limit_usd_micros: i64,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}
