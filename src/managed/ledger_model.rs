use std::fmt::{Debug, Formatter};

use chrono::{DateTime, NaiveDate, Utc};
use diesel::{Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::model::{ManagedKeyAllocation, ManagedUsageBucket};
use crate::schema::{managed_budget_accounts, managed_key_leases};

pub const OWNER_TENANT: &str = "tenant";
pub const OWNER_SUBJECT: &str = "subject";

/// Monetary snapshot, never access authority nor a substitute for the ledger.
/// The repository reads both accounts and stores the reservation inside one
/// immediate transaction. Balances never use tokens or floats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedBudgetBalance {
    pub limit_usd_micros: i64,
    pub spent_usd_micros: i64,
    pub reserved_usd_micros: i64,
}

impl ManagedBudgetBalance {
    /// Transfers a reservation whose rejection is proven. The repository must
    /// check every attempt and store the new reservation in the same
    /// transaction; never use it for uncertain issuances.
    pub fn without_rejected_reservation(&self, amount: i64) -> Result<Self, AppError> {
        self.available_usd_micros()?;
        let remaining = self
            .reserved_usd_micros
            .checked_sub(amount)
            .filter(|remaining| amount > 0 && *remaining >= 0)
            .ok_or(AppError::Conflict)?;
        Ok(Self {
            reserved_usd_micros: remaining,
            ..self.clone()
        })
    }

    /// Repeated or late observations never duplicate nor revert charges. The
    /// leftover of a revoked key is not released by this operation.
    pub fn apply_confirmed_usage(
        &self,
        lease_limit: i64,
        previously_accounted: i64,
        confirmed: i64,
    ) -> Result<Self, AppError> {
        self.available_usd_micros()?;
        if lease_limit <= 0 || previously_accounted < 0 || confirmed < 0 {
            return Err(AppError::Invalid);
        }
        let delta = confirmed.max(previously_accounted) - previously_accounted;
        let held = (lease_limit - previously_accounted).max(0);
        let spent = self
            .spent_usd_micros
            .checked_add(delta)
            .ok_or(AppError::Conflict)?;
        let reserved = self
            .reserved_usd_micros
            .checked_sub(delta.min(held))
            .filter(|remaining| *remaining >= 0)
            .ok_or(AppError::Conflict)?;
        Ok(Self {
            limit_usd_micros: self.limit_usd_micros,
            spent_usd_micros: spent,
            reserved_usd_micros: reserved,
        })
    }

    pub fn available_usd_micros(&self) -> Result<i64, AppError> {
        if self.limit_usd_micros < 0 || self.spent_usd_micros < 0 || self.reserved_usd_micros < 0 {
            return Err(AppError::Invalid);
        }
        // Confirmed spend may exceed the ceiling (or the ceiling may have been
        // lowered). Keep that accounting and close access, without inventing
        // balance nor overflowing while adding two i64 counters.
        Ok(self
            .limit_usd_micros
            .saturating_sub(self.spent_usd_micros)
            .saturating_sub(self.reserved_usd_micros)
            .max(0))
    }

    pub fn reserve(&self, amount_usd_micros: i64) -> Result<Self, AppError> {
        if amount_usd_micros <= 0 || amount_usd_micros > ManagedKeyAllocation::MAX_LIMIT_USD_MICROS
        {
            return Err(AppError::Invalid);
        }
        if amount_usd_micros > self.available_usd_micros()? {
            return Err(AppError::Budget);
        }
        let reserved_usd_micros = self
            .reserved_usd_micros
            .checked_add(amount_usd_micros)
            .ok_or(AppError::Invalid)?;
        Ok(Self {
            reserved_usd_micros,
            ..self.clone()
        })
    }
}

/// Both balances are updated together or neither is. Pure calculation:
/// idempotency and concurrency belong to the transactional repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedBudgetReservation {
    pub tenant: ManagedBudgetBalance,
    pub subject: ManagedBudgetBalance,
}

impl ManagedBudgetReservation {
    pub fn reserve(
        tenant: &ManagedBudgetBalance,
        subject: &ManagedBudgetBalance,
        amount_usd_micros: i64,
    ) -> Result<Self, AppError> {
        Ok(Self {
            tenant: tenant.reserve(amount_usd_micros)?,
            subject: subject.reserve(amount_usd_micros)?,
        })
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Queryable, Selectable, Insertable,
)]
#[diesel(table_name = managed_budget_accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ManagedBudgetAccount {
    pub id: String,
    pub client_id: String,
    pub tenant: String,
    pub owner_kind: String,
    pub owner_id: String,
    pub workspace_id: String,
    pub bucket: String,
    pub period_key: String,
    pub limit_usd_micros: i64,
    pub spent_usd_micros: i64,
    pub reserved_usd_micros: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ManagedBudgetAccount {
    pub fn balance(&self) -> ManagedBudgetBalance {
        ManagedBudgetBalance {
            limit_usd_micros: self.limit_usd_micros,
            spent_usd_micros: self.spent_usd_micros,
            reserved_usd_micros: self.reserved_usd_micros,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedLeaseState {
    Reserved,
    Provisioning,
    Uncertain,
    Issued,
    RevocationPending,
    Revoked,
}

impl ManagedLeaseState {
    /// States whose key exists or may exist at OpenRouter and must be revoked.
    pub const LIVE: [&'static str; 4] = ["reserved", "provisioning", "uncertain", "issued"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Provisioning => "provisioning",
            Self::Uncertain => "uncertain",
            Self::Issued => "issued",
            Self::RevocationPending => "revocation_pending",
            Self::Revoked => "revoked",
        }
    }
}

/// Pure rules used inside the transaction. They grant no access and do not
/// replace SQLite's write lock nor its unique indexes.
pub struct ManagedLedgerRules;

impl ManagedLedgerRules {
    pub fn validate_reserved_budget(
        tenant: &ManagedBudgetAccount,
        subject: &ManagedBudgetAccount,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        Self::validate_remaining_budget(tenant, subject, allocation, 0, now)
    }

    pub fn validate_remaining_budget(
        tenant: &ManagedBudgetAccount,
        subject: &ManagedBudgetAccount,
        allocation: &ManagedKeyAllocation,
        accounted_usage: i64,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        Self::validate_accounts(tenant, subject, allocation, now)?;
        if accounted_usage < 0 || accounted_usage >= allocation.limit_usd_micros {
            return Err(AppError::Budget);
        }
        let remaining = allocation.limit_usd_micros - accounted_usage;
        for account in [tenant, subject] {
            account.balance().available_usd_micros()?;
            if account.reserved_usd_micros < remaining
                || i128::from(account.spent_usd_micros) + i128::from(account.reserved_usd_micros)
                    > i128::from(account.limit_usd_micros)
            {
                return Err(AppError::Budget);
            }
        }
        Ok(())
    }

    pub fn period_key(bucket: ManagedUsageBucket, date: NaiveDate) -> String {
        match bucket {
            ManagedUsageBucket::Daily => date.to_string(),
            ManagedUsageBucket::Migration => "lifetime".to_string(),
        }
    }

    pub fn reserve(
        tenant: &ManagedBudgetAccount,
        subject: &ManagedBudgetAccount,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<ManagedBudgetReservation, AppError> {
        Self::validate_accounts(tenant, subject, allocation, now)?;
        ManagedBudgetReservation::reserve(
            &tenant.balance(),
            &subject.balance(),
            allocation.limit_usd_micros,
        )
    }

    pub fn validate_accounts(
        tenant: &ManagedBudgetAccount,
        subject: &ManagedBudgetAccount,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        Self::validate_allocation(allocation, now)?;
        let period = Self::period_key(allocation.bucket, now.date_naive());
        let client = allocation.client_id.to_string();
        let workspace = allocation.workspace_id.to_string();
        for (account, kind, owner_id) in [
            (tenant, OWNER_TENANT, &allocation.tenant),
            (subject, OWNER_SUBJECT, &allocation.subject),
        ] {
            if account.id.is_empty()
                || account.client_id != client
                || account.tenant != allocation.tenant
                || account.workspace_id != workspace
                || account.owner_kind != kind
                || account.owner_id != *owner_id
                || account.bucket != allocation.bucket.as_str()
                || account.period_key != period
            {
                return Err(AppError::Forbidden);
            }
        }
        if tenant.id == subject.id {
            return Err(AppError::Invalid);
        }
        Ok(())
    }

    pub fn validate_allocation(
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        allocation.validate(now)?;
        if !allocation
            .expires_at
            .timestamp_subsec_nanos()
            .is_multiple_of(1_000)
        {
            return Err(AppError::Invalid);
        }
        Ok(())
    }
}

/// Internal row, not a credential response. Not even the ciphertext appears in
/// JSON or Debug.
#[derive(Clone, Serialize, Deserialize, Queryable, Selectable, Insertable)]
#[diesel(table_name = managed_key_leases)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ManagedKeyLease {
    pub id: String,
    pub client_id: String,
    pub client_slug: String,
    pub is_current: bool,
    pub tenant: String,
    pub subject: String,
    pub workspace_id: String,
    pub bucket: String,
    pub period_key: String,
    pub lease_date: NaiveDate,
    pub limit_usd_micros: i64,
    pub expires_at: DateTime<Utc>,
    pub status: String,
    pub key_hash: Option<String>,
    #[serde(skip)]
    pub api_key_sealed: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub accounted_usage_usd_micros: i64,
    pub usage_checked_at: Option<DateTime<Utc>>,
}

impl Debug for ManagedKeyLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedKeyLease")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("api_key_sealed", &"[REDACTED]")
            .finish()
    }
}

impl ManagedKeyLease {
    pub fn can_authorize_recovery(&self) -> bool {
        self.is_current && matches!(self.status.as_str(), "uncertain" | "revocation_pending")
    }

    /// Allows looking for a new balance, never reusing the one reserved by this key.
    pub fn permits_replacement(&self) -> bool {
        self.status == "revoked" && self.key_hash.is_some() && self.usage_checked_at.is_some()
    }

    pub fn reserved(
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<Self, AppError> {
        ManagedLedgerRules::validate_allocation(allocation, now)?;
        Ok(Self {
            id: allocation.id.to_string(),
            client_id: allocation.client_id.to_string(),
            client_slug: allocation.client_slug.clone(),
            is_current: true,
            tenant: allocation.tenant.clone(),
            subject: allocation.subject.clone(),
            workspace_id: allocation.workspace_id.to_string(),
            bucket: allocation.bucket.as_str().to_string(),
            period_key: ManagedLedgerRules::period_key(allocation.bucket, now.date_naive()),
            lease_date: now.date_naive(),
            limit_usd_micros: allocation.limit_usd_micros,
            expires_at: allocation.expires_at,
            status: ManagedLeaseState::Reserved.as_str().to_string(),
            key_hash: None,
            api_key_sealed: None,
            created_at: now,
            updated_at: now,
            accounted_usage_usd_micros: 0,
            usage_checked_at: None,
        })
    }

    pub fn allocation(&self) -> Result<ManagedKeyAllocation, AppError> {
        Ok(ManagedKeyAllocation {
            id: Uuid::parse_str(&self.id).map_err(|_| AppError::Internal)?,
            client_id: Uuid::parse_str(&self.client_id).map_err(|_| AppError::Internal)?,
            client_slug: self.client_slug.clone(),
            tenant: self.tenant.clone(),
            subject: self.subject.clone(),
            workspace_id: Uuid::parse_str(&self.workspace_id).map_err(|_| AppError::Internal)?,
            bucket: ManagedUsageBucket::parse(&self.bucket).map_err(|_| AppError::Internal)?,
            limit_usd_micros: self.limit_usd_micros,
            expires_at: self.expires_at,
        })
    }

    /// An id sent by another device does not open another logical allocation.
    pub fn matches_request(&self, requested: &ManagedKeyAllocation) -> Result<bool, AppError> {
        let mut stored = self.allocation()?;
        stored.id = requested.id;
        Ok(stored == *requested)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedReservationOutcome {
    pub lease: ManagedKeyLease,
    pub created: bool,
}
