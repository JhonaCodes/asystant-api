use chrono::{DateTime, NaiveDate, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl,
    SelectableHelper, SqliteConnection,
};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::client_model::ManagedClient;
use crate::managed::ledger_model::{
    ManagedBudgetAccount, ManagedKeyLease, ManagedLedgerRules, ManagedReservationOutcome,
    OWNER_SUBJECT, OWNER_TENANT,
};
use crate::managed::model::{ManagedFailure, ManagedKeyAllocation, OpenRouterManagedKeyData};
use crate::managed::vault::ManagedSealedKey;
use crate::repository::PoolConfig;
use crate::schema::managed_attempts::dsl as attempts;
use crate::schema::managed_budget_accounts::dsl as budgets;
use crate::schema::managed_client_workspaces::dsl as workspaces;
use crate::schema::managed_clients::dsl as clients;
use crate::schema::managed_key_leases::dsl as leases;

/// Ledger only. No transaction stays open during external HTTP. The service
/// resolves the client and the policies; balances or tenants supplied by the
/// caller are never authority.
pub trait ManagedLedgerRepository: Send + Sync {
    fn fail_managed_attempt(
        &self,
        allocation: &ManagedKeyAllocation,
        stage: &str,
        failure: ManagedFailure,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
    fn reserve_managed_key(
        &self,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<ManagedReservationOutcome, AppError>;
    fn claim_managed_key(
        &self,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<Option<ManagedKeyLease>, AppError>;
    fn confirm_managed_key(
        &self,
        allocation: &ManagedKeyAllocation,
        data: &OpenRouterManagedKeyData,
        sealed: &ManagedSealedKey,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
}

impl ManagedLedgerRepository for PoolConfig {
    fn fail_managed_attempt(
        &self,
        allocation: &ManagedKeyAllocation,
        stage: &str,
        failure: ManagedFailure,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        self.conn()?.immediate_transaction(|conn| {
            let count = diesel::update(
                leases::managed_key_leases
                    .filter(leases::id.eq(allocation.id.to_string()))
                    .filter(leases::client_id.eq(allocation.client_id.to_string()))
                    .filter(leases::tenant.eq(&allocation.tenant))
                    .filter(leases::subject.eq(&allocation.subject))
                    .filter(leases::status.eq("provisioning")),
            )
            .set((
                leases::status.eq(if failure.retryable() {
                    "reserved"
                } else {
                    "uncertain"
                }),
                leases::updated_at.eq(now),
            ))
            .execute(conn)?;
            let transitioned = count == 1;
            let count = diesel::update(
                attempts::managed_attempts
                    .filter(attempts::lease_id.eq(allocation.id.to_string()))
                    .filter(attempts::finished_at.is_null()),
            )
            .set((
                attempts::stage.eq(stage),
                attempts::category.eq(failure.kind.as_str()),
                attempts::provider_status.eq(failure.provider_status.map(i32::from)),
                attempts::finished_at.eq(Some(now)),
            ))
            .execute(conn)?;
            if count != 1 {
                return Err(AppError::Conflict);
            }
            Ok(transitioned)
        })
    }

    fn reserve_managed_key(
        &self,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<ManagedReservationOutcome, AppError> {
        ManagedLedgerRules::validate_allocation(allocation, now)?;
        self.conn()?.immediate_transaction(|conn| {
            Self::assert_managed_client(conn, allocation)?;
            let mut accounts = Self::lock_managed_budget_accounts(conn, allocation, now)?;
            let existing = Self::current_managed_lease(
                conn,
                allocation.client_id,
                &allocation.tenant,
                &allocation.subject,
                allocation.bucket.as_str(),
                now.date_naive(),
            )?;
            if let Some(lease) = existing {
                let rejected = Self::has_only_rejected_managed_attempts(conn, &lease)?;
                if (lease.permits_replacement() || rejected)
                    && lease.id != allocation.id.to_string()
                {
                    if rejected {
                        for account in &mut accounts {
                            account.reserved_usd_micros = account
                                .balance()
                                .without_rejected_reservation(lease.limit_usd_micros)?
                                .reserved_usd_micros;
                        }
                    }
                    // Inside the reservation: an insufficient balance also rolls
                    // back the pointer change. The historical row stays intact.
                    diesel::update(leases::managed_key_leases.filter(leases::id.eq(&lease.id)))
                        .set((leases::is_current.eq(false), leases::status.eq("revoked")))
                        .execute(conn)?;
                } else {
                    if !lease.matches_request(allocation)? {
                        // The day's allocation exists with another policy; the
                        // budget is never replenished.
                        return Err(AppError::Conflict);
                    }
                    ManagedLedgerRules::validate_remaining_budget(
                        &accounts[0],
                        &accounts[1],
                        allocation,
                        lease.accounted_usage_usd_micros,
                        now,
                    )?;
                    return Ok(ManagedReservationOutcome {
                        lease,
                        created: false,
                    });
                }
            }
            let lease = Self::persist_managed_reservation(conn, &accounts, allocation, now)?;
            Ok(ManagedReservationOutcome {
                lease,
                created: true,
            })
        })
    }

    fn claim_managed_key(
        &self,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<Option<ManagedKeyLease>, AppError> {
        ManagedLedgerRules::validate_allocation(allocation, now)?;
        self.conn()?.immediate_transaction(|conn| {
            Self::assert_managed_client(conn, allocation)?;
            // Compare-and-set: only whoever obtains this row may POST. A restart
            // in provisioning requires reconciliation, never a retry.
            let [tenant, subject] = Self::lock_managed_budget_accounts(conn, allocation, now)?;
            ManagedLedgerRules::validate_reserved_budget(&tenant, &subject, allocation, now)?;
            let Some(pending) = Self::pending_lease(conn, allocation, "reserved", now)? else {
                return Ok(None);
            };
            let claimed =
                diesel::update(leases::managed_key_leases.filter(leases::id.eq(&pending.id)))
                    .set((
                        leases::status.eq("provisioning"),
                        leases::updated_at.eq(now),
                    ))
                    .returning(ManagedKeyLease::as_returning())
                    .get_result(conn)
                    .optional()?;
            if claimed.is_some() {
                diesel::insert_into(attempts::managed_attempts)
                    .values((
                        attempts::id.eq(Uuid::new_v4().to_string()),
                        attempts::lease_id.eq(allocation.id.to_string()),
                        attempts::stage.eq("create"),
                        attempts::category.eq("started"),
                        attempts::created_at.eq(now),
                    ))
                    .execute(conn)?;
            }
            Ok(claimed)
        })
    }

    fn confirm_managed_key(
        &self,
        allocation: &ManagedKeyAllocation,
        data: &OpenRouterManagedKeyData,
        sealed: &ManagedSealedKey,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        ManagedLedgerRules::validate_allocation(allocation, now)?;
        data.validate_issued_for(allocation, now)?;
        self.conn()?.immediate_transaction(|conn| {
            Self::assert_managed_client(conn, allocation)?;
            let [tenant, subject] = Self::lock_managed_budget_accounts(conn, allocation, now)?;
            ManagedLedgerRules::validate_reserved_budget(&tenant, &subject, allocation, now)?;
            let Some(pending) = Self::pending_lease(conn, allocation, "provisioning", now)? else {
                return Ok(false);
            };
            let count =
                diesel::update(leases::managed_key_leases.filter(leases::id.eq(&pending.id)))
                    .set((
                        leases::status.eq("issued"),
                        leases::key_hash.eq(&data.hash),
                        leases::api_key_sealed.eq(sealed.bytes()),
                        leases::updated_at.eq(now),
                    ))
                    .execute(conn)?;
            if count == 1 {
                diesel::update(
                    attempts::managed_attempts
                        .filter(attempts::lease_id.eq(allocation.id.to_string()))
                        .filter(attempts::finished_at.is_null()),
                )
                .set((
                    attempts::stage.eq("persist"),
                    attempts::category.eq("issued"),
                    attempts::finished_at.eq(Some(now)),
                ))
                .execute(conn)?;
            }
            Ok(count == 1)
        })
    }
}

impl PoolConfig {
    /// The exact lease a compare-and-set may move: same identity, policy, status
    /// and a still-valid expiry. Callers run inside an immediate transaction, so
    /// no other writer can move it between this read and their update.
    fn pending_lease(
        conn: &mut SqliteConnection,
        allocation: &ManagedKeyAllocation,
        status: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ManagedKeyLease>, AppError> {
        Ok(leases::managed_key_leases
            .filter(leases::id.eq(allocation.id.to_string()))
            .filter(leases::client_id.eq(allocation.client_id.to_string()))
            .filter(leases::tenant.eq(&allocation.tenant))
            .filter(leases::subject.eq(&allocation.subject))
            .filter(leases::status.eq(status))
            .filter(leases::workspace_id.eq(allocation.workspace_id.to_string()))
            .filter(leases::bucket.eq(allocation.bucket.as_str()))
            .filter(leases::limit_usd_micros.eq(allocation.limit_usd_micros))
            .filter(leases::expires_at.eq(allocation.expires_at))
            .filter(leases::expires_at.gt(now))
            .select(ManagedKeyLease::as_select())
            .first::<ManagedKeyLease>(conn)
            .optional()?)
    }

    /// The caller already holds the write lock over the client, accounts and allocation.
    pub(super) fn persist_managed_reservation(
        conn: &mut SqliteConnection,
        accounts: &[ManagedBudgetAccount; 2],
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<ManagedKeyLease, AppError> {
        let [tenant, subject] = accounts;
        let reserved = ManagedLedgerRules::reserve(tenant, subject, allocation, now)?;
        for (account, balance) in [(tenant, reserved.tenant), (subject, reserved.subject)] {
            diesel::update(
                budgets::managed_budget_accounts
                    .filter(budgets::id.eq(&account.id))
                    .filter(budgets::client_id.eq(allocation.client_id.to_string())),
            )
            .set((
                budgets::reserved_usd_micros.eq(balance.reserved_usd_micros),
                budgets::updated_at.eq(now),
            ))
            .execute(conn)?;
        }
        Ok(diesel::insert_into(leases::managed_key_leases)
            .values(ManagedKeyLease::reserved(allocation, now)?)
            .returning(ManagedKeyLease::as_returning())
            .get_result(conn)?)
    }

    pub(super) fn current_managed_lease(
        conn: &mut SqliteConnection,
        client: Uuid,
        tenant: &str,
        subject: &str,
        bucket: &str,
        date: NaiveDate,
    ) -> Result<Option<ManagedKeyLease>, AppError> {
        Ok(leases::managed_key_leases
            .filter(leases::client_id.eq(client.to_string()))
            .filter(leases::tenant.eq(tenant))
            .filter(leases::subject.eq(subject))
            .filter(leases::bucket.eq(bucket))
            .filter(leases::lease_date.eq(date))
            .filter(leases::is_current.eq(true))
            .select(ManagedKeyLease::as_select())
            .first::<ManagedKeyLease>(conn)
            .optional()?)
    }

    pub(super) fn has_only_rejected_managed_attempts(
        conn: &mut SqliteConnection,
        lease: &ManagedKeyLease,
    ) -> Result<bool, AppError> {
        // Never reuse this identity: a worker may keep its snapshot. An empty
        // remote list is never evidence of rejection.
        if lease.status == "revocation_pending"
            && lease.key_hash.is_none()
            && lease.api_key_sealed.is_none()
            && lease.accounted_usage_usd_micros == 0
        {
            let attempts_count = attempts::managed_attempts
                .filter(attempts::lease_id.eq(&lease.id))
                .count()
                .get_result::<i64>(conn)?;
            let uncertain_count = attempts::managed_attempts
                .filter(attempts::lease_id.eq(&lease.id))
                .filter(
                    attempts::category
                        .ne("configuration")
                        .and(attempts::category.ne("rejected"))
                        .or(attempts::finished_at.is_null()),
                )
                .count()
                .get_result::<i64>(conn)?;
            return Ok(attempts_count > 0 && uncertain_count == 0);
        }
        Ok(false)
    }

    pub(super) fn lock_managed_budget_accounts(
        conn: &mut SqliteConnection,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<[ManagedBudgetAccount; 2], AppError> {
        let period = ManagedLedgerRules::period_key(allocation.bucket, now.date_naive());
        let tenant =
            Self::budget_account(conn, allocation, OWNER_TENANT, &allocation.tenant, &period)?;
        let subject = Self::budget_account(
            conn,
            allocation,
            OWNER_SUBJECT,
            &allocation.subject,
            &period,
        )?;
        ManagedLedgerRules::validate_accounts(&tenant, &subject, allocation, now)?;
        Ok([tenant, subject])
    }

    fn budget_account(
        conn: &mut SqliteConnection,
        allocation: &ManagedKeyAllocation,
        owner_kind: &str,
        owner_id: &str,
        period: &str,
    ) -> Result<ManagedBudgetAccount, AppError> {
        budgets::managed_budget_accounts
            .filter(budgets::client_id.eq(allocation.client_id.to_string()))
            .filter(budgets::tenant.eq(&allocation.tenant))
            .filter(budgets::owner_kind.eq(owner_kind))
            .filter(budgets::owner_id.eq(owner_id))
            .filter(budgets::bucket.eq(allocation.bucket.as_str()))
            .filter(budgets::period_key.eq(period))
            .select(ManagedBudgetAccount::as_select())
            .first::<ManagedBudgetAccount>(conn)
            .optional()?
            // No budget configured for this period.
            .ok_or(AppError::Forbidden)
    }

    pub(super) fn assert_managed_client(
        conn: &mut SqliteConnection,
        allocation: &ManagedKeyAllocation,
    ) -> Result<(), AppError> {
        let client = Self::active_managed_client(conn, allocation.client_id)?;
        if client.slug != allocation.client_slug {
            return Err(AppError::Forbidden);
        }
        Self::assert_client_workspace(conn, &client.id, &allocation.workspace_id.to_string())
    }

    /// A client may only create keys in the OpenRouter workspaces assigned to it.
    pub(super) fn assert_client_workspace(
        conn: &mut SqliteConnection,
        client_id: &str,
        workspace_id: &str,
    ) -> Result<(), AppError> {
        let owned = workspaces::managed_client_workspaces
            .filter(workspaces::workspace_id.eq(workspace_id))
            .filter(workspaces::client_id.eq(client_id))
            .count()
            .get_result::<i64>(conn)?;
        if owned != 1 {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }

    pub(super) fn active_managed_client(
        conn: &mut SqliteConnection,
        client: Uuid,
    ) -> Result<ManagedClient, AppError> {
        clients::managed_clients
            .filter(clients::id.eq(client.to_string()))
            .filter(clients::suspended_at.is_null())
            .select(ManagedClient::as_select())
            .first::<ManagedClient>(conn)
            .optional()?
            .ok_or(AppError::Forbidden)
    }
}
