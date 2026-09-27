use chrono::{DateTime, Duration, Utc};
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};

use crate::error::AppError;
use crate::managed::ledger_model::ManagedKeyLease;
use crate::managed::model::OpenRouterManagedKeyData;
use crate::repository::PoolConfig;
use crate::schema::managed_budget_accounts::dsl as budgets;
use crate::schema::managed_key_leases::dsl as leases;

const PAGE: i64 = 200;

pub trait ManagedRevocationRepository: Send + Sync {
    fn pending_managed_revocations(
        &self,
        after: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ManagedKeyLease>, AppError>;
    fn confirm_managed_revocation(
        &self,
        lease: &ManagedKeyLease,
        hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
}

pub trait ManagedUsageRepository: Send + Sync {
    fn managed_usage_candidates(
        &self,
        after: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ManagedKeyLease>, AppError>;
    fn record_managed_usage(
        &self,
        lease: &ManagedKeyLease,
        observation: &OpenRouterManagedKeyData,
        now: DateTime<Utc>,
    ) -> Result<(), AppError>;
}

impl ManagedRevocationRepository for PoolConfig {
    fn pending_managed_revocations(
        &self,
        after: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ManagedKeyLease>, AppError> {
        self.conn()?.immediate_transaction(|conn| {
            // Two minutes exceed both POST timeouts. The compare-and-set rejects a
            // late confirmation; recovery will look the key up by name.
            diesel::update(
                leases::managed_key_leases.filter(
                    leases::status
                        .eq("uncertain")
                        .or(leases::status
                            .eq("provisioning")
                            .and(leases::updated_at.le(now - Duration::minutes(2))))
                        .or(leases::status.eq("issued").and(leases::expires_at.le(now))),
                ),
            )
            .set((
                leases::status.eq("revocation_pending"),
                leases::api_key_sealed.eq(None::<Vec<u8>>),
                leases::updated_at.eq(now),
            ))
            .execute(conn)?;
            Ok(leases::managed_key_leases
                .filter(leases::status.eq("revocation_pending"))
                .filter(leases::id.gt(after))
                .order(leases::id.asc())
                .limit(PAGE)
                .select(ManagedKeyLease::as_select())
                .load(conn)?)
        })
    }

    fn confirm_managed_revocation(
        &self,
        lease: &ManagedKeyLease,
        hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        // Remote confirmation is NOT monetary settlement. The reserved balance is
        // not released here, least of all for uncertain issuances.
        let count = diesel::update(
            leases::managed_key_leases
                .filter(leases::id.eq(&lease.id))
                .filter(leases::client_id.eq(&lease.client_id))
                .filter(leases::tenant.eq(&lease.tenant))
                .filter(leases::subject.eq(&lease.subject))
                .filter(leases::workspace_id.eq(&lease.workspace_id))
                .filter(leases::status.eq("revocation_pending"))
                .filter(leases::key_hash.is_null().or(leases::key_hash.eq(hash))),
        )
        .set((
            leases::status.eq("revoked"),
            leases::key_hash.eq(hash),
            leases::usage_checked_at.eq(None::<DateTime<Utc>>),
            leases::api_key_sealed.eq(None::<Vec<u8>>),
            leases::updated_at.eq(now),
        ))
        .execute(&mut self.conn()?)?;
        Ok(count == 1)
    }
}

impl ManagedUsageRepository for PoolConfig {
    fn managed_usage_candidates(
        &self,
        after: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ManagedKeyLease>, AppError> {
        // Keep observing revoked keys: an in-flight inference can be charged
        // after OpenRouter confirmed disabled=true.
        Ok(leases::managed_key_leases
            .filter(leases::key_hash.is_not_null())
            .filter(leases::status.eq_any(["issued", "revocation_pending", "revoked"]))
            // Revoked keys are observed at once and then daily; never poll the
            // whole history every minute nor assume a final settlement.
            .filter(
                leases::status
                    .ne("revoked")
                    .or(leases::usage_checked_at.is_null())
                    .or(leases::usage_checked_at.le(now - Duration::days(1))),
            )
            .filter(leases::id.gt(after))
            .order(leases::id.asc())
            .limit(PAGE)
            .select(ManagedKeyLease::as_select())
            .load(&mut self.conn()?)?)
    }

    fn record_managed_usage(
        &self,
        lease: &ManagedKeyLease,
        observation: &OpenRouterManagedKeyData,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let allocation = lease.allocation()?;
        let confirmed_usage = observation.confirmed_usage_micros()?;
        if lease.key_hash.as_deref() != Some(observation.hash.as_str())
            || observation.workspace_id != Some(allocation.workspace_id)
        {
            return Err(AppError::Forbidden);
        }
        self.conn()?.immediate_transaction(|conn| {
            // Same order as issuance: tenant, subject, allocation. The period is
            // the issuance one, even when the observation arrives tomorrow.
            let accounts = Self::lock_managed_budget_accounts(conn, &allocation, lease.created_at)?;
            let stored = leases::managed_key_leases
                .filter(leases::id.eq(&lease.id))
                .select(ManagedKeyLease::as_select())
                .first::<ManagedKeyLease>(conn)?;
            if stored.key_hash != lease.key_hash || stored.allocation()? != allocation {
                return Err(AppError::Conflict);
            }
            let accounted = stored.accounted_usage_usd_micros.max(confirmed_usage);
            for account in accounts {
                let balance = account.balance().apply_confirmed_usage(
                    stored.limit_usd_micros,
                    stored.accounted_usage_usd_micros,
                    accounted,
                )?;
                diesel::update(
                    budgets::managed_budget_accounts.filter(budgets::id.eq(&account.id)),
                )
                .set((
                    budgets::spent_usd_micros.eq(balance.spent_usd_micros),
                    budgets::reserved_usd_micros.eq(balance.reserved_usd_micros),
                    budgets::updated_at.eq(now),
                ))
                .execute(conn)?;
            }
            let checked_at = stored
                .usage_checked_at
                .map_or(now, |checked| checked.max(now));
            diesel::update(leases::managed_key_leases.filter(leases::id.eq(&stored.id)))
                .set((
                    leases::accounted_usage_usd_micros.eq(accounted),
                    leases::usage_checked_at.eq(Some(checked_at)),
                ))
                .execute(conn)?;
            // An external change of the key is never fixed by recreating it.
            if observation.disabled {
                diesel::update(leases::managed_key_leases.filter(leases::id.eq(&stored.id)))
                    .set((
                        leases::status.eq("revoked"),
                        leases::api_key_sealed.eq(None::<Vec<u8>>),
                        leases::updated_at.eq(now),
                    ))
                    .execute(conn)?;
            } else if stored.status == "revoked"
                || observation.name != allocation.provider_name()
                || observation.limit != Some(allocation.limit_usd())
                || observation.limit_reset.is_some()
                || !observation.include_byok_in_limit
                || observation.expires_at != Some(allocation.expires_at)
            {
                diesel::update(leases::managed_key_leases.filter(leases::id.eq(&stored.id)))
                    .set((
                        leases::status.eq("revocation_pending"),
                        leases::api_key_sealed.eq(None::<Vec<u8>>),
                        leases::updated_at.eq(now),
                    ))
                    .execute(conn)?;
            }
            Ok(())
        })
    }
}
