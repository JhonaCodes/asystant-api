use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::ledger_model::{ManagedKeyLease, OWNER_SUBJECT, OWNER_TENANT};
use crate::managed::model::ManagedKeyAllocation;
use crate::managed::policy_model::{ManagedRecovery, ManagedRecoveryRequest};
use crate::repository::PoolConfig;
use crate::schema::managed_key_leases::dsl as leases;
use crate::schema::managed_recoveries::dsl as recoveries;

pub trait ManagedRecoveryRepository: Send + Sync {
    fn authorize_managed_recovery(
        &self,
        client: Uuid,
        tenant: &str,
        previous: Uuid,
        request: &ManagedRecoveryRequest,
        now: DateTime<Utc>,
    ) -> Result<ManagedRecovery, AppError>;
}

impl ManagedRecoveryRepository for PoolConfig {
    fn authorize_managed_recovery(
        &self,
        client: Uuid,
        tenant: &str,
        previous: Uuid,
        request: &ManagedRecoveryRequest,
        now: DateTime<Utc>,
    ) -> Result<ManagedRecovery, AppError> {
        request.validate()?;
        let client_id = client.to_string();
        let previous_id = previous.to_string();
        self.conn()?.immediate_transaction(|conn| {
            let snapshot = leases::managed_key_leases
                .filter(leases::id.eq(&previous_id))
                .filter(leases::client_id.eq(&client_id))
                .filter(leases::tenant.eq(tenant))
                .select(ManagedKeyLease::as_select())
                .first::<ManagedKeyLease>(conn)
                .optional()?
                .ok_or(AppError::NotFound)?;
            let mut allocation = snapshot.allocation()?;
            allocation.id = Uuid::new_v4();
            allocation.limit_usd_micros = request.limit_usd_micros;
            allocation.expires_at = ManagedKeyAllocation::end_of_day(now)?;
            allocation.validate(now)?;
            // Same order as issuance: client -> tenant -> subject -> lease.
            Self::assert_managed_client(conn, &allocation)?;
            for (kind, owner) in [
                (OWNER_TENANT, tenant),
                (OWNER_SUBJECT, snapshot.subject.as_str()),
            ] {
                let policy =
                    Self::owner_policy(conn, &client_id, tenant, kind, owner, &snapshot.bucket)?;
                if policy.workspace_id != allocation.workspace_id.to_string()
                    || policy.limit_usd_micros <= 0
                {
                    return Err(AppError::Forbidden);
                }
                Self::materialize_managed_account(conn, &policy, allocation.bucket, now)?;
            }
            let accounts = Self::lock_managed_budget_accounts(conn, &allocation, now)?;
            // Repeating the same authorization never creates another reservation
            // nor identity.
            if let Some(existing) = recoveries::managed_recoveries
                .filter(recoveries::previous_lease_id.eq(&previous_id))
                .filter(recoveries::client_id.eq(&client_id))
                .select(ManagedRecovery::as_select())
                .first::<ManagedRecovery>(conn)
                .optional()?
            {
                if existing.limit_usd_micros != request.limit_usd_micros
                    || existing.reason != request.reason.trim()
                {
                    return Err(AppError::Conflict);
                }
                return Ok(existing);
            }
            if !snapshot.can_authorize_recovery() {
                // The allocation changed or is not pending reconciliation.
                return Err(AppError::Conflict);
            }
            if Self::current_managed_lease(
                conn,
                client,
                tenant,
                &snapshot.subject,
                &snapshot.bucket,
                now.date_naive(),
            )?
            .is_some_and(|current| current.id != previous_id)
            {
                // The subject already holds another current allocation.
                return Err(AppError::Conflict);
            }
            diesel::update(leases::managed_key_leases.filter(leases::id.eq(&previous_id)))
                .set((
                    leases::is_current.eq(false),
                    leases::status.eq("revocation_pending"),
                    leases::api_key_sealed.eq(None::<Vec<u8>>),
                    leases::updated_at.eq(now),
                ))
                .execute(conn)?;
            // The old reservation is never discounted, not even without a hash.
            Self::persist_managed_reservation(conn, &accounts, &allocation, now)?;
            let recovery = ManagedRecovery {
                id: Uuid::new_v4().to_string(),
                client_id: client_id.clone(),
                tenant: tenant.to_string(),
                previous_lease_id: previous_id.clone(),
                replacement_lease_id: allocation.id.to_string(),
                actor: request.actor.clone(),
                limit_usd_micros: request.limit_usd_micros,
                reason: request.reason.trim().to_string(),
                created_at: now,
            };
            diesel::insert_into(recoveries::managed_recoveries)
                .values(&recovery)
                .execute(conn)?;
            Ok(recovery)
        })
    }
}
