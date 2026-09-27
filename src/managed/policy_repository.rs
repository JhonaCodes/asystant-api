use chrono::{DateTime, Utc};
use diesel::{
    BoolExpressionMethods, Connection, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl,
    SelectableHelper, SqliteConnection,
};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::ledger_model::{
    ManagedBudgetAccount, ManagedKeyLease, ManagedLeaseState, ManagedLedgerRules, OWNER_SUBJECT,
    OWNER_TENANT,
};
use crate::managed::model::{ManagedKeyAllocation, ManagedUsageBucket};
use crate::managed::policy_model::{
    ManagedBudgetOverview, ManagedCredentialStatus, ManagedPolicy, ManagedPolicyChange,
    ManagedPolicyRules,
};
use crate::repository::PoolConfig;
use crate::schema::managed_budget_accounts::dsl as budgets;
use crate::schema::managed_key_leases::dsl as leases;
use crate::schema::managed_policies::dsl as policies;
use crate::schema::managed_policy_events::dsl as events;

pub trait ManagedPolicyRepository: Send + Sync {
    fn managed_budget_overview(
        &self,
        client: Uuid,
        tenant: &str,
        now: DateTime<Utc>,
    ) -> Result<ManagedBudgetOverview, AppError>;
    fn set_managed_policy(
        &self,
        change: &ManagedPolicyChange,
        now: DateTime<Utc>,
    ) -> Result<ManagedPolicy, AppError>;
    fn resolve_managed_allocation(
        &self,
        client: Uuid,
        tenant: &str,
        subject: &str,
        bucket: ManagedUsageBucket,
        now: DateTime<Utc>,
    ) -> Result<ManagedKeyAllocation, AppError>;
}

impl ManagedPolicyRepository for PoolConfig {
    fn managed_budget_overview(
        &self,
        client: Uuid,
        tenant: &str,
        now: DateTime<Utc>,
    ) -> Result<ManagedBudgetOverview, AppError> {
        let client_id = client.to_string();
        self.conn()?.transaction(|conn| {
            Self::active_managed_client(conn, client)?;
            let policies = policies::managed_policies
                .filter(policies::client_id.eq(&client_id))
                .filter(policies::tenant.eq(tenant))
                .order((
                    policies::owner_kind.asc(),
                    policies::owner_id.asc(),
                    policies::bucket.asc(),
                ))
                .select(ManagedPolicy::as_select())
                .load(conn)?;
            let accounts = budgets::managed_budget_accounts
                .filter(budgets::client_id.eq(&client_id))
                .filter(budgets::tenant.eq(tenant))
                .filter(
                    budgets::period_key
                        .eq_any([now.date_naive().to_string(), "lifetime".to_string()]),
                )
                .select(ManagedBudgetAccount::as_select())
                .load(conn)?;
            // Pending states from previous days stay visible too.
            let credentials = leases::managed_key_leases
                .filter(leases::client_id.eq(&client_id))
                .filter(leases::tenant.eq(tenant))
                .filter(
                    leases::lease_date
                        .eq(now.date_naive())
                        .or(leases::status.eq_any([
                            "provisioning",
                            "uncertain",
                            "revocation_pending",
                        ])),
                )
                .select(ManagedKeyLease::as_select())
                .load::<ManagedKeyLease>(conn)?
                .into_iter()
                .map(ManagedCredentialStatus::from)
                .collect();
            Ok(ManagedBudgetOverview {
                policies,
                accounts,
                credentials,
            })
        })
    }

    fn set_managed_policy(
        &self,
        change: &ManagedPolicyChange,
        now: DateTime<Utc>,
    ) -> Result<ManagedPolicy, AppError> {
        change.validate()?;
        let client_id = change.client_id.to_string();
        // The immediate transaction serializes the whole tenant distribution,
        // including its first row, against issuance.
        self.conn()?.immediate_transaction(|conn| {
            Self::active_managed_client(conn, change.client_id)?;
            let current = policies::managed_policies
                .filter(policies::client_id.eq(&client_id))
                .filter(policies::tenant.eq(&change.tenant))
                .filter(policies::bucket.eq(change.bucket.as_str()))
                .select(ManagedPolicy::as_select())
                .load::<ManagedPolicy>(conn)?;
            let previous = current.iter().find(|policy| {
                policy.owner_kind == change.owner_kind && policy.owner_id == change.owner_id
            });
            let tenant_policy = current
                .iter()
                .find(|policy| policy.owner_kind == OWNER_TENANT);
            let workspace = if change.owner_kind == OWNER_TENANT {
                change.workspace_id.ok_or(AppError::Invalid)?.to_string()
            } else {
                // The tenant ceiling must exist before distributing it.
                tenant_policy
                    .ok_or(AppError::Forbidden)?
                    .workspace_id
                    .clone()
            };
            Self::assert_client_workspace(conn, &client_id, &workspace)?;
            if current
                .iter()
                .any(|policy| policy.workspace_id != workspace)
            {
                // The workspace never changes under existing budgets.
                return Err(AppError::Conflict);
            }
            let others = current
                .iter()
                .filter(|policy| {
                    policy.owner_kind == OWNER_SUBJECT
                        && (change.owner_kind == OWNER_TENANT || policy.owner_id != change.owner_id)
                })
                .try_fold(0_i64, |sum, policy| {
                    sum.checked_add(policy.limit_usd_micros)
                })
                .ok_or(AppError::Conflict)?;
            if change.owner_kind == OWNER_TENANT {
                ManagedPolicyRules::validate_distribution(change.limit_usd_micros, others, 0)?;
            } else {
                let ceiling = tenant_policy.ok_or(AppError::Forbidden)?.limit_usd_micros;
                ManagedPolicyRules::validate_distribution(
                    ceiling,
                    others,
                    change.limit_usd_micros,
                )?;
            }
            let policy = ManagedPolicy {
                id: previous.map_or_else(|| Uuid::new_v4().to_string(), |policy| policy.id.clone()),
                client_id: client_id.clone(),
                tenant: change.tenant.clone(),
                owner_kind: change.owner_kind.clone(),
                owner_id: change.owner_id.clone(),
                workspace_id: workspace,
                bucket: change.bucket.as_str().to_string(),
                limit_usd_micros: change.limit_usd_micros,
                updated_by: change.actor.clone(),
                updated_at: now,
            };
            // Repeating the PUT adds no audit and does not invalidate keys again.
            if let Some(previous) =
                previous.filter(|previous| previous.limit_usd_micros == policy.limit_usd_micros)
            {
                return Ok(previous.clone());
            }
            diesel::insert_into(policies::managed_policies)
                .values(&policy)
                .on_conflict(policies::id)
                .do_update()
                .set((
                    policies::limit_usd_micros.eq(policy.limit_usd_micros),
                    policies::updated_by.eq(&change.actor),
                    policies::updated_at.eq(now),
                ))
                .execute(conn)?;
            diesel::insert_into(events::managed_policy_events)
                .values((
                    events::id.eq(Uuid::new_v4().to_string()),
                    events::policy_id.eq(&policy.id),
                    events::actor.eq(&change.actor),
                    events::previous_limit_usd_micros
                        .eq(previous.map(|policy| policy.limit_usd_micros)),
                    events::limit_usd_micros.eq(policy.limit_usd_micros),
                    events::created_at.eq(now),
                ))
                .execute(conn)?;
            // Updates only the limit: NEVER usage nor reservations, not even on retry.
            Self::materialize_managed_account(conn, &policy, change.bucket, now)?;
            if previous.is_some_and(|previous| policy.limit_usd_micros < previous.limit_usd_micros)
            {
                let mut targets = leases::managed_key_leases
                    .filter(leases::client_id.eq(&client_id))
                    .filter(leases::tenant.eq(&change.tenant))
                    .filter(leases::bucket.eq(change.bucket.as_str()))
                    .filter(leases::status.eq_any(ManagedLeaseState::LIVE))
                    .into_boxed();
                if change.owner_kind == OWNER_SUBJECT {
                    targets = targets.filter(leases::subject.eq(&change.owner_id));
                }
                let ids = targets.select(leases::id).load::<String>(conn)?;
                Self::revoke_leases(conn, &ids, now)?;
            }
            Ok(policy)
        })
    }

    fn resolve_managed_allocation(
        &self,
        client: Uuid,
        tenant: &str,
        subject: &str,
        bucket: ManagedUsageBucket,
        now: DateTime<Utc>,
    ) -> Result<ManagedKeyAllocation, AppError> {
        let client_id = client.to_string();
        self.conn()?.immediate_transaction(|conn| {
            let managed_client = Self::active_managed_client(conn, client)?;
            let mut allocation = ManagedKeyAllocation {
                id: Uuid::new_v4(),
                client_id: client,
                client_slug: managed_client.slug,
                tenant: tenant.to_string(),
                subject: subject.to_string(),
                workspace_id: Uuid::nil(),
                bucket,
                limit_usd_micros: 1,
                expires_at: ManagedKeyAllocation::end_of_day(now)?,
            };
            let mut available = i64::MAX;
            for (kind, owner) in [(OWNER_TENANT, tenant), (OWNER_SUBJECT, subject)] {
                let policy =
                    Self::owner_policy(conn, &client_id, tenant, kind, owner, bucket.as_str())?;
                if kind == OWNER_TENANT {
                    allocation.workspace_id =
                        Uuid::parse_str(&policy.workspace_id).map_err(|_| AppError::Internal)?;
                }
                if policy.workspace_id != allocation.workspace_id.to_string()
                    || policy.limit_usd_micros == 0
                {
                    return Err(AppError::Forbidden);
                }
                let account = Self::materialize_managed_account(conn, &policy, bucket, now)?;
                available = available.min(account.balance().available_usd_micros()?);
            }
            // Recovering from another session does not compute a smaller budget
            // because of this subject's own reservation.
            if let Some(existing) = Self::current_managed_lease(
                conn,
                client,
                tenant,
                subject,
                bucket.as_str(),
                now.date_naive(),
            )? {
                if Self::has_only_rejected_managed_attempts(conn, &existing)? {
                    available = i64::MAX;
                    for account in
                        Self::lock_managed_budget_accounts(conn, &existing.allocation()?, now)?
                    {
                        available = available.min(
                            account
                                .balance()
                                .without_rejected_reservation(existing.limit_usd_micros)?
                                .available_usd_micros()?,
                        );
                    }
                } else if !existing.permits_replacement() {
                    return existing.allocation();
                }
            }
            if available <= 0 {
                // Pending reservations are not released when replacing a key.
                return Err(AppError::Budget);
            }
            allocation.limit_usd_micros = available;
            allocation.validate(now)?;
            Ok(allocation)
        })
    }
}

impl PoolConfig {
    /// The budget policy of one owner; without it there is no budget to issue from.
    pub(super) fn owner_policy(
        conn: &mut SqliteConnection,
        client_id: &str,
        tenant: &str,
        owner_kind: &str,
        owner_id: &str,
        bucket: &str,
    ) -> Result<ManagedPolicy, AppError> {
        policies::managed_policies
            .filter(policies::client_id.eq(client_id))
            .filter(policies::tenant.eq(tenant))
            .filter(policies::owner_kind.eq(owner_kind))
            .filter(policies::owner_id.eq(owner_id))
            .filter(policies::bucket.eq(bucket))
            .select(ManagedPolicy::as_select())
            .first::<ManagedPolicy>(conn)
            .optional()?
            .ok_or(AppError::Forbidden)
    }

    pub(super) fn materialize_managed_account(
        conn: &mut SqliteConnection,
        policy: &ManagedPolicy,
        bucket: ManagedUsageBucket,
        now: DateTime<Utc>,
    ) -> Result<ManagedBudgetAccount, AppError> {
        let account = ManagedBudgetAccount {
            id: Uuid::new_v4().to_string(),
            client_id: policy.client_id.clone(),
            tenant: policy.tenant.clone(),
            owner_kind: policy.owner_kind.clone(),
            owner_id: policy.owner_id.clone(),
            workspace_id: policy.workspace_id.clone(),
            bucket: policy.bucket.clone(),
            period_key: ManagedLedgerRules::period_key(bucket, now.date_naive()),
            limit_usd_micros: policy.limit_usd_micros,
            spent_usd_micros: 0,
            reserved_usd_micros: 0,
            created_at: now,
            updated_at: now,
        };
        Ok(diesel::insert_into(budgets::managed_budget_accounts)
            .values(&account)
            .on_conflict((
                budgets::client_id,
                budgets::tenant,
                budgets::owner_kind,
                budgets::owner_id,
                budgets::bucket,
                budgets::period_key,
            ))
            .do_update()
            .set((
                budgets::limit_usd_micros.eq(policy.limit_usd_micros),
                budgets::updated_at.eq(now),
            ))
            .returning(ManagedBudgetAccount::as_returning())
            .get_result(conn)?)
    }

    /// Live keys go to the revocation queue without their ciphertext; a
    /// reservation that never reached the provider is closed directly.
    pub(super) fn revoke_leases(
        conn: &mut SqliteConnection,
        ids: &[String],
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        diesel::update(
            leases::managed_key_leases
                .filter(leases::id.eq_any(ids))
                .filter(leases::status.ne("reserved")),
        )
        .set((
            leases::status.eq("revocation_pending"),
            leases::api_key_sealed.eq(None::<Vec<u8>>),
            leases::updated_at.eq(now),
        ))
        .execute(conn)?;
        diesel::update(
            leases::managed_key_leases
                .filter(leases::id.eq_any(ids))
                .filter(leases::status.eq("reserved")),
        )
        .set((leases::status.eq("revoked"), leases::updated_at.eq(now)))
        .execute(conn)?;
        Ok(())
    }
}
