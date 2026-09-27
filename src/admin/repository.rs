use chrono::{DateTime, Duration, NaiveDate, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl,
    SelectableHelper,
};

use crate::admin::model::{AdminSession, AdminUser, AuditEntry, NewAuditEntry, SignInAttempt};
use crate::error::AppError;
use crate::managed::client_model::{ManagedClientKey, ManagedClientWorkspace};
use crate::managed::ledger_model::{ManagedBudgetAccount, ManagedKeyLease, OWNER_TENANT};
use crate::managed::policy_model::ManagedPolicy;
use crate::repository::PoolConfig;
use crate::schema::admin_audit_log::dsl as audit;
use crate::schema::admin_sessions::dsl as sessions;
use crate::schema::admin_sign_in_attempts::dsl as attempts;
use crate::schema::admin_users::dsl as admins;
use crate::schema::managed_budget_accounts::dsl as budgets;
use crate::schema::managed_client_keys::dsl as keys;
use crate::schema::managed_client_workspaces::dsl as workspaces;
use crate::schema::managed_key_leases::dsl as leases;
use crate::schema::managed_policies::dsl as policies;

/// Operators, their sessions, sign-in attempts and the audit trail.
pub trait AdminRepository: Send + Sync {
    fn insert_admin(&self, admin: &AdminUser) -> Result<(), AppError>;
    fn admin_by_username(&self, username: &str) -> Result<Option<AdminUser>, AppError>;
    fn reset_admin(
        &self,
        username: &str,
        password_hash: &str,
        totp_sealed: &[u8],
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
    fn advance_totp_step(&self, admin_id: &str, step: i64) -> Result<bool, AppError>;
    fn record_sign_in(
        &self,
        admin_id: &str,
        source: &str,
        now: DateTime<Utc>,
    ) -> Result<(), AppError>;
    fn update_password(
        &self,
        admin_id: &str,
        hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), AppError>;
    fn set_pending_totp(&self, admin_id: &str, sealed: Option<&[u8]>) -> Result<(), AppError>;
    fn confirm_totp(&self, admin_id: &str, sealed: &[u8], step: i64) -> Result<bool, AppError>;
    fn record_attempt(&self, attempt: &SignInAttempt) -> Result<(), AppError>;
    fn recent_failures(
        &self,
        username: &str,
        source: &str,
        since: DateTime<Utc>,
    ) -> Result<(i64, i64), AppError>;
    fn insert_session(&self, session: &AdminSession) -> Result<(), AppError>;
    fn session_by_token(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
        idle: Duration,
    ) -> Result<Option<(AdminSession, AdminUser)>, AppError>;
    fn touch_session(&self, session_id: &str, now: DateTime<Utc>) -> Result<(), AppError>;
    fn active_sessions(
        &self,
        admin_id: &str,
        now: DateTime<Utc>,
        idle: Duration,
    ) -> Result<Vec<AdminSession>, AppError>;
    fn revoke_session(
        &self,
        admin_id: &str,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
    fn revoke_other_sessions(
        &self,
        admin_id: &str,
        keep: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, AppError>;
    fn append_audit(&self, entry: &NewAuditEntry) -> Result<(), AppError>;
    fn audit_entries(
        &self,
        company_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditEntry>, AppError>;
}

impl AdminRepository for PoolConfig {
    fn insert_admin(&self, admin: &AdminUser) -> Result<(), AppError> {
        diesel::insert_into(admins::admin_users)
            .values(admin)
            .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn admin_by_username(&self, username: &str) -> Result<Option<AdminUser>, AppError> {
        Ok(admins::admin_users
            .filter(admins::username.eq(username))
            .filter(admins::disabled_at.is_null())
            .select(AdminUser::as_select())
            .first::<AdminUser>(&mut self.conn()?)
            .optional()?)
    }

    fn reset_admin(
        &self,
        username: &str,
        password_hash: &str,
        totp_sealed: &[u8],
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        self.conn()?.immediate_transaction(|conn| {
            let Some(id) = admins::admin_users
                .filter(admins::username.eq(username))
                .select(admins::id)
                .first::<String>(conn)
                .optional()?
            else {
                return Ok(false);
            };
            diesel::update(admins::admin_users.filter(admins::id.eq(&id)))
                .set((
                    admins::password_hash.eq(password_hash),
                    admins::totp_sealed.eq(totp_sealed),
                    admins::totp_last_step.eq(0_i64),
                    admins::pending_totp_sealed.eq(None::<Vec<u8>>),
                    admins::password_changed_at.eq(now),
                    admins::disabled_at.eq(None::<DateTime<Utc>>),
                ))
                .execute(conn)?;
            // A reset ends every session that the old credentials opened.
            diesel::update(
                sessions::admin_sessions
                    .filter(sessions::admin_id.eq(&id))
                    .filter(sessions::revoked_at.is_null()),
            )
            .set(sessions::revoked_at.eq(Some(now)))
            .execute(conn)?;
            Ok(true)
        })
    }

    fn advance_totp_step(&self, admin_id: &str, step: i64) -> Result<bool, AppError> {
        // Compare-and-set: two requests with the same code cannot both pass.
        let count = diesel::update(
            admins::admin_users
                .filter(admins::id.eq(admin_id))
                .filter(admins::totp_last_step.lt(step)),
        )
        .set(admins::totp_last_step.eq(step))
        .execute(&mut self.conn()?)?;
        Ok(count == 1)
    }

    fn record_sign_in(
        &self,
        admin_id: &str,
        source: &str,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        diesel::update(admins::admin_users.filter(admins::id.eq(admin_id)))
            .set((
                admins::last_sign_in_at.eq(Some(now)),
                admins::last_sign_in_source.eq(Some(source)),
            ))
            .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn update_password(
        &self,
        admin_id: &str,
        hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        diesel::update(admins::admin_users.filter(admins::id.eq(admin_id)))
            .set((
                admins::password_hash.eq(hash),
                admins::password_changed_at.eq(now),
            ))
            .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn set_pending_totp(&self, admin_id: &str, sealed: Option<&[u8]>) -> Result<(), AppError> {
        diesel::update(admins::admin_users.filter(admins::id.eq(admin_id)))
            .set(admins::pending_totp_sealed.eq(sealed))
            .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn confirm_totp(&self, admin_id: &str, sealed: &[u8], step: i64) -> Result<bool, AppError> {
        let count = diesel::update(
            admins::admin_users
                .filter(admins::id.eq(admin_id))
                .filter(admins::pending_totp_sealed.eq(sealed)),
        )
        .set((
            admins::totp_sealed.eq(sealed),
            admins::pending_totp_sealed.eq(None::<Vec<u8>>),
            admins::totp_last_step.eq(step),
        ))
        .execute(&mut self.conn()?)?;
        Ok(count == 1)
    }

    fn record_attempt(&self, attempt: &SignInAttempt) -> Result<(), AppError> {
        diesel::insert_into(attempts::admin_sign_in_attempts)
            .values(attempt)
            .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn recent_failures(
        &self,
        username: &str,
        source: &str,
        since: DateTime<Utc>,
    ) -> Result<(i64, i64), AppError> {
        let mut conn = self.conn()?;
        let by_username = attempts::admin_sign_in_attempts
            .filter(attempts::username.eq(username))
            .filter(attempts::succeeded.eq(false))
            .filter(attempts::created_at.gt(since))
            .count()
            .get_result::<i64>(&mut conn)?;
        let by_source = attempts::admin_sign_in_attempts
            .filter(attempts::source.eq(source))
            .filter(attempts::succeeded.eq(false))
            .filter(attempts::created_at.gt(since))
            .count()
            .get_result::<i64>(&mut conn)?;
        Ok((by_username, by_source))
    }

    fn insert_session(&self, session: &AdminSession) -> Result<(), AppError> {
        diesel::insert_into(sessions::admin_sessions)
            .values(session)
            .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn session_by_token(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
        idle: Duration,
    ) -> Result<Option<(AdminSession, AdminUser)>, AppError> {
        let mut conn = self.conn()?;
        let Some(session) = sessions::admin_sessions
            .filter(sessions::token_hash.eq(token_hash))
            .filter(sessions::revoked_at.is_null())
            .filter(sessions::expires_at.gt(now))
            .filter(sessions::last_seen_at.gt(now - idle))
            .select(AdminSession::as_select())
            .first::<AdminSession>(&mut conn)
            .optional()?
        else {
            return Ok(None);
        };
        let admin = admins::admin_users
            .filter(admins::id.eq(&session.admin_id))
            .filter(admins::disabled_at.is_null())
            .select(AdminUser::as_select())
            .first::<AdminUser>(&mut conn)
            .optional()?;
        Ok(admin.map(|admin| (session, admin)))
    }

    fn touch_session(&self, session_id: &str, now: DateTime<Utc>) -> Result<(), AppError> {
        diesel::update(sessions::admin_sessions.filter(sessions::id.eq(session_id)))
            .set(sessions::last_seen_at.eq(now))
            .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn active_sessions(
        &self,
        admin_id: &str,
        now: DateTime<Utc>,
        idle: Duration,
    ) -> Result<Vec<AdminSession>, AppError> {
        Ok(sessions::admin_sessions
            .filter(sessions::admin_id.eq(admin_id))
            .filter(sessions::revoked_at.is_null())
            .filter(sessions::expires_at.gt(now))
            .filter(sessions::last_seen_at.gt(now - idle))
            .order(sessions::created_at.desc())
            .select(AdminSession::as_select())
            .load(&mut self.conn()?)?)
    }

    fn revoke_session(
        &self,
        admin_id: &str,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let count = diesel::update(
            sessions::admin_sessions
                .filter(sessions::id.eq(session_id))
                .filter(sessions::admin_id.eq(admin_id))
                .filter(sessions::revoked_at.is_null()),
        )
        .set(sessions::revoked_at.eq(Some(now)))
        .execute(&mut self.conn()?)?;
        Ok(count == 1)
    }

    fn revoke_other_sessions(
        &self,
        admin_id: &str,
        keep: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, AppError> {
        Ok(diesel::update(
            sessions::admin_sessions
                .filter(sessions::admin_id.eq(admin_id))
                .filter(sessions::id.ne(keep))
                .filter(sessions::revoked_at.is_null()),
        )
        .set(sessions::revoked_at.eq(Some(now)))
        .execute(&mut self.conn()?)?)
    }

    fn append_audit(&self, entry: &NewAuditEntry) -> Result<(), AppError> {
        diesel::insert_into(audit::admin_audit_log)
            .values(entry)
            .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn audit_entries(
        &self,
        company_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditEntry>, AppError> {
        let mut query = audit::admin_audit_log
            .order(audit::id.desc())
            .limit(limit)
            .select(AuditEntry::as_select())
            .into_boxed();
        if let Some(company) = company_id {
            query = query.filter(audit::company_id.eq(company));
        }
        Ok(query.load(&mut self.conn()?)?)
    }
}

/// Read-only views of the ledger for the console. Aggregation happens in the
/// service; these only load bounded sets of rows.
pub trait ReportRepository: Send + Sync {
    fn tenant_accounts(
        &self,
        client_id: Option<&str>,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<ManagedBudgetAccount>, AppError>;
    fn lifetime_tenant_accounts(
        &self,
        client_id: Option<&str>,
    ) -> Result<Vec<ManagedBudgetAccount>, AppError>;
    fn leases_on(
        &self,
        client_id: Option<&str>,
        date: NaiveDate,
    ) -> Result<Vec<ManagedKeyLease>, AppError>;
    fn attention_leases(&self, now: DateTime<Utc>) -> Result<Vec<ManagedKeyLease>, AppError>;
    fn tenant_policies(&self, client_id: &str) -> Result<Vec<ManagedPolicy>, AppError>;
    fn policies_of_tenant(
        &self,
        client_id: &str,
        tenant: &str,
    ) -> Result<Vec<ManagedPolicy>, AppError>;
    fn subject_accounts(
        &self,
        client_id: &str,
        tenant: &str,
        date: NaiveDate,
    ) -> Result<Vec<ManagedBudgetAccount>, AppError>;
    fn all_keys(&self) -> Result<Vec<ManagedClientKey>, AppError>;
    fn all_workspaces(&self) -> Result<Vec<ManagedClientWorkspace>, AppError>;
}

impl ReportRepository for PoolConfig {
    fn tenant_accounts(
        &self,
        client_id: Option<&str>,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<ManagedBudgetAccount>, AppError> {
        // period_key is YYYY-MM-DD for daily accounts, so text order is date order.
        let mut query = budgets::managed_budget_accounts
            .filter(budgets::owner_kind.eq(OWNER_TENANT))
            .filter(budgets::bucket.eq("daily"))
            .filter(budgets::period_key.ge(from.to_string()))
            .filter(budgets::period_key.le(to.to_string()))
            .select(ManagedBudgetAccount::as_select())
            .into_boxed();
        if let Some(client) = client_id {
            query = query.filter(budgets::client_id.eq(client));
        }
        Ok(query.load(&mut self.conn()?)?)
    }

    fn lifetime_tenant_accounts(
        &self,
        client_id: Option<&str>,
    ) -> Result<Vec<ManagedBudgetAccount>, AppError> {
        let mut query = budgets::managed_budget_accounts
            .filter(budgets::owner_kind.eq(OWNER_TENANT))
            .filter(budgets::period_key.eq("lifetime"))
            .select(ManagedBudgetAccount::as_select())
            .into_boxed();
        if let Some(client) = client_id {
            query = query.filter(budgets::client_id.eq(client));
        }
        Ok(query.load(&mut self.conn()?)?)
    }

    fn leases_on(
        &self,
        client_id: Option<&str>,
        date: NaiveDate,
    ) -> Result<Vec<ManagedKeyLease>, AppError> {
        let mut query = leases::managed_key_leases
            .filter(leases::lease_date.eq(date))
            .select(ManagedKeyLease::as_select())
            .into_boxed();
        if let Some(client) = client_id {
            query = query.filter(leases::client_id.eq(client));
        }
        Ok(query.load(&mut self.conn()?)?)
    }

    fn attention_leases(&self, now: DateTime<Utc>) -> Result<Vec<ManagedKeyLease>, AppError> {
        Ok(leases::managed_key_leases
            .filter(
                leases::status
                    .eq_any(["uncertain", "revocation_pending"])
                    .or(leases::status
                        .eq("provisioning")
                        .and(leases::updated_at.le(now - Duration::minutes(2)))),
            )
            .order(leases::updated_at.asc())
            .limit(50)
            .select(ManagedKeyLease::as_select())
            .load(&mut self.conn()?)?)
    }

    fn tenant_policies(&self, client_id: &str) -> Result<Vec<ManagedPolicy>, AppError> {
        Ok(policies::managed_policies
            .filter(policies::client_id.eq(client_id))
            .select(ManagedPolicy::as_select())
            .load(&mut self.conn()?)?)
    }

    fn policies_of_tenant(
        &self,
        client_id: &str,
        tenant: &str,
    ) -> Result<Vec<ManagedPolicy>, AppError> {
        Ok(policies::managed_policies
            .filter(policies::client_id.eq(client_id))
            .filter(policies::tenant.eq(tenant))
            .filter(policies::bucket.eq("daily"))
            .order(policies::owner_id.asc())
            .select(ManagedPolicy::as_select())
            .load(&mut self.conn()?)?)
    }

    fn subject_accounts(
        &self,
        client_id: &str,
        tenant: &str,
        date: NaiveDate,
    ) -> Result<Vec<ManagedBudgetAccount>, AppError> {
        Ok(budgets::managed_budget_accounts
            .filter(budgets::client_id.eq(client_id))
            .filter(budgets::tenant.eq(tenant))
            .filter(budgets::bucket.eq("daily"))
            .filter(budgets::period_key.eq(date.to_string()))
            .select(ManagedBudgetAccount::as_select())
            .load(&mut self.conn()?)?)
    }

    fn all_keys(&self) -> Result<Vec<ManagedClientKey>, AppError> {
        Ok(keys::managed_client_keys
            .select(ManagedClientKey::as_select())
            .load(&mut self.conn()?)?)
    }

    fn all_workspaces(&self) -> Result<Vec<ManagedClientWorkspace>, AppError> {
        Ok(workspaces::managed_client_workspaces
            .select(ManagedClientWorkspace::as_select())
            .load(&mut self.conn()?)?)
    }
}
