use chrono::{DateTime, Duration, NaiveDate, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl,
    SelectableHelper, SqliteConnection,
};

use crate::admin::model::{
    AdminSession, AdminSetupToken, AdminUser, AuditEntry, NewAuditEntry, SetupCompletion,
    SignInAttempt,
};
use crate::error::AppError;
use crate::managed::client_model::{ManagedClientKey, ManagedClientWorkspace};
use crate::managed::ledger_model::{ManagedBudgetAccount, ManagedKeyLease, OWNER_TENANT};
use crate::managed::policy_model::ManagedPolicy;
use crate::repository::PoolConfig;
use crate::schema::admin_audit_log::dsl as audit;
use crate::schema::admin_sessions::dsl as sessions;
use crate::schema::admin_setup_tokens::dsl as setups;
use crate::schema::admin_sign_in_attempts::dsl as attempts;
use crate::schema::admin_users::dsl as admins;
use crate::schema::managed_budget_accounts::dsl as budgets;
use crate::schema::managed_client_keys::dsl as keys;
use crate::schema::managed_client_workspaces::dsl as workspaces;
use crate::schema::managed_key_leases::dsl as leases;
use crate::schema::managed_policies::dsl as policies;

/// Operators, their sessions, sign-in attempts and the audit trail.
pub trait AdminRepository: Send + Sync {
    fn admin_by_username(&self, username: &str) -> Result<Option<AdminUser>, AppError>;
    /// Stores a link for a new account; the previous unused one for the same
    /// account stops working. False when the account it would create exists.
    fn issue_setup_token(&self, token: &AdminSetupToken) -> Result<bool, AppError>;
    /// Locks the account and ends its sessions at once, and stores the link
    /// that sets it up again. False when there is no such account.
    fn start_reset(&self, token: &AdminSetupToken, now: DateTime<Utc>) -> Result<bool, AppError>;
    /// An unused, unexpired link and whether its account already exists.
    fn setup_token(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(AdminSetupToken, bool)>, AppError>;
    /// Consumes the link and leaves the new credentials on the account, in one
    /// transaction.
    fn complete_setup(&self, completion: &SetupCompletion) -> Result<AdminUser, AppError>;
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
    fn admin_by_username(&self, username: &str) -> Result<Option<AdminUser>, AppError> {
        Ok(admins::admin_users
            .filter(admins::username.eq(username))
            .filter(admins::disabled_at.is_null())
            .select(AdminUser::as_select())
            .first::<AdminUser>(&mut self.conn()?)
            .optional()?)
    }

    fn issue_setup_token(&self, token: &AdminSetupToken) -> Result<bool, AppError> {
        self.conn()?.immediate_transaction(|conn| {
            match &token.username {
                // The first administrator: only while there is none.
                None => {
                    let admins = admins::admin_users.count().get_result::<i64>(conn)?;
                    if admins > 0 {
                        return Ok(false);
                    }
                    diesel::delete(
                        setups::admin_setup_tokens
                            .filter(setups::username.is_null())
                            .filter(setups::used_at.is_null()),
                    )
                    .execute(conn)?;
                }
                Some(username) => {
                    if Self::admin_id(conn, username)?.is_some() {
                        return Ok(false);
                    }
                    Self::discard_setup_tokens(conn, username)?;
                }
            }
            diesel::insert_into(setups::admin_setup_tokens)
                .values(token)
                .execute(conn)?;
            Ok(true)
        })
    }

    fn start_reset(&self, token: &AdminSetupToken, now: DateTime<Utc>) -> Result<bool, AppError> {
        let Some(username) = token.username.as_deref() else {
            return Err(AppError::Invalid);
        };
        self.conn()?.immediate_transaction(|conn| {
            let Some(id) = Self::admin_id(conn, username)? else {
                return Ok(false);
            };
            // The old password and authenticator stop working now, not when
            // the link is used: a reset is also the answer to a stolen account.
            diesel::update(admins::admin_users.filter(admins::id.eq(&id)))
                .set((
                    admins::disabled_at.eq(Some(now)),
                    admins::pending_totp_sealed.eq(None::<Vec<u8>>),
                ))
                .execute(conn)?;
            diesel::update(
                sessions::admin_sessions
                    .filter(sessions::admin_id.eq(&id))
                    .filter(sessions::revoked_at.is_null()),
            )
            .set(sessions::revoked_at.eq(Some(now)))
            .execute(conn)?;
            Self::discard_setup_tokens(conn, username)?;
            diesel::insert_into(setups::admin_setup_tokens)
                .values(token)
                .execute(conn)?;
            Ok(true)
        })
    }

    fn setup_token(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(AdminSetupToken, bool)>, AppError> {
        let mut conn = self.conn()?;
        let Some(token) = Self::open_setup_token(&mut conn, token_hash, now)? else {
            return Ok(None);
        };
        let exists = match token.username.as_deref() {
            Some(username) => Self::admin_id(&mut conn, username)?.is_some(),
            None => false,
        };
        Ok(Some((token, exists)))
    }

    fn complete_setup(&self, completion: &SetupCompletion) -> Result<AdminUser, AppError> {
        let now = completion.now;
        self.conn()?.immediate_transaction(|conn| {
            let token = Self::open_setup_token(conn, &completion.token_hash, now)?
                .ok_or(AppError::Conflict)?;
            match token.username.as_deref() {
                // A first-run link printed before an administrator existed
                // cannot create a second one.
                None if admins::admin_users.count().get_result::<i64>(conn)? > 0 => {
                    return Err(AppError::Conflict);
                }
                Some(username) if username != completion.username => {
                    return Err(AppError::Conflict);
                }
                _ => {}
            }
            match Self::admin_id(conn, &completion.username)? {
                Some(id) => {
                    diesel::update(admins::admin_users.filter(admins::id.eq(&id)))
                        .set((
                            admins::password_hash.eq(&completion.password_hash),
                            admins::totp_sealed.eq(&token.totp_sealed),
                            admins::totp_last_step.eq(completion.totp_step),
                            admins::pending_totp_sealed.eq(None::<Vec<u8>>),
                            admins::password_changed_at.eq(now),
                            admins::disabled_at.eq(None::<DateTime<Utc>>),
                        ))
                        .execute(conn)?;
                }
                None => {
                    let admin = AdminUser {
                        id: completion.admin_id.clone(),
                        username: completion.username.clone(),
                        password_hash: completion.password_hash.clone(),
                        totp_sealed: token.totp_sealed.clone(),
                        totp_last_step: completion.totp_step,
                        pending_totp_sealed: None,
                        created_at: now,
                        password_changed_at: now,
                        last_sign_in_at: None,
                        last_sign_in_source: None,
                        disabled_at: None,
                    };
                    diesel::insert_into(admins::admin_users)
                        .values(&admin)
                        .execute(conn)?;
                }
            }
            diesel::update(
                setups::admin_setup_tokens.filter(setups::token_hash.eq(&token.token_hash)),
            )
            .set(setups::used_at.eq(Some(now)))
            .execute(conn)?;
            Ok(admins::admin_users
                .filter(admins::username.eq(&completion.username))
                .select(AdminUser::as_select())
                .first::<AdminUser>(conn)?)
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

impl PoolConfig {
    fn admin_id(conn: &mut SqliteConnection, username: &str) -> Result<Option<String>, AppError> {
        Ok(admins::admin_users
            .filter(admins::username.eq(username))
            .select(admins::id)
            .first::<String>(conn)
            .optional()?)
    }

    /// Only the newest link of an account works.
    fn discard_setup_tokens(conn: &mut SqliteConnection, username: &str) -> Result<(), AppError> {
        diesel::delete(
            setups::admin_setup_tokens
                .filter(setups::username.eq(username))
                .filter(setups::used_at.is_null()),
        )
        .execute(conn)?;
        Ok(())
    }

    fn open_setup_token(
        conn: &mut SqliteConnection,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AdminSetupToken>, AppError> {
        Ok(setups::admin_setup_tokens
            .filter(setups::token_hash.eq(token_hash))
            .filter(setups::used_at.is_null())
            .filter(setups::expires_at.gt(now))
            .select(AdminSetupToken::as_select())
            .first::<AdminSetupToken>(conn)
            .optional()?)
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
