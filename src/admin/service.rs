use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Datelike, Duration, Months, NaiveDate, Utc};
use uuid::Uuid;

use crate::admin::credentials::{Passwords, Tokens, Totp};
use crate::admin::model::{
    AdminContext, AdminCredentials, AdminSession, AdminUser, AdminUsername, AttentionItem,
    AuditEvent, AuditPage, AuditResult, CompanyForm, CompanyPage, CompanyRow, CompanySettingsForm,
    CompanyToday, DayTotal, IssuedSession, KeyForm, LeaseView, Money, NewAuditEntry, OverviewPage,
    PasswordForm, RecoveryForm, RequestOrigin, SecurityPage, SignInAttempt, SignInForm, SubjectRow,
    SuspendForm, SystemView, TenantPage, TenantRow, TotpEnrollment, TotpStartForm, Usage,
    WorkerView, WorkspaceForm, WorkspaceRow,
};
use crate::admin::repository::{AdminRepository, ReportRepository};
use crate::crypto::Random;
use crate::error::AppError;
use crate::managed::client_model::{ClientKeyState, CreatedKey, ManagedClient, ManagedClientKey};
use crate::managed::client_service::ClientService;
use crate::managed::key_service::Clock;
use crate::managed::ledger_model::{ManagedBudgetAccount, OWNER_SUBJECT, OWNER_TENANT};
use crate::managed::model::ManagedSecret;
use crate::managed::policy_service::PolicyService;
use crate::managed::vault::SecretBox;
use crate::managed::worker::WorkerHealth;
use crate::repository::PoolConfig;

/// Operator console: authentication of administrators, audited actions over
/// clients and the read models of every page.
pub struct AdminService {
    pool: PoolConfig,
    vault: Arc<SecretBox>,
    clients: ClientService,
    policies: PolicyService,
    health: Option<Arc<WorkerHealth>>,
    /// Verified when the username does not exist, so both paths cost the same.
    decoy_hash: String,
    clock: Clock,
}

impl AdminService {
    pub const ISSUER: &'static str = "asystant";
    pub const SESSION_IDLE_MINUTES: i64 = 30;
    pub const SESSION_HOURS: i64 = 8;
    pub const LOCKOUT_MINUTES: i64 = 15;
    pub const LOCKOUT_ATTEMPTS: i64 = 5;
    const AUDIT_PAGE: i64 = 200;

    pub fn new(
        pool: PoolConfig,
        encryption_key: &str,
        health: Option<Arc<WorkerHealth>>,
    ) -> Result<Self, AppError> {
        Self::with_clock(pool, encryption_key, health, Arc::new(Utc::now))
    }

    pub fn with_clock(
        pool: PoolConfig,
        encryption_key: &str,
        health: Option<Arc<WorkerHealth>>,
        clock: Clock,
    ) -> Result<Self, AppError> {
        Ok(Self {
            vault: Arc::new(SecretBox::from_base64_key(encryption_key)?),
            clients: ClientService::new(pool.clone()),
            policies: PolicyService::new(pool.clone()),
            decoy_hash: Passwords::hash(&Random::base62(24)?)?,
            health,
            pool,
            clock,
        })
    }

    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    fn idle() -> Duration {
        Duration::minutes(Self::SESSION_IDLE_MINUTES)
    }

    // ------------------------------------------------------------------
    // Administrators (command line)
    // ------------------------------------------------------------------

    pub async fn create_admin(&self, username: &str) -> Result<AdminCredentials, AppError> {
        AdminUsername::validate(username)?;
        let (password, hash, secret, sealed) = self.fresh_credentials().await?;
        let now = self.now();
        let admin = AdminUser {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            password_hash: hash,
            totp_sealed: sealed,
            totp_last_step: 0,
            pending_totp_sealed: None,
            created_at: now,
            password_changed_at: now,
            last_sign_in_at: None,
            last_sign_in_source: None,
            disabled_at: None,
        };
        self.pool
            .blocking(move |pool| pool.insert_admin(&admin))
            .await?;
        self.record(
            None,
            &Self::console(),
            AuditEvent {
                action: "Administrator created",
                company_id: None,
                target: username,
                detail: "From the command line",
                result: AuditResult::Done,
            },
        )
        .await?;
        Ok(Self::credentials(username, password, &secret))
    }

    /// New password and authenticator; every open session ends.
    pub async fn reset_admin(&self, username: &str) -> Result<AdminCredentials, AppError> {
        AdminUsername::validate(username)?;
        let (password, hash, secret, sealed) = self.fresh_credentials().await?;
        let name = username.to_string();
        let now = self.now();
        let found = self
            .pool
            .blocking(move |pool| pool.reset_admin(&name, &hash, &sealed, now))
            .await?;
        if !found {
            return Err(AppError::NotFound);
        }
        self.record(
            None,
            &Self::console(),
            AuditEvent {
                action: "Administrator reset",
                company_id: None,
                target: username,
                detail: "New password and authenticator from the command line",
                result: AuditResult::Done,
            },
        )
        .await?;
        Ok(Self::credentials(username, password, &secret))
    }

    async fn fresh_credentials(
        &self,
    ) -> Result<(ManagedSecret, String, Vec<u8>, Vec<u8>), AppError> {
        let password = Passwords::generate()?;
        let plain = password.clone();
        let hash = self.pool.blocking(move |_| Passwords::hash(&plain)).await?;
        let secret = Totp::generate_secret()?;
        let sealed = self.vault.seal(&secret)?;
        Ok((ManagedSecret::new(password)?, hash, secret, sealed))
    }

    fn credentials(username: &str, password: ManagedSecret, secret: &[u8]) -> AdminCredentials {
        AdminCredentials {
            username: username.to_string(),
            password,
            totp_secret: Totp::base32(secret),
            totp_uri: Totp::provisioning_uri(Self::ISSUER, username, secret),
        }
    }

    fn console() -> RequestOrigin {
        RequestOrigin {
            source: "command line".to_string(),
            user_agent: "asystant_api".to_string(),
        }
    }

    // ------------------------------------------------------------------
    // Sign-in and sessions
    // ------------------------------------------------------------------

    pub async fn sign_in(
        &self,
        form: &SignInForm,
        origin: &RequestOrigin,
    ) -> Result<IssuedSession, AppError> {
        let username = form.username.trim().to_lowercase();
        let now = self.now();
        let since = now - Duration::minutes(Self::LOCKOUT_MINUTES);
        let (name, source) = (username.clone(), origin.source.clone());
        let (by_username, by_source) = self
            .pool
            .blocking(move |pool| pool.recent_failures(&name, &source, since))
            .await?;
        let known = AdminUsername::validate(&username).is_ok();
        let actor = known.then(|| username.clone());
        if by_username >= Self::LOCKOUT_ATTEMPTS || by_source >= Self::LOCKOUT_ATTEMPTS {
            self.record(
                actor.as_deref(),
                origin,
                AuditEvent {
                    action: "Sign-in refused",
                    company_id: None,
                    target: "Console",
                    detail: "Locked: 5 failed attempts in 15 minutes",
                    result: AuditResult::Refused,
                },
            )
            .await?;
            return Err(AppError::Limited);
        }
        let name = username.clone();
        let admin = if known {
            self.pool
                .blocking(move |pool| pool.admin_by_username(&name))
                .await?
        } else {
            None
        };
        let stored_hash = admin.as_ref().map_or_else(
            || self.decoy_hash.clone(),
            |admin| admin.password_hash.clone(),
        );
        let password = form.password.clone();
        let password_ok = self
            .pool
            .blocking(move |_| Ok(Passwords::verify(&stored_hash, &password)))
            .await?;
        let mut reason = "Unknown username";
        let mut signed_in = None;
        if let Some(admin) = admin.filter(|_| password_ok) {
            reason = "Wrong or reused authenticator code";
            if self.consume_code(&admin, &form.code, now).await? {
                signed_in = Some(admin);
            }
        } else if actor.is_some() {
            reason = "Wrong username or password";
        }
        let attempt = SignInAttempt {
            id: Uuid::new_v4().to_string(),
            username: username.clone(),
            source: origin.source.clone(),
            succeeded: signed_in.is_some(),
            created_at: now,
        };
        self.pool
            .blocking(move |pool| pool.record_attempt(&attempt))
            .await?;
        let Some(admin) = signed_in else {
            self.record(
                actor.as_deref(),
                origin,
                AuditEvent {
                    action: "Sign-in refused",
                    company_id: None,
                    target: "Console",
                    detail: reason,
                    result: AuditResult::Refused,
                },
            )
            .await?;
            return Err(AppError::Authentication);
        };
        let token = Tokens::random()?;
        let session = AdminSession {
            id: Uuid::new_v4().to_string(),
            token_hash: Tokens::hash(&token),
            admin_id: admin.id.clone(),
            csrf_token: Tokens::random()?,
            user_agent: origin.user_agent.chars().take(200).collect(),
            source: origin.source.clone(),
            created_at: now,
            last_seen_at: now,
            expires_at: now + Duration::hours(Self::SESSION_HOURS),
            revoked_at: None,
        };
        let (admin_id, source) = (admin.id.clone(), origin.source.clone());
        self.pool
            .blocking(move |pool| {
                pool.insert_session(&session)?;
                pool.record_sign_in(&admin_id, &source, now)
            })
            .await?;
        self.record(
            Some(&admin.username),
            origin,
            AuditEvent {
                action: "Signed in",
                company_id: None,
                target: "Console",
                detail: &origin.user_agent,
                result: AuditResult::Done,
            },
        )
        .await?;
        Ok(IssuedSession {
            token: ManagedSecret::new(token)?,
        })
    }

    /// The session behind a cookie, if it is still valid. Every use extends the
    /// idle window; the absolute lifetime never moves.
    pub async fn session(&self, token: &str) -> Result<AdminContext, AppError> {
        if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::Authentication);
        }
        let hash = Tokens::hash(token);
        let now = self.now();
        let (session, admin) = self
            .pool
            .blocking(move |pool| pool.session_by_token(&hash, now, Self::idle()))
            .await?
            .ok_or(AppError::Authentication)?;
        let id = session.id.clone();
        self.pool
            .blocking(move |pool| pool.touch_session(&id, now))
            .await?;
        Ok(AdminContext { admin, session })
    }

    pub async fn sign_out(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
    ) -> Result<(), AppError> {
        let (admin, session) = (ctx.admin.id.clone(), ctx.session.id.clone());
        let now = self.now();
        self.pool
            .blocking(move |pool| pool.revoke_session(&admin, &session, now))
            .await?;
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Signed out",
                company_id: None,
                target: "Console",
                detail: "",
                result: AuditResult::Done,
            },
        )
        .await
    }

    /// Accepts a fresh authenticator code once; the step is consumed atomically.
    async fn consume_code(
        &self,
        admin: &AdminUser,
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let Ok(secret) = self.vault.open(&admin.totp_sealed) else {
            return Ok(false);
        };
        let Some(step) = Totp::verify(&secret, code, now, admin.totp_last_step) else {
            return Ok(false);
        };
        let id = admin.id.clone();
        self.pool
            .blocking(move |pool| pool.advance_totp_step(&id, step))
            .await
    }

    /// Sensitive actions need a new code even inside a session.
    async fn step_up(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        code: &str,
        action: &str,
    ) -> Result<(), AppError> {
        if self.consume_code(&ctx.admin, code, self.now()).await? {
            return Ok(());
        }
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: &format!("{action} refused"),
                company_id: None,
                target: "Console",
                detail: "Wrong or reused authenticator code",
                result: AuditResult::Refused,
            },
        )
        .await?;
        Err(AppError::Authentication)
    }

    async fn record(
        &self,
        actor: Option<&str>,
        origin: &RequestOrigin,
        event: AuditEvent<'_>,
    ) -> Result<(), AppError> {
        let entry = NewAuditEntry {
            created_at: self.now(),
            actor: actor.map(str::to_string),
            action: event.action.to_string(),
            company_id: event.company_id.map(str::to_string),
            target: event.target.chars().take(200).collect(),
            detail: event.detail.chars().take(400).collect(),
            source: origin.source.clone(),
            result: event.result.as_str().to_string(),
        };
        self.pool
            .blocking(move |pool| pool.append_audit(&entry))
            .await
    }

    // ------------------------------------------------------------------
    // Clients and keys
    // ------------------------------------------------------------------

    pub async fn company(&self, slug: &str) -> Result<ManagedClient, AppError> {
        self.clients.by_slug(slug).await
    }

    pub async fn create_company(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        form: CompanyForm,
    ) -> Result<ManagedClient, AppError> {
        self.step_up(ctx, origin, &form.code, "Company creation")
            .await?;
        let request = form.to_request()?;
        let workspaces = request.workspaces.len();
        let client = self.clients.create(request).await?;
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Company created",
                company_id: Some(&client.id),
                target: &client.name,
                detail: &format!("Slug {}, {workspaces} workspace(s)", client.slug),
                result: AuditResult::Done,
            },
        )
        .await?;
        Ok(client)
    }

    pub async fn update_company(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        slug: &str,
        form: CompanySettingsForm,
    ) -> Result<(), AppError> {
        self.step_up(ctx, origin, &form.code, "Company update")
            .await?;
        let client = self.clients.by_slug(slug).await?;
        let settings = form.to_settings()?;
        let cap = settings.daily_cap_usd_micros.map_or_else(
            || "no cap".to_string(),
            |cap| format!("daily cap {}", Money(cap)),
        );
        self.clients.update(&client, settings).await?;
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Company updated",
                company_id: Some(&client.id),
                target: &client.name,
                detail: &cap,
                result: AuditResult::Done,
            },
        )
        .await
    }

    pub async fn add_workspace(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        slug: &str,
        form: WorkspaceForm,
    ) -> Result<(), AppError> {
        self.step_up(ctx, origin, &form.code, "Workspace assignment")
            .await?;
        let client = self.clients.by_slug(slug).await?;
        let workspace = Uuid::parse_str(form.workspace_id.trim()).map_err(|_| AppError::Invalid)?;
        self.clients.add_workspace(&client, workspace).await?;
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Workspace assigned",
                company_id: Some(&client.id),
                target: &client.name,
                detail: &workspace.to_string(),
                result: AuditResult::Done,
            },
        )
        .await
    }

    pub async fn remove_workspace(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        slug: &str,
        workspace: Uuid,
        code: &str,
    ) -> Result<(), AppError> {
        self.step_up(ctx, origin, code, "Workspace removal").await?;
        let client = self.clients.by_slug(slug).await?;
        if !self.clients.remove_workspace(&client, workspace).await? {
            return Err(AppError::NotFound);
        }
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Workspace removed",
                company_id: Some(&client.id),
                target: &client.name,
                detail: &workspace.to_string(),
                result: AuditResult::Done,
            },
        )
        .await
    }

    pub async fn create_key(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        slug: &str,
        form: KeyForm,
    ) -> Result<(ManagedClient, CreatedKey), AppError> {
        self.step_up(ctx, origin, &form.code, "API key creation")
            .await?;
        let client = self.clients.by_slug(slug).await?;
        let request = form.to_request(&ctx.admin.username)?;
        let replaces = request.replaces;
        let created = self.clients.create_key(&client, request).await?;
        let detail = match replaces {
            Some(previous) => format!(
                "“{}” {}, replaces key {previous}",
                created.key.label,
                created.key.masked()
            ),
            None => format!("“{}” {}", created.key.label, created.key.masked()),
        };
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "API key created",
                company_id: Some(&client.id),
                target: &client.name,
                detail: &detail,
                result: AuditResult::Done,
            },
        )
        .await?;
        Ok((client, created))
    }

    pub async fn revoke_key(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        slug: &str,
        key: Uuid,
        code: &str,
    ) -> Result<(), AppError> {
        self.step_up(ctx, origin, code, "API key revocation")
            .await?;
        let client = self.clients.by_slug(slug).await?;
        let keys = self.clients.keys(&client).await?;
        let label = keys
            .iter()
            .find(|candidate| candidate.id == key.to_string())
            .map(|candidate| format!("“{}” {}", candidate.label, candidate.masked()))
            .ok_or(AppError::NotFound)?;
        if !self.clients.revoke_key(&client, key).await? {
            return Err(AppError::Conflict);
        }
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "API key revoked",
                company_id: Some(&client.id),
                target: &client.name,
                detail: &label,
                result: AuditResult::Done,
            },
        )
        .await
    }

    pub async fn suspend(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        slug: &str,
        form: SuspendForm,
    ) -> Result<(), AppError> {
        self.step_up(ctx, origin, &form.code, "Company suspension")
            .await?;
        let client = self.clients.by_slug(slug).await?;
        if form.confirm.trim() != client.slug {
            return Err(AppError::Invalid);
        }
        if !self.clients.suspend(&client).await? {
            return Err(AppError::Conflict);
        }
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Company suspended",
                company_id: Some(&client.id),
                target: &client.name,
                detail: "API keys rejected; live OpenRouter keys queued for revocation",
                result: AuditResult::Done,
            },
        )
        .await
    }

    pub async fn reactivate(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        slug: &str,
        code: &str,
    ) -> Result<(), AppError> {
        self.step_up(ctx, origin, code, "Company reactivation")
            .await?;
        let client = self.clients.by_slug(slug).await?;
        if !self.clients.reactivate(&client).await? {
            return Err(AppError::Conflict);
        }
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Company reactivated",
                company_id: Some(&client.id),
                target: &client.name,
                detail: "Needs new API keys",
                result: AuditResult::Done,
            },
        )
        .await
    }

    pub async fn authorize_recovery(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        slug: &str,
        tenant: &str,
        lease: Uuid,
        form: RecoveryForm,
    ) -> Result<(), AppError> {
        self.step_up(ctx, origin, &form.code, "Recovery").await?;
        let client = self.clients.by_slug(slug).await?;
        let request = form.to_request(&ctx.admin.username)?;
        let limit = Money(request.limit_usd_micros);
        self.policies
            .authorize_recovery(&client, tenant.to_string(), lease, request)
            .await?;
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Recovery authorized",
                company_id: Some(&client.id),
                target: &client.name,
                detail: &format!("Tenant {tenant}, lease {lease}, new limit {limit}"),
                result: AuditResult::Done,
            },
        )
        .await
    }

    // ------------------------------------------------------------------
    // Own account
    // ------------------------------------------------------------------

    pub async fn change_password(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        form: PasswordForm,
    ) -> Result<(), AppError> {
        self.verify_password(ctx, &form.current).await?;
        self.step_up(ctx, origin, &form.code, "Password change")
            .await?;
        Passwords::validate(&form.next)?;
        let next = form.next.clone();
        let hash = self.pool.blocking(move |_| Passwords::hash(&next)).await?;
        let (admin, keep) = (ctx.admin.id.clone(), ctx.session.id.clone());
        let now = self.now();
        self.pool
            .blocking(move |pool| {
                pool.update_password(&admin, &hash, now)?;
                pool.revoke_other_sessions(&admin, &keep, now).map(|_| ())
            })
            .await?;
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Password changed",
                company_id: None,
                target: "Console",
                detail: "Other sessions signed out",
                result: AuditResult::Done,
            },
        )
        .await
    }

    pub async fn start_totp_replacement(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        form: TotpStartForm,
    ) -> Result<TotpEnrollment, AppError> {
        self.verify_password(ctx, &form.password).await?;
        self.step_up(ctx, origin, &form.code, "Authenticator replacement")
            .await?;
        let secret = Totp::generate_secret()?;
        let sealed = self.vault.seal(&secret)?;
        let admin = ctx.admin.id.clone();
        self.pool
            .blocking(move |pool| pool.set_pending_totp(&admin, Some(&sealed)))
            .await?;
        Ok(TotpEnrollment {
            secret: Totp::base32(&secret),
            uri: Totp::provisioning_uri(Self::ISSUER, &ctx.admin.username, &secret),
        })
    }

    /// The new authenticator replaces the old one only after it produced a code.
    pub async fn confirm_totp_replacement(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        code: &str,
    ) -> Result<(), AppError> {
        let sealed = ctx
            .admin
            .pending_totp_sealed
            .clone()
            .ok_or(AppError::Conflict)?;
        let secret = self.vault.open(&sealed)?;
        let Some(step) = Totp::verify(&secret, code, self.now(), 0) else {
            self.record(
                Some(&ctx.admin.username),
                origin,
                AuditEvent {
                    action: "Authenticator replacement refused",
                    company_id: None,
                    target: "Console",
                    detail: "Wrong code from the new authenticator",
                    result: AuditResult::Refused,
                },
            )
            .await?;
            return Err(AppError::Authentication);
        };
        let admin = ctx.admin.id.clone();
        let confirmed = self
            .pool
            .blocking(move |pool| pool.confirm_totp(&admin, &sealed, step))
            .await?;
        if !confirmed {
            return Err(AppError::Conflict);
        }
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Authenticator replaced",
                company_id: None,
                target: "Console",
                detail: "",
                result: AuditResult::Done,
            },
        )
        .await
    }

    pub async fn revoke_session(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
        session: &str,
    ) -> Result<(), AppError> {
        let (admin, target) = (ctx.admin.id.clone(), session.to_string());
        let now = self.now();
        if !self
            .pool
            .blocking(move |pool| pool.revoke_session(&admin, &target, now))
            .await?
        {
            return Err(AppError::NotFound);
        }
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Session signed out",
                company_id: None,
                target: "Console",
                detail: session,
                result: AuditResult::Done,
            },
        )
        .await
    }

    pub async fn revoke_other_sessions(
        &self,
        ctx: &AdminContext,
        origin: &RequestOrigin,
    ) -> Result<(), AppError> {
        let (admin, keep) = (ctx.admin.id.clone(), ctx.session.id.clone());
        let now = self.now();
        let count = self
            .pool
            .blocking(move |pool| pool.revoke_other_sessions(&admin, &keep, now))
            .await?;
        self.record(
            Some(&ctx.admin.username),
            origin,
            AuditEvent {
                action: "Other sessions signed out",
                company_id: None,
                target: "Console",
                detail: &format!("{count} session(s)"),
                result: AuditResult::Done,
            },
        )
        .await
    }

    async fn verify_password(&self, ctx: &AdminContext, password: &str) -> Result<(), AppError> {
        let (hash, password) = (ctx.admin.password_hash.clone(), password.to_string());
        if self
            .pool
            .blocking(move |_| Ok(Passwords::verify(&hash, &password)))
            .await?
        {
            return Ok(());
        }
        Err(AppError::Authentication)
    }

    // ------------------------------------------------------------------
    // Pages
    // ------------------------------------------------------------------

    fn worker(&self) -> WorkerView {
        WorkerView {
            configured: self.health.is_some(),
            last_revocation: self
                .health
                .as_ref()
                .and_then(|health| health.last_revocation()),
            last_usage: self.health.as_ref().and_then(|health| health.last_usage()),
        }
    }

    fn month_start(today: NaiveDate) -> NaiveDate {
        today.with_day(1).unwrap_or(today)
    }

    pub async fn overview_page(&self) -> Result<OverviewPage, AppError> {
        let now = self.now();
        let today = now.date_naive();
        let first = today - Duration::days(29);
        let from = first.min(Self::month_start(today));
        let accounts = self
            .pool
            .blocking(move |pool| pool.tenant_accounts(None, from, today))
            .await?;
        let lifetime = self
            .pool
            .blocking(|pool| pool.lifetime_tenant_accounts(None))
            .await?;
        let leases_today = self
            .pool
            .blocking(move |pool| pool.leases_on(None, today))
            .await?;
        let attention = self
            .pool
            .blocking(move |pool| pool.attention_leases(now))
            .await?;
        let clients = self.clients.list().await?;
        let today_key = today.to_string();
        let month_key = Self::month_start(today).to_string();
        let mut per_day: BTreeMap<String, i64> = BTreeMap::new();
        for account in &accounts {
            *per_day.entry(account.period_key.clone()).or_default() += account.spent_usd_micros;
        }
        let series = (0..30)
            .map(|offset| {
                let date = first + Duration::days(offset);
                DayTotal {
                    date,
                    spent: per_day.get(&date.to_string()).copied().unwrap_or_default(),
                }
            })
            .collect();
        let todays = accounts
            .iter()
            .filter(|account| account.period_key == today_key);
        let spent_today = todays.clone().map(|account| account.spent_usd_micros).sum();
        let held_today = todays
            .clone()
            .map(|account| account.reserved_usd_micros)
            .sum::<i64>()
            + lifetime
                .iter()
                .map(|account| account.reserved_usd_micros)
                .sum::<i64>();
        let month_to_date = accounts
            .iter()
            .filter(|account| account.period_key >= month_key)
            .map(|account| account.spent_usd_micros)
            .sum();
        let names: HashMap<&str, &ManagedClient> = clients
            .iter()
            .map(|client| (client.id.as_str(), client))
            .collect();
        let by_company = clients
            .iter()
            .filter(|client| client.is_active())
            .map(|client| CompanyToday {
                name: client.name.clone(),
                slug: client.slug.clone(),
                usage: Self::usage_of(client, todays.clone(), &lifetime),
            })
            .collect();
        let attention = attention
            .into_iter()
            .map(|lease| {
                let client = names.get(lease.client_id.as_str());
                AttentionItem {
                    company_name: client
                        .map_or_else(|| lease.client_slug.clone(), |client| client.name.clone()),
                    company_slug: lease.client_slug.clone(),
                    held: (lease.limit_usd_micros - lease.accounted_usage_usd_micros).max(0),
                    tenant: lease.tenant,
                    subject: lease.subject,
                    status: lease.status,
                    since: lease.updated_at,
                }
            })
            .collect();
        Ok(OverviewPage {
            now,
            spent_today,
            held_today,
            month_to_date,
            keys_today: leases_today
                .iter()
                .filter(|lease| lease.key_hash.is_some())
                .count() as i64,
            active_companies: clients.iter().filter(|client| client.is_active()).count(),
            series,
            by_company,
            attention,
            worker: self.worker(),
        })
    }

    fn usage_of<'a>(
        client: &ManagedClient,
        today: impl Iterator<Item = &'a ManagedBudgetAccount>,
        lifetime: &[ManagedBudgetAccount],
    ) -> Usage {
        let mut usage = Usage {
            limit: client.daily_cap_usd_micros,
            ..Usage::default()
        };
        for account in today.filter(|account| account.client_id == client.id) {
            usage.spent += account.spent_usd_micros;
            usage.held += account.reserved_usd_micros;
        }
        usage.held += lifetime
            .iter()
            .filter(|account| account.client_id == client.id)
            .map(|account| account.reserved_usd_micros)
            .sum::<i64>();
        usage
    }

    pub async fn companies_page(&self) -> Result<Vec<CompanyRow>, AppError> {
        let now = self.now();
        let today = now.date_naive();
        let month = Self::month_start(today);
        let clients = self.clients.list().await?;
        let accounts = self
            .pool
            .blocking(move |pool| pool.tenant_accounts(None, month, today))
            .await?;
        let lifetime = self
            .pool
            .blocking(|pool| pool.lifetime_tenant_accounts(None))
            .await?;
        let keys = self.pool.blocking(|pool| pool.all_keys()).await?;
        let workspaces = self.pool.blocking(|pool| pool.all_workspaces()).await?;
        let today_key = today.to_string();
        Ok(clients
            .into_iter()
            .map(|client| {
                let own_keys = keys.iter().filter(|key| key.client_id == client.id);
                let state = |wanted| {
                    own_keys
                        .clone()
                        .filter(|key| key.state(now) == wanted)
                        .count()
                };
                CompanyRow {
                    workspaces: workspaces
                        .iter()
                        .filter(|workspace| workspace.client_id == client.id)
                        .count(),
                    active_keys: state(ClientKeyState::Active),
                    rotating_keys: state(ClientKeyState::Rotating),
                    revoked_keys: state(ClientKeyState::Revoked),
                    today: Self::usage_of(
                        &client,
                        accounts
                            .iter()
                            .filter(|account| account.period_key == today_key),
                        &lifetime,
                    ),
                    month_spent: accounts
                        .iter()
                        .filter(|account| account.client_id == client.id)
                        .map(|account| account.spent_usd_micros)
                        .sum(),
                    client,
                }
            })
            .collect())
    }

    pub async fn company_page(&self, slug: &str) -> Result<CompanyPage, AppError> {
        let now = self.now();
        let today = now.date_naive();
        let month = Self::month_start(today);
        let client = self.clients.by_slug(slug).await?;
        let keys = self.clients.keys(&client).await?;
        let assigned = self.clients.workspaces(&client).await?;
        let client_id = client.id.clone();
        let (policies, accounts, lifetime, leases) = {
            let id = client_id.clone();
            let policies = self
                .pool
                .blocking(move |pool| pool.tenant_policies(&id))
                .await?;
            let id = client_id.clone();
            let accounts = self
                .pool
                .blocking(move |pool| pool.tenant_accounts(Some(&id), month, today))
                .await?;
            let id = client_id.clone();
            let lifetime = self
                .pool
                .blocking(move |pool| pool.lifetime_tenant_accounts(Some(&id)))
                .await?;
            let id = client_id.clone();
            let leases = self
                .pool
                .blocking(move |pool| pool.leases_on(Some(&id), today))
                .await?;
            (policies, accounts, lifetime, leases)
        };
        let today_key = today.to_string();
        let todays: Vec<&ManagedBudgetAccount> = accounts
            .iter()
            .filter(|account| account.period_key == today_key)
            .collect();
        let ceilings: Vec<_> = policies
            .iter()
            .filter(|policy| policy.owner_kind == OWNER_TENANT && policy.bucket == "daily")
            .collect();
        let tenants = ceilings
            .iter()
            .map(|policy| {
                let account = todays
                    .iter()
                    .find(|account| account.tenant == policy.tenant);
                let tenant_leases = leases.iter().filter(|lease| lease.tenant == policy.tenant);
                TenantRow {
                    tenant: policy.tenant.clone(),
                    workspace_id: policy.workspace_id.clone(),
                    usage: Usage {
                        spent: account.map_or(0, |account| account.spent_usd_micros),
                        held: account.map_or(0, |account| account.reserved_usd_micros),
                        limit: Some(policy.limit_usd_micros),
                    },
                    subjects: policies
                        .iter()
                        .filter(|subject| {
                            subject.owner_kind == OWNER_SUBJECT
                                && subject.tenant == policy.tenant
                                && subject.bucket == "daily"
                        })
                        .count(),
                    attention: tenant_leases
                        .clone()
                        .filter(|lease| {
                            matches!(lease.status.as_str(), "uncertain" | "revocation_pending")
                        })
                        .count(),
                    live_keys: tenant_leases
                        .filter(|lease| lease.status == "issued")
                        .count(),
                }
            })
            .collect();
        let workspaces = assigned
            .into_iter()
            .map(|workspace| WorkspaceRow {
                tenants: ceilings
                    .iter()
                    .filter(|policy| policy.workspace_id == workspace.workspace_id)
                    .map(|policy| policy.tenant.as_str())
                    .collect::<HashSet<_>>()
                    .len(),
                workspace_id: workspace.workspace_id,
            })
            .collect();
        let mut today = Usage {
            limit: client.daily_cap_usd_micros,
            ..Usage::default()
        };
        for account in &todays {
            today.spent += account.spent_usd_micros;
            today.held += account.reserved_usd_micros;
        }
        today.held += lifetime
            .iter()
            .map(|account| account.reserved_usd_micros)
            .sum::<i64>();
        Ok(CompanyPage {
            now,
            month_spent: accounts
                .iter()
                .map(|account| account.spent_usd_micros)
                .sum(),
            migration_spent: lifetime
                .iter()
                .map(|account| account.spent_usd_micros)
                .sum(),
            keys_today: leases
                .iter()
                .filter(|lease| lease.key_hash.is_some())
                .count() as i64,
            live_keys: leases
                .iter()
                .filter(|lease| lease.status == "issued")
                .count(),
            client,
            keys,
            workspaces,
            tenants,
            today,
        })
    }

    pub async fn tenant_page(&self, slug: &str, tenant: &str) -> Result<TenantPage, AppError> {
        let today = self.now().date_naive();
        let client = self.clients.by_slug(slug).await?;
        let (id, name) = (client.id.clone(), tenant.to_string());
        let policies = self
            .pool
            .blocking(move |pool| pool.policies_of_tenant(&id, &name))
            .await?;
        let ceiling = policies
            .iter()
            .find(|policy| policy.owner_kind == OWNER_TENANT)
            .ok_or(AppError::NotFound)?;
        let (id, name) = (client.id.clone(), tenant.to_string());
        let accounts = self
            .pool
            .blocking(move |pool| pool.subject_accounts(&id, &name, today))
            .await?;
        let id = client.id.clone();
        let leases = self
            .pool
            .blocking(move |pool| pool.leases_on(Some(&id), today))
            .await?;
        let tenant_account = accounts
            .iter()
            .find(|account| account.owner_kind == OWNER_TENANT);
        let subjects = policies
            .iter()
            .filter(|policy| policy.owner_kind == OWNER_SUBJECT)
            .map(|policy| SubjectRow {
                subject: policy.owner_id.clone(),
                budget: policy.limit_usd_micros,
                lease: leases
                    .iter()
                    .filter(|lease| {
                        lease.tenant == tenant
                            && lease.subject == policy.owner_id
                            && lease.is_current
                    })
                    .max_by_key(|lease| lease.created_at)
                    .map(|lease| LeaseView {
                        id: lease.id.clone(),
                        status: lease.status.clone(),
                        limit: lease.limit_usd_micros,
                        accounted: lease.accounted_usage_usd_micros,
                        held: (lease.limit_usd_micros - lease.accounted_usage_usd_micros).max(0),
                        expires_at: lease.expires_at,
                        updated_at: lease.updated_at,
                        can_recover: lease.can_authorize_recovery(),
                    }),
            })
            .collect();
        Ok(TenantPage {
            tenant: tenant.to_string(),
            workspace_id: Some(ceiling.workspace_id.clone()),
            usage: Usage {
                spent: tenant_account.map_or(0, |account| account.spent_usd_micros),
                held: tenant_account.map_or(0, |account| account.reserved_usd_micros),
                limit: Some(ceiling.limit_usd_micros),
            },
            subjects,
            client,
        })
    }

    pub async fn audit_page(&self, company: Option<String>) -> Result<AuditPage, AppError> {
        let companies = self.clients.list().await?;
        let company_id = company
            .as_deref()
            .filter(|slug| !slug.is_empty())
            .and_then(|slug| companies.iter().find(|client| client.slug == slug))
            .map(|client| client.id.clone());
        let entries = self
            .pool
            .blocking(move |pool| pool.audit_entries(company_id.as_deref(), Self::AUDIT_PAGE))
            .await?;
        Ok(AuditPage {
            entries,
            filter: company.filter(|slug| companies.iter().any(|client| &client.slug == slug)),
            companies,
        })
    }

    pub async fn security_page(
        &self,
        ctx: &AdminContext,
        managed_configured: bool,
    ) -> Result<SecurityPage, AppError> {
        let admin = ctx.admin.id.clone();
        let now = self.now();
        let sessions = self
            .pool
            .blocking(move |pool| pool.active_sessions(&admin, now, Self::idle()))
            .await?;
        Ok(SecurityPage {
            admin: ctx.admin.clone(),
            sessions,
            current_session: ctx.session.id.clone(),
            system: SystemView {
                managed_configured,
                worker: self.worker(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        })
    }

    /// Daily tenant spend of one month as CSV. Cells that a spreadsheet would
    /// run as a formula are quoted with a leading apostrophe.
    pub async fn export_csv(
        &self,
        slug: Option<&str>,
        month: Option<&str>,
    ) -> Result<(String, String), AppError> {
        let today = self.now().date_naive();
        let first = match month {
            Some(month) => NaiveDate::parse_from_str(&format!("{month}-01"), "%Y-%m-%d")
                .map_err(|_| AppError::Invalid)?,
            None => Self::month_start(today),
        };
        let last = first
            .checked_add_months(Months::new(1))
            .and_then(|next| next.pred_opt())
            .ok_or(AppError::Invalid)?;
        let client = match slug {
            Some(slug) => Some(self.clients.by_slug(slug).await?),
            None => None,
        };
        let clients = self.clients.list().await?;
        let id = client.as_ref().map(|client| client.id.clone());
        let accounts = self
            .pool
            .blocking(move |pool| pool.tenant_accounts(id.as_deref(), first, last))
            .await?;
        let names: HashMap<&str, &str> = clients
            .iter()
            .map(|client| (client.id.as_str(), client.slug.as_str()))
            .collect();
        let mut rows = accounts;
        rows.sort_by(|a, b| {
            (&a.period_key, &a.client_id, &a.tenant).cmp(&(&b.period_key, &b.client_id, &b.tenant))
        });
        let mut csv = String::from("date,company,tenant,ceiling_usd,spent_usd,held_usd\n");
        for account in rows {
            let company = names
                .get(account.client_id.as_str())
                .copied()
                .unwrap_or("unknown");
            csv.push_str(&format!(
                "{},{},{},{},{},{}\n",
                account.period_key,
                Self::cell(company),
                Self::cell(&account.tenant),
                Self::usd(account.limit_usd_micros),
                Self::usd(account.spent_usd_micros),
                Self::usd(account.reserved_usd_micros),
            ));
        }
        let name = format!(
            "asystant-{}-{}.csv",
            client.as_ref().map_or("all", |client| client.slug.as_str()),
            first.format("%Y-%m")
        );
        Ok((name, csv))
    }

    fn usd(micros: i64) -> String {
        format!("{}.{:06}", micros / 1_000_000, (micros % 1_000_000).abs())
    }

    fn cell(value: &str) -> String {
        let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
            format!("'{value}")
        } else {
            value.to_string()
        };
        format!("\"{}\"", guarded.replace('"', "\"\""))
    }

    pub fn keys_for_rotation(
        keys: &[ManagedClientKey],
        now: DateTime<Utc>,
    ) -> Vec<&ManagedClientKey> {
        keys.iter()
            .filter(|key| key.state(now) == ClientKeyState::Active)
            .collect()
    }
}
