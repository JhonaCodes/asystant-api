use std::fmt::{Debug, Display, Formatter};

use chrono::{DateTime, NaiveDate, Utc};
use diesel::{Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::error::AppError;
use crate::managed::client_model::{
    ClientSettings, ManagedClient, ManagedClientKey, NewClientRequest, NewKeyRequest, SourceRange,
};
use crate::managed::model::ManagedSecret;
use crate::managed::policy_model::ManagedRecoveryRequest;
use crate::schema::{admin_audit_log, admin_sessions, admin_sign_in_attempts, admin_users};

/// An operator of the console. The TOTP secret is sealed; the password is an
/// argon2id hash.
#[derive(Clone, Serialize, Deserialize, Queryable, Selectable, Insertable)]
#[diesel(table_name = admin_users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AdminUser {
    pub id: String,
    pub username: String,
    #[serde(skip)]
    pub password_hash: String,
    #[serde(skip)]
    pub totp_sealed: Vec<u8>,
    pub totp_last_step: i64,
    #[serde(skip)]
    pub pending_totp_sealed: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub password_changed_at: DateTime<Utc>,
    pub last_sign_in_at: Option<DateTime<Utc>>,
    pub last_sign_in_source: Option<String>,
    pub disabled_at: Option<DateTime<Utc>>,
}

impl Debug for AdminUser {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminUser")
            .field("id", &self.id)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

pub struct AdminUsername;

impl AdminUsername {
    pub fn validate(username: &str) -> Result<(), AppError> {
        let valid = username.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        });
        if !(3..=64).contains(&username.len()) || !valid {
            return Err(AppError::Invalid);
        }
        Ok(())
    }
}

/// A signed-in browser. Only the hash of its cookie token is stored.
#[derive(Clone, Serialize, Deserialize, Queryable, Selectable, Insertable)]
#[diesel(table_name = admin_sessions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AdminSession {
    pub id: String,
    #[serde(skip)]
    pub token_hash: String,
    pub admin_id: String,
    #[serde(skip)]
    pub csrf_token: String,
    pub user_agent: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Debug for AdminSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminSession")
            .field("id", &self.id)
            .field("admin_id", &self.admin_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Insertable)]
#[diesel(table_name = admin_sign_in_attempts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct SignInAttempt {
    pub id: String,
    pub username: String,
    pub source: String,
    pub succeeded: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Done,
    Refused,
}

impl AuditResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Refused => "refused",
        }
    }
}

/// What one audit entry records, besides who and from where.
#[derive(Debug, Clone, Copy)]
pub struct AuditEvent<'a> {
    pub action: &'a str,
    pub company_id: Option<&'a str>,
    pub target: &'a str,
    pub detail: &'a str,
    pub result: AuditResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = admin_audit_log)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NewAuditEntry {
    pub created_at: DateTime<Utc>,
    pub actor: Option<String>,
    pub action: String,
    pub company_id: Option<String>,
    pub target: String,
    pub detail: String,
    pub source: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = admin_audit_log)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AuditEntry {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub actor: Option<String>,
    pub action: String,
    pub company_id: Option<String>,
    pub target: String,
    pub detail: String,
    pub source: String,
    pub result: String,
}

/// The administrator and session behind one request.
#[derive(Debug, Clone)]
pub struct AdminContext {
    pub admin: AdminUser,
    pub session: AdminSession,
}

impl AdminContext {
    pub fn csrf(&self) -> &str {
        &self.session.csrf_token
    }
}

/// Where the request came from and with what browser, for audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestOrigin {
    pub source: String,
    pub user_agent: String,
}

/// Shown once by the command line when an administrator is created or reset.
#[derive(Clone)]
pub struct AdminCredentials {
    pub username: String,
    pub password: ManagedSecret,
    pub totp_secret: String,
    pub totp_uri: String,
}

impl Debug for AdminCredentials {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminCredentials")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// A new authenticator waiting for its first code before it replaces the old one.
#[derive(Debug, Clone)]
pub struct TotpEnrollment {
    pub secret: String,
    pub uri: String,
}

/// A new session and the cookie token that authenticates it.
#[derive(Clone)]
pub struct IssuedSession {
    pub token: ManagedSecret,
}

impl Debug for IssuedSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("IssuedSession([REDACTED])")
    }
}

/// Integer USD micros shown as dollars and cents, never through floating point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Money(pub i64);

impl Money {
    pub fn cents(self) -> i64 {
        (self.0 + 5_000).div_euclid(10_000)
    }

    /// `12.34` → 12,340,000 micros; at most two decimals.
    pub fn parse_usd(value: &str) -> Result<i64, AppError> {
        let value = value.trim().trim_start_matches('$');
        let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
        if whole.is_empty()
            || fraction.len() > 2
            || !whole.bytes().all(|c| c.is_ascii_digit())
            || !fraction.bytes().all(|c| c.is_ascii_digit())
        {
            return Err(AppError::Invalid);
        }
        let whole = whole.parse::<i64>().map_err(|_| AppError::Invalid)?;
        let cents = format!("{fraction:0<2}")
            .parse::<i64>()
            .map_err(|_| AppError::Invalid)?;
        whole
            .checked_mul(1_000_000)
            .and_then(|micros| micros.checked_add(cents * 10_000))
            .ok_or(AppError::Invalid)
    }
}

impl Display for Money {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let cents = self.cents();
        let sign = if cents < 0 { "-" } else { "" };
        let cents = cents.abs();
        let dollars = (cents / 100).to_string();
        let mut grouped = String::new();
        for (index, digit) in dollars.chars().enumerate() {
            if index > 0 && (dollars.len() - index).is_multiple_of(3) {
                grouped.push(',');
            }
            grouped.push(digit);
        }
        write!(formatter, "{sign}${grouped}.{:02}", cents % 100)
    }
}

/// Spent, held and available against a limit, for the meters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Usage {
    pub spent: i64,
    pub held: i64,
    pub limit: Option<i64>,
}

impl Usage {
    pub fn available(&self) -> Option<i64> {
        self.limit.map(|limit| {
            limit
                .saturating_sub(self.spent)
                .saturating_sub(self.held)
                .max(0)
        })
    }

    /// Share of the limit in percent, capped to 100, for SVG widths.
    pub fn share(part: i64, limit: Option<i64>) -> f64 {
        match limit {
            Some(limit) if limit > 0 => (part.max(0) as f64 * 100.0 / limit as f64).min(100.0),
            _ => 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayTotal {
    pub date: NaiveDate,
    pub spent: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyToday {
    pub name: String,
    pub slug: String,
    pub usage: Usage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttentionItem {
    pub company_name: String,
    pub company_slug: String,
    pub tenant: String,
    pub subject: String,
    pub status: String,
    pub since: DateTime<Utc>,
    pub held: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WorkerView {
    pub configured: bool,
    pub last_revocation: Option<DateTime<Utc>>,
    pub last_usage: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewPage {
    pub now: DateTime<Utc>,
    pub spent_today: i64,
    pub held_today: i64,
    pub month_to_date: i64,
    pub keys_today: i64,
    pub active_companies: usize,
    pub series: Vec<DayTotal>,
    pub by_company: Vec<CompanyToday>,
    pub attention: Vec<AttentionItem>,
    pub worker: WorkerView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyRow {
    pub client: ManagedClient,
    pub workspaces: usize,
    pub active_keys: usize,
    pub rotating_keys: usize,
    pub revoked_keys: usize,
    pub today: Usage,
    pub month_spent: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRow {
    pub workspace_id: String,
    pub tenants: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRow {
    pub tenant: String,
    pub workspace_id: String,
    pub usage: Usage,
    pub subjects: usize,
    pub attention: usize,
    pub live_keys: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyPage {
    pub now: DateTime<Utc>,
    pub client: ManagedClient,
    pub keys: Vec<ManagedClientKey>,
    pub workspaces: Vec<WorkspaceRow>,
    pub tenants: Vec<TenantRow>,
    pub today: Usage,
    pub month_spent: i64,
    pub migration_spent: i64,
    pub keys_today: i64,
    pub live_keys: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseView {
    pub id: String,
    pub status: String,
    pub limit: i64,
    pub accounted: i64,
    pub held: i64,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub can_recover: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectRow {
    pub subject: String,
    pub budget: i64,
    pub lease: Option<LeaseView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPage {
    pub client: ManagedClient,
    pub tenant: String,
    pub workspace_id: Option<String>,
    pub usage: Usage,
    pub subjects: Vec<SubjectRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPage {
    pub entries: Vec<AuditEntry>,
    pub companies: Vec<ManagedClient>,
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemView {
    pub managed_configured: bool,
    pub worker: WorkerView,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPage {
    pub admin: AdminUser,
    pub sessions: Vec<AdminSession>,
    pub current_session: String,
    pub system: SystemView,
}

// ---------- Forms ----------

#[derive(Clone, Serialize, Deserialize)]
pub struct SignInForm {
    pub csrf: String,
    pub username: String,
    pub password: String,
    pub code: String,
}

impl Debug for SignInForm {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignInForm")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfForm {
    pub csrf: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeForm {
    pub csrf: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyForm {
    pub csrf: String,
    pub name: String,
    pub slug: String,
    pub workspaces: String,
    #[serde(default)]
    pub models: String,
    #[serde(default)]
    pub daily_cap_usd: String,
    #[serde(default)]
    pub contact: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanySettingsForm {
    pub csrf: String,
    pub name: String,
    pub models: String,
    #[serde(default)]
    pub daily_cap_usd: String,
    #[serde(default)]
    pub contact: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceForm {
    pub csrf: String,
    pub workspace_id: String,
    pub code: String,
}

/// Checkbox values arrive only when checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyForm {
    pub csrf: String,
    pub label: String,
    #[serde(default)]
    pub can_issue: Option<String>,
    #[serde(default)]
    pub can_manage: Option<String>,
    pub expiry_days: i64,
    #[serde(default)]
    pub allowed_sources: String,
    #[serde(default)]
    pub replaces: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendForm {
    pub csrf: String,
    pub confirm: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryForm {
    pub csrf: String,
    pub limit_usd: String,
    pub reason: String,
    #[serde(default)]
    pub acknowledge: Option<String>,
    pub code: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordForm {
    pub csrf: String,
    pub current: String,
    pub next: String,
    pub code: String,
}

impl Debug for PasswordForm {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PasswordForm([REDACTED])")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TotpStartForm {
    pub csrf: String,
    pub password: String,
    pub code: String,
}

impl Debug for TotpStartForm {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TotpStartForm([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub company: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoticeQuery {
    #[serde(default)]
    pub notice: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportQuery {
    #[serde(default)]
    pub month: Option<String>,
}

// ---------- Form parsing ----------

/// Parsing shared by the console forms: text areas, lists and money.
pub struct FormInput;

impl FormInput {
    pub fn lines(value: &str) -> impl Iterator<Item = &str> {
        value.lines().map(str::trim).filter(|line| !line.is_empty())
    }

    pub fn list(value: &str) -> Vec<String> {
        value
            .split([',', '\n'])
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect()
    }

    pub fn optional(value: &str) -> Option<String> {
        Some(value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    pub fn optional_usd(value: &str) -> Result<Option<i64>, AppError> {
        Self::optional(value)
            .map(|value| Money::parse_usd(&value))
            .transpose()
    }

    pub fn checked(value: &Option<String>) -> bool {
        value
            .as_deref()
            .is_some_and(|value| value == "on" || value == "true")
    }
}

impl CompanyForm {
    pub fn to_request(&self) -> Result<NewClientRequest, AppError> {
        let workspaces = FormInput::lines(&self.workspaces)
            .map(|line| Uuid::parse_str(line).map_err(|_| AppError::Invalid))
            .collect::<Result<Vec<_>, _>>()?;
        let request = NewClientRequest {
            slug: self.slug.trim().to_string(),
            name: self.name.trim().to_string(),
            workspaces,
            allowed_models: FormInput::list(&self.models),
            contact: FormInput::optional(&self.contact),
            daily_cap_usd_micros: FormInput::optional_usd(&self.daily_cap_usd)?,
        };
        request.validate()?;
        Ok(request)
    }
}

impl CompanySettingsForm {
    pub fn to_settings(&self) -> Result<ClientSettings, AppError> {
        let settings = ClientSettings {
            name: self.name.trim().to_string(),
            allowed_models: FormInput::list(&self.models),
            contact: FormInput::optional(&self.contact),
            daily_cap_usd_micros: FormInput::optional_usd(&self.daily_cap_usd)?,
        };
        settings.validate()?;
        Ok(settings)
    }
}

impl KeyForm {
    pub fn to_request(&self, created_by: &str) -> Result<NewKeyRequest, AppError> {
        let request = NewKeyRequest {
            label: self.label.trim().to_string(),
            can_issue: FormInput::checked(&self.can_issue),
            can_manage: FormInput::checked(&self.can_manage),
            expires_in_days: self.expiry_days,
            allowed_sources: FormInput::lines(&self.allowed_sources)
                .map(SourceRange::parse)
                .collect::<Result<Vec<_>, _>>()?,
            replaces: FormInput::optional(&self.replaces)
                .map(|id| Uuid::parse_str(&id).map_err(|_| AppError::Invalid))
                .transpose()?,
            created_by: created_by.to_string(),
        };
        request.validate()?;
        Ok(request)
    }
}

impl RecoveryForm {
    pub fn to_request(&self, actor: &str) -> Result<ManagedRecoveryRequest, AppError> {
        let request = ManagedRecoveryRequest {
            limit_usd_micros: Money::parse_usd(&self.limit_usd)?,
            reason: self.reason.trim().to_string(),
            acknowledge_pending_reserve: FormInput::checked(&self.acknowledge),
            actor: actor.to_string(),
        };
        request.validate()?;
        Ok(request)
    }
}
