use actix_web::cookie::{Cookie, SameSite};
use actix_web::http::StatusCode;
use actix_web::http::header::{
    CONTENT_DISPOSITION, CONTENT_TYPE, LOCATION, ORIGIN, REFERER, USER_AGENT,
};
use actix_web::middleware::DefaultHeaders;
use actix_web::web::{self, Data, Form, Path, Query, ServiceConfig};
use actix_web::{HttpRequest, HttpResponse};
use serde::Deserialize;
use uuid::Uuid;

use crate::admin::credentials::Tokens;
use crate::admin::model::{
    AdminContext, AuditQuery, CodeForm, CompanyForm, CompanySettingsForm, CsrfForm, ExportQuery,
    IssuedSession, KeyForm, NoticeQuery, PasswordForm, RecoveryForm, RequestOrigin, SetupForm,
    SetupQuery, SignInForm, SuspendForm, TotpStartForm, WorkspaceForm,
};
use crate::admin::service::AdminService;
use crate::admin::view;
use crate::error::AppError;
use crate::source::SourceResolver;

const SESSION_COOKIE: &str = "__Host-asystant_session";
const LOGIN_COOKIE: &str = "__Host-asystant_login";
const FORM_LIMIT: usize = 16 * 1024;

/// Everything the console needs per request.
pub struct AdminState {
    pub service: AdminService,
    pub sources: SourceResolver,
    /// The only `Origin` accepted on a form submission, e.g. `https://ai.jhonacode.com`.
    pub public_origin: String,
    pub managed_configured: bool,
}

impl AdminState {
    fn origin(&self, request: &HttpRequest) -> RequestOrigin {
        RequestOrigin {
            source: self.sources.describe(request),
            user_agent: request
                .headers()
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("unknown")
                .chars()
                .take(200)
                .collect(),
        }
    }

    /// Browsers send `Origin` on every form POST; `Referer` is the fallback.
    fn same_origin(&self, request: &HttpRequest) -> bool {
        let header = |name| {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
        };
        match (header(ORIGIN), header(REFERER)) {
            (Some(origin), _) => origin == self.public_origin,
            (None, Some(referer)) => referer.starts_with(&format!("{}/", self.public_origin)),
            (None, None) => false,
        }
    }
}

fn page(body: String) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

fn page_with(status: StatusCode, body: String) -> HttpResponse {
    HttpResponse::build(status)
        .content_type("text/html; charset=utf-8")
        .body(body)
}

fn redirect(location: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((LOCATION, location.to_string()))
        .finish()
}

fn cookie(name: &'static str, value: String, seconds: i64) -> Cookie<'static> {
    Cookie::build(name, value)
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(actix_web::cookie::time::Duration::seconds(seconds))
        .finish()
}

fn with_cookie(mut response: HttpResponse, cookie: &Cookie<'static>) -> HttpResponse {
    if response.add_cookie(cookie).is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    response
}

fn to_login() -> HttpResponse {
    with_cookie(
        redirect("/admin/login"),
        &cookie(SESSION_COOKIE, String::new(), 0),
    )
}

/// Stable codes for the fixed messages of `view::notice`.
fn error_code(error: &AppError) -> &'static str {
    match error {
        AppError::Authentication => "code",
        AppError::Invalid => "invalid",
        AppError::Conflict => "conflict",
        AppError::Budget => "budget",
        AppError::Forbidden => "forbidden",
        AppError::NotFound => "not_found",
        _ => "unavailable",
    }
}

fn after(path: &str, result: Result<(), AppError>, notice: &str) -> HttpResponse {
    match result {
        Ok(()) => redirect(&format!("{path}?notice={notice}")),
        Err(error) => redirect(&format!("{path}?error={}", error_code(&error))),
    }
}

fn company_path(slug: &str) -> String {
    format!("/admin/companies/{}", view::segment(slug))
}

fn notice_of(query: &NoticeQuery) -> Option<view::Notice> {
    view::notice(query.notice.as_deref(), query.error.as_deref())
}

async fn context(request: &HttpRequest, state: &AdminState) -> Result<AdminContext, HttpResponse> {
    let token = request.cookie(SESSION_COOKIE).ok_or_else(to_login)?;
    state
        .service
        .session(token.value())
        .await
        .map_err(|_| to_login())
}

/// A signed-in administrator submitting a form of this console.
async fn form_context(
    request: &HttpRequest,
    state: &AdminState,
    csrf: &str,
) -> Result<AdminContext, HttpResponse> {
    let ctx = context(request, state).await?;
    if !state.same_origin(request) || !Tokens::equal(ctx.csrf(), csrf) {
        return Err(HttpResponse::Forbidden().finish());
    }
    Ok(ctx)
}

macro_rules! signed_in {
    ($expression:expr) => {
        match $expression {
            Ok(ctx) => ctx,
            Err(response) => return response,
        }
    };
}

fn failed(ctx: &AdminContext, error: AppError) -> HttpResponse {
    match error {
        AppError::NotFound => page_with(StatusCode::NOT_FOUND, view::not_found(ctx)),
        _ => page_with(StatusCode::SERVICE_UNAVAILABLE, view::not_found(ctx)),
    }
}

// ---------------------------------------------------------------- sign-in

async fn login_page(
    request: HttpRequest,
    state: Data<AdminState>,
    query: Query<NoticeQuery>,
) -> HttpResponse {
    if context(&request, &state).await.is_ok() {
        return redirect("/admin");
    }
    let Ok(csrf) = Tokens::random() else {
        return HttpResponse::ServiceUnavailable().finish();
    };
    let body = view::login(&csrf, query.error.as_deref());
    with_cookie(page(body), &cookie(LOGIN_COOKIE, csrf, 600))
}

async fn login(
    request: HttpRequest,
    state: Data<AdminState>,
    form: Form<SignInForm>,
) -> HttpResponse {
    if !fresh_form(&request, &state, &form.csrf) {
        return redirect("/admin/login?error=1");
    }
    match state.service.sign_in(&form, &state.origin(&request)).await {
        Ok(issued) => signed_in_at("/admin", &issued),
        Err(AppError::Limited) => redirect("/admin/login?error=locked"),
        Err(_) => redirect("/admin/login?error=1"),
    }
}

/// The session cookie of a new sign-in; the one-time login form token ends.
fn signed_in_at(location: &str, issued: &IssuedSession) -> HttpResponse {
    let response = with_cookie(
        redirect(location),
        &cookie(
            SESSION_COOKIE,
            issued.token.expose().to_string(),
            AdminService::SESSION_HOURS * 3600,
        ),
    );
    with_cookie(response, &cookie(LOGIN_COOKIE, String::new(), 0))
}

/// Pre-session forms (sign-in, setup) prove they came from a page this
/// console served: the same origin and the token of the login cookie.
fn fresh_form(request: &HttpRequest, state: &AdminState, csrf: &str) -> bool {
    state.same_origin(request)
        && request
            .cookie(LOGIN_COOKIE)
            .is_some_and(|cookie| Tokens::equal(cookie.value(), csrf))
}

// ---------------------------------------------------------------- setup

async fn setup_page(state: Data<AdminState>, query: Query<SetupQuery>) -> HttpResponse {
    let Ok(csrf) = Tokens::random() else {
        return HttpResponse::ServiceUnavailable().finish();
    };
    match state.service.setup_page(&query.token).await {
        Ok(data) => {
            let body = view::setup(&csrf, &query.token, &data, query.error.as_deref());
            with_cookie(page(body), &cookie(LOGIN_COOKIE, csrf, 1800))
        }
        Err(AppError::NotFound) => page_with(StatusCode::NOT_FOUND, view::setup_invalid()),
        Err(_) => HttpResponse::ServiceUnavailable().finish(),
    }
}

async fn setup(
    request: HttpRequest,
    state: Data<AdminState>,
    form: Form<SetupForm>,
) -> HttpResponse {
    // Only a well-formed token goes back into a Location header.
    if form.token.len() != 64 || !form.token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return page_with(StatusCode::NOT_FOUND, view::setup_invalid());
    }
    let back = |error: &str| redirect(&format!("/admin/setup?token={}&error={error}", form.token));
    if !fresh_form(&request, &state, &form.csrf) {
        return back("expired");
    }
    match state
        .service
        .complete_setup(&form, &state.origin(&request))
        .await
    {
        Ok(issued) => signed_in_at("/admin?notice=welcome", &issued),
        Err(AppError::Invalid) => back("invalid"),
        Err(AppError::Authentication) => back("code"),
        Err(AppError::Limited) => back("locked"),
        Err(AppError::NotFound | AppError::Conflict) => {
            page_with(StatusCode::NOT_FOUND, view::setup_invalid())
        }
        Err(_) => back("unavailable"),
    }
}

async fn logout(
    request: HttpRequest,
    state: Data<AdminState>,
    form: Form<CsrfForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    if state
        .service
        .sign_out(&ctx, &state.origin(&request))
        .await
        .is_err()
    {
        return HttpResponse::ServiceUnavailable().finish();
    }
    to_login()
}

// ---------------------------------------------------------------- pages

async fn overview(
    request: HttpRequest,
    state: Data<AdminState>,
    query: Query<NoticeQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    match state.service.overview_page().await {
        Ok(data) => page(view::overview(&ctx, &data, notice_of(&query))),
        Err(error) => failed(&ctx, error),
    }
}

async fn companies(
    request: HttpRequest,
    state: Data<AdminState>,
    query: Query<NoticeQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    match state.service.companies_page().await {
        Ok(rows) => page(view::companies(&ctx, &rows, notice_of(&query))),
        Err(error) => failed(&ctx, error),
    }
}

async fn company_new(
    request: HttpRequest,
    state: Data<AdminState>,
    query: Query<NoticeQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    page(view::company_new(&ctx, notice_of(&query)))
}

async fn company_create(
    request: HttpRequest,
    state: Data<AdminState>,
    form: Form<CompanyForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    match state
        .service
        .create_company(&ctx, &state.origin(&request), form.into_inner())
        .await
    {
        Ok(client) => redirect(&format!(
            "{}?notice=company_created",
            company_path(&client.slug)
        )),
        Err(error) => redirect(&format!(
            "/admin/companies/new?error={}",
            error_code(&error)
        )),
    }
}

async fn company(
    request: HttpRequest,
    state: Data<AdminState>,
    slug: Path<String>,
    query: Query<NoticeQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    match state.service.company_page(&slug).await {
        Ok(data) => page(view::company(&ctx, &data, notice_of(&query))),
        Err(error) => failed(&ctx, error),
    }
}

async fn company_settings(
    request: HttpRequest,
    state: Data<AdminState>,
    slug: Path<String>,
    form: Form<CompanySettingsForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let result = state
        .service
        .update_company(&ctx, &state.origin(&request), &slug, form.into_inner())
        .await;
    after(&company_path(&slug), result, "company_updated")
}

async fn workspace_add(
    request: HttpRequest,
    state: Data<AdminState>,
    slug: Path<String>,
    form: Form<WorkspaceForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let result = state
        .service
        .add_workspace(&ctx, &state.origin(&request), &slug, form.into_inner())
        .await;
    after(&company_path(&slug), result, "workspace_added")
}

async fn workspace_remove_page(
    request: HttpRequest,
    state: Data<AdminState>,
    path: Path<(String, Uuid)>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    let (slug, workspace) = path.into_inner();
    let client = match state.service.company(&slug).await {
        Ok(client) => client,
        Err(error) => return failed(&ctx, error),
    };
    page(view::confirm(
        &ctx,
        "Remove workspace",
        &format!(
            "{} will no longer be able to place tenant keys in workspace {workspace}.",
            client.name
        ),
        &format!(
            "{}/workspaces/{workspace}/remove",
            company_path(&client.slug)
        ),
        "Remove workspace",
        &company_path(&client.slug),
    ))
}

async fn workspace_remove(
    request: HttpRequest,
    state: Data<AdminState>,
    path: Path<(String, Uuid)>,
    form: Form<CodeForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let (slug, workspace) = path.into_inner();
    let result = state
        .service
        .remove_workspace(&ctx, &state.origin(&request), &slug, workspace, &form.code)
        .await;
    after(&company_path(&slug), result, "workspace_removed")
}

#[derive(Debug, Clone, Deserialize)]
struct ReplacesQuery {
    #[serde(default)]
    replaces: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

async fn key_new(
    request: HttpRequest,
    state: Data<AdminState>,
    slug: Path<String>,
    query: Query<ReplacesQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    let data = match state.service.company_page(&slug).await {
        Ok(data) => data,
        Err(error) => return failed(&ctx, error),
    };
    let rotatable = AdminService::keys_for_rotation(&data.keys, data.now);
    page(view::key_new(
        &ctx,
        &data.client,
        &rotatable,
        query.replaces.as_deref(),
        view::notice(None, query.error.as_deref()),
    ))
}

/// The new key is rendered in this response, never stored nor redirected.
async fn key_create(
    request: HttpRequest,
    state: Data<AdminState>,
    slug: Path<String>,
    form: Form<KeyForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    match state
        .service
        .create_key(&ctx, &state.origin(&request), &slug, form.into_inner())
        .await
    {
        Ok((client, created)) => page(view::key_created(&ctx, &client, &created)),
        Err(error) => redirect(&format!(
            "{}/keys/new?error={}",
            company_path(&slug),
            error_code(&error)
        )),
    }
}

async fn key_revoke_page(
    request: HttpRequest,
    state: Data<AdminState>,
    path: Path<(String, Uuid)>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    let (slug, key) = path.into_inner();
    let data = match state.service.company_page(&slug).await {
        Ok(data) => data,
        Err(error) => return failed(&ctx, error),
    };
    let Some(found) = data
        .keys
        .iter()
        .find(|candidate| candidate.id == key.to_string())
    else {
        return failed(&ctx, AppError::NotFound);
    };
    page(view::confirm(
        &ctx,
        "Revoke API key",
        &format!(
            "Calls with “{}” ({}) are refused from now on. Anything of {} still using it stops working.",
            found.label,
            found.masked(),
            data.client.name
        ),
        &format!("{}/keys/{key}/revoke", company_path(&data.client.slug)),
        "Revoke key",
        &company_path(&data.client.slug),
    ))
}

async fn key_revoke(
    request: HttpRequest,
    state: Data<AdminState>,
    path: Path<(String, Uuid)>,
    form: Form<CodeForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let (slug, key) = path.into_inner();
    let result = state
        .service
        .revoke_key(&ctx, &state.origin(&request), &slug, key, &form.code)
        .await;
    after(&company_path(&slug), result, "key_revoked")
}

async fn company_suspend(
    request: HttpRequest,
    state: Data<AdminState>,
    slug: Path<String>,
    form: Form<SuspendForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let result = state
        .service
        .suspend(&ctx, &state.origin(&request), &slug, form.into_inner())
        .await;
    after(&company_path(&slug), result, "company_suspended")
}

async fn company_reactivate(
    request: HttpRequest,
    state: Data<AdminState>,
    slug: Path<String>,
    form: Form<CodeForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let result = state
        .service
        .reactivate(&ctx, &state.origin(&request), &slug, &form.code)
        .await;
    after(&company_path(&slug), result, "company_reactivated")
}

async fn tenant(
    request: HttpRequest,
    state: Data<AdminState>,
    path: Path<(String, String)>,
    query: Query<NoticeQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    let (slug, tenant) = path.into_inner();
    match state.service.tenant_page(&slug, &tenant).await {
        Ok(data) => page(view::tenant(&ctx, &data, notice_of(&query))),
        Err(error) => failed(&ctx, error),
    }
}

async fn recovery(
    request: HttpRequest,
    state: Data<AdminState>,
    path: Path<(String, String, Uuid)>,
    form: Form<RecoveryForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let (slug, tenant, lease) = path.into_inner();
    let result = state
        .service
        .authorize_recovery(
            &ctx,
            &state.origin(&request),
            &slug,
            &tenant,
            lease,
            form.into_inner(),
        )
        .await;
    after(
        &format!("{}/tenants/{}", company_path(&slug), view::segment(&tenant)),
        result,
        "recovery_authorized",
    )
}

fn csv(name: &str, body: String) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((CONTENT_TYPE, "text/csv; charset=utf-8"))
        .insert_header((
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        ))
        .body(body)
}

async fn export_all(
    request: HttpRequest,
    state: Data<AdminState>,
    query: Query<ExportQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    match state.service.export_csv(None, query.month.as_deref()).await {
        Ok((name, body)) => csv(&name, body),
        Err(error) => failed(&ctx, error),
    }
}

async fn export_company(
    request: HttpRequest,
    state: Data<AdminState>,
    slug: Path<String>,
    query: Query<ExportQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    match state
        .service
        .export_csv(Some(&slug), query.month.as_deref())
        .await
    {
        Ok((name, body)) => csv(&name, body),
        Err(error) => failed(&ctx, error),
    }
}

async fn audit(
    request: HttpRequest,
    state: Data<AdminState>,
    query: Query<AuditQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    match state.service.audit_page(query.into_inner().company).await {
        Ok(data) => page(view::audit(&ctx, &data)),
        Err(error) => failed(&ctx, error),
    }
}

async fn security(
    request: HttpRequest,
    state: Data<AdminState>,
    query: Query<NoticeQuery>,
) -> HttpResponse {
    let ctx = signed_in!(context(&request, &state).await);
    match state
        .service
        .security_page(&ctx, state.managed_configured)
        .await
    {
        Ok(data) => page(view::security(&ctx, &data, notice_of(&query))),
        Err(error) => failed(&ctx, error),
    }
}

async fn password(
    request: HttpRequest,
    state: Data<AdminState>,
    form: Form<PasswordForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let result = state
        .service
        .change_password(&ctx, &state.origin(&request), form.into_inner())
        .await;
    after("/admin/security", result, "password_changed")
}

async fn authenticator_start(
    request: HttpRequest,
    state: Data<AdminState>,
    form: Form<TotpStartForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    match state
        .service
        .start_totp_replacement(&ctx, &state.origin(&request), form.into_inner())
        .await
    {
        Ok(enrollment) => page(view::totp_enrollment(&ctx, &enrollment)),
        Err(error) => redirect(&format!("/admin/security?error={}", error_code(&error))),
    }
}

async fn authenticator_confirm(
    request: HttpRequest,
    state: Data<AdminState>,
    form: Form<CodeForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let result = state
        .service
        .confirm_totp_replacement(&ctx, &state.origin(&request), &form.code)
        .await;
    after("/admin/security", result, "authenticator_replaced")
}

async fn session_revoke(
    request: HttpRequest,
    state: Data<AdminState>,
    session: Path<String>,
    form: Form<CsrfForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let result = state
        .service
        .revoke_session(&ctx, &state.origin(&request), &session)
        .await;
    after("/admin/security", result, "session_revoked")
}

async fn sessions_revoke(
    request: HttpRequest,
    state: Data<AdminState>,
    form: Form<CsrfForm>,
) -> HttpResponse {
    let ctx = signed_in!(form_context(&request, &state, &form.csrf).await);
    let result = state
        .service
        .revoke_other_sessions(&ctx, &state.origin(&request))
        .await;
    after("/admin/security", result, "sessions_revoked")
}

async fn styles() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .body(include_str!("style.css"))
}

pub async fn root() -> HttpResponse {
    redirect("/admin")
}

/// The console under `/admin`, with its own headers: no scripts, no framing,
/// nothing cached and nothing shared with other origins.
pub fn routes(config: &mut ServiceConfig) {
    config.service(
        web::scope("/admin")
            .wrap(
                DefaultHeaders::new()
                    .add((
                        "Content-Security-Policy",
                        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
                    ))
                    .add(("Cache-Control", "no-store"))
                    // Under `no-referrer` browsers post forms with `Origin: null`,
                    // which the origin check refuses; `same-origin` still keeps
                    // setup links from leaking to other sites.
                    .add(("Referrer-Policy", "same-origin"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("Cross-Origin-Opener-Policy", "same-origin"))
                    .add(("Cross-Origin-Resource-Policy", "same-origin"))
                    .add(("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")),
            )
            .app_data(
                web::FormConfig::default()
                    .limit(FORM_LIMIT)
                    .error_handler(|_, _| AppError::Invalid.into()),
            )
            .app_data(web::PathConfig::default().error_handler(|_, _| AppError::NotFound.into()))
            .app_data(web::QueryConfig::default().error_handler(|_, _| AppError::Invalid.into()))
            .route("", web::get().to(overview))
            .route("/", web::get().to(overview))
            .route("/style.css", web::get().to(styles))
            .route("/login", web::get().to(login_page))
            .route("/login", web::post().to(login))
            .route("/setup", web::get().to(setup_page))
            .route("/setup", web::post().to(setup))
            .route("/logout", web::post().to(logout))
            .route("/export.csv", web::get().to(export_all))
            .route("/companies", web::get().to(companies))
            .route("/companies", web::post().to(company_create))
            .route("/companies/new", web::get().to(company_new))
            .route("/companies/{slug}", web::get().to(company))
            .route("/companies/{slug}/settings", web::post().to(company_settings))
            .route("/companies/{slug}/workspaces", web::post().to(workspace_add))
            .route("/companies/{slug}/workspaces/{workspace}/remove", web::get().to(workspace_remove_page))
            .route("/companies/{slug}/workspaces/{workspace}/remove", web::post().to(workspace_remove))
            .route("/companies/{slug}/keys/new", web::get().to(key_new))
            .route("/companies/{slug}/keys", web::post().to(key_create))
            .route("/companies/{slug}/keys/{key}/revoke", web::get().to(key_revoke_page))
            .route("/companies/{slug}/keys/{key}/revoke", web::post().to(key_revoke))
            .route("/companies/{slug}/suspend", web::post().to(company_suspend))
            .route("/companies/{slug}/reactivate", web::post().to(company_reactivate))
            .route("/companies/{slug}/export.csv", web::get().to(export_company))
            .route("/companies/{slug}/tenants/{tenant}", web::get().to(tenant))
            .route("/companies/{slug}/tenants/{tenant}/leases/{lease}/recovery", web::post().to(recovery))
            .route("/audit", web::get().to(audit))
            .route("/security", web::get().to(security))
            .route("/security/password", web::post().to(password))
            .route("/security/authenticator", web::post().to(authenticator_start))
            .route("/security/authenticator/confirm", web::post().to(authenticator_confirm))
            .route("/security/sessions/revoke-others", web::post().to(sessions_revoke))
            .route("/security/sessions/{session}/revoke", web::post().to(session_revoke)),
    );
}
