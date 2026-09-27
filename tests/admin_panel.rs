//! The operator console through real HTTP, SQLite and argon2id + TOTP, with a
//! fixed clock so authenticator codes are deterministic.
use std::sync::Arc;

use actix_web::cookie::Cookie;
use actix_web::http::StatusCode;
use actix_web::http::header::LOCATION;
use actix_web::{App, test, web};
use asystant_api::admin::credentials::Totp;
use asystant_api::admin::handler::{self as console, AdminState};
use asystant_api::admin::service::AdminService;
use asystant_api::handler;
use asystant_api::managed::client_service::ClientService;
use asystant_api::managed::handler::ManagedState;
use asystant_api::managed::key_service::Clock;
use asystant_api::managed::policy_service::PolicyService;
use asystant_api::repository::PoolConfig;
use asystant_api::source::SourceResolver;
use chrono::{DateTime, Utc};

const VAULT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const ORIGIN: &str = "https://console.test";
const WORKSPACE: &str = "6f1d7c1e-2b7a-4c8e-9a51-3d2f0b9e4a17";

fn fixed_now() -> DateTime<Utc> {
    // 10 seconds into a 30-second authenticator step.
    "2026-09-27T12:00:10Z".parse().unwrap()
}

struct Console {
    _dir: tempfile::TempDir,
    state: web::Data<AdminState>,
    managed: web::Data<ManagedState>,
    password: String,
    secret: Vec<u8>,
}

impl Console {
    /// The code of the step `offset` steps away from the fixed clock.
    fn code(&self, offset: i64) -> String {
        let step = Totp::step(fixed_now()) + offset;
        format!("{:06}", Totp::code(&self.secret, step).unwrap())
    }
}

fn base32_decode(text: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buffer, mut bits, mut out) = (0_u32, 0_u32, Vec::new());
    for c in text.bytes() {
        let value = alphabet.iter().position(|a| *a == c).unwrap() as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

async fn console() -> Console {
    let dir = tempfile::tempdir().unwrap();
    let pool = PoolConfig::new(dir.path().join("console.db").to_str().unwrap()).unwrap();
    let clock: Clock = Arc::new(fixed_now);
    let service = AdminService::with_clock(pool.clone(), VAULT_KEY, None, clock).unwrap();
    let credentials = service.create_admin("jhonacode").await.unwrap();
    let state = web::Data::new(AdminState {
        service,
        sources: SourceResolver::default(),
        public_origin: ORIGIN.to_string(),
        managed_configured: false,
    });
    let managed = web::Data::new(ManagedState {
        clients: ClientService::new(pool.clone()),
        policies: PolicyService::new(pool),
        credentials: None,
        sources: SourceResolver::default(),
    });
    Console {
        _dir: dir,
        state,
        managed,
        password: credentials.password.expose().to_string(),
        secret: base32_decode(&credentials.totp_secret),
    }
}

macro_rules! app {
    ($console:expr) => {
        test::init_service(
            App::new()
                .app_data($console.state.clone())
                .app_data($console.managed.clone())
                .configure(console::routes)
                .configure(handler::routes),
        )
        .await
    };
}

fn csrf_of(body: &str) -> String {
    body.split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string()
}

fn cookie_named(response: &actix_web::dev::ServiceResponse, name: &str) -> Option<Cookie<'static>> {
    response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == name)
        .map(|cookie| cookie.into_owned())
}

fn location(response: &actix_web::dev::ServiceResponse) -> String {
    response
        .headers()
        .get(LOCATION)
        .map(|value| value.to_str().unwrap().to_string())
        .unwrap_or_default()
}

/// Signs in with the given password and code; returns the redirect target and
/// the session cookie when there is one.
macro_rules! sign_in {
    ($app:expr, $password:expr, $code:expr) => {{
        let page = test::call_service(
            $app,
            test::TestRequest::get().uri("/admin/login").to_request(),
        )
        .await;
        let login_cookie = cookie_named(&page, "__Host-asystant_login").unwrap();
        let body = String::from_utf8(test::read_body(page).await.to_vec()).unwrap();
        let response = test::call_service(
            $app,
            test::TestRequest::post()
                .uri("/admin/login")
                .insert_header(("Origin", ORIGIN))
                .cookie(login_cookie)
                .set_form([
                    ("csrf", csrf_of(&body)),
                    ("username", "jhonacode".to_string()),
                    ("password", $password.to_string()),
                    ("code", $code.to_string()),
                ])
                .to_request(),
        )
        .await;
        (
            location(&response),
            cookie_named(&response, "__Host-asystant_session"),
        )
    }};
}

macro_rules! page {
    ($app:expr, $session:expr, $uri:expr) => {{
        let response = test::call_service(
            $app,
            test::TestRequest::get()
                .uri($uri)
                .cookie($session.clone())
                .to_request(),
        )
        .await;
        let status = response.status();
        (
            status,
            String::from_utf8(test::read_body(response).await.to_vec()).unwrap(),
        )
    }};
}

macro_rules! post {
    ($app:expr, $session:expr, $uri:expr, $origin:expr, $form:expr) => {{
        test::call_service(
            $app,
            test::TestRequest::post()
                .uri($uri)
                .insert_header(("Origin", $origin))
                .cookie($session.clone())
                .set_form($form)
                .to_request(),
        )
        .await
    }};
}

#[actix_rt::test]
async fn an_operator_signs_in_creates_a_company_and_hands_out_a_scoped_key() {
    let console = console().await;
    let app = app!(console);

    let anonymous =
        test::call_service(&app, test::TestRequest::get().uri("/admin").to_request()).await;
    assert_eq!(anonymous.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&anonymous), "/admin/login");

    let (target, session) = sign_in!(&app, console.password, console.code(-1));
    assert_eq!(target, "/admin");
    let session = session.expect("a session cookie");
    assert!(session.http_only().unwrap_or(false));
    assert_eq!(session.secure(), Some(true));

    let (status, overview) = page!(&app, session, "/admin");
    assert_eq!(status, StatusCode::OK);
    assert!(overview.contains("<h1>Overview</h1>"));
    assert!(!overview.contains("<script"));
    let csrf = csrf_of(&overview);
    let company = |code: String| {
        [
            ("csrf", csrf.clone()),
            ("name", "AulaMás".to_string()),
            ("slug", "aulamas".to_string()),
            ("workspaces", WORKSPACE.to_string()),
            ("models", String::new()),
            ("daily_cap_usd", "40.00".to_string()),
            ("contact", String::new()),
            ("code", code),
        ]
    };

    // The code that opened the session cannot authorize anything else.
    let replayed = post!(
        &app,
        session,
        "/admin/companies",
        ORIGIN,
        company(console.code(-1))
    );
    assert_eq!(location(&replayed), "/admin/companies/new?error=code");

    let created = post!(
        &app,
        session,
        "/admin/companies",
        ORIGIN,
        company(console.code(0))
    );
    assert_eq!(
        location(&created),
        "/admin/companies/aulamas?notice=company_created"
    );
    let (_, detail) = page!(&app, session, "/admin/companies/aulamas");
    assert!(detail.contains("Needs an API key"));
    assert!(detail.contains("$40.00 daily cap"));

    let response = post!(
        &app,
        session,
        "/admin/companies/aulamas/keys",
        ORIGIN,
        [
            ("csrf", csrf.clone()),
            ("label", "Production backend".to_string()),
            ("can_issue", "on".to_string()),
            ("expiry_days", "90".to_string()),
            ("allowed_sources", String::new()),
            ("replaces", String::new()),
            ("code", console.code(1)),
        ]
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("Cache-Control").unwrap(), "no-store");
    let shown = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
    let key = shown
        .split("aria-label=\"New API key\">")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .to_string();
    assert!(key.starts_with("ask_live_") && key.len() == 58, "{key}");

    // The key authenticates, but only for what it was given.
    let manage = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/v1/managed/tenants/colegio-1/budget")
            .insert_header(("Authorization", format!("Bearer {key}")))
            .to_request(),
    )
    .await;
    assert_eq!(manage.status(), StatusCode::FORBIDDEN);
    let issue = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/v1/managed/credentials")
            .insert_header(("Authorization", format!("Bearer {key}")))
            .set_json(serde_json::json!({"tenant": "colegio-1", "subject": "docente-1", "bucket": "daily"}))
            .to_request(),
    )
    .await;
    assert_eq!(
        issue.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "authenticated and permitted; issuance itself is not configured here"
    );

    let (_, audit) = page!(&app, session, "/admin/audit");
    for entry in [
        "Signed in",
        "Company creation refused",
        "Company created",
        "API key created",
    ] {
        assert!(audit.contains(entry), "{entry} missing from the audit log");
    }
    assert!(!audit.contains(&key), "the audit log must never hold a key");
}

#[actix_rt::test]
async fn forms_without_the_session_token_or_from_another_origin_are_refused() {
    let console = console().await;
    let app = app!(console);
    let (_, session) = sign_in!(&app, console.password, console.code(-1));
    let session = session.unwrap();
    let (_, overview) = page!(&app, session, "/admin");
    let csrf = csrf_of(&overview);
    let form = |csrf: String| {
        [
            ("csrf", csrf),
            ("name", "Intruder".to_string()),
            ("slug", "intruder".to_string()),
            ("workspaces", WORKSPACE.to_string()),
            ("code", console.code(0)),
        ]
    };

    let forged = post!(
        &app,
        session,
        "/admin/companies",
        ORIGIN,
        form("0".repeat(64))
    );
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);
    let foreign = post!(
        &app,
        session,
        "/admin/companies",
        "https://evil.test",
        form(csrf.clone())
    );
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
    let unsigned = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/admin/companies")
            .set_form(form(csrf))
            .to_request(),
    )
    .await;
    assert_eq!(unsigned.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&unsigned), "/admin/login");

    let (_, companies) = page!(&app, session, "/admin/companies");
    assert!(!companies.contains("intruder"));
}

#[actix_rt::test]
async fn five_failed_sign_ins_lock_the_console_even_for_the_right_password() {
    let console = console().await;
    let app = app!(console);
    for _ in 0..5 {
        let (target, session) = sign_in!(&app, "wrong-password-123", console.code(0));
        assert_eq!(target, "/admin/login?error=1");
        assert!(session.is_none());
    }
    let (target, session) = sign_in!(&app, console.password, console.code(0));
    assert_eq!(target, "/admin/login?error=locked");
    assert!(session.is_none());
}
