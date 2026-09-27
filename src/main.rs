use std::{env, sync::Arc};

use actix_web::{
    App, HttpServer,
    middleware::{DefaultHeaders, from_fn},
    web,
};
use anyhow::{anyhow, bail};
use asystant_api::{
    admin::{
        handler::{self as console, AdminState},
        service::AdminService,
    },
    admission::{self, Admission},
    handler,
    health::HealthService,
    managed::{
        client_service::ClientService,
        credential_service::CredentialService,
        handler::ManagedState,
        key_service::Clock,
        model::ManagedSettings,
        openrouter::{OpenRouterKeyManager, OpenRouterManagementClient},
        policy_service::PolicyService,
        vault::ManagedKeyVault,
        worker::{ManagedWorker, WorkerHealth},
    },
    repository::PoolConfig,
    source::SourceResolver,
};
use chrono::Utc;
use log::warn;

/// Variables of the removed ticket/session/turn gateway. Refusing them makes a
/// deployment that still depends on that flow fail loudly instead of serving 404s.
const REMOVED_VARIABLES: [&str; 5] = [
    "ASYSTANT_PRODUCTS",
    "ASYSTANT_MODELS",
    "ASYSTANT_ORIGINS",
    "ASYSTANT_ADMIN_TOKEN",
    "OPENROUTER_API_KEY",
];
const PUBLIC_ORIGIN_ENV: &str = "ASYSTANT_PUBLIC_ORIGIN";
const USAGE: &str = "usage: asystant_api [--migrate-only | --serve | admin create <username> | admin reset <username>]";

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    anyhow::ensure!(
        env::var_os("DATABASE_URL").is_none(),
        "DATABASE_URL is no longer supported; configure DATABASE_PATH and migrate existing data before switching storage"
    );
    if let Some(name) = REMOVED_VARIABLES
        .iter()
        .find(|name| env::var_os(name).is_some())
    {
        bail!(
            "{name} belongs to the removed ticket/session gateway; remove it and configure the managed-key flow (docs/managed-keys.md)"
        );
    }
    let args: Vec<String> = env::args().skip(1).collect();
    let database_path = env::var("DATABASE_PATH").unwrap_or_else(|_| "asystant.db".into());
    let serve_only = match args.first().map(String::as_str) {
        Some("--migrate-only") => {
            PoolConfig::connect(&database_path)?.migrate()?;
            return Ok(());
        }
        Some("admin") => return administrators(args.get(1..).unwrap_or(&[]), &database_path).await,
        Some("--serve") => true,
        None => false,
        Some(_) => bail!(USAGE),
    };
    let pool = if serve_only {
        PoolConfig::connect(&database_path)?
    } else {
        PoolConfig::new(&database_path)?
    };
    let settings = ManagedSettings::from_env().map_err(|_| {
        anyhow!(
            "{} and {} must be set together; the encryption key must be 32 bytes in base64",
            ManagedSettings::MANAGEMENT_KEY_ENV,
            ManagedSettings::ENCRYPTION_KEY_ENV
        )
    })?;
    let sources = SourceResolver::new(env::var(SourceResolver::HEADER_ENV).ok().as_deref())
        .map_err(|_| anyhow!("{} is not a valid header name", SourceResolver::HEADER_ENV))?;
    let health = Arc::new(WorkerHealth::default());
    let (credentials, _worker, encryption_key) = match settings {
        Some(settings) => {
            let vault = Arc::new(ManagedKeyVault::from_base64_key(
                settings.encryption_key.expose(),
            )?);
            let manager: Arc<dyn OpenRouterKeyManager> =
                Arc::new(OpenRouterManagementClient::new(settings.management_key)?);
            let worker = ManagedWorker::start(pool.clone(), manager.clone(), health.clone())?;
            let clock: Clock = Arc::new(Utc::now);
            (
                Some(CredentialService::new(pool.clone(), manager, vault, clock)),
                Some(worker),
                Some(settings.encryption_key),
            )
        }
        None => (None, None, None),
    };
    let public_origin = env::var(PUBLIC_ORIGIN_ENV)
        .ok()
        .map(|origin| origin.trim().trim_end_matches('/').to_string())
        .filter(|origin| !origin.is_empty());
    let console = match (&encryption_key, &public_origin) {
        (Some(key), Some(origin)) => Some(web::Data::new(AdminState {
            service: AdminService::new(pool.clone(), key.expose(), Some(health.clone()))?,
            sources: sources.clone(),
            public_origin: origin.clone(),
            managed_configured: true,
        })),
        (Some(_), None) => {
            warn!("{PUBLIC_ORIGIN_ENV} is not set; the /admin console is disabled");
            None
        }
        _ => None,
    };
    let https = public_origin
        .as_deref()
        .is_some_and(|origin| origin.starts_with("https://"));
    let managed = web::Data::new(ManagedState {
        clients: ClientService::new(pool.clone()),
        policies: PolicyService::new(pool.clone()),
        credentials,
        sources,
    });
    let health = web::Data::new(HealthService::new(pool));
    let admission = web::Data::new(Admission::default());
    HttpServer::new(move || {
        let mut headers = DefaultHeaders::new()
            .add(("X-Content-Type-Options", "nosniff"))
            .add(("Referrer-Policy", "no-referrer"))
            .add((
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'",
            ));
        if https {
            headers = headers.add((
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains",
            ));
        }
        let app = App::new()
            .app_data(admission.clone())
            .app_data(managed.clone())
            .app_data(health.clone())
            .wrap(from_fn(admission::enforce))
            .wrap(headers)
            .configure(handler::routes);
        match console.clone() {
            Some(state) => app
                .app_data(state)
                .configure(console::routes)
                .route("/", web::get().to(console::root)),
            None => app,
        }
    })
    // Longer than the 40-second key creation, so an in-flight issuance finishes.
    .shutdown_timeout(45)
    .bind(env::var("ASYSTANT_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into()))?
    .run()
    .await?;
    Ok(())
}

/// `admin create <username>` and `admin reset <username>`: the only way to get
/// console credentials. They are printed once, here.
async fn administrators(args: &[String], database_path: &str) -> anyhow::Result<()> {
    let [action, username] = args else {
        bail!(USAGE);
    };
    let key = env::var(ManagedSettings::ENCRYPTION_KEY_ENV).map_err(|_| {
        anyhow!(
            "{} is required: it encrypts the authenticator secret",
            ManagedSettings::ENCRYPTION_KEY_ENV
        )
    })?;
    let service = AdminService::new(PoolConfig::new(database_path)?, &key, None)?;
    let credentials = match action.as_str() {
        "create" => service.create_admin(username).await?,
        "reset" => service.reset_admin(username).await?,
        _ => bail!(USAGE),
    };
    println!("Administrator: {}", credentials.username);
    println!("Password:      {}", credentials.password.expose());
    println!("Authenticator secret (base32): {}", credentials.totp_secret);
    println!("Authenticator link: {}", credentials.totp_uri);
    println!();
    println!(
        "Add the secret to your authenticator app, sign in at /admin and change the password under Security."
    );
    Ok(())
}
