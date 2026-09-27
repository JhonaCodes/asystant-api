use std::{env, sync::Arc};

use actix_web::{
    App, HttpServer,
    middleware::{DefaultHeaders, from_fn},
    web,
};
use anyhow::anyhow;
use asystant_api::{
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
        worker::ManagedWorker,
    },
    repository::PoolConfig,
};
use chrono::Utc;

/// Variables of the removed ticket/session/turn gateway. Refusing them makes a
/// deployment that still depends on that flow fail loudly instead of serving 404s.
const REMOVED_VARIABLES: [&str; 5] = [
    "ASYSTANT_PRODUCTS",
    "ASYSTANT_MODELS",
    "ASYSTANT_ORIGINS",
    "ASYSTANT_ADMIN_TOKEN",
    "OPENROUTER_API_KEY",
];

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
        anyhow::bail!(
            "{name} belongs to the removed ticket/session gateway; remove it and configure the managed-key flow (docs/managed-keys.md)"
        );
    }
    let mode = env::args().nth(1);
    if let Some(mode) = mode.as_deref()
        && mode != "--migrate-only"
        && mode != "--serve"
    {
        anyhow::bail!("usage: asystant_api [--migrate-only | --serve]");
    }
    let database_path = env::var("DATABASE_PATH").unwrap_or_else(|_| "asystant.db".into());
    if mode.as_deref() == Some("--migrate-only") {
        PoolConfig::connect(&database_path)?.migrate()?;
        return Ok(());
    }
    let pool = if mode.as_deref() == Some("--serve") {
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
    let (credentials, _worker) = match settings {
        Some(settings) => {
            let vault = Arc::new(ManagedKeyVault::from_base64_key(
                settings.encryption_key.expose(),
            )?);
            let manager: Arc<dyn OpenRouterKeyManager> =
                Arc::new(OpenRouterManagementClient::new(settings.management_key)?);
            let worker = ManagedWorker::start(pool.clone(), manager.clone())?;
            let clock: Clock = Arc::new(Utc::now);
            (
                Some(CredentialService::new(pool.clone(), manager, vault, clock)),
                Some(worker),
            )
        }
        None => (None, None),
    };
    let managed = web::Data::new(ManagedState {
        clients: ClientService::new(pool.clone()),
        policies: PolicyService::new(pool.clone()),
        credentials,
    });
    let health = web::Data::new(HealthService::new(pool));
    let admission = web::Data::new(Admission::default());
    HttpServer::new(move || {
        App::new()
            .app_data(admission.clone())
            .app_data(managed.clone())
            .app_data(health.clone())
            .wrap(from_fn(admission::enforce))
            .wrap(
                DefaultHeaders::new()
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("Referrer-Policy", "no-referrer"))
                    .add((
                        "Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'",
                    )),
            )
            .configure(handler::routes)
    })
    // Longer than the 40-second key creation, so an in-flight issuance finishes.
    .shutdown_timeout(45)
    .bind(env::var("ASYSTANT_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into()))?
    .run()
    .await?;
    Ok(())
}
