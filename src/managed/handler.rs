use actix_web::http::header::AUTHORIZATION;
use actix_web::web::{self, Data, Json, Path, ServiceConfig};
use actix_web::{HttpRequest, HttpResponse};
use serde::Serialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::client_model::ManagedClient;
use crate::managed::client_service::ClientService;
use crate::managed::credential_service::CredentialService;
use crate::managed::model::{ManagedCredentialRequest, ManagedFailureKind};
use crate::managed::policy_model::{ManagedRecoveryRequest, SubjectBudgetRequest, TenantBudgetRequest};
use crate::managed::policy_service::PolicyService;

/// Maximum JSON body of a managed request.
pub const REQUEST_LIMIT: usize = 64 * 1024;

/// Services behind `/v1/managed`. `credentials` is `None` when the OpenRouter
/// management settings are not configured.
pub struct ManagedState {
    pub clients: ClientService,
    pub policies: PolicyService,
    pub credentials: Option<CredentialService>,
}

async fn client(request: &HttpRequest, state: &ManagedState) -> Result<ManagedClient, AppError> {
    let key = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(AppError::Authentication)?;
    state.clients.authenticate(key).await
}

fn no_store(body: &impl Serialize) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(body)
}

async fn issue_credential(
    request: HttpRequest,
    state: Data<ManagedState>,
    input: Json<ManagedCredentialRequest>,
) -> Result<HttpResponse, AppError> {
    let client = client(&request, &state).await?;
    let credentials = state
        .credentials
        .as_ref()
        .ok_or(AppError::from(ManagedFailureKind::Configuration))?;
    Ok(no_store(
        &credentials.issue(&client, input.into_inner()).await?,
    ))
}

async fn tenant_budget(
    request: HttpRequest,
    state: Data<ManagedState>,
    tenant: Path<String>,
) -> Result<HttpResponse, AppError> {
    let client = client(&request, &state).await?;
    Ok(no_store(
        &state
            .policies
            .overview(&client, tenant.into_inner())
            .await?,
    ))
}

async fn set_tenant_budget(
    request: HttpRequest,
    state: Data<ManagedState>,
    tenant: Path<String>,
    input: Json<TenantBudgetRequest>,
) -> Result<HttpResponse, AppError> {
    let client = client(&request, &state).await?;
    Ok(no_store(
        &state
            .policies
            .set_tenant(&client, tenant.into_inner(), input.into_inner())
            .await?,
    ))
}

async fn set_subject_budget(
    request: HttpRequest,
    state: Data<ManagedState>,
    path: Path<(String, String)>,
    input: Json<SubjectBudgetRequest>,
) -> Result<HttpResponse, AppError> {
    let client = client(&request, &state).await?;
    let (tenant, subject) = path.into_inner();
    Ok(no_store(
        &state
            .policies
            .set_subject(&client, tenant, subject, input.into_inner())
            .await?,
    ))
}

async fn authorize_recovery(
    request: HttpRequest,
    state: Data<ManagedState>,
    path: Path<(String, Uuid)>,
    input: Json<ManagedRecoveryRequest>,
) -> Result<HttpResponse, AppError> {
    let client = client(&request, &state).await?;
    let (tenant, lease) = path.into_inner();
    Ok(no_store(
        &state
            .policies
            .authorize_recovery(&client, tenant, lease, input.into_inner())
            .await?,
    ))
}

pub fn routes(config: &mut ServiceConfig) {
    // Extraction failures answer like any other error: JSON body and no-store.
    config
        .app_data(
            web::JsonConfig::default()
                .limit(REQUEST_LIMIT)
                .error_handler(|_, _| AppError::Invalid.into()),
        )
        .app_data(web::PathConfig::default().error_handler(|_, _| AppError::Invalid.into()))
        .route("/credentials", web::post().to(issue_credential))
        .route("/tenants/{tenant}/budget", web::get().to(tenant_budget))
        .route("/tenants/{tenant}/budget", web::put().to(set_tenant_budget))
        .route(
            "/tenants/{tenant}/subjects/{subject}/budget",
            web::put().to(set_subject_budget),
        )
        .route(
            "/tenants/{tenant}/leases/{lease}/recovery",
            web::post().to(authorize_recovery),
        );
}
