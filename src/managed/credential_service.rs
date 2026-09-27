use std::sync::Arc;

use chrono::Duration;

use crate::error::AppError;
use crate::managed::client_model::ManagedClient;
use crate::managed::key_service::{Clock, ManagedKeyService};
use crate::managed::model::{ExternalId, ManagedCredentialRequest, ManagedCredentialResponse};
use crate::managed::openrouter::OpenRouterKeyManager;
use crate::managed::policy_repository::ManagedPolicyRepository;
use crate::managed::vault::ManagedKeyVault;
use crate::repository::PoolConfig;

/// Hands a subject its provider key for the day. The client is authenticated
/// by its own key; tenant and subject come from the client's verified session.
pub struct CredentialService {
    pool: PoolConfig,
    issuer: ManagedKeyService,
    clock: Clock,
}

impl CredentialService {
    pub fn new(
        pool: PoolConfig,
        manager: Arc<dyn OpenRouterKeyManager>,
        vault: Arc<ManagedKeyVault>,
        clock: Clock,
    ) -> Self {
        let issuer = ManagedKeyService::new(pool.clone(), manager, vault, clock.clone());
        Self {
            pool,
            issuer,
            clock,
        }
    }

    pub async fn issue(
        &self,
        client: &ManagedClient,
        request: ManagedCredentialRequest,
    ) -> Result<ManagedCredentialResponse, AppError> {
        ExternalId::validate(&request.tenant)?;
        ExternalId::validate(&request.subject)?;
        let client_id = client.uuid()?;
        let now = (self.clock)();
        let (tenant, subject, bucket) = (
            request.tenant.clone(),
            request.subject.clone(),
            request.bucket,
        );
        // Resolution and claim read permissions and money again from the
        // database. No amount or identity from the request is authority.
        let allocation = self
            .pool
            .blocking(move |pool| {
                pool.resolve_managed_allocation(client_id, &tenant, &subject, bucket, now)
            })
            .await?;
        if allocation.client_id != client_id
            || allocation.tenant != request.tenant
            || allocation.subject != request.subject
            || allocation.bucket != request.bucket
        {
            return Err(AppError::Forbidden);
        }
        let expires_at = allocation.expires_at;
        let api_key = self.issuer.provision_authorized(allocation).await?;
        let now = (self.clock)();
        if expires_at <= now {
            // The allocation expired; check again.
            return Err(AppError::Conflict);
        }
        Ok(ManagedCredentialResponse {
            tenant: request.tenant,
            subject: request.subject,
            bucket: request.bucket,
            expires_at,
            refresh_after: (now + Duration::minutes(1)).min(expires_at),
            allowed_models: client.models()?,
            api_key,
        })
    }
}
