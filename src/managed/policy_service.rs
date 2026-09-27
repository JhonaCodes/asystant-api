use chrono::Utc;
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::client_model::ManagedClient;
use crate::managed::ledger_model::{OWNER_SUBJECT, OWNER_TENANT};
use crate::managed::model::ExternalId;
use crate::managed::policy_model::{
    ManagedBudgetOverview, ManagedPolicy, ManagedPolicyChange, ManagedRecovery,
    ManagedRecoveryRequest, SubjectBudgetRequest, TenantBudgetRequest,
};
use crate::managed::policy_repository::ManagedPolicyRepository;
use crate::managed::recovery_repository::ManagedRecoveryRepository;
use crate::repository::PoolConfig;

/// Budget administration of one client over its own tenants and subjects.
/// Every call is scoped by the authenticated client, never by the request.
pub struct PolicyService {
    pool: PoolConfig,
}

impl PolicyService {
    pub fn new(pool: PoolConfig) -> Self {
        Self { pool }
    }

    pub async fn overview(
        &self,
        client: &ManagedClient,
        tenant: String,
    ) -> Result<ManagedBudgetOverview, AppError> {
        ExternalId::validate(&tenant)?;
        let client = client.uuid()?;
        self.pool
            .blocking(move |pool| pool.managed_budget_overview(client, &tenant, Utc::now()))
            .await
    }

    pub async fn set_tenant(
        &self,
        client: &ManagedClient,
        tenant: String,
        request: TenantBudgetRequest,
    ) -> Result<ManagedPolicy, AppError> {
        self.save(ManagedPolicyChange {
            client_id: client.uuid()?,
            owner_kind: OWNER_TENANT.to_string(),
            owner_id: tenant.clone(),
            tenant,
            workspace_id: Some(request.workspace_id),
            bucket: request.bucket,
            limit_usd_micros: request.limit_usd_micros,
            actor: request.actor,
        })
        .await
    }

    pub async fn set_subject(
        &self,
        client: &ManagedClient,
        tenant: String,
        subject: String,
        request: SubjectBudgetRequest,
    ) -> Result<ManagedPolicy, AppError> {
        self.save(ManagedPolicyChange {
            client_id: client.uuid()?,
            tenant,
            owner_kind: OWNER_SUBJECT.to_string(),
            owner_id: subject,
            workspace_id: None,
            bucket: request.bucket,
            limit_usd_micros: request.limit_usd_micros,
            actor: request.actor,
        })
        .await
    }

    pub async fn authorize_recovery(
        &self,
        client: &ManagedClient,
        tenant: String,
        previous: Uuid,
        request: ManagedRecoveryRequest,
    ) -> Result<ManagedRecovery, AppError> {
        ExternalId::validate(&tenant)?;
        request.validate()?;
        let client = client.uuid()?;
        self.pool
            .blocking(move |pool| {
                pool.authorize_managed_recovery(client, &tenant, previous, &request, Utc::now())
            })
            .await
    }

    async fn save(&self, change: ManagedPolicyChange) -> Result<ManagedPolicy, AppError> {
        change.validate()?;
        self.pool
            .blocking(move |pool| pool.set_managed_policy(&change, Utc::now()))
            .await
    }
}
