use std::net::IpAddr;

use chrono::Utc;
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::client_model::{
    AuthenticatedClient, ClientKey, ClientSettings, CreatedKey, KeyPermission, ManagedClient,
    ManagedClientKey, ManagedClientWorkspace, NewClientRequest, NewKeyRequest, SourceRange,
};
use crate::managed::client_repository::ClientRepository;
use crate::repository::PoolConfig;

/// Companies or services that integrate with the API, their API keys, and the
/// authentication of every call they make.
pub struct ClientService {
    pool: PoolConfig,
}

impl ClientService {
    pub fn new(pool: PoolConfig) -> Self {
        Self { pool }
    }

    pub async fn create(&self, request: NewClientRequest) -> Result<ManagedClient, AppError> {
        request.validate()?;
        let now = Utc::now();
        let client = ManagedClient {
            id: Uuid::new_v4().to_string(),
            slug: request.slug.clone(),
            name: request.name.trim().to_string(),
            allowed_models: serde_json::to_string(&request.models())
                .map_err(|_| AppError::Internal)?,
            contact: request.contact.clone(),
            daily_cap_usd_micros: request.daily_cap_usd_micros,
            created_at: now,
            suspended_at: None,
        };
        let assigned = request
            .workspaces
            .iter()
            .map(|workspace| ManagedClientWorkspace {
                workspace_id: workspace.to_string(),
                client_id: client.id.clone(),
                created_at: now,
            })
            .collect::<Vec<_>>();
        let stored = client.clone();
        self.pool
            .blocking(move |pool| pool.create_client(&stored, &assigned))
            .await?;
        Ok(client)
    }

    /// The returned key is the only time it exists in plaintext.
    pub async fn create_key(
        &self,
        client: &ManagedClient,
        request: NewKeyRequest,
    ) -> Result<CreatedKey, AppError> {
        request.validate()?;
        let now = Utc::now();
        let api_key = ClientKey::generate()?;
        let sources = request
            .allowed_sources
            .iter()
            .map(SourceRange::render)
            .collect::<Vec<_>>();
        let key = ManagedClientKey {
            id: Uuid::new_v4().to_string(),
            client_id: client.id.clone(),
            label: request.label.trim().to_string(),
            display_prefix: ClientKey::display_prefix(api_key.expose()),
            display_suffix: ClientKey::display_suffix(api_key.expose()),
            key_hash: ClientKey::hash(api_key.expose()),
            can_issue: request.can_issue,
            can_manage: request.can_manage,
            allowed_sources: serde_json::to_string(&sources).map_err(|_| AppError::Internal)?,
            created_by: request.created_by.clone(),
            created_at: now,
            expires_at: request.expires_at(now),
            replaced_by: None,
            revoked_at: None,
            last_used_at: None,
            last_used_source: None,
        };
        let stored = key.clone();
        let replaces = request.replaces;
        self.pool
            .blocking(move |pool| pool.create_key(&stored, replaces, now))
            .await?;
        Ok(CreatedKey { key, api_key })
    }

    /// Resolves the client of a call. A key limited to source ranges refuses
    /// any other address, and an unknown address.
    pub async fn authenticate(
        &self,
        key: &str,
        permission: KeyPermission,
        source: Option<IpAddr>,
    ) -> Result<AuthenticatedClient, AppError> {
        if !ClientKey::is_well_formed(key) {
            return Err(AppError::Authentication);
        }
        let hash = ClientKey::hash(key);
        let now = Utc::now();
        let (client, key) = self
            .pool
            .blocking(move |pool| pool.active_key(&hash, now))
            .await?
            .ok_or(AppError::Authentication)?;
        let ranges = key.sources()?;
        if !ranges.is_empty()
            && !source.is_some_and(|address| ranges.iter().any(|range| range.contains(address)))
        {
            return Err(AppError::Forbidden);
        }
        if !key.permits(permission) {
            return Err(AppError::Forbidden);
        }
        let key_id = key.id.clone();
        let seen_from = source.map_or_else(|| "unknown".to_string(), |address| address.to_string());
        self.pool
            .blocking(move |pool| pool.touch_key(&key_id, &seen_from, now))
            .await?;
        Ok(AuthenticatedClient {
            client,
            key_id: key.id,
        })
    }

    pub async fn by_slug(&self, slug: &str) -> Result<ManagedClient, AppError> {
        let slug = slug.to_string();
        self.pool
            .blocking(move |pool| pool.client_by_slug(&slug))
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn list(&self) -> Result<Vec<ManagedClient>, AppError> {
        self.pool.blocking(|pool| pool.list_clients()).await
    }

    pub async fn keys(&self, client: &ManagedClient) -> Result<Vec<ManagedClientKey>, AppError> {
        let client = client.uuid()?;
        self.pool
            .blocking(move |pool| pool.client_keys(client))
            .await
    }

    pub async fn workspaces(
        &self,
        client: &ManagedClient,
    ) -> Result<Vec<ManagedClientWorkspace>, AppError> {
        let client = client.uuid()?;
        self.pool
            .blocking(move |pool| pool.client_workspaces(client))
            .await
    }

    pub async fn update(
        &self,
        client: &ManagedClient,
        settings: ClientSettings,
    ) -> Result<(), AppError> {
        settings.validate()?;
        let client = client.uuid()?;
        self.pool
            .blocking(move |pool| pool.update_client(client, &settings))
            .await
    }

    pub async fn add_workspace(
        &self,
        client: &ManagedClient,
        workspace: Uuid,
    ) -> Result<(), AppError> {
        if workspace.is_nil() {
            return Err(AppError::Invalid);
        }
        let assigned = ManagedClientWorkspace {
            workspace_id: workspace.to_string(),
            client_id: client.id.clone(),
            created_at: Utc::now(),
        };
        self.pool
            .blocking(move |pool| pool.add_workspace(&assigned))
            .await
    }

    pub async fn remove_workspace(
        &self,
        client: &ManagedClient,
        workspace: Uuid,
    ) -> Result<bool, AppError> {
        let client = client.uuid()?;
        self.pool
            .blocking(move |pool| pool.remove_workspace(client, workspace))
            .await
    }

    pub async fn revoke_key(&self, client: &ManagedClient, key: Uuid) -> Result<bool, AppError> {
        let client = client.uuid()?;
        self.pool
            .blocking(move |pool| pool.revoke_key(client, key, Utc::now()))
            .await
    }

    /// Rejects every API key of the client and queues its live provider keys.
    pub async fn suspend(&self, client: &ManagedClient) -> Result<bool, AppError> {
        let client = client.uuid()?;
        self.pool
            .blocking(move |pool| pool.suspend_client(client, Utc::now()))
            .await
    }

    pub async fn reactivate(&self, client: &ManagedClient) -> Result<bool, AppError> {
        let client = client.uuid()?;
        self.pool
            .blocking(move |pool| pool.reactivate_client(client))
            .await
    }
}
