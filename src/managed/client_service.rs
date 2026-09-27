use chrono::Utc;
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::client_model::{
    ClientKey, CreatedClient, ManagedClient, ManagedClientWorkspace, NewClientRequest,
};
use crate::managed::client_repository::ClientRepository;
use crate::repository::PoolConfig;

/// Creates the companies or services that integrate with the API and
/// authenticates their calls by key.
pub struct ClientService {
    pool: PoolConfig,
}

impl ClientService {
    pub fn new(pool: PoolConfig) -> Self {
        Self { pool }
    }

    /// The returned key is the only time it exists in plaintext.
    pub async fn create(&self, request: NewClientRequest) -> Result<CreatedClient, AppError> {
        request.validate()?;
        let api_key = ClientKey::generate()?;
        let now = Utc::now();
        let client = ManagedClient {
            id: Uuid::new_v4().to_string(),
            slug: request.slug.clone(),
            name: request.name.trim().to_string(),
            key_hash: ClientKey::hash(api_key.expose()),
            allowed_models: serde_json::to_string(&request.models())
                .map_err(|_| AppError::Internal)?,
            created_at: now,
            revoked_at: None,
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
        Ok(CreatedClient {
            client,
            workspaces: request.workspaces,
            api_key,
        })
    }

    pub async fn authenticate(&self, key: &str) -> Result<ManagedClient, AppError> {
        if !ClientKey::is_well_formed(key) {
            return Err(AppError::Authentication);
        }
        let hash = ClientKey::hash(key);
        self.pool
            .blocking(move |pool| pool.active_client_by_key_hash(&hash))
            .await?
            .ok_or(AppError::Authentication)
    }

    pub async fn list(&self) -> Result<Vec<ManagedClient>, AppError> {
        self.pool.blocking(|pool| pool.list_clients()).await
    }

    /// Revoking also queues every live provider key of the client.
    pub async fn revoke(&self, client: Uuid) -> Result<bool, AppError> {
        self.pool
            .blocking(move |pool| pool.revoke_client(client, Utc::now()))
            .await
    }
}
