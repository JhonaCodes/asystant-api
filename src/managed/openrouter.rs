use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, Method, Request, RequestBuilder, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::model::{
    ManagedFailure, ManagedFailureKind, ManagedKeyAllocation, ManagedSecret, OpenRouterIssuedKey,
    OpenRouterManagedKeyData, OpenRouterManagedKeyEnvelope,
};

const MANAGEMENT_URL: &str = "https://openrouter.ai/api/v1/keys";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Administration only: this contract cannot run inference.
#[async_trait]
pub trait OpenRouterKeyManager: Send + Sync {
    async fn create_key(
        &self,
        allocation: &ManagedKeyAllocation,
    ) -> Result<OpenRouterIssuedKey, AppError>;
    async fn get_key(&self, hash: &str) -> Result<OpenRouterManagedKeyData, AppError>;
    async fn disable_key(&self, hash: &str) -> Result<OpenRouterManagedKeyData, AppError>;
    async fn list_keys(
        &self,
        workspace_id: Uuid,
        offset: usize,
    ) -> Result<Vec<OpenRouterManagedKeyData>, AppError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedKeyList {
    data: Vec<OpenRouterManagedKeyData>,
}

pub struct OpenRouterManagementClient {
    client: Client,
    credential: ManagedSecret,
}

impl OpenRouterManagementClient {
    pub fn new(credential: ManagedSecret) -> Result<Self, AppError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| AppError::Internal)?;
        Ok(Self { client, credential })
    }

    /// Pure constructor, so the contract can be verified without creating keys.
    pub fn create_key_request(
        &self,
        allocation: &ManagedKeyAllocation,
        now: DateTime<Utc>,
    ) -> Result<Request, AppError> {
        allocation.validate(now)?;
        self.request(Method::POST, MANAGEMENT_URL)?
            .json(&json!({
                "name": allocation.provider_name(),
                "limit": allocation.limit_usd(),
                "limit_reset": null,
                "include_byok_in_limit": true,
                "expires_at": allocation.expires_at.to_rfc3339_opts(SecondsFormat::AutoSi, true),
                "workspace_id": allocation.workspace_id,
            }))
            .build()
            .map_err(|_| Self::request_error())
    }

    pub fn get_key_request(&self, hash: &str) -> Result<Request, AppError> {
        OpenRouterManagedKeyData::validate_hash(hash)?;
        self.request(Method::GET, &format!("{MANAGEMENT_URL}/{hash}"))?
            .build()
            .map_err(|_| Self::request_error())
    }

    pub fn disable_key_request(&self, hash: &str) -> Result<Request, AppError> {
        OpenRouterManagedKeyData::validate_hash(hash)?;
        self.request(Method::PATCH, &format!("{MANAGEMENT_URL}/{hash}"))?
            .json(&json!({ "disabled": true }))
            .build()
            .map_err(|_| Self::request_error())
    }

    pub fn list_keys_request(
        &self,
        workspace_id: Uuid,
        offset: usize,
    ) -> Result<Request, AppError> {
        if workspace_id.is_nil() {
            return Err(AppError::Invalid);
        }
        let mut url = Url::parse(MANAGEMENT_URL).map_err(|_| Self::request_error())?;
        url.query_pairs_mut()
            .append_pair("workspace_id", &workspace_id.to_string())
            .append_pair("offset", &offset.to_string())
            .append_pair("include_disabled", "true");
        self.request(Method::GET, url.as_str())?
            .build()
            .map_err(|_| Self::request_error())
    }

    fn request(&self, method: Method, url: &str) -> Result<RequestBuilder, AppError> {
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {}", self.credential.expose()))
                .map_err(|_| AppError::from(ManagedFailureKind::Configuration))?;
        authorization.set_sensitive(true);
        Ok(self
            .client
            .request(method, url)
            .header(AUTHORIZATION, authorization))
    }

    async fn execute<T: DeserializeOwned>(&self, request: Request) -> Result<T, AppError> {
        // Never retry POST: a timeout can hide a created key. The service must
        // reconcile the reservation before provisioning again.
        let mut response = self
            .client
            .execute(request)
            .await
            .map_err(|_| AppError::from(ManagedFailureKind::Transport))?;
        if !response.status().is_success() {
            // Never read nor propagate the body: it may reflect credentials.
            return Err(AppError::Managed(ManagedFailure::from_http(
                response.status().as_u16(),
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Self::request_error())? {
            if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
                return Err(Self::request_error());
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| Self::request_error())
    }

    fn request_error() -> AppError {
        AppError::from(ManagedFailureKind::InvalidConfirmation)
    }
}

#[async_trait]
impl OpenRouterKeyManager for OpenRouterManagementClient {
    async fn create_key(
        &self,
        allocation: &ManagedKeyAllocation,
    ) -> Result<OpenRouterIssuedKey, AppError> {
        let issued: OpenRouterIssuedKey = self
            .execute(self.create_key_request(allocation, Utc::now())?)
            .await?;
        // A failure stays pending reconciliation by provider_name: never repeat
        // the POST nor release the reservation on an incomplete confirmation.
        issued
            .data
            .validate_issued_for(allocation, Utc::now())
            .map_err(|_| Self::request_error())?;
        Ok(issued)
    }

    async fn get_key(&self, hash: &str) -> Result<OpenRouterManagedKeyData, AppError> {
        let envelope: OpenRouterManagedKeyEnvelope =
            self.execute(self.get_key_request(hash)?).await?;
        if envelope.data.hash != hash || envelope.data.confirmed_usage_micros().is_err() {
            return Err(Self::request_error());
        }
        Ok(envelope.data)
    }

    async fn disable_key(&self, hash: &str) -> Result<OpenRouterManagedKeyData, AppError> {
        let envelope: OpenRouterManagedKeyEnvelope =
            self.execute(self.disable_key_request(hash)?).await?;
        if !envelope.data.disabled || envelope.data.hash != hash {
            return Err(Self::request_error());
        }
        Ok(envelope.data)
    }

    async fn list_keys(
        &self,
        workspace_id: Uuid,
        offset: usize,
    ) -> Result<Vec<OpenRouterManagedKeyData>, AppError> {
        let envelope: ManagedKeyList = self
            .execute(self.list_keys_request(workspace_id, offset)?)
            .await?;
        for key in &envelope.data {
            OpenRouterManagedKeyData::validate_hash(&key.hash)
                .map_err(|_| Self::request_error())?;
            if key.workspace_id != Some(workspace_id) {
                return Err(AppError::from(ManagedFailureKind::Identity));
            }
            key.confirmed_usage_micros()
                .map_err(|_| Self::request_error())?;
        }
        Ok(envelope.data)
    }
}
