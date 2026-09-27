use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream};
use log::warn;

use crate::error::AppError;
use crate::managed::ledger_model::ManagedKeyLease;
use crate::managed::model::{ManagedFailure, ManagedFailureKind, OpenRouterManagedKeyData};
use crate::managed::openrouter::OpenRouterKeyManager;
use crate::managed::reconciliation_repository::{ManagedRevocationRepository, ManagedUsageRepository};
use crate::repository::PoolConfig;

const CONCURRENCY: usize = 8;
const MAX_LISTED_KEYS: usize = 10_000;

/// Paginated sweep by identity, not by the offset of rows that keep leaving.
/// One failure does not stop the other leases; it stays durable and is
/// reported once the whole sweep finishes. Returns how many were confirmed.
async fn sweep<Page, PageFuture, Visit, VisitFuture>(
    page: Page,
    visit: Visit,
) -> Result<usize, AppError>
where
    Page: Fn(String) -> PageFuture,
    PageFuture: Future<Output = Result<Vec<ManagedKeyLease>, AppError>>,
    Visit: Fn(ManagedKeyLease) -> VisitFuture,
    VisitFuture: Future<Output = Result<bool, AppError>>,
{
    let mut after = String::new();
    let mut confirmed = 0;
    let mut failed = false;
    loop {
        let pending = page(after.clone()).await?;
        let Some(last) = pending.last() else {
            break;
        };
        if last.id <= after {
            return Err(AppError::from(ManagedFailureKind::Pending));
        }
        after = last.id.clone();
        let observations = stream::iter(pending)
            .map(&visit)
            .buffer_unordered(CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        for observation in observations {
            match observation {
                Ok(true) => confirmed += 1,
                Ok(false) => {}
                Err(_) => failed = true,
            }
        }
    }
    if failed {
        return Err(AppError::from(ManagedFailureKind::Pending));
    }
    Ok(confirmed)
}

pub struct RevocationService {
    pool: PoolConfig,
    manager: Arc<dyn OpenRouterKeyManager>,
}

impl RevocationService {
    pub fn new(pool: PoolConfig, manager: Arc<dyn OpenRouterKeyManager>) -> Self {
        Self { pool, manager }
    }

    pub async fn reconcile_pending(&self, now: DateTime<Utc>) -> Result<usize, AppError> {
        sweep(
            |after| {
                self.pool.blocking_or(AppError::from(ManagedFailureKind::Pending), move |pool| {
                    pool.pending_managed_revocations(&after, now)
                })
            },
            |lease| async move {
                let id = lease.id.clone();
                let result = self.revoke(lease, now).await;
                if let Err(error) = &result {
                    let failure = ManagedFailure::safe(error, ManagedFailureKind::Persistence);
                    warn!(
                        "Managed key reconciliation: allocation={} category={:?} provider_status={:?}",
                        id, failure.kind, failure.provider_status
                    );
                }
                result
            },
        )
        .await
    }

    pub async fn revoke(
        &self,
        lease: ManagedKeyLease,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        if lease.status != "revocation_pending" {
            return Err(AppError::from(ManagedFailureKind::Pending));
        }
        let allocation = lease.allocation()?;
        let keys = if let Some(hash) = &lease.key_hash {
            vec![
                self.manager
                    .get_key(hash)
                    .await
                    .map_err(Self::provider_failure)?,
            ]
        } else {
            let mut matches = Vec::new();
            let mut seen = HashSet::new();
            let mut offset = 0;
            loop {
                let page = self
                    .manager
                    .list_keys(allocation.workspace_id, offset)
                    .await
                    .map_err(Self::provider_failure)?;
                if page.is_empty() {
                    break;
                }
                offset += page.len();
                // A provider that ignores offset cannot cause an endless loop.
                if offset > MAX_LISTED_KEYS {
                    return Err(AppError::from(ManagedFailureKind::Pagination));
                }
                for key in page {
                    if key.workspace_id != Some(allocation.workspace_id) {
                        return Err(AppError::from(ManagedFailureKind::Identity));
                    }
                    if !seen.insert(key.hash.clone()) {
                        return Err(AppError::from(ManagedFailureKind::Pagination));
                    }
                    if key.name == allocation.provider_name() {
                        matches.push(key);
                    }
                }
            }
            matches
        };
        // Not finding it yet does NOT prove the POST never happened.
        let Some(hash) = keys.first().map(|key| key.hash.clone()) else {
            return Err(AppError::from(ManagedFailureKind::NotFound));
        };
        let key_count = keys.len();
        for key in keys {
            if (lease.key_hash.is_none() && key.name != allocation.provider_name())
                || key.workspace_id != Some(allocation.workspace_id)
                || lease
                    .key_hash
                    .as_ref()
                    .is_some_and(|hash| *hash != key.hash)
            {
                return Err(AppError::from(ManagedFailureKind::Identity));
            }
            OpenRouterManagedKeyData::validate_hash(&key.hash)?;
            let disabled = self
                .manager
                .disable_key(&key.hash)
                .await
                .map_err(Self::provider_failure)?;
            if !disabled.disabled
                || disabled.hash != key.hash
                || disabled.workspace_id != key.workspace_id
            {
                return Err(AppError::from(ManagedFailureKind::InvalidConfirmation));
            }
        }
        // All of them are disabled, but several keys need per-key accounting
        // before a single allocation can be confirmed.
        if key_count != 1 {
            return Err(AppError::from(ManagedFailureKind::MultipleKeys));
        }
        self.pool
            .blocking_or(AppError::from(ManagedFailureKind::Pending), move |pool| {
                pool.confirm_managed_revocation(&lease, &hash, now)
            })
            .await
    }

    fn provider_failure(error: AppError) -> AppError {
        AppError::Managed(ManagedFailure::safe(&error, ManagedFailureKind::Transport))
    }
}

pub struct UsageService {
    pool: PoolConfig,
    manager: Arc<dyn OpenRouterKeyManager>,
}

impl UsageService {
    pub fn new(pool: PoolConfig, manager: Arc<dyn OpenRouterKeyManager>) -> Self {
        Self { pool, manager }
    }

    pub async fn reconcile(&self, now: DateTime<Utc>) -> Result<usize, AppError> {
        sweep(
            |after| {
                self.pool
                    .blocking_or(AppError::from(ManagedFailureKind::Pending), move |pool| {
                        pool.managed_usage_candidates(&after, now)
                    })
            },
            |lease| async move { self.observe(lease, now).await.map(|()| true) },
        )
        .await
    }

    async fn observe(&self, lease: ManagedKeyLease, now: DateTime<Utc>) -> Result<(), AppError> {
        let hash = lease
            .key_hash
            .as_deref()
            .ok_or(AppError::from(ManagedFailureKind::Pending))?;
        let observation = self
            .manager
            .get_key(hash)
            .await
            .map_err(|_| AppError::from(ManagedFailureKind::Pending))?;
        self.pool
            .blocking_or(AppError::from(ManagedFailureKind::Pending), move |pool| {
                pool.record_managed_usage(&lease, &observation, now)
            })
            .await
    }
}
