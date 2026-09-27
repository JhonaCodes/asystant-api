use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use log::warn;

use crate::error::AppError;
use crate::managed::ledger_model::ManagedLedgerRules;
use crate::managed::ledger_repository::ManagedLedgerRepository;
use crate::managed::model::{ManagedFailure, ManagedFailureKind, ManagedKeyAllocation, ManagedSecret};
use crate::managed::openrouter::OpenRouterKeyManager;
use crate::managed::vault::ManagedKeyVault;
use crate::repository::PoolConfig;

pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Key orchestration only. The caller must authenticate the client and
/// resolve the amount from server policies; this is not a handler.
pub struct ManagedKeyService {
    pool: PoolConfig,
    manager: Arc<dyn OpenRouterKeyManager>,
    vault: Arc<ManagedKeyVault>,
    clock: Clock,
}

impl ManagedKeyService {
    pub fn new(
        pool: PoolConfig,
        manager: Arc<dyn OpenRouterKeyManager>,
        vault: Arc<ManagedKeyVault>,
        clock: Clock,
    ) -> Self {
        Self {
            pool,
            manager,
            vault,
            clock,
        }
    }

    pub async fn provision_authorized(
        &self,
        allocation: ManagedKeyAllocation,
    ) -> Result<ManagedSecret, AppError> {
        let now = (self.clock)();
        ManagedLedgerRules::validate_allocation(&allocation, now)?;
        let request = allocation.clone();
        let reserved = self
            .ledger(move |pool| pool.reserve_managed_key(&request, now))
            .await?;
        if !reserved.lease.matches_request(&allocation)? {
            return Err(AppError::from(ManagedFailureKind::Pending));
        }
        let stored = reserved.lease.allocation()?;
        ManagedLedgerRules::validate_allocation(&stored, (self.clock)())?;
        match reserved.lease.status.as_str() {
            "issued" => {
                let hash = reserved
                    .lease
                    .key_hash
                    .as_deref()
                    .ok_or(AppError::from(ManagedFailureKind::Pending))?;
                let sealed = reserved
                    .lease
                    .api_key_sealed
                    .as_deref()
                    .ok_or(AppError::from(ManagedFailureKind::Pending))?;
                return self.vault.open(&stored, hash, sealed);
            }
            "reserved" => {}
            _ => return Err(AppError::from(ManagedFailureKind::Pending)),
        }
        let request = stored.clone();
        let now = (self.clock)();
        let claimed = self
            .ledger(move |pool| pool.claim_managed_key(&request, now))
            .await?
            .ok_or(AppError::from(ManagedFailureKind::Pending))?;
        if claimed.id != stored.id.to_string()
            || claimed.status != "provisioning"
            || !claimed.matches_request(&stored)?
        {
            return Err(AppError::from(ManagedFailureKind::Pending));
        }
        let mut stage = "create";
        let issuance = async {
            ManagedLedgerRules::validate_allocation(&stored, (self.clock)())?;
            let issued =
                tokio::time::timeout(Duration::from_secs(40), self.manager.create_key(&stored))
                    .await
                    .map_err(|_| AppError::from(ManagedFailureKind::Transport))??;
            stage = "validate";
            issued.data.validate_issued_for(&stored, (self.clock)())?;
            stage = "seal";
            let sealed = self.vault.seal(&stored, &issued.data.hash, &issued.key)?;
            let request = stored.clone();
            let data = issued.data;
            let now = (self.clock)();
            stage = "persist";
            let confirmed = self
                .ledger(move |pool| pool.confirm_managed_key(&request, &data, &sealed, now))
                .await?;
            if !confirmed {
                return Err(AppError::from(ManagedFailureKind::Pending));
            }
            ManagedLedgerRules::validate_allocation(&stored, (self.clock)())?;
            Ok(issued.key)
        }
        .await;
        match issuance {
            Ok(key) => Ok(key),
            Err(error) => {
                let now = (self.clock)();
                let failure = match stage {
                    "create" => ManagedFailure::safe(&error, ManagedFailureKind::Pending),
                    "validate" => ManagedFailure::new(ManagedFailureKind::InvalidConfirmation),
                    _ => ManagedFailure::new(ManagedFailureKind::Persistence),
                };
                warn!(
                    "Managed key issuance: allocation={} stage={} category={:?} provider_status={:?}",
                    stored.id, stage, failure.kind, failure.provider_status
                );
                // State and evidence change together. A database failure keeps
                // the durable claim and never enables another POST.
                let saved = self
                    .ledger(move |pool| pool.fail_managed_attempt(&stored, stage, failure, now))
                    .await;
                if !matches!(saved, Ok(true)) {
                    return Err(AppError::from(ManagedFailureKind::Pending));
                }
                Err(AppError::Managed(failure))
            }
        }
    }

    async fn ledger<T: Send + 'static>(
        &self,
        operation: impl FnOnce(PoolConfig) -> Result<T, AppError> + Send + 'static,
    ) -> Result<T, AppError> {
        self.pool
            .blocking_or(AppError::from(ManagedFailureKind::Pending), operation)
            .await
    }
}
