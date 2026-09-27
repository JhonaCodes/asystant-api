use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use log::warn;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};

use crate::error::AppError;
use crate::managed::openrouter::OpenRouterKeyManager;
use crate::managed::reconciliation_service::{RevocationService, UsageService};
use crate::repository::PoolConfig;

/// Pending work lives in SQLite. This process does not own the queue and can
/// restart: PATCH disabled=true and its confirmation are idempotent.
pub struct ManagedWorker {
    revocation_task: JoinHandle<()>,
    usage_task: JoinHandle<()>,
}

impl ManagedWorker {
    pub const REVOCATION_INTERVAL: Duration = Duration::from_secs(15);
    pub const USAGE_INTERVAL: Duration = Duration::from_secs(60);

    pub fn start(
        pool: PoolConfig,
        manager: Arc<dyn OpenRouterKeyManager>,
    ) -> Result<Self, AppError> {
        let runtime = Handle::try_current().map_err(|_| AppError::Internal)?;
        let usage = UsageService::new(pool.clone(), manager.clone());
        let revocation = RevocationService::new(pool, manager);
        let revocation_task = runtime.spawn(async move {
            let mut schedule = interval(Self::REVOCATION_INTERVAL);
            schedule.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                schedule.tick().await;
                if revocation.reconcile_pending(Utc::now()).await.is_err() {
                    // Never log OpenRouter bodies nor secrets.
                    warn!(
                        "Managed keys keep pending revocations; remote confirmation will be retried"
                    );
                }
            }
        });
        // Usage history never holds the revocation worker back.
        let usage_task = runtime.spawn(async move {
            let mut schedule = interval(Self::USAGE_INTERVAL);
            schedule.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                schedule.tick().await;
                if usage.reconcile(Utc::now()).await.is_err() {
                    warn!("Managed keys keep usage pending reconciliation; no balance is invented");
                }
            }
        });
        Ok(Self {
            revocation_task,
            usage_task,
        })
    }
}

impl Drop for ManagedWorker {
    fn drop(&mut self) {
        self.revocation_task.abort();
        self.usage_task.abort();
    }
}
