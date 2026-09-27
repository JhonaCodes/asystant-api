use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use log::warn;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};

use crate::error::AppError;
use crate::managed::openrouter::OpenRouterKeyManager;
use crate::managed::reconciliation_service::{RevocationService, UsageService};
use crate::repository::PoolConfig;

/// Last time each sweep finished without errors, for the operator console.
/// Zero means "not yet".
#[derive(Debug, Default)]
pub struct WorkerHealth {
    revocation_ok: AtomicI64,
    usage_ok: AtomicI64,
}

impl WorkerHealth {
    pub fn last_revocation(&self) -> Option<DateTime<Utc>> {
        Self::read(&self.revocation_ok)
    }

    pub fn last_usage(&self) -> Option<DateTime<Utc>> {
        Self::read(&self.usage_ok)
    }

    fn read(value: &AtomicI64) -> Option<DateTime<Utc>> {
        match value.load(Ordering::Relaxed) {
            0 => None,
            seconds => DateTime::from_timestamp(seconds, 0),
        }
    }

    fn mark(value: &AtomicI64) {
        value.store(Utc::now().timestamp(), Ordering::Relaxed);
    }
}

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
        health: Arc<WorkerHealth>,
    ) -> Result<Self, AppError> {
        let runtime = Handle::try_current().map_err(|_| AppError::Internal)?;
        let usage = UsageService::new(pool.clone(), manager.clone());
        let revocation = RevocationService::new(pool, manager);
        let revocation_health = health.clone();
        let revocation_task = runtime.spawn(async move {
            let mut schedule = interval(Self::REVOCATION_INTERVAL);
            schedule.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                schedule.tick().await;
                match revocation.reconcile_pending(Utc::now()).await {
                    Ok(_) => WorkerHealth::mark(&revocation_health.revocation_ok),
                    // Never log OpenRouter bodies nor secrets.
                    Err(_) => warn!(
                        "Managed keys keep pending revocations; remote confirmation will be retried"
                    ),
                }
            }
        });
        // Usage history never holds the revocation worker back.
        let usage_task = runtime.spawn(async move {
            let mut schedule = interval(Self::USAGE_INTERVAL);
            schedule.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                schedule.tick().await;
                match usage.reconcile(Utc::now()).await {
                    Ok(_) => WorkerHealth::mark(&health.usage_ok),
                    Err(_) => warn!(
                        "Managed keys keep usage pending reconciliation; no balance is invented"
                    ),
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
