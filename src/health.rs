use crate::{
    error::AppError,
    repository::{HealthRepository, PoolConfig},
};

/// Readiness: the database answers and its schema is migrated.
pub struct HealthService {
    pool: PoolConfig,
}

impl HealthService {
    pub fn new(pool: PoolConfig) -> Self {
        Self { pool }
    }

    pub async fn check_ready(&self) -> Result<(), AppError> {
        self.pool.blocking(|pool| pool.check_ready()).await
    }
}
