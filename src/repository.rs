use std::time::Duration;

use diesel::{
    connection::SimpleConnection,
    prelude::*,
    r2d2::{ConnectionManager, CustomizeConnection, Pool, PooledConnection},
};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

use crate::{error::AppError, schema::managed_clients};

/// Apply connection-local guarantees on every pooled SQLite connection.
#[derive(Debug)]
struct SqlitePragmas;
impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqlitePragmas {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        conn.batch_execute(
            "PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;",
        )
        .map_err(diesel::r2d2::Error::QueryError)
    }
}

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();
#[derive(Clone)]
pub struct PoolConfig {
    pool: Pool<ConnectionManager<SqliteConnection>>,
}
impl PoolConfig {
    pub fn new(url: &str) -> anyhow::Result<Self> {
        let config = Self::connect(url)?;
        config.migrate()?;
        Ok(config)
    }
    pub fn connect(path: &str) -> anyhow::Result<Self> {
        // Durable files only: separate pooled :memory: databases break accounting.
        anyhow::ensure!(
            !path.is_empty()
                && !path.contains("://")
                && !path.starts_with("file:")
                && path != ":memory:",
            "DATABASE_PATH must point to a local persistent SQLite file"
        );
        let mut initial = SqliteConnection::establish(path)?;
        initial.batch_execute("PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;")?;
        let pool = Pool::builder()
            .max_size(8)
            .connection_timeout(Duration::from_secs(6))
            .connection_customizer(Box::new(SqlitePragmas))
            .build(ConnectionManager::new(path))?;
        Ok(Self { pool })
    }
    pub fn migrate(&self) -> anyhow::Result<()> {
        self.conn()?
            .run_pending_migrations(MIGRATIONS)
            .map_err(|_| anyhow::anyhow!("migration failed"))?;
        Ok(())
    }
    pub(crate) fn conn(
        &self,
    ) -> Result<PooledConnection<ConnectionManager<SqliteConnection>>, AppError> {
        self.pool.get().map_err(|_| AppError::Internal)
    }
    /// Runs blocking Diesel work off the async runtime.
    pub async fn blocking<T: Send + 'static>(
        &self,
        operation: impl FnOnce(PoolConfig) -> Result<T, AppError> + Send + 'static,
    ) -> Result<T, AppError> {
        self.blocking_or(AppError::Internal, operation).await
    }
    /// Same as `blocking`, with the error to report when the worker thread dies.
    pub async fn blocking_or<T: Send + 'static>(
        &self,
        join_error: AppError,
        operation: impl FnOnce(PoolConfig) -> Result<T, AppError> + Send + 'static,
    ) -> Result<T, AppError> {
        let pool = self.clone();
        tokio::task::spawn_blocking(move || operation(pool))
            .await
            .map_err(|_| join_error)?
    }
}

pub trait HealthRepository {
    fn check_ready(&self) -> Result<(), AppError>;
}
impl HealthRepository for PoolConfig {
    fn check_ready(&self) -> Result<(), AppError> {
        let mut conn = self
            .pool
            .get_timeout(Duration::from_secs(2))
            .map_err(|_| AppError::Internal)?;
        // A real schema query detects a reachable but unmigrated database.
        managed_clients::table
            .select(managed_clients::id)
            .limit(1)
            .load::<String>(&mut conn)?;
        Ok(())
    }
}
