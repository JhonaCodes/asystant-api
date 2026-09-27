//! SQLite-specific durability and migration contracts.
use asystant_api::repository::{HealthRepository, PoolConfig};
use diesel::{Connection, SqliteConnection, connection::SimpleConnection};

#[test]
fn migrations_are_idempotent_and_readiness_requires_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.db");
    let pool = PoolConfig::connect(path.to_str().unwrap()).unwrap();
    assert!(pool.check_ready().is_err());
    pool.migrate().unwrap();
    pool.migrate().unwrap();
    pool.check_ready().unwrap();
}

#[test]
fn migration_drops_the_removed_gateway_tables_of_a_deployed_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deployed.db");
    let mut conn = SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    // The shape a database deployed with the ticket/session gateway already has.
    conn.batch_execute(
        "CREATE TABLE __diesel_schema_migrations (version VARCHAR(50) PRIMARY KEY NOT NULL, run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
         INSERT INTO __diesel_schema_migrations (version) VALUES ('0001'), ('00000000000002');
         CREATE TABLE sessions (token_hash TEXT PRIMARY KEY NOT NULL);
         CREATE TABLE accounts (id TEXT PRIMARY KEY NOT NULL, held_micros BIGINT NOT NULL);
         CREATE TABLE admin_policy (id INTEGER PRIMARY KEY, document TEXT NOT NULL);",
    )
    .unwrap();
    drop(conn);
    let pool = PoolConfig::new(path.to_str().unwrap()).unwrap();
    pool.check_ready().unwrap();
    let mut conn = SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    for table in ["sessions", "accounts", "admin_policy"] {
        assert!(
            conn.batch_execute(&format!("SELECT * FROM {table}"))
                .is_err(),
            "{table} must be dropped"
        );
    }
}

#[test]
fn refuses_ephemeral_and_remote_database_paths() {
    for path in [
        "",
        ":memory:",
        "file:db?mode=memory",
        "postgres://localhost/db",
    ] {
        assert!(PoolConfig::connect(path).is_err());
    }
}
