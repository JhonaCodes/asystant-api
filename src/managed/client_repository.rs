use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SelectableHelper};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::client_model::{ManagedClient, ManagedClientWorkspace};
use crate::managed::ledger_model::ManagedLeaseState;
use crate::repository::PoolConfig;
use crate::schema::managed_client_workspaces::dsl as workspaces;
use crate::schema::managed_clients::dsl as clients;
use crate::schema::managed_key_leases::dsl as leases;

pub trait ClientRepository: Send + Sync {
    fn create_client(
        &self,
        client: &ManagedClient,
        workspaces: &[ManagedClientWorkspace],
    ) -> Result<(), AppError>;
    fn active_client_by_key_hash(&self, key_hash: &str) -> Result<Option<ManagedClient>, AppError>;
    fn list_clients(&self) -> Result<Vec<ManagedClient>, AppError>;
    fn revoke_client(&self, client: Uuid, now: DateTime<Utc>) -> Result<bool, AppError>;
}

impl ClientRepository for PoolConfig {
    fn create_client(
        &self,
        client: &ManagedClient,
        assigned: &[ManagedClientWorkspace],
    ) -> Result<(), AppError> {
        // A repeated slug, key hash or a workspace already owned by another
        // client violates a unique index: Conflict, and nothing is stored.
        self.conn()?.immediate_transaction(|conn| {
            diesel::insert_into(clients::managed_clients)
                .values(client)
                .execute(conn)?;
            diesel::insert_into(workspaces::managed_client_workspaces)
                .values(assigned)
                .execute(conn)?;
            Ok(())
        })
    }

    fn active_client_by_key_hash(&self, key_hash: &str) -> Result<Option<ManagedClient>, AppError> {
        Ok(clients::managed_clients
            .filter(clients::key_hash.eq(key_hash))
            .filter(clients::revoked_at.is_null())
            .select(ManagedClient::as_select())
            .first::<ManagedClient>(&mut self.conn()?)
            .optional()?)
    }

    fn list_clients(&self) -> Result<Vec<ManagedClient>, AppError> {
        Ok(clients::managed_clients
            .order(clients::slug.asc())
            .select(ManagedClient::as_select())
            .load(&mut self.conn()?)?)
    }

    fn revoke_client(&self, client: Uuid, now: DateTime<Utc>) -> Result<bool, AppError> {
        let client_id = client.to_string();
        self.conn()?.immediate_transaction(|conn| {
            let count = diesel::update(
                clients::managed_clients
                    .filter(clients::id.eq(&client_id))
                    .filter(clients::revoked_at.is_null()),
            )
            .set(clients::revoked_at.eq(Some(now)))
            .execute(conn)?;
            if count != 1 {
                return Ok(false);
            }
            // Its live provider keys join the revocation queue at once.
            let ids = leases::managed_key_leases
                .filter(leases::client_id.eq(&client_id))
                .filter(leases::status.eq_any(ManagedLeaseState::LIVE))
                .select(leases::id)
                .load::<String>(conn)?;
            Self::revoke_leases(conn, &ids, now)?;
            Ok(true)
        })
    }
}
