use chrono::{DateTime, Duration, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl,
    SelectableHelper, SqliteConnection,
};
use uuid::Uuid;

use crate::error::AppError;
use crate::managed::client_model::{
    ClientSettings, ManagedClient, ManagedClientKey, ManagedClientWorkspace, NewKeyRequest,
};
use crate::managed::ledger_model::{ManagedLeaseState, OWNER_TENANT};
use crate::repository::PoolConfig;
use crate::schema::managed_client_keys::dsl as keys;
use crate::schema::managed_client_workspaces::dsl as workspaces;
use crate::schema::managed_clients::dsl as clients;
use crate::schema::managed_key_leases::dsl as leases;
use crate::schema::managed_policies::dsl as policies;

/// How often the last use of a key is written: often enough to show on the
/// panel, rarely enough not to turn every request into a write.
const LAST_USE_RESOLUTION: i64 = 60;

pub trait ClientRepository: Send + Sync {
    fn create_client(
        &self,
        client: &ManagedClient,
        workspaces: &[ManagedClientWorkspace],
    ) -> Result<(), AppError>;
    fn create_key(
        &self,
        key: &ManagedClientKey,
        replaces: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<(), AppError>;
    fn active_key(
        &self,
        key_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(ManagedClient, ManagedClientKey)>, AppError>;
    fn touch_key(&self, key_id: &str, source: &str, now: DateTime<Utc>) -> Result<(), AppError>;
    fn revoke_key(&self, client: Uuid, key: Uuid, now: DateTime<Utc>) -> Result<bool, AppError>;
    fn client_by_slug(&self, slug: &str) -> Result<Option<ManagedClient>, AppError>;
    fn list_clients(&self) -> Result<Vec<ManagedClient>, AppError>;
    fn client_keys(&self, client: Uuid) -> Result<Vec<ManagedClientKey>, AppError>;
    fn client_workspaces(&self, client: Uuid) -> Result<Vec<ManagedClientWorkspace>, AppError>;
    fn update_client(&self, client: Uuid, settings: &ClientSettings) -> Result<(), AppError>;
    fn add_workspace(&self, workspace: &ManagedClientWorkspace) -> Result<(), AppError>;
    fn remove_workspace(&self, client: Uuid, workspace: Uuid) -> Result<bool, AppError>;
    fn suspend_client(&self, client: Uuid, now: DateTime<Utc>) -> Result<bool, AppError>;
    fn reactivate_client(&self, client: Uuid) -> Result<bool, AppError>;
}

impl ClientRepository for PoolConfig {
    fn create_client(
        &self,
        client: &ManagedClient,
        assigned: &[ManagedClientWorkspace],
    ) -> Result<(), AppError> {
        // A repeated slug or a workspace already owned by another client
        // violates a unique index: Conflict, and nothing is stored.
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

    fn create_key(
        &self,
        key: &ManagedClientKey,
        replaces: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        self.conn()?.immediate_transaction(|conn| {
            let client = Self::active_client_row(conn, &key.client_id)?;
            diesel::insert_into(keys::managed_client_keys)
                .values(key)
                .execute(conn)?;
            if let Some(previous) = replaces {
                // The previous key keeps working for the overlap only, and can
                // only be replaced once.
                let deadline = NewKeyRequest::rotation_deadline(now);
                let count = diesel::update(
                    keys::managed_client_keys
                        .filter(keys::id.eq(previous.to_string()))
                        .filter(keys::client_id.eq(&client.id))
                        .filter(keys::revoked_at.is_null())
                        .filter(keys::replaced_by.is_null())
                        .filter(keys::expires_at.gt(now)),
                )
                .set(keys::replaced_by.eq(&key.id))
                .execute(conn)?;
                if count != 1 {
                    return Err(AppError::Conflict);
                }
                diesel::update(
                    keys::managed_client_keys
                        .filter(keys::id.eq(previous.to_string()))
                        .filter(keys::expires_at.gt(deadline)),
                )
                .set(keys::expires_at.eq(deadline))
                .execute(conn)?;
            }
            Ok(())
        })
    }

    fn active_key(
        &self,
        key_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(ManagedClient, ManagedClientKey)>, AppError> {
        let mut conn = self.conn()?;
        let Some(key) = keys::managed_client_keys
            .filter(keys::key_hash.eq(key_hash))
            .filter(keys::revoked_at.is_null())
            .filter(keys::expires_at.gt(now))
            .select(ManagedClientKey::as_select())
            .first::<ManagedClientKey>(&mut conn)
            .optional()?
        else {
            return Ok(None);
        };
        let client = clients::managed_clients
            .filter(clients::id.eq(&key.client_id))
            .filter(clients::suspended_at.is_null())
            .select(ManagedClient::as_select())
            .first::<ManagedClient>(&mut conn)
            .optional()?;
        Ok(client.map(|client| (client, key)))
    }

    fn touch_key(&self, key_id: &str, source: &str, now: DateTime<Utc>) -> Result<(), AppError> {
        diesel::update(
            keys::managed_client_keys
                .filter(keys::id.eq(key_id))
                .filter(
                    keys::last_used_at
                        .is_null()
                        .or(keys::last_used_at.le(now - Duration::seconds(LAST_USE_RESOLUTION))),
                ),
        )
        .set((
            keys::last_used_at.eq(Some(now)),
            keys::last_used_source.eq(Some(source)),
        ))
        .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn revoke_key(&self, client: Uuid, key: Uuid, now: DateTime<Utc>) -> Result<bool, AppError> {
        let count = diesel::update(
            keys::managed_client_keys
                .filter(keys::id.eq(key.to_string()))
                .filter(keys::client_id.eq(client.to_string()))
                .filter(keys::revoked_at.is_null()),
        )
        .set(keys::revoked_at.eq(Some(now)))
        .execute(&mut self.conn()?)?;
        Ok(count == 1)
    }

    fn client_by_slug(&self, slug: &str) -> Result<Option<ManagedClient>, AppError> {
        Ok(clients::managed_clients
            .filter(clients::slug.eq(slug))
            .select(ManagedClient::as_select())
            .first::<ManagedClient>(&mut self.conn()?)
            .optional()?)
    }

    fn list_clients(&self) -> Result<Vec<ManagedClient>, AppError> {
        Ok(clients::managed_clients
            .order(clients::name.asc())
            .select(ManagedClient::as_select())
            .load(&mut self.conn()?)?)
    }

    fn client_keys(&self, client: Uuid) -> Result<Vec<ManagedClientKey>, AppError> {
        Ok(keys::managed_client_keys
            .filter(keys::client_id.eq(client.to_string()))
            .order(keys::created_at.desc())
            .select(ManagedClientKey::as_select())
            .load(&mut self.conn()?)?)
    }

    fn client_workspaces(&self, client: Uuid) -> Result<Vec<ManagedClientWorkspace>, AppError> {
        Ok(workspaces::managed_client_workspaces
            .filter(workspaces::client_id.eq(client.to_string()))
            .order(workspaces::created_at.asc())
            .select(ManagedClientWorkspace::as_select())
            .load(&mut self.conn()?)?)
    }

    fn update_client(&self, client: Uuid, settings: &ClientSettings) -> Result<(), AppError> {
        let client_id = client.to_string();
        self.conn()?.immediate_transaction(|conn| {
            if let Some(cap) = settings.daily_cap_usd_micros {
                // A cap below what the tenants already hold would make every
                // ceiling invalid at once: lower the ceilings first.
                if Self::daily_tenant_ceilings(conn, &client_id, None)? > cap {
                    return Err(AppError::Conflict);
                }
            }
            let models =
                serde_json::to_string(&settings.allowed_models).map_err(|_| AppError::Internal)?;
            let count = diesel::update(clients::managed_clients.filter(clients::id.eq(&client_id)))
                .set((
                    clients::name.eq(settings.name.trim()),
                    clients::allowed_models.eq(models),
                    clients::contact.eq(settings.contact.as_deref()),
                    clients::daily_cap_usd_micros.eq(settings.daily_cap_usd_micros),
                ))
                .execute(conn)?;
            if count != 1 {
                return Err(AppError::NotFound);
            }
            Ok(())
        })
    }

    fn add_workspace(&self, workspace: &ManagedClientWorkspace) -> Result<(), AppError> {
        // A workspace owned by another client violates the primary key: Conflict.
        diesel::insert_into(workspaces::managed_client_workspaces)
            .values(workspace)
            .execute(&mut self.conn()?)?;
        Ok(())
    }

    fn remove_workspace(&self, client: Uuid, workspace: Uuid) -> Result<bool, AppError> {
        let client_id = client.to_string();
        let workspace_id = workspace.to_string();
        self.conn()?.immediate_transaction(|conn| {
            let used = policies::managed_policies
                .filter(policies::client_id.eq(&client_id))
                .filter(policies::workspace_id.eq(&workspace_id))
                .count()
                .get_result::<i64>(conn)?;
            if used > 0 {
                // Budgets still create keys there.
                return Err(AppError::Conflict);
            }
            let count = diesel::delete(
                workspaces::managed_client_workspaces
                    .filter(workspaces::workspace_id.eq(&workspace_id))
                    .filter(workspaces::client_id.eq(&client_id)),
            )
            .execute(conn)?;
            Ok(count == 1)
        })
    }

    fn suspend_client(&self, client: Uuid, now: DateTime<Utc>) -> Result<bool, AppError> {
        let client_id = client.to_string();
        self.conn()?.immediate_transaction(|conn| {
            let count = diesel::update(
                clients::managed_clients
                    .filter(clients::id.eq(&client_id))
                    .filter(clients::suspended_at.is_null()),
            )
            .set(clients::suspended_at.eq(Some(now)))
            .execute(conn)?;
            if count != 1 {
                return Ok(false);
            }
            // Its API keys stop at once; reactivating needs new keys.
            diesel::update(
                keys::managed_client_keys
                    .filter(keys::client_id.eq(&client_id))
                    .filter(keys::revoked_at.is_null()),
            )
            .set(keys::revoked_at.eq(Some(now)))
            .execute(conn)?;
            // Its live provider keys join the revocation queue.
            let ids = leases::managed_key_leases
                .filter(leases::client_id.eq(&client_id))
                .filter(leases::status.eq_any(ManagedLeaseState::LIVE))
                .select(leases::id)
                .load::<String>(conn)?;
            Self::revoke_leases(conn, &ids, now)?;
            Ok(true)
        })
    }

    fn reactivate_client(&self, client: Uuid) -> Result<bool, AppError> {
        let count = diesel::update(
            clients::managed_clients
                .filter(clients::id.eq(client.to_string()))
                .filter(clients::suspended_at.is_not_null()),
        )
        .set(clients::suspended_at.eq(None::<DateTime<Utc>>))
        .execute(&mut self.conn()?)?;
        Ok(count == 1)
    }
}

impl PoolConfig {
    fn active_client_row(
        conn: &mut SqliteConnection,
        client_id: &str,
    ) -> Result<ManagedClient, AppError> {
        clients::managed_clients
            .filter(clients::id.eq(client_id))
            .filter(clients::suspended_at.is_null())
            .select(ManagedClient::as_select())
            .first::<ManagedClient>(conn)
            .optional()?
            .ok_or(AppError::Forbidden)
    }

    /// Sum of the client's daily tenant ceilings, optionally leaving one tenant out.
    pub(super) fn daily_tenant_ceilings(
        conn: &mut SqliteConnection,
        client_id: &str,
        except_tenant: Option<&str>,
    ) -> Result<i64, AppError> {
        let mut query = policies::managed_policies
            .filter(policies::client_id.eq(client_id))
            .filter(policies::owner_kind.eq(OWNER_TENANT))
            .filter(policies::bucket.eq("daily"))
            .select(policies::limit_usd_micros)
            .into_boxed();
        if let Some(tenant) = except_tenant {
            query = query.filter(policies::tenant.ne(tenant));
        }
        query
            .load::<i64>(conn)?
            .into_iter()
            .try_fold(0_i64, i64::checked_add)
            .ok_or(AppError::Conflict)
    }
}
