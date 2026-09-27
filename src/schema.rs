diesel::table! {
    managed_clients (id) {
        id -> Text,
        slug -> Text,
        name -> Text,
        key_hash -> Text,
        allowed_models -> Text,
        created_at -> TimestamptzSqlite,
        revoked_at -> Nullable<TimestamptzSqlite>,
    }
}

diesel::table! {
    managed_client_workspaces (workspace_id) {
        workspace_id -> Text,
        client_id -> Text,
        created_at -> TimestamptzSqlite,
    }
}

diesel::table! {
    managed_policies (id) {
        id -> Text,
        client_id -> Text,
        tenant -> Text,
        owner_kind -> Text,
        owner_id -> Text,
        workspace_id -> Text,
        bucket -> Text,
        limit_usd_micros -> BigInt,
        updated_by -> Text,
        updated_at -> TimestamptzSqlite,
    }
}

diesel::table! {
    managed_policy_events (id) {
        id -> Text,
        policy_id -> Text,
        actor -> Text,
        previous_limit_usd_micros -> Nullable<BigInt>,
        limit_usd_micros -> BigInt,
        created_at -> TimestamptzSqlite,
    }
}

diesel::table! {
    managed_budget_accounts (id) {
        id -> Text,
        client_id -> Text,
        tenant -> Text,
        owner_kind -> Text,
        owner_id -> Text,
        workspace_id -> Text,
        bucket -> Text,
        period_key -> Text,
        limit_usd_micros -> BigInt,
        spent_usd_micros -> BigInt,
        reserved_usd_micros -> BigInt,
        created_at -> TimestamptzSqlite,
        updated_at -> TimestamptzSqlite,
    }
}

diesel::table! {
    managed_key_leases (id) {
        id -> Text,
        client_id -> Text,
        client_slug -> Text,
        is_current -> Bool,
        tenant -> Text,
        subject -> Text,
        workspace_id -> Text,
        bucket -> Text,
        period_key -> Text,
        lease_date -> Date,
        limit_usd_micros -> BigInt,
        expires_at -> TimestamptzSqlite,
        status -> Text,
        key_hash -> Nullable<Text>,
        api_key_sealed -> Nullable<Binary>,
        created_at -> TimestamptzSqlite,
        updated_at -> TimestamptzSqlite,
        accounted_usage_usd_micros -> BigInt,
        usage_checked_at -> Nullable<TimestamptzSqlite>,
    }
}

diesel::table! {
    managed_attempts (id) {
        id -> Text,
        lease_id -> Text,
        stage -> Text,
        category -> Text,
        provider_status -> Nullable<Integer>,
        created_at -> TimestamptzSqlite,
        finished_at -> Nullable<TimestamptzSqlite>,
    }
}

diesel::table! {
    managed_recoveries (id) {
        id -> Text,
        client_id -> Text,
        tenant -> Text,
        previous_lease_id -> Text,
        replacement_lease_id -> Text,
        actor -> Text,
        limit_usd_micros -> BigInt,
        reason -> Text,
        created_at -> TimestamptzSqlite,
    }
}
