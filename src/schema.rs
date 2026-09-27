diesel::table! {
    managed_clients (id) {
        id -> Text,
        slug -> Text,
        name -> Text,
        allowed_models -> Text,
        contact -> Nullable<Text>,
        daily_cap_usd_micros -> Nullable<BigInt>,
        created_at -> TimestamptzSqlite,
        suspended_at -> Nullable<TimestamptzSqlite>,
    }
}

diesel::table! {
    managed_client_keys (id) {
        id -> Text,
        client_id -> Text,
        label -> Text,
        display_prefix -> Text,
        display_suffix -> Text,
        key_hash -> Text,
        can_issue -> Bool,
        can_manage -> Bool,
        allowed_sources -> Text,
        created_by -> Text,
        created_at -> TimestamptzSqlite,
        expires_at -> TimestamptzSqlite,
        replaced_by -> Nullable<Text>,
        revoked_at -> Nullable<TimestamptzSqlite>,
        last_used_at -> Nullable<TimestamptzSqlite>,
        last_used_source -> Nullable<Text>,
    }
}

diesel::table! {
    admin_users (id) {
        id -> Text,
        username -> Text,
        password_hash -> Text,
        totp_sealed -> Binary,
        totp_last_step -> BigInt,
        pending_totp_sealed -> Nullable<Binary>,
        created_at -> TimestamptzSqlite,
        password_changed_at -> TimestamptzSqlite,
        last_sign_in_at -> Nullable<TimestamptzSqlite>,
        last_sign_in_source -> Nullable<Text>,
        disabled_at -> Nullable<TimestamptzSqlite>,
    }
}

diesel::table! {
    admin_sessions (id) {
        id -> Text,
        token_hash -> Text,
        admin_id -> Text,
        csrf_token -> Text,
        user_agent -> Text,
        source -> Text,
        created_at -> TimestamptzSqlite,
        last_seen_at -> TimestamptzSqlite,
        expires_at -> TimestamptzSqlite,
        revoked_at -> Nullable<TimestamptzSqlite>,
    }
}

diesel::table! {
    admin_sign_in_attempts (id) {
        id -> Text,
        username -> Text,
        source -> Text,
        succeeded -> Bool,
        created_at -> TimestamptzSqlite,
    }
}

diesel::table! {
    admin_audit_log (id) {
        id -> BigInt,
        created_at -> TimestamptzSqlite,
        actor -> Nullable<Text>,
        action -> Text,
        company_id -> Nullable<Text>,
        target -> Text,
        detail -> Text,
        source -> Text,
        result -> Text,
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
