//! Managed OpenRouter keys through the real HTTP routes and SQLite ledger,
//! with an in-memory OpenRouter management API.
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use actix_web::{App, http::StatusCode, test, web};
use asystant_api::{
    error::AppError,
    handler,
    managed::{
        client_model::{ManagedClient, NewClientRequest, NewKeyRequest, SourceRange},
        client_service::ClientService,
        credential_service::CredentialService,
        handler::ManagedState,
        key_service::Clock,
        model::{
            ManagedFailure, ManagedFailureKind, ManagedKeyAllocation, ManagedSecret,
            OpenRouterIssuedKey, OpenRouterManagedKeyData,
        },
        openrouter::OpenRouterKeyManager,
        policy_service::PolicyService,
        reconciliation_service::{RevocationService, UsageService},
        vault::ManagedKeyVault,
    },
    repository::PoolConfig,
    source::SourceResolver,
};
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

const VAULT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const WORKSPACE: &str = "6f1d7c1e-2b7a-4c8e-9a51-3d2f0b9e4a17";
const OTHER_WORKSPACE: &str = "0b8e3a52-7c41-4d6f-8e2a-91c5f3d7a604";

/// What the next `create_key` call does.
enum Creation {
    /// OpenRouter answers 400: it proves nothing was created.
    Rejected,
    /// The key is created at OpenRouter but the response never arrives.
    LostResponse,
}

#[derive(Default)]
struct FakeState {
    created: Vec<ManagedKeyAllocation>,
    disabled: Vec<String>,
    keys: BTreeMap<String, OpenRouterManagedKeyData>,
    next: VecDeque<Creation>,
}

#[derive(Clone, Default)]
struct FakeOpenRouter(Arc<Mutex<FakeState>>);

impl FakeOpenRouter {
    fn then(&self, creation: Creation) {
        self.0.lock().unwrap().next.push_back(creation);
    }
    fn set_usage(&self, hash: &str, usd: f64) {
        self.0.lock().unwrap().keys.get_mut(hash).unwrap().usage = usd;
    }
    fn created(&self) -> usize {
        self.0.lock().unwrap().created.len()
    }
}

fn not_found() -> AppError {
    AppError::Managed(ManagedFailure::new(ManagedFailureKind::NotFound))
}

#[async_trait::async_trait]
impl OpenRouterKeyManager for FakeOpenRouter {
    async fn create_key(
        &self,
        allocation: &ManagedKeyAllocation,
    ) -> Result<OpenRouterIssuedKey, AppError> {
        let mut state = self.0.lock().unwrap();
        let next = state.next.pop_front();
        if matches!(next, Some(Creation::Rejected)) {
            return Err(AppError::Managed(ManagedFailure::from_http(400)));
        }
        let number = state.created.len() + 1;
        let data = OpenRouterManagedKeyData {
            hash: format!("{number:064x}"),
            name: allocation.provider_name(),
            disabled: false,
            limit: Some(allocation.limit_usd()),
            limit_reset: None,
            include_byok_in_limit: true,
            usage: 0.0,
            byok_usage: 0.0,
            expires_at: Some(allocation.expires_at),
            workspace_id: Some(allocation.workspace_id),
        };
        state.created.push(allocation.clone());
        state.keys.insert(data.hash.clone(), data.clone());
        if matches!(next, Some(Creation::LostResponse)) {
            return Err(AppError::Managed(ManagedFailure::new(
                ManagedFailureKind::Transport,
            )));
        }
        Ok(OpenRouterIssuedKey {
            data,
            key: ManagedSecret::new(format!("sk-or-v1-test-{number}")).unwrap(),
        })
    }
    async fn get_key(&self, hash: &str) -> Result<OpenRouterManagedKeyData, AppError> {
        self.0
            .lock()
            .unwrap()
            .keys
            .get(hash)
            .cloned()
            .ok_or_else(not_found)
    }
    async fn disable_key(&self, hash: &str) -> Result<OpenRouterManagedKeyData, AppError> {
        let mut state = self.0.lock().unwrap();
        let key = state.keys.get_mut(hash).ok_or_else(not_found)?;
        key.disabled = true;
        let key = key.clone();
        state.disabled.push(hash.to_string());
        Ok(key)
    }
    async fn list_keys(
        &self,
        workspace_id: Uuid,
        offset: usize,
    ) -> Result<Vec<OpenRouterManagedKeyData>, AppError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .keys
            .values()
            .filter(|key| key.workspace_id == Some(workspace_id))
            .skip(offset)
            .cloned()
            .collect())
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    pool: PoolConfig,
    fake: FakeOpenRouter,
    state: web::Data<ManagedState>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let pool = PoolConfig::new(dir.path().join("managed.db").to_str().unwrap()).unwrap();
    let fake = FakeOpenRouter::default();
    let manager: Arc<dyn OpenRouterKeyManager> = Arc::new(fake.clone());
    let vault = Arc::new(ManagedKeyVault::from_base64_key(VAULT_KEY).unwrap());
    let clock: Clock = Arc::new(Utc::now);
    let state = web::Data::new(ManagedState {
        clients: ClientService::new(pool.clone()),
        policies: PolicyService::new(pool.clone()),
        credentials: Some(CredentialService::new(pool.clone(), manager, vault, clock)),
        sources: SourceResolver::default(),
    });
    Fixture {
        _dir: dir,
        pool,
        fake,
        state,
    }
}

fn new_client(slug: &str, workspace: &str) -> NewClientRequest {
    NewClientRequest {
        slug: slug.into(),
        name: slug.into(),
        workspaces: vec![Uuid::parse_str(workspace).unwrap()],
        allowed_models: vec![],
        contact: None,
        daily_cap_usd_micros: None,
    }
}

struct Client {
    client: ManagedClient,
    key: String,
}

impl Client {
    fn key(&self) -> &str {
        &self.key
    }
}

/// A company with one key that may both issue credentials and manage budgets.
async fn client(state: &ManagedState, slug: &str, workspace: &str) -> Client {
    let client = state
        .clients
        .create(new_client(slug, workspace))
        .await
        .unwrap();
    let created = state
        .clients
        .create_key(
            &client,
            NewKeyRequest {
                label: "Backend".into(),
                can_issue: true,
                can_manage: true,
                expires_in_days: 90,
                allowed_sources: vec![],
                replaces: None,
                created_by: "test".into(),
            },
        )
        .await
        .unwrap();
    Client {
        client,
        key: created.api_key.expose().to_string(),
    }
}

fn request(method: &str, uri: &str, key: Option<&str>, body: Option<Value>) -> test::TestRequest {
    let mut request = match method {
        "GET" => test::TestRequest::get(),
        "PUT" => test::TestRequest::put(),
        _ => test::TestRequest::post(),
    }
    .uri(uri);
    if let Some(key) = key {
        request = request.insert_header(("Authorization", format!("Bearer {key}")));
    }
    if let Some(body) = body {
        request = request.set_json(body);
    }
    request
}

macro_rules! call {
    ($app:expr, $request:expr) => {{
        let response = test::call_service($app, $request.to_request()).await;
        let status = response.status();
        let cache = response
            .headers()
            .get("Cache-Control")
            .map(|value| value.to_str().unwrap().to_string());
        let body = test::read_body(response).await;
        let json: Value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, json, cache)
    }};
}

macro_rules! subject_budget {
    ($app:expr, $key:expr, $limit:expr) => {{
        let (status, body, _) = call!(
            $app,
            request(
                "PUT",
                "/v1/managed/tenants/colegio-1/subjects/docente-1/budget",
                Some($key),
                Some(json!({"bucket": "daily", "limit_usd_micros": $limit, "actor": "rector-1"})),
            )
        );
        assert_eq!(status, StatusCode::OK, "{body}");
    }};
}

macro_rules! budget {
    ($app:expr, $key:expr, $subject_limit:expr) => {{
        let (tenant, body, _) = call!(
            $app,
            request(
                "PUT",
                "/v1/managed/tenants/colegio-1/budget",
                Some($key),
                Some(json!({"workspace_id": WORKSPACE, "bucket": "daily", "limit_usd_micros": 10_000_000, "actor": "operator-1"})),
            )
        );
        assert_eq!(tenant, StatusCode::OK, "{body}");
        subject_budget!($app, $key, $subject_limit);
    }};
}

macro_rules! app {
    ($fixture:expr) => {
        test::init_service(
            App::new()
                .app_data($fixture.state.clone())
                .configure(handler::routes),
        )
        .await
    };
}

fn credential_body() -> Value {
    json!({"tenant": "colegio-1", "subject": "docente-1", "bucket": "daily"})
}

fn account<'a>(view: &'a Value, owner_kind: &str) -> &'a Value {
    view["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|account| account["owner_kind"] == owner_kind)
        .unwrap()
}

#[actix_rt::test]
async fn issues_one_provider_key_per_subject_and_day_and_reuses_it() {
    let fixture = fixture();
    let app = app!(fixture);
    let aulamas = client(&fixture.state, "aulamas", WORKSPACE).await;
    let key = aulamas.key();
    budget!(&app, key, 1_000_000);

    let (first, first_body, cache) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(key),
            Some(credential_body())
        )
    );
    assert_eq!(first, StatusCode::OK, "{first_body}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    let (second, second_body, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(key),
            Some(credential_body())
        )
    );
    assert_eq!(second, StatusCode::OK, "{second_body}");

    assert_eq!(first_body["api_key"], "sk-or-v1-test-1");
    assert_eq!(second_body["api_key"], first_body["api_key"]);
    assert_eq!(first_body["allowed_models"], json!(["openai/gpt-oss-120b"]));
    let end_of_day = ManagedKeyAllocation::end_of_day(Utc::now()).unwrap();
    let created = fixture.fake.0.lock().unwrap().created.clone();
    assert_eq!(
        created.len(),
        1,
        "the second request must reuse the sealed key"
    );
    assert!(created[0].provider_name().starts_with("aulamas:daily:"));
    assert_eq!(created[0].limit_usd_micros, 1_000_000);
    assert_eq!(created[0].expires_at, end_of_day);
    assert_eq!(created[0].workspace_id.to_string(), WORKSPACE);
    assert_eq!(
        first_body["expires_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<Utc>>()
            .unwrap(),
        end_of_day
    );
}

#[actix_rt::test]
async fn a_client_key_only_reaches_its_own_tenants_and_workspaces() {
    let fixture = fixture();
    let app = app!(fixture);
    let aulamas = client(&fixture.state, "aulamas", WORKSPACE).await;
    let turnosqr = client(&fixture.state, "turnosqr", OTHER_WORKSPACE).await;
    budget!(&app, aulamas.key(), 1_000_000);

    // A workspace belongs to one client only.
    assert!(matches!(
        fixture
            .state
            .clients
            .create(new_client("intruder", WORKSPACE))
            .await,
        Err(AppError::Conflict)
    ));
    let (hijack, _, _) = call!(
        &app,
        request(
            "PUT",
            "/v1/managed/tenants/empresa-1/budget",
            Some(turnosqr.key()),
            Some(
                json!({"workspace_id": WORKSPACE, "bucket": "daily", "limit_usd_micros": 1_000_000, "actor": "operator-2"})
            ),
        )
    );
    assert_eq!(hijack, StatusCode::FORBIDDEN);

    let (missing, _, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            None,
            Some(credential_body())
        )
    );
    assert_eq!(missing, StatusCode::UNAUTHORIZED);
    let (forged, _, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(&format!("ask_{}", "0".repeat(64))),
            Some(credential_body())
        )
    );
    assert_eq!(forged, StatusCode::UNAUTHORIZED);

    let (foreign, _, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(turnosqr.key()),
            Some(credential_body())
        )
    );
    assert_eq!(foreign, StatusCode::FORBIDDEN);
    let (overview, foreign_view, _) = call!(
        &app,
        request(
            "GET",
            "/v1/managed/tenants/colegio-1/budget",
            Some(turnosqr.key()),
            None
        )
    );
    assert_eq!(overview, StatusCode::OK);
    assert_eq!(foreign_view["policies"], json!([]));
    let (_, own_view, _) = call!(
        &app,
        request(
            "GET",
            "/v1/managed/tenants/colegio-1/budget",
            Some(aulamas.key()),
            None
        )
    );
    assert_eq!(own_view["policies"].as_array().unwrap().len(), 2);
    assert_eq!(fixture.fake.created(), 0);

    let revoked = fixture
        .state
        .clients
        .suspend(&aulamas.client)
        .await
        .unwrap();
    assert!(revoked);
    let (after_revoke, _, _) = call!(
        &app,
        request(
            "GET",
            "/v1/managed/tenants/colegio-1/budget",
            Some(aulamas.key()),
            None
        )
    );
    assert_eq!(after_revoke, StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn lowering_a_subject_budget_disables_its_provider_key() {
    let fixture = fixture();
    let app = app!(fixture);
    let aulamas = client(&fixture.state, "aulamas", WORKSPACE).await;
    let key = aulamas.key();
    budget!(&app, key, 1_000_000);
    let (issued, _, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(key),
            Some(credential_body())
        )
    );
    assert_eq!(issued, StatusCode::OK);

    subject_budget!(&app, key, 500_000);
    let confirmed = RevocationService::new(fixture.pool.clone(), Arc::new(fixture.fake.clone()))
        .reconcile_pending(Utc::now())
        .await
        .unwrap();

    assert_eq!(confirmed, 1);
    assert_eq!(
        fixture.fake.0.lock().unwrap().disabled,
        vec![format!("{:064x}", 1)]
    );
    let (_, view, _) = call!(
        &app,
        request(
            "GET",
            "/v1/managed/tenants/colegio-1/budget",
            Some(key),
            None
        )
    );
    assert_eq!(view["credentials"][0]["status"], "revoked");
}

#[actix_rt::test]
async fn confirmed_usage_settles_both_budgets_once_and_rounds_up() {
    let fixture = fixture();
    let app = app!(fixture);
    let aulamas = client(&fixture.state, "aulamas", WORKSPACE).await;
    let key = aulamas.key();
    budget!(&app, key, 1_000_000);
    let (issued, _, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(key),
            Some(credential_body())
        )
    );
    assert_eq!(issued, StatusCode::OK);
    // 0.2500001 USD is 250,000.1 micros: charged as 250,001, never less.
    fixture.fake.set_usage(&format!("{:064x}", 1), 0.2500001);

    let usage = UsageService::new(fixture.pool.clone(), Arc::new(fixture.fake.clone()));
    assert_eq!(usage.reconcile(Utc::now()).await.unwrap(), 1);
    assert_eq!(usage.reconcile(Utc::now()).await.unwrap(), 1);

    let (_, view, _) = call!(
        &app,
        request(
            "GET",
            "/v1/managed/tenants/colegio-1/budget",
            Some(key),
            None
        )
    );
    for owner in ["tenant", "subject"] {
        let account = account(&view, owner);
        assert_eq!(account["spent_usd_micros"], 250_001, "{owner}");
        assert_eq!(account["reserved_usd_micros"], 749_999, "{owner}");
    }
    assert_eq!(
        view["credentials"][0]["accounted_usage_usd_micros"],
        250_001
    );
}

#[actix_rt::test]
async fn an_uncertain_issuance_is_recovered_and_its_hidden_key_revoked_by_name() {
    let fixture = fixture();
    let app = app!(fixture);
    let aulamas = client(&fixture.state, "aulamas", WORKSPACE).await;
    let key = aulamas.key();
    budget!(&app, key, 1_000_000);
    fixture.fake.then(Creation::LostResponse);

    let (uncertain, failure, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(key),
            Some(credential_body())
        )
    );
    assert_eq!(uncertain, StatusCode::CONFLICT);
    assert_eq!(failure["code"], "managed_reconciliation_pending");
    let (_, view, _) = call!(
        &app,
        request(
            "GET",
            "/v1/managed/tenants/colegio-1/budget",
            Some(key),
            None
        )
    );
    let lease = view["credentials"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(view["credentials"][0]["status"], "uncertain");
    assert_eq!(view["credentials"][0]["can_authorize_recovery"], true);

    let (malformed, _, cache) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/tenants/colegio-1/leases/not-a-uuid/recovery",
            Some(key),
            Some(json!({}))
        )
    );
    assert_eq!(malformed, StatusCode::BAD_REQUEST);
    assert_eq!(cache.as_deref(), Some("no-store"));
    // The uncertain reservation stays held, so the replacement needs headroom.
    subject_budget!(&app, key, 1_400_000);
    let (recovered, recovery, _) = call!(
        &app,
        request(
            "POST",
            &format!("/v1/managed/tenants/colegio-1/leases/{lease}/recovery"),
            Some(key),
            Some(json!({
                "limit_usd_micros": 400_000,
                "reason": "Provider timeout during issuance",
                "acknowledge_pending_reserve": true,
                "actor": "operator-1"
            }))
        )
    );
    assert_eq!(recovered, StatusCode::OK, "{recovery}");
    assert_eq!(recovery["previous_lease_id"], lease);

    let (reissued, credential, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(key),
            Some(credential_body())
        )
    );
    assert_eq!(reissued, StatusCode::OK, "{credential}");
    assert_eq!(credential["api_key"], "sk-or-v1-test-2");
    assert_eq!(fixture.fake.created(), 2);

    // The first key exists at OpenRouter but its hash was never learned.
    let confirmed = RevocationService::new(fixture.pool.clone(), Arc::new(fixture.fake.clone()))
        .reconcile_pending(Utc::now())
        .await
        .unwrap();
    assert_eq!(confirmed, 1);
    assert_eq!(
        fixture.fake.0.lock().unwrap().disabled,
        vec![format!("{:064x}", 1)]
    );
}

#[actix_rt::test]
async fn a_rejected_creation_returns_the_claim_for_a_retry() {
    let fixture = fixture();
    let app = app!(fixture);
    let aulamas = client(&fixture.state, "aulamas", WORKSPACE).await;
    let key = aulamas.key();
    budget!(&app, key, 1_000_000);
    fixture.fake.then(Creation::Rejected);

    let (rejected, failure, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(key),
            Some(credential_body())
        )
    );
    assert_eq!(rejected, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failure["code"], "managed_creation_rejected");
    let (retried, credential, _) = call!(
        &app,
        request(
            "POST",
            "/v1/managed/credentials",
            Some(key),
            Some(credential_body())
        )
    );
    assert_eq!(retried, StatusCode::OK, "{credential}");
    assert_eq!(credential["api_key"], "sk-or-v1-test-1");
    assert_eq!(fixture.fake.created(), 1);
}

#[actix_rt::test]
async fn published_contract_documents_every_managed_route() {
    let fixture = fixture();
    let app = app!(fixture);
    let response = test::call_service(
        &app,
        test::TestRequest::get().uri("/openapi.yaml").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let contract: Value = serde_json::from_slice(&test::read_body(response).await).unwrap();
    for path in [
        "/v1/managed/credentials",
        "/v1/managed/tenants/{tenant}/budget",
        "/v1/managed/tenants/{tenant}/subjects/{subject}/budget",
        "/v1/managed/tenants/{tenant}/leases/{lease}/recovery",
    ] {
        assert!(
            contract["paths"].get(path).is_some(),
            "{path} is undocumented"
        );
    }
    assert!(contract["paths"].get("/v1/turns").is_none());
}

#[actix_rt::test]
async fn a_key_limited_to_source_addresses_refuses_every_other_address() {
    let fixture = fixture();
    let app = app!(fixture);
    let client = fixture
        .state
        .clients
        .create(new_client("aulamas", WORKSPACE))
        .await
        .unwrap();
    let created = fixture
        .state
        .clients
        .create_key(
            &client,
            NewKeyRequest {
                label: "Operations".into(),
                can_issue: false,
                can_manage: true,
                expires_in_days: 30,
                allowed_sources: vec![SourceRange::parse("10.0.0.0/8").unwrap()],
                replaces: None,
                created_by: "test".into(),
            },
        )
        .await
        .unwrap();
    let key = created.api_key.expose();
    let from = |address: [u8; 4]| {
        request(
            "GET",
            "/v1/managed/tenants/colegio-1/budget",
            Some(key),
            None,
        )
        .peer_addr((address, 40_000).into())
    };

    let (outside, _, _) = call!(&app, from([203, 0, 113, 9]));
    assert_eq!(outside, StatusCode::FORBIDDEN);
    let (inside, view, _) = call!(&app, from([10, 1, 2, 3]));
    assert_eq!(inside, StatusCode::OK, "{view}");
}
