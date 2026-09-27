use actix_web::{HttpResponse, web};
use serde_json::json;

use crate::{error::AppError, health::HealthService, managed};

pub fn routes(config: &mut web::ServiceConfig) {
    config
        .configure(public_routes)
        .service(web::scope("/v1").configure(api_routes));
}
pub fn public_routes(config: &mut web::ServiceConfig) {
    config
        .route("/openapi.yaml", web::get().to(specification))
        .route("/health/live", web::get().to(live))
        .route("/health/ready", web::get().to(ready));
}
pub fn api_routes(config: &mut web::ServiceConfig) {
    config.service(web::scope("/managed").configure(managed::handler::routes));
}

pub async fn live() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(json!({"status":"alive"}))
}

pub async fn ready(health: web::Data<HealthService>) -> Result<HttpResponse, AppError> {
    health.check_ready().await?;
    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(json!({"status":"ready"})))
}

/// Public protocol documentation; contains no deployment secrets nor client data.
pub async fn specification() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/yaml")
        .body(include_str!("../openapi.yaml"))
}
