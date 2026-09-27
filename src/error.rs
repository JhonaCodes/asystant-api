use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde_json::json;
use thiserror::Error;

use crate::managed::model::ManagedFailure;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("authentication required")]
    Authentication,
    #[error("invalid request")]
    Invalid,
    #[error("not allowed for this client")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("budget exhausted")]
    Budget,
    #[error("request conflicts with the current state")]
    Conflict,
    #[error("request limit reached")]
    Limited,
    #[error("provider unavailable")]
    Provider,
    #[error("{}", .0.message())]
    Managed(ManagedFailure),
    #[error("service unavailable")]
    Internal,
}
impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Authentication => StatusCode::UNAUTHORIZED,
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Budget => StatusCode::PAYMENT_REQUIRED,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Limited => StatusCode::TOO_MANY_REQUESTS,
            Self::Provider => StatusCode::BAD_GATEWAY,
            Self::Managed(failure) if failure.retryable() => StatusCode::SERVICE_UNAVAILABLE,
            Self::Managed(_) => StatusCode::CONFLICT,
            Self::Internal => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
    fn error_response(&self) -> HttpResponse {
        let mut response = HttpResponse::build(self.status_code());
        response.insert_header(("Cache-Control", "no-store"));
        if matches!(self, Self::Limited) {
            response.insert_header(("Retry-After", "60"));
        }
        if let Self::Managed(failure) = self {
            return response.json(json!({"error": self.to_string(), "code": failure.code()}));
        }
        response.json(json!({"error": self.to_string()}))
    }
}
impl From<diesel::result::Error> for AppError {
    fn from(error: diesel::result::Error) -> Self {
        match error {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => Self::Conflict,
            _ => Self::Internal,
        }
    }
}
